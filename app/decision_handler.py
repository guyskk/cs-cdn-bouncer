import logging
import time
from collections import OrderedDict

from pycrowdsec.client import QueryClient, StreamDecisionClient

from app.config import CONFIG
from app.tencent_cdn_api import TencentCdnAPI
from app.tencent_edgeone_api import TencentEdgeoneAPI

LOG = logging.getLogger(__name__)


class CrowdsecDecisionHandler:
    def __init__(self) -> None:
        self.crowdsec_client = StreamDecisionClient(
            lapi_url=CONFIG.crowdsec_lapi_url,
            api_key=CONFIG.crowdsec_lapi_key,
            interval=CONFIG.crowdsec_stream_interval,
            scopes=["ip", "range"],
            only_include_decisions_from=["crowdsec"],
        )
        if CONFIG.tencent_cdn_domain:
            self.cdn_api = TencentCdnAPI(
                secret_id=CONFIG.tencent_secret_id,
                secret_key=CONFIG.tencent_secret_key,
            )
        else:
            self.cdn_api = None
        if CONFIG.tencent_teo_zone_id:
            self.teo_api = TencentEdgeoneAPI(
                secret_id=CONFIG.tencent_secret_id,
                secret_key=CONFIG.tencent_secret_key,
            )
        else:
            self.teo_api = None
        # decision dict: value(ip) -> decision
        self._current_decision_d = OrderedDict()

    def _check_crowdsec_client(self):
        client = QueryClient(
            api_key=self.crowdsec_client.api_key,
            lapi_url=self.crowdsec_client.lapi_url,
        )
        client.get_decisions_for("1.1.1.1")

    def _check_target_api(self):
        domain = CONFIG.tencent_cdn_domain
        if self.cdn_api and domain:
            result = self.cdn_api.get_domain_config(domain)
            if result is None:
                raise RuntimeError(f"tencent cdn domain {domain} not found")
        zone_id = CONFIG.tencent_teo_zone_id
        if self.teo_api and zone_id:
            result = self.teo_api.get_zone_config(zone_id)
            if result is None:
                raise RuntimeError(f"tencent teo zone {zone_id} not found")

    def _get_ban_ip_list(self):
        ret = [x["value"] for x in self._current_decision_d.values()]
        # 按倒序排列，decision中越新的越靠后
        return list(reversed(ret))

    def _apply_decision(self, ban_ip_list: list[str]):
        domain = CONFIG.tencent_cdn_domain
        if self.cdn_api and domain:
            self.cdn_api.apply_decision(domain=domain, ban_ip_list=ban_ip_list)
        zone_id = CONFIG.tencent_teo_zone_id
        if self.teo_api and zone_id:
            self.teo_api.apply_decision(domain=zone_id, ban_ip_list=ban_ip_list)

    def _handle_crowdsec_decision(self):
        """
        Decision example: {
            "duration": "1m43s",
            "id": 301011,
            "origin": "crowdsec",
            "scenario": "crowdsecurity/http-probing",
            "scope": "Ip",
            "type": "ban",
            "uuid": "0999cdb8-833c-49ec-8054-876d574eead2",
            "value": "x.x.x.x"
        }
        """
        for decision in self.crowdsec_client.get_deleted_decision():
            ip = decision["value"]
            self._current_decision_d.pop(ip, None)
        new_decision_ip_s = []
        for decision in self.crowdsec_client.get_new_decision():
            ip = decision["value"]
            self._current_decision_d[ip] = decision
            new_decision_ip_s.append(ip)
        num_new = len(new_decision_ip_s)
        if num_new > 0:
            ip_list_str = "\n".join(new_decision_ip_s)
            LOG.info(f"new crowdsec decision num={num_new}:\n{ip_list_str}")
            ban_ip_list = self._get_ban_ip_list()
            self._apply_decision(ban_ip_list)

    def main(self, dryrun: bool = False):
        flag = "[DRYRUN] " if dryrun else ""
        LOG.info(f"{flag}starting crowdsec cdn bouncer")
        self._check_crowdsec_client()
        self._check_target_api()
        self.crowdsec_client.run()
        # Wait for initial polling by bouncer, so we start with a hydrated state
        time.sleep(3)
        LOG.info(f"{flag}crowdsec cdn bouncer running")
        if dryrun:
            return
        while True and self.crowdsec_client.is_running():
            time.sleep(10)
            try:
                self._handle_crowdsec_decision()
            except Exception as ex:
                LOG.error(f"handle crowdsec decision error {ex}", exc_info=ex)
                time.sleep(30)
