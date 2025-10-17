import datetime
import logging

from tencentcloud.common import credential
from tencentcloud.teo.v20220901 import models, teo_client

from app.ip_list import IpListBuilder

LOG = logging.getLogger(__name__)


class TencentEdgeoneAPI:
    def __init__(self, *, secret_id: str, secret_key: str):
        self._secret_id = secret_id
        self._secret_key = secret_key
        self._ip_limit = 2000
        self._client: teo_client.TeoClient | None = None

    def _create_client(self):
        cred = credential.Credential(self._secret_id, self._secret_key)
        client = teo_client.TeoClient(cred, "")
        return client

    def _get_client(self):
        if not self._client:
            self._client = self._create_client()
        return self._client

    def list_zone(self, limit: int = 100) -> list[models.Zone]:
        req = models.DescribeZonesRequest()
        req.Offset = 0
        req.Limit = limit
        resp = self._get_client().DescribeZones(req)
        return resp.Zones or []

    def get_zone_config(self, zone_id: str) -> models.SecurityPolicy | None:
        req = models.DescribeSecurityPolicyRequest()
        req.ZoneId = zone_id
        req.Entity = "ZoneDefaultPolicy"
        resp = self._get_client().DescribeSecurityPolicy(req)
        return resp.SecurityPolicy

    def modify_zone_config(self, request: models.ModifySecurityPolicyRequest):
        resp = self._get_client().ModifySecurityPolicy(request)
        return resp

    def _split_rule_s(self, zone_config: models.SecurityPolicy):
        rule_s: list[models.CustomRule] = []
        if zone_config.CustomRules:
            rule_s = zone_config.CustomRules.Rules or []
        other_rule_s: list[models.CustomRule] = []
        target_rule: models.CustomRule | None = None
        for rule in rule_s:
            name = rule.Name or ""
            if name.lower().startswith("crowdsec"):
                target_rule = rule
                continue
            other_rule_s.append(rule)
        return target_rule, other_rule_s

    def _get_rule_ip_list(self, rule: models.CustomRule | None) -> list[str]:
        """
        {
            "Name": "crowdsec",
            "Condition": "${http.request.ip} in ['1.202.123.0/24','101.46.136.199']",
            "Action": { "Name": "Deny" },
            "Enabled": "on",
            "Id": "2181048501",
            "RuleType": "BasicAccessRule",
            "Priority": 0
        }
        """
        if not rule:
            return []
        if rule.RuleType != "BasicAccessRule":
            return []
        cond_prefix = "${http.request.ip} in"
        cond_str: str = rule.Condition or ""
        if not cond_str.startswith(cond_prefix):
            return []
        ip_list_str = cond_str[len(cond_prefix) :].strip()
        ip_list: list[str] = []
        for item in ip_list_str.strip("[]").split(","):
            ip = item.strip().strip("'")
            ip_list.append(ip)
        return ip_list

    def _build_ip_rule(
        self,
        ip_list: list[str],
        name: str,
        origin_rule: models.CustomRule | None,
    ):
        rule = models.CustomRule()
        rule.Name = name
        ip_item_s = []
        for ip in ip_list:
            ip_item_s.append(f"'{ip}'")
        ip_list_str = "[" + ",".join(ip_item_s) + "]"
        rule.Condition = "${http.request.ip} in " + ip_list_str
        action = models.SecurityAction()
        action.Name = "Deny"
        rule.Action = action
        rule.Enabled = "on"
        rule.RuleType = "BasicAccessRule"
        rule.Priority = 0
        if origin_rule:
            rule.Id = origin_rule.Id
            rule.Enabled = origin_rule.Enabled
        return rule

    def apply_decision(self, domain: str, ban_ip_list: list[str]):
        """
        对接EdgeOne实现封禁IP
        https://cloud.tencent.com/document/api/1552/80721#SecurityConfig
        EdgeOne IP数量 限制为每个Rule 2000个IP
        """
        zone_config = self.get_zone_config(domain)
        if zone_config is None:
            LOG.warning(f"zone_id not found: {domain}")
            return False
        target_rule, other_rule_s = self._split_rule_s(zone_config)
        existed_ip_s = self._get_rule_ip_list(target_rule)
        ip_list_builder = IpListBuilder(
            max_size=self._ip_limit,
            ignore_ip_s=[],
        )
        for ip in ban_ip_list:
            ip_list_builder.add_ip(ip)
        target_ip_s = ip_list_builder.to_list()
        discard_ip_s = ip_list_builder.get_discard_list()
        if existed_ip_s == target_ip_s:
            LOG.info(f"IP list no change, no need to apply to {domain}")
            return True
        now_str = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        rule_name = f"crowdsec-{now_str}"
        ip_rule = self._build_ip_rule(
            target_ip_s,
            origin_rule=target_rule,
            name=rule_name,
        )
        apply_rule_s = other_rule_s + [ip_rule]
        self._log_apply_decision(
            domain=domain,
            remark=rule_name,
            ip_s=target_ip_s,
            discard_ip_s=discard_ip_s,
        )
        req = models.ModifySecurityPolicyRequest()
        req.ZoneId = domain
        req.Entity = "ZoneDefaultPolicy"
        req.SecurityConfig = models.SecurityConfig()
        req.SecurityPolicy = models.SecurityPolicy()
        req.SecurityPolicy.CustomRules = models.CustomRules()
        req.SecurityPolicy.CustomRules.Rules = apply_rule_s
        resp = self.modify_zone_config(req)
        LOG.info(f"modify domain {domain} success, requestId={resp.RequestId}")
        return True

    def _log_apply_decision(
        self,
        domain: str,
        remark: str,
        ip_s: list[str],
        discard_ip_s: list[tuple[str, str]],
    ):
        title = f"apply decision to {domain} blacklist={len(ip_s)} discard={len(discard_ip_s)}"
        LOG.info(title)
        blacklist_str = "\n".join(ip_s)
        discard_str = "\n".join([f"{ip} {reason}" for ip, reason in discard_ip_s])
        msg = f"{remark}"
        if blacklist_str:
            msg += f"\n===blacklist===\n{blacklist_str}"
        if discard_str:
            msg += f"\n===discard===\n{discard_str}"
        LOG.info(msg)
