import datetime
import difflib
import logging
import textwrap
from dataclasses import dataclass

from tencentcloud.common import credential
from tencentcloud.teo.v20220901 import models, teo_client

from app.config import CONFIG
from app.ip_group import IPGroupManager
from app.ip_list import IpListBuilder

LOG = logging.getLogger(__name__)


@dataclass
class ResultRuleItem:
    rule: models.CustomRule
    ip_list: list[str]
    is_modified: bool


class TencentEdgeoneAPI:
    def __init__(self, *, secret_id: str, secret_key: str):
        self._secret_id = secret_id
        self._secret_key = secret_key
        self._max_ip_per_rule = 2000
        self._ip_limit = self._max_ip_per_rule * CONFIG.tencent_teo_max_rule
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
        target_rule_s: list[models.CustomRule] = []
        other_rule_s: list[models.CustomRule] = []
        for rule in rule_s:
            name = rule.Name or ""
            if name.lower().startswith("crowdsec"):
                target_rule_s.append(rule)
            else:
                other_rule_s.append(rule)
        target_rule_s = list(sorted(target_rule_s, key=lambda x: str(x.Name)))
        return target_rule_s, other_rule_s

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
        return rule

    def _ip_list_key(self, ip_list: list[str]):
        ip_list_str = ",".join(sorted(ip_list))
        return ip_list_str

    def _build_ip_rule_list(
        self,
        existed_rule_s: list[models.CustomRule],
        target_ip_s: list[str],
    ) -> list[ResultRuleItem]:
        existed_group_s: list[list[str]] = []
        existed_rule_d: dict[str, models.CustomRule] = {}
        for rule in existed_rule_s:
            rule_ip_s = self._get_rule_ip_list(rule)
            rule_key = self._ip_list_key(rule_ip_s)
            existed_group_s.append(rule_ip_s)
            existed_rule_d[rule_key] = rule

        # 将IP分组，并更新到已有规则中
        ip_group = IPGroupManager(max_per_group=self._max_ip_per_rule)
        ip_group.load(existed_group_s)
        ip_group.update(target_ip_s)
        target_group_s = ip_group.get_groups()

        # 构建新的IP规则列表
        result_rule_s: list[ResultRuleItem] = []
        now_str = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        for idx, group in enumerate(target_group_s):
            rule_key = self._ip_list_key(group)
            origin_rule = existed_rule_d.pop(rule_key, None)
            rule_name = f"crowdsec-{idx}-{now_str}"
            ip_rule = self._build_ip_rule(
                group,
                name=rule_name,
                origin_rule=origin_rule,
            )
            is_modified = origin_rule is None
            result_rule_s.append(
                ResultRuleItem(
                    rule=ip_rule,
                    is_modified=is_modified,
                    ip_list=group,
                )
            )

        # 复用规则ID，使用相似匹配
        def _pick_best_match_rule(key: str):
            if not existed_rule_d:
                return None
            origin_key_s = list(existed_rule_d.keys())
            match_s = difflib.get_close_matches(key, origin_key_s, n=1, cutoff=0.01)
            if not match_s:
                return None
            match_key = match_s[0]
            return existed_rule_d.pop(match_key)

        for item in result_rule_s:
            if item.rule.Id is None:
                rule_key = self._ip_list_key(item.ip_list)
                origin_rule = _pick_best_match_rule(rule_key)
                if origin_rule:
                    item.rule.Id = origin_rule.Id

        return result_rule_s

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
        existed_rule_s, other_rule_s = self._split_rule_s(zone_config)
        # 构建完整IP黑名单列表
        ip_list_builder = IpListBuilder(
            max_size=self._ip_limit,
            ignore_ip_s=[],
        )
        ip_list_builder.update(ban_ip_list)
        target_ip_s = ip_list_builder.to_list()
        discard_ip_s = ip_list_builder.get_discard_list()

        result_rule_s = self._build_ip_rule_list(
            existed_rule_s=existed_rule_s,
            target_ip_s=target_ip_s,
        )
        num_modified = sum(x.is_modified for x in result_rule_s)
        if num_modified <= 0:
            LOG.info(f"IP rules no change, no need to apply to {domain}")
            return True

        apply_rule_s = other_rule_s + [x.rule for x in result_rule_s]
        self._log_apply_decision(
            domain=domain,
            result_rule_s=result_rule_s,
            target_ip_s=target_ip_s,
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
        result_rule_s: list[ResultRuleItem],
        target_ip_s: list[str],
        discard_ip_s: list[tuple[str, str]],
    ):
        msg = f"apply decision to {domain} blacklist={len(target_ip_s)} discard={len(discard_ip_s)}"
        blacklist_str = "\n".join(target_ip_s)
        blacklist_str = textwrap.shorten(blacklist_str, 800)
        discard_str = "\n".join([f"{ip} {reason}" for ip, reason in discard_ip_s])
        discard_str = textwrap.shorten(discard_str, 800)
        for item in result_rule_s:
            flag = "modified" if item.is_modified else "no-change"
            msg += f"\nrule: {item.rule.Name} id={item.rule.Id} num_ip={len(item.ip_list)} {flag}"
        if blacklist_str:
            msg += f"\n===blacklist===\n{blacklist_str}"
        if discard_str:
            msg += f"\n===discard===\n{discard_str}"
        LOG.info(msg)
