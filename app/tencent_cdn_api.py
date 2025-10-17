import datetime
import logging

from tencentcloud.cdn.v20180606 import cdn_client, models
from tencentcloud.common import credential

from app.ip_list import IpListBuilder

LOG = logging.getLogger(__name__)


class TencentCdnAPI:
    def __init__(self, *, secret_id: str, secret_key: str):
        self._secret_id = secret_id
        self._secret_key = secret_key
        self._client: cdn_client.CdnClient | None = None

    def _create_client(self):
        cred = credential.Credential(self._secret_id, self._secret_key)
        client = cdn_client.CdnClient(cred, "")
        return client

    def _get_client(self):
        if not self._client:
            self._client = self._create_client()
        return self._client

    def list_domain(self, limit: int = 100) -> list[models.BriefDomain]:
        req = models.DescribeDomainsRequest()
        req.Offset = 0
        req.Limit = limit
        filter1 = models.DomainFilter()
        filter1.Name = "status"
        filter1.Value = ["online", "processing"]
        req.Filters = [filter1]
        resp = self._get_client().DescribeDomains(req)
        return resp.Domains or []

    def get_domain_config(self, domain: str) -> models.DetailDomain | None:
        req = models.DescribeDomainsConfigRequest()
        req.Offset = 0
        req.Limit = 1
        filter1 = models.DomainFilter()
        filter1.Name = "domain"
        filter1.Value = [domain]
        req.Filters = [filter1]
        resp = self._get_client().DescribeDomainsConfig(req)
        if not resp.Domains:
            return None
        return resp.Domains[0]

    def modify_domain_config(self, request: models.ModifyDomainConfigRequest):
        resp = self._get_client().ModifyDomainConfig(request)
        return resp

    def _split_ip_filter_s(self, domain_config: models.DetailDomain):
        ip_filter_s: list[models.IpFilterPathRule] = []
        if domain_config.IpFilter:
            ip_filter_s = domain_config.IpFilter.FilterRules or []
        target_ip_filter: models.IpFilterPathRule | None = None
        other_ip_filter_s: list[models.IpFilterPathRule] = []
        for ip_filter in ip_filter_s:
            if ip_filter.FilterType == "blacklist":
                remark = ip_filter.Remark or ""
                if remark.lower().startswith("crowdsec"):
                    target_ip_filter = ip_filter
                    continue
            other_ip_filter_s.append(ip_filter)
        if target_ip_filter is None:
            target_ip_filter = models.IpFilterPathRule()
        return target_ip_filter, other_ip_filter_s

    def apply_decision(self, domain: str, ban_ip_list: list[str]):
        """
        https://cloud.tencent.com/document/product/228/41431

        配置约束：
        单个规则中，IP 黑名单与 IP 白名单二选一，不可同时配置。
        最多可以配置20条规则。
        所有规则一起 IP 白名单IP/IP段可支持500个，黑名单IP/IP段可支持200个。
        不支持配置 IPV4 及 IPV6 保留地址及网段作为 IP 黑白名单。
        支持 IPV4、IPV6 地址及网段格式/X（IPV4:1≤X≤32；IPV6:1≤X≤128），不支持 IP: 端口格式。
        不支持带参数的文件目录。

        实现方案：
        创建或者获取1条ip_filter rule记录，其他记录保留
        统计其他记录中的ip黑名单，保存方便查询
        过滤筛选ip黑名单列表，排除不支持的，排除已经在其他记录中封禁的
        整合ip黑名单列表，合并相似的IP地址
        """
        domain_config = self.get_domain_config(domain)
        if domain_config is None:
            LOG.warning(f"domain not found: {domain}")
            return False
        target_ip_filter, other_ip_filter_s = self._split_ip_filter_s(domain_config)
        whitelist_ip_s = []
        blacklist_ip_s = []
        for ip_filter in other_ip_filter_s:
            ip_s = ip_filter.Filters or []
            if ip_filter.FilterType == "blacklist":
                blacklist_ip_s.extend(ip_s)
            else:
                whitelist_ip_s.extend(ip_s)
        ip_list_builder = IpListBuilder(
            max_size=200 - len(blacklist_ip_s),
            ignore_ip_s=whitelist_ip_s + blacklist_ip_s,
        )
        for ip in ban_ip_list:
            ip_list_builder.add_ip(ip)
        target_ip_s = ip_list_builder.to_list()
        discard_ip_s = ip_list_builder.get_discard_list()
        existed_ip_s = target_ip_filter.Filters or []
        if existed_ip_s == target_ip_s:
            LOG.info(f"IP list no change, no need to apply to {domain}")
            return True
        target_ip_filter.Filters = target_ip_s
        now_str = datetime.datetime.now().isoformat()
        remark = f"crowdsec {now_str}"
        target_ip_filter.Remark = remark
        target_ip_filter.FilterType = "blacklist"
        target_ip_filter.RuleType = "all"
        target_ip_filter.RulePaths = ["*"]
        filter_rule_s = list(other_ip_filter_s)
        filter_rule_s.append(target_ip_filter)
        self._log_apply_decision(
            domain=domain,
            remark=remark,
            ip_s=target_ip_s,
            discard_ip_s=discard_ip_s,
        )
        req_ip_filter = domain_config.IpFilter or models.IpFilter()
        req_ip_filter.Switch = "on"
        req_ip_filter.FilterType = "blacklist"
        req_ip_filter.FilterRules = filter_rule_s
        value_str = req_ip_filter.to_json_string()
        req = models.ModifyDomainConfigRequest()
        req.Domain = domain
        req.Route = "IpFilter"
        req.Value = '{"update":' + value_str + "}"
        resp = self.modify_domain_config(req)
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
