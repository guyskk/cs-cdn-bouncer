from netaddr import IPAddress, IPNetwork, IPSet


class IpListBuilder:
    """
    IP地址列表构建器，用于智能管理IPv4地址集合，支持网段合并和容量控制。

    功能特性：
    - 自动将相同前缀的IPv4地址尝试合并为/24网段
    - 严格限制集合大小，超限时自动丢弃新IP
    - 支持输出优化后的IP列表和被丢弃的IP列表
    - 自动过滤无效或非IPv4地址
    """

    def __init__(self, *, max_size: int, ignore_ip_s: list[str] | None = None):
        self.max_size = max_size
        self._ip_set = IPSet()
        self._ignore_ip_set = IPSet(ignore_ip_s or [])
        self._discard_ip_s: list[tuple[str, str]] = []

    def _discard_ip(self, ip: str, reason: str):
        self._discard_ip_s.append((ip, reason))

    def _add_to_ip_set(self, ip: IPNetwork | IPAddress, source_ip: str):
        tmp_set = self._ip_set.copy()
        tmp_set.add(ip)
        if len(tmp_set.iter_cidrs()) <= self.max_size:
            self._ip_set = tmp_set
        else:
            self._discard_ip(source_ip, "full")

    def add_ip(self, ip: str):
        if "/" in ip:
            ip_net = IPNetwork(ip)
            if ip_net.version != 4:
                self._discard_ip(ip, "not ipv4")
                return
            if ip_net in self._ignore_ip_set:
                self._discard_ip(ip, "ignore")
                return
            self._add_to_ip_set(ip_net, ip)
        else:
            ip_obj = IPAddress(ip)
            if ip_obj.version != 4:
                self._discard_ip(ip, "not ipv4")
                return
            if ip_obj in self._ignore_ip_set:
                self._discard_ip(ip, "ignore")
                return
            # 尝试合并/24网段，如果能合并，则合并
            ip_net = IPNetwork(f"{ip}/24")
            if self._ip_set.isdisjoint(IPSet([ip_net])):
                # 不能合并，则尝试添加单个IP
                self._add_to_ip_set(ip_obj, ip)
            else:
                # 能合并，则尝试合并/24网段
                self._add_to_ip_set(ip_net, ip)

    def to_list(self):
        self._ip_set.compact()
        ret: list[str] = []
        for ip_net in self._ip_set.iter_cidrs():
            if ip_net.prefixlen == 32:
                ret.append(str(ip_net.ip))
            else:
                ret.append(str(ip_net))
        return list(sorted(ret))

    def get_discard_list(self):
        return self._discard_ip_s
