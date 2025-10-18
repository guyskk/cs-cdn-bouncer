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
        # 当前预估CIDR数量，避免频繁计算
        self._current_cidr_count = 0
        # 当前IP集合是否已满，避免频繁计算
        self._is_full = False
        # 缓存已处理的/24网段，用于快速查找
        self._processed_net24: set[str] = set()
        # 缓存IP对象，用于一次性添加到IPSet中，性能更好
        self._buffer_ip_s: list[IPAddress | IPNetwork] = []

    def _discard_ip(self, ip: str, reason: str):
        self._discard_ip_s.append((ip, reason))

    def _flush_buffer(self):
        self._ip_set.update(self._buffer_ip_s)
        self._buffer_ip_s.clear()

    def _add_to_ip_set(
        self,
        ip: IPNetwork | IPAddress,
        source_ip: str,
        can_merge=False,
    ):
        if can_merge or self._current_cidr_count < self.max_size:
            self._buffer_ip_s.append(ip)
            self._current_cidr_count += 1
            return
        if not self._is_full:
            self._flush_buffer()
            self._current_cidr_count = len(self._ip_set.iter_cidrs())
        if self._current_cidr_count < self.max_size:
            self._buffer_ip_s.append(ip)
            self._current_cidr_count += 1
            return
        self._is_full = True
        self._discard_ip(source_ip, "full")

    def update(self, ip_list: list[str]):
        for ip in ip_list:
            self._add_ip_impl(ip)
        self._flush_buffer()

    def _add_ip_impl(self, ip: str):
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
            net24_key = str(ip_net.cidr)
            if net24_key in self._processed_net24:
                # 能合并，则尝试合并/24网段
                self._add_to_ip_set(ip_net, ip, can_merge=True)
            else:
                # 不能合并，则尝试添加单个IP
                self._add_to_ip_set(ip_obj, ip)
            self._processed_net24.add(net24_key)

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
