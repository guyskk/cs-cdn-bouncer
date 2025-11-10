from app.ip_list import IpListBuilder


def test_ip_list_builder_initialization():
    builder = IpListBuilder(max_size=5)
    assert builder.to_list() == []
    assert builder.get_discard_list() == []


def test_add_single_ipv4():
    builder = IpListBuilder(max_size=5)
    builder.update(["192.168.1.1"])
    assert builder.to_list() == ["192.168.1.1"]


def test_add_multiple_ips_in_same_subnet():
    """测试同一网段的多个IP，IPSet会自动紧凑化合并相邻IP"""
    builder = IpListBuilder(max_size=15)
    # 添加9个IP，IPSet会自动合并相邻的IP
    builder.update([f"192.168.1.{i}" for i in range(1, 10)])
    result = builder.to_list()
    # 验证结果（IPSet会智能合并，如192.168.1.1-2合并为/31，1.4-7合并为/30等）
    assert len(result) < 9, "IPSet应该自动紧凑化合并部分相邻IP"
    # 验证所有IP都在192.168.1.x网段
    assert all(ip.startswith("192.168.1.") for ip in result)


def test_merge_subnet_after_10_ips():
    """测试添加10个同一网段的IP后会合并为/24网段"""
    builder = IpListBuilder(max_size=15)
    # 添加10个IP，应该合并为/24网段
    builder.update([f"192.168.1.{i}" for i in range(1, 11)])
    assert builder.to_list() == ["192.168.1.0/24"], "达到10个IP后应该合并为网段"


def test_max_size_limit():
    builder = IpListBuilder(max_size=2)
    builder.update(["10.0.0.1", "11.0.0.1", "12.0.0.1"])
    assert len(builder.to_list()) == 2
    assert ("12.0.0.1", "full") in builder.get_discard_list()
    assert len(builder.get_discard_list()) == 1


def test_invalid_ipv6_discarded():
    builder = IpListBuilder(max_size=5)
    builder.update(["2001:db8::1"])
    assert builder.to_list() == []
    assert ("2001:db8::1", "not ipv4") in builder.get_discard_list()


def test_cidr_notation_support():
    builder = IpListBuilder(max_size=5)
    builder.update(["172.16.0.0/24"])
    assert builder.to_list() == ["172.16.0.0/24"]


def test_get_discard_list():
    builder = IpListBuilder(max_size=1)
    builder.update(["192.168.0.1", "10.0.0.1"])
    assert builder.get_discard_list() == [("10.0.0.1", "full")]


def test_ignore_ip_functionality():
    """测试忽略IP功能 - 注意：当前实现只支持精确匹配，不支持网段匹配"""
    builder = IpListBuilder(max_size=5, ignore_ip_s=["192.168.1.1", "10.0.0.1"])
    builder.update(["192.168.1.1", "10.0.0.1", "172.16.0.1"])
    assert builder.to_list() == ["172.16.0.1"]
    assert ("192.168.1.1", "ignore") in builder.get_discard_list()
    assert ("10.0.0.1", "ignore") in builder.get_discard_list()
    assert len(builder.get_discard_list()) == 2


def test_add_to_ip_set_exceed_max_size():
    builder = IpListBuilder(max_size=1)
    builder.update(["192.168.0.0/24"])  # Should be added
    builder.update(["10.0.0.0/24"])  # Should be discarded
    assert builder.to_list() == ["192.168.0.0/24"]
    assert ("10.0.0.0/24", "full") in builder.get_discard_list()


def test_to_list_compact_output():
    """测试紧凑输出 - 需要10个IP才会合并为网段"""
    builder = IpListBuilder(max_size=15)
    # 添加10个同一网段的IP，应该合并为/24网段
    builder.update([f"192.168.1.{i}" for i in [1, 10, 20, 30, 40, 50, 100, 150, 200, 250]])
    assert builder.to_list() == ["192.168.1.0/24"], "添加10个不同IP后应该合并为网段"


def test_to_list_sorted_output():
    builder = IpListBuilder(max_size=5)
    builder.update(["10.0.2.1", "10.0.1.1", "10.0.0.1"])
    assert builder.to_list() == ["10.0.0.1", "10.0.1.1", "10.0.2.1"]
