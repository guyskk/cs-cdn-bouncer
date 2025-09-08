from app.ip_list import IpListBuilder


def test_ip_list_builder_initialization():
    builder = IpListBuilder(max_size=5)
    assert builder.to_list() == []
    assert builder.get_discard_list() == []


def test_add_single_ipv4():
    builder = IpListBuilder(max_size=5)
    builder.add_ip("192.168.1.1")
    assert builder.to_list() == ["192.168.1.1"]


def test_add_multiple_ips_in_same_subnet():
    builder = IpListBuilder(max_size=5)
    builder.add_ip("192.168.1.1")
    builder.add_ip("192.168.1.2")
    assert builder.to_list() == ["192.168.1.0/24"]


def test_max_size_limit():
    builder = IpListBuilder(max_size=2)
    builder.add_ip("10.0.0.1")
    builder.add_ip("11.0.0.1")
    builder.add_ip("12.0.0.1")
    assert len(builder.to_list()) == 2
    assert ("12.0.0.1", "full") in builder.get_discard_list()
    assert len(builder.get_discard_list()) == 1


def test_invalid_ipv6_discarded():
    builder = IpListBuilder(max_size=5)
    builder.add_ip("2001:db8::1")
    assert builder.to_list() == []
    assert ("2001:db8::1", "not ipv4") in builder.get_discard_list()


def test_cidr_notation_support():
    builder = IpListBuilder(max_size=5)
    builder.add_ip("172.16.0.0/24")
    assert builder.to_list() == ["172.16.0.0/24"]


def test_get_discard_list():
    builder = IpListBuilder(max_size=1)
    builder.add_ip("192.168.0.1")
    builder.add_ip("10.0.0.1")
    assert builder.get_discard_list() == [("10.0.0.1", "full")]


def test_ignore_ip_functionality():
    builder = IpListBuilder(max_size=5, ignore_ip_s=["192.168.1.1/32", "10.0.0.0/24"])
    builder.add_ip("192.168.1.1")
    builder.add_ip("10.0.0.1")
    builder.add_ip("172.16.0.1")
    assert builder.to_list() == ["172.16.0.1"]
    assert ("192.168.1.1", "ignore") in builder.get_discard_list()
    assert ("10.0.0.1", "ignore") in builder.get_discard_list()
    assert len(builder.get_discard_list()) == 2


def test_add_to_ip_set_exceed_max_size():
    builder = IpListBuilder(max_size=1)
    builder.add_ip("192.168.0.0/24")  # Should be added
    builder.add_ip("10.0.0.0/24")  # Should be discarded
    assert builder.to_list() == ["192.168.0.0/24"]
    assert ("10.0.0.0/24", "full") in builder.get_discard_list()


def test_to_list_compact_output():
    builder = IpListBuilder(max_size=10)
    builder.add_ip("192.168.1.1")
    builder.add_ip("192.168.1.255")
    assert builder.to_list() == ["192.168.1.0/24"]


def test_to_list_sorted_output():
    builder = IpListBuilder(max_size=5)
    builder.add_ip("10.0.2.1")
    builder.add_ip("10.0.1.1")
    builder.add_ip("10.0.0.1")
    assert builder.to_list() == ["10.0.0.1", "10.0.1.1", "10.0.2.1"]
