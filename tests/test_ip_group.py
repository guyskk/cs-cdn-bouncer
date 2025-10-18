from app.ip_group import IPGroupManager


def test_ip_group_manager():
    # 创建管理器
    manager = IPGroupManager(max_per_group=2000)

    # 测试1: 初始加载1500个IP
    initial_groups = [
        [f"192.168.1.{i}" for i in range(1, 1501)]  # 只有一个组，1500个IP
    ]
    manager.load(initial_groups)

    groups = manager.get_groups()
    assert len(groups) == 1
    assert len(groups[0]) == 1500

    # 测试2: 更新IP列表（添加IP）增加到2500个IP
    all_ips = [f"192.168.1.{i}" for i in range(1, 2501)]
    manager.update(all_ips)

    groups = manager.get_groups()
    assert len(groups) == 2
    assert len(groups[0]) == 2000
    assert len(groups[1]) == 500

    # 测试3: 更新IP列表（删除一些，添加一些）删除500个，添加500个
    all_ips = [f"192.168.1.{i}" for i in range(501, 2501)]  # 删除前500个
    all_ips.extend([f"10.0.0.{i}" for i in range(1, 501)])  # 添加500个新IP
    manager.update(all_ips)
    groups = manager.get_groups()
    assert len(groups) == 2
    assert len(groups[0]) == 1500
    assert len(groups[1]) == 1000


def test_ip_group_edge_case():
    # 边界情况测试
    manager = IPGroupManager(max_per_group=5)

    # 初始加载一个组
    initial_groups = [["ip1", "ip2", "ip3"]]
    manager.load(initial_groups)

    # 初始加载后
    groups = manager.get_groups()
    assert len(groups) == 1
    assert len(groups[0]) == 3

    # 更新到刚好填满一个组
    all_ips = ["ip1", "ip2", "ip3", "ip4", "ip5"]
    changes = manager.update(all_ips)
    groups = manager.get_groups()
    assert len(groups) == 1
    assert len(groups[0]) == 5
    assert changes["added"] == 2
    assert changes["removed"] == 0

    # 再添加一个IP，应该创建新组
    all_ips.append("ip6")
    changes = manager.update(all_ips)
    groups = manager.get_groups()
    assert len(groups) == 2
    assert len(groups[0]) == 5
    assert len(groups[1]) == 1
    assert changes["added"] == 1
    assert changes["removed"] == 0
