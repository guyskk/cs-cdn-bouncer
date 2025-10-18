class IPGroupManager:
    def __init__(self, max_per_group=2000):
        self.max_per_group = max_per_group
        self.groups: list[set[str]] = []  # 组的列表，每个组是一个IP集合
        self.ip_to_group: dict[str, int] = {}  # IP到组索引的映射

    def load(self, existed_groups: list[list[str]]):
        """
        加载现有的分组和IP
        existed_groups: 列表，每个元素是一个IP列表，表示一个组
        """
        self.groups = []
        self.ip_to_group = {}

        # 加载现有分组
        for group_ips in existed_groups:
            group_set = set(group_ips)
            self.groups.append(group_set)

            # 建立IP到组的映射
            group_idx = len(self.groups) - 1
            for ip in group_ips:
                self.ip_to_group[ip] = group_idx

    def update(self, all_ip_list: list[str]):
        """
        根据所有IP列表更新分组
        all_ip_list: 当前所有的IP列表
        """
        # 将输入转换为集合以便比较
        current_ips = set(all_ip_list)
        previous_ips = set(self.ip_to_group.keys())

        # 计算需要删除和添加的IP
        ips_to_remove = previous_ips - current_ips
        ips_to_add = current_ips - previous_ips

        # 执行删除操作
        for ip in ips_to_remove:
            self._remove_ip(ip)

        # 执行添加操作
        for ip in ips_to_add:
            self._add_ip(ip)

        # 返回变化统计
        return {
            "removed": len(ips_to_remove),
            "added": len(ips_to_add),
            "group_count": len(self.groups),
            "total_ips": len(current_ips),
        }

    def _remove_ip(self, ip: str):
        """内部方法：移除IP"""
        if ip in self.ip_to_group:
            group_idx = self.ip_to_group[ip]
            self.groups[group_idx].remove(ip)
            self.ip_to_group.pop(ip)
            # 删除空组
            if not self.groups[group_idx]:
                self.groups.pop(group_idx)

    def _add_ip(self, ip: str):
        """内部方法：添加IP到合适的组"""
        # 按组大小排序，优先选择IP数量少的组
        sorted_groups = sorted(enumerate(self.groups), key=lambda x: len(x[1]))

        # 寻找第一个未满的组
        for group_idx, group in sorted_groups:
            if len(group) < self.max_per_group:
                self.groups[group_idx].add(ip)
                self.ip_to_group[ip] = group_idx
                return group_idx

        # 如果所有组都满了，创建新组
        new_group_idx = len(self.groups)
        self.groups.append(set())
        self.groups[new_group_idx].add(ip)
        self.ip_to_group[ip] = new_group_idx
        return new_group_idx

    def get_groups(self):
        """获取当前分组情况"""
        return [list(sorted(group)) for group in self.groups]

    def get_total_ip_count(self):
        """获取总IP数量"""
        return len(self.ip_to_group)
