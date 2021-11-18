from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, Iterable, Set
from typing import List

from fastly_api import FastlyAPI, ACL


class ACLCollection:
    def __init__(self, acl_count: int, api: FastlyAPI, service_id: str, version: str):
        self.acls: List[ACL] = []
        self.api: FastlyAPI = api
        self.service_id = service_id
        self.version = version
        self.state: Set = set()
        self._create_acls(acl_count)

    def _create_acls(self, acl_count: int) -> None:
        for i in range(acl_count):
            acl_name = f"crowdsec_{i}"
            acl = self.api.create_acl_for_service(
                service_id=self.service_id, version=self.version, name=acl_name
            )
            self.acls.append(acl)

    def insert_item(self, item: str) -> bool:
        """
        Returns True if the item was successfully allocated
        """

        self.state.add(item)
        # Check if item is already present in some ACL
        if any([item in acl.entries for acl in self.acls]):
            return False
        for acl in self.acls:
            if not acl.is_full():
                acl.entries_to_add.add(item)
                acl.entry_count += 1
                return True
        return False

    def remove_item(self, item: str) -> bool:
        """
        Returns True if item is found, and removed.
        """
        self.state.discard(item)
        for acl in self.acls:
            if item not in acl.entries:
                continue
            acl.entries_to_delete.add(item)
            acl.entry_count -= 1
            return True
        return False

    def transform_state(self, new_state):
        new_state = set(new_state.keys())
        new_items = new_state - self.state
        expired_items = self.state - new_state
        for new_item in new_items:
            print(f"adding {new_item}")
            self.insert_item(new_item)

        for expired_item in expired_items:
            print(f"removing {expired_item}")
            self.remove_item(expired_item)

        self.commit()

    def commit(self) -> None:
        for i, acl in enumerate(self.acls):
            acl = self.api.process_acl(acl)
            acl.entries_to_add = set()
            acl.entries_to_delete = set()
            self.acls[i] = acl

    def generate_condtions(self) -> str:
        conditions = []
        for acl in self.acls:
            conditions.append(f"(client.ip ~ {acl.name})")

        return " || ".join(conditions)

@dataclass
class Service:
    current_conditional_by_action: Dict[str, str] = field(default_factory=dict)
    countries_by_action: Dict[str, Set[str]] = field(default_factory=dict)
    autonomoussystems_by_action: Dict[str, Set[str]] = field(default_factory=dict)
    acl_collection_by_action: Dict[str, ACLCollection] = field(default_factory=dict)

    def transform_state(self, new_state: Dict[str,str]):
        # TODO do more strict validation. 
        new_acl_state_by_action = {}
        for item, action in new_state.items():
            # hacky check to see it's not IP
            if "." not in item and ":" not in item: 
                # It's a AS number
                if item.isnumeric():
                    self.autonomoussystems_by_action[action].add(item)
                
                # It's a country. 
                elif len(item) == 2 : 
                    self.countries_by_action[action].add(item)
            else:
                new_acl_state_by_action[action] = 
    
    @staticmethod
    def generate_equalto_conditions_for_items(items:Iterable, equal_to:str):
        return " || ".join(
            [f"{equal_to} == {item}" for item in items]
        )

    def generate_conditional_for_action(self, action):
        acl_conditions = self.acl_collection_by_action[action].generate_condtions()
        country_conditions = self.generate_equalto_conditions_for_items(
            self.countries_by_action[action], "client.geo.country_code"
        )
        as_conditions = self.generate_equalto_conditions_for_items(
            self.countries_by_action[action], "client.as.number"
        )

        return f"if ( {acl_conditions} || {country_conditions} || {as_conditions} )"