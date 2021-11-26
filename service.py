from collections import defaultdict
from dataclasses import dataclass, field
import logging
from multiprocessing.pool import ThreadPool
from typing import Dict, Iterable, Set
from typing import List

import vcl_templates
from fastly_api import VCL, FastlyAPI, ACL
from utils import with_suffix

logger: logging.Logger = logging.getLogger("")


class ACLCollection:
    def __init__(self, api: FastlyAPI, service_id: str, version: str, action: str):
        self.acls: List[ACL] = []
        self.api: FastlyAPI = api
        self.service_id = service_id
        self.version = version
        self.action = action
        self.state: Set = set()

    def create_acls(self, acl_count: int) -> None:
        def create_acl(i):
            acl_name = f"crowdsec_{self.action}_{i}"
            logger.info(with_suffix(f"creating acl {acl_name} ", service_id=self.service_id))
            acl = self.api.create_acl_for_service(
                service_id=self.service_id, version=self.version, name=acl_name
            )
            logger.info(with_suffix(f"created acl {acl_name}", service_id=self.service_id))
            self.acls.append(acl)

        with ThreadPool(acl_count) as tp:
            tp.map(create_acl, range(acl_count))

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

    def transform_to_state(self, new_state):
        new_items = new_state - self.state
        expired_items = self.state - new_state
        if new_items:
            logger.info(
                with_suffix(f"adding {new_items} to acl collection", service_id=self.service_id)
            )

        if expired_items:
            logger.info(
                with_suffix(
                    f"removing {expired_items} from acl collection", service_id=self.service_id
                )
            )

        for new_item in new_items:
            self.insert_item(new_item)

        for expired_item in expired_items:
            self.remove_item(expired_item)

    def commit(self) -> None:
        acls_to_change = list(
            filter(lambda acl: acl.entries_to_add or acl.entries_to_delete, self.acls)
        )

        def update_acl(acl: ACL):
            logger.debug(
                with_suffix(
                    f"commiting changes to acl {acl.name}",
                    service_id=self.service_id,
                    acl_collection=self.action,
                )
            )
            self.api.process_acl(acl)
            logger.debug(
                with_suffix(
                    f"commited changes to acl {acl.name}",
                    service_id=self.service_id,
                    acl_collection=self.action,
                )
            )
            acl.entries_to_add = set()
            acl.entries_to_delete = set()

        if len(acls_to_change):
            with ThreadPool(len(acls_to_change)) as tp:
                tp.map(update_acl, acls_to_change)
                logger.info(
                    with_suffix(
                        f"acl collection for {self.action} updated", service_id=self.service_id
                    )
                )

    def generate_condtions(self) -> str:
        conditions = []
        for acl in self.acls:
            conditions.append(f"(client.ip ~ {acl.name})")

        return " || ".join(conditions)


@dataclass
class Service:
    api: FastlyAPI
    version: str
    service_id: str
    recaptcha_site_key: str
    recaptcha_secret: str
    supported_actions: List = field(default_factory=list)
    vcl_by_action: Dict[str, VCL] = field(default_factory=dict)
    static_vcls: List[VCL] = field(default_factory=list)
    current_conditional_by_action: Dict[str, str] = field(default_factory=dict)
    countries_by_action: Dict[str, Set[str]] = field(default_factory=dict)
    autonomoussystems_by_action: Dict[str, Set[str]] = field(default_factory=dict)
    acl_collection_by_action: Dict[str, ACLCollection] = field(default_factory=dict)

    def __post_init__(self):
        if not self.supported_actions:
            self.supported_actions = ["ban", "captcha"]
        
        self.countries_by_action = {action: set() for action in self.supported_actions}
        self.autonomoussystems_by_action = {action: set() for action in self.supported_actions}

        if not self.vcl_by_action:
            self.vcl_by_action = {
                "ban": VCL(
                    name="crowdsec_ban_rule",
                    service_id=self.service_id,
                    action='error 403 "Forbidden";',
                    version=self.version,
                ),
                "captcha": VCL(
                    name="crowdsec_captcha_rule",
                    service_id=self.service_id,
                    version=self.version,
                    action=vcl_templates.CAPTCHA_RECV_VCL.format(
                        RECAPTCHA_SECRET=self.recaptcha_secret,
                    ),
                ),
            }
            for action in [action for action in self.vcl_by_action if action not in self.supported_actions]:
                del self.vcl_by_action[action]

        if not self.static_vcls and "captcha" in self.supported_actions:
            self.static_vcls = [
                VCL(
                    name=f"crowdsec_captcha_renderer",
                    service_id=self.service_id,
                    action=vcl_templates.CAPTCHA_RENDER_VCL.format(
                        RECAPTCHA_SITE_KEY=self.recaptcha_site_key
                    ),
                    version=self.version,
                    type="error",
                ),
                VCL(
                    name=f"crowdsec_captcha_validator",
                    service_id=self.service_id,
                    action=vcl_templates.CAPTCHA_VALIDATOR_VCL,
                    version=self.version,
                    type="deliver",
                ),
                VCL(
                    name=f"crowdsec_captcha_google_backend",
                    service_id=self.service_id,
                    action=vcl_templates.GOOGLE_BACKEND.format(SERVICE_ID=self.service_id),
                    version=self.version,
                    type="init",
                ),
            ]

        with ThreadPool(len(self.static_vcls)) as tp:
            res = tp.map(self.api.create_vcl, self.static_vcls)
        
    def clear_sets(self):
        for action in self.supported_actions:
            self.countries_by_action[action].clear()
            self.autonomoussystems_by_action[action].clear()


    def transform_state(self, new_state: Dict[str, str]):
        new_acl_state_by_action = {action: set() for action in self.supported_actions}
        self.clear_sets()

        for item, action in new_state.items():
            if action not in self.supported_actions:
                continue

            if (
                item in self.autonomoussystems_by_action[action]
                or item in self.countries_by_action[action]
            ):
                continue

            # hacky check to see it's not IP
            if "." not in item and ":" not in item:
                # It's a AS number
                if item.isnumeric():
                    self.autonomoussystems_by_action[action].add(item)

                # It's a country.
                elif len(item) == 2:
                    self.countries_by_action[action].add(item)
            else:
                new_acl_state_by_action[action].add(item)

        for action in new_acl_state_by_action:
            self.acl_collection_by_action[action].transform_to_state(
                new_acl_state_by_action[action]
            )
        self.commit()

    def commit(self):
        for action in self.vcl_by_action:
            self.acl_collection_by_action[action].commit()
            self.update_vcl(action)

    def update_vcl(self, action: str):
        vcl = self.vcl_by_action[action]
        new_conditional = self.generate_conditional_for_action(action)
        if new_conditional != vcl.conditional:
            vcl.conditional = new_conditional
            vcl = self.api.create_or_update_vcl(vcl)
            self.vcl_by_action[action] = vcl

    @staticmethod
    def generate_equalto_conditions_for_items(items: Iterable, equal_to: str, quote=False):
        if not quote:
            return " || ".join([f"{equal_to} == {item}" for item in items])
        return " || ".join([f'{equal_to} == "{item}"' for item in items])

    def generate_conditional_for_action(self, action):
        acl_conditions = self.acl_collection_by_action[action].generate_condtions()
        country_conditions = self.generate_equalto_conditions_for_items(
            self.countries_by_action[action], "client.geo.country_code", quote=True
        )
        as_conditions = self.generate_equalto_conditions_for_items(
            self.autonomoussystems_by_action[action], "client.as.number"
        )

        condition = " || ".join(
            [
                condition
                for condition in [acl_conditions, country_conditions, as_conditions]
                if condition
            ]
        )
        return f"if ( {condition} )"
