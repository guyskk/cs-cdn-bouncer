import ipaddress
import logging
from urllib.parse import urljoin
from dateutil.parser import parse as parse_date
from dataclasses import field, dataclass
from typing import Dict, Set, Tuple

import requests

from utils import with_suffix

logger: logging.Logger = logging.getLogger("")


ACL_CAPACITY = 100


@dataclass
class ACL:
    id: str
    name: str
    service_id: str
    version: str
    entries_to_add: Set[str] = field(default_factory=set)
    entries_to_delete: Set[str] = field(default_factory=set)
    entries: Dict[str, str] = field(default_factory=dict)
    entry_count: int = 0
    created: bool = False

    def is_full(self) -> bool:
        is_full = self.entry_count == ACL_CAPACITY
        if is_full:
            f"ACL {self.name} is full"
        return is_full


@dataclass
class VCL:
    name: str
    service_id: str
    version: str
    action: str
    conditional: str = ""
    type: str = "recv"
    dynamic: str = "1"
    id: str = ""

    def to_dict(self):
        return {
            "name": self.name,
            "service_id": self.service_id,
            "version": self.version,
            "type": self.type,
            "content": f"{self.conditional} {{ {self.action} }}",
            "dynamic": self.dynamic,
        }


class FastlyAPI:
    base_url = "https://api.fastly.com"

    def __init__(self, token):
        self.session = requests.Session()
        self.session.headers["Fastly-Key"] = token
        self.session.hooks = {"response": self.check_for_errors}
        self._acl_count = 0

    def get_version_to_clone(self, service_id: str) -> str:
        """
        Gets the version to clone from. If service has active version, then the active version will be cloned.
        Else the the version which was last updated would be cloned
        """

        service_versions_resp = self.session.get(self.api_url(f"/service/{service_id}/version"))
        service_versions = service_versions_resp.json()

        version_to_clone = None
        last_updated = None
        for service_version in service_versions:
            if not last_updated:
                version_to_clone = service_version["number"]
            elif last_updated < parse_date(service_version["updated_at"]):
                last_updated = parse_date(service_version["updated_at"])
                version_to_clone = service_version["number"]

        return str(version_to_clone)

    def create_new_version_for_service(self, service_id: str) -> str:
        """
        Creates new version for service.
        Returns the new version.
        """
        version_to_clone_from = self.get_version_to_clone(service_id)
        resp = self.session.put(
            self.api_url(f"/service/{service_id}/version/{version_to_clone_from}/clone")
        ).json()

        return str(resp["number"])

    def create_acl_for_service(self, service_id, version, name=None) -> ACL:
        """
        Create an ACL resource for the given service_id and version. If "name"
        parameter is not specified, a random name would be used for the ACL.
        Returns the id of the ACL.
        """
        if not name:
            name = f"acl_{str(self._acl_count)}"
        resp = self.session.post(
            self.api_url(f"/service/{service_id}/version/{version}/acl"), data=f"name={name}"
        ).json()
        self._acl_count += 1
        return ACL(
            id=resp["id"], service_id=service_id, version=str(version), name=name, created=True
        )

    def create_or_update_dynamic_vcl(self, vcl: VCL) -> VCL:
        if not vcl.id:
            vcl = self.create_dynamic_vcl(vcl)
        else:
            vcl = self.update_dynamic_vcl(vcl)
        return vcl

    def create_dynamic_vcl(self, vcl: VCL):
        resp = self.session.post(
            self.api_url(f"/service/{vcl.service_id}/version/{vcl.version}/snippet"),
            data=vcl.to_dict(),
        ).json()
        vcl.id = resp["id"]
        return vcl

    def update_dynamic_vcl(self, vcl: VCL):
        resp = self.session.put(
            self.api_url(f"/service/{vcl.service_id}/snippet/{vcl.id}"),
            data=vcl.to_dict(),
        ).json()
        return vcl

    def process_acl(self, acl: ACL):
        # update_entries = []
        # for entry_to_add in acl.entries_to_add:
        #     if entry_to_add in acl.entries:
        #         continue
        #     network = ipaddress.ip_network(entry_to_add)
        #     ip, subnet = str(network.network_address), network.prefixlen
        #     update_entries.append({"op": "create", "ip": ip, "subnet": subnet})

        # for entry_to_delete in acl.entries_to_delete:
        #     if entry_to_delete not in acl.entries:
        #         continue
        #     update_entries.append(
        #         {
        #             "op": "delete",
        #             "id": entry_to_delete,
        #         }
        #     )
        logger.debug(with_suffix(f"entries to delete {acl.entries_to_delete}", acl_id=acl.id))
        logger.debug(with_suffix(f"entries to add {acl.entries_to_add}", acl_id=acl.id))
    
        for entry_to_delete in acl.entries_to_delete:
            if entry_to_delete not in acl.entries:
                continue
            self.session.delete(
                self.api_url(
                    f"/service/{acl.service_id}/acl/{acl.id}/entry/{acl.entries[entry_to_delete]}"
                )
            ).json()
            del acl.entries[entry_to_delete]

        for entry_to_add in acl.entries_to_add:
            if entry_to_add in acl.entries:
                continue
            network = ipaddress.ip_network(entry_to_add)
            ip, subnet = str(network.network_address), network.prefixlen
            resp = self.session.post(
                self.api_url(f"/service/{acl.service_id}/acl/{acl.id}/entry"),
                json={
                    "ip": ip,
                    "subnet": subnet,
                },
            ).json()
            acl.entries[entry_to_add] = resp["id"]

        return acl

        # if not update_entries:
        #         return

        # for i in range(0, len(update_entries), 100):
        #     update_entries_batch = update_entries[i:i + 100]
        #     request_body = {"entries": update_entries_batch}
        #     resp = self.session.patch(
        #         self.api_url(f"/service/{acl.service_id}/acl/{acl.id}/entries"),
        #         json=request_body
        #     ).json()

    @staticmethod
    def api_url(endpoint: str) -> str:
        return urljoin(FastlyAPI.base_url, endpoint)

    @staticmethod
    def check_for_errors(resp, *args, **kwargs):
        resp.raise_for_status()
