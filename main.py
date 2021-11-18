import argparse
from pathlib import Path
from dataclasses import dataclass
from time import sleep
from typing import List

import yaml
from pycrowdsec.client import StreamClient


from fastly_api import VCL, FastlyAPI
from service import ACLCollection

fastly_api: FastlyAPI
acl_collections: List[ACLCollection] = []

# TODO: Validate config in post init method
@dataclass
class CrowdSecConfig:
    lapi_key: str
    update_frequency: int
    lapi_url: str = "http://localhost:8080/"


@dataclass
class FastlyConfig:
    token: str
    service_ids: List[str]


@dataclass
class Config:
    crowdsec_config: CrowdSecConfig
    fastly_config: FastlyConfig


def setup_fastly_api(config: FastlyConfig):
    global fastly_api
    fastly_api = FastlyAPI(config.token)


def parse_config_file(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Config file at {path} doesn't exist")
    with open(path) as f:
        data = yaml.safe_load(f)
        return Config(
            crowdsec_config=CrowdSecConfig(**data["crowdsec_config"]), 
            fastly_config=FastlyConfig(**data["fastly_config"]),
            )


def setup_fastly_infra(config: Config):
    for service_id in config.fastly_config.service_ids:
        new_version = fastly_api.create_new_version_for_service(service_id)
        acl_collection = ACLCollection(
            acl_count=1, api=fastly_api, service_id=service_id, version=new_version
        )
        acl_collections.append(acl_collection)

    for i, acl_collection in enumerate(acl_collections):
        conditions = acl_collection.generate_condtions()
        rule = f"if ({conditions} && !req.http.Fastly-FF) {{ error 403; }}  "
        print(rule)
        fastly_api.create_dynamic_vcl(
            vcl=VCL(
                content=rule,
                name=f"crowdsec_rule{i}",
                service_id=acl_collection.service_id,
                type="recv",
                version=acl_collection.version,
            )
        )
        

def run():
    crowdsec_client = StreamClient(
        api_key="8ea971e684988b15f48e49f4a080f77c",
        interval=3
    )
    crowdsec_client.run()
    while True:
        new_state = crowdsec_client.get_current_decisions()
        for acl_collection in acl_collections:
            acl_collection.transform_state(new_state)
        sleep(3)





if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-c", type=Path, help="Path to configuration file.")
    args = arg_parser.parse_args()
    config = parse_config_file(args.c)
    setup_fastly_api(config.fastly_config)
    setup_fastly_infra(config)
    run()

