import argparse
import logging
import sys
from pathlib import Path
from math import ceil
from dataclasses import dataclass
from time import sleep
from typing import List

import yaml
from pycrowdsec.client import StreamClient


from fastly_api import ACL_CAPACITY, FastlyAPI
from service import ACLCollection, Service
from utils import with_suffix

VERSION = "0.0.1"

fastly_api: FastlyAPI
acl_collections: List[ACLCollection] = []
services: List[Service] = []
logger: logging.Logger = logging.getLogger("")

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
    max_items: int


@dataclass
class Config:
    log_level: str
    # log_mode: str
    crowdsec_config: CrowdSecConfig
    fastly_config: FastlyConfig

    def get_log_level(self) -> int:
        log_level_by_str = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
        }
        return log_level_by_str.get(self.log_level.lower())


class CustomFormatter(logging.Formatter):
    FORMATS = {
        logging.ERROR: "[%(asctime)s] %(levelname)s - %(message)s",
        logging.WARNING: "[%(asctime)s] %(levelname)s - %(message)s",
        logging.DEBUG: "[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s",
        "DEFAULT": "[%(asctime)s] %(levelname)s - %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


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
            log_level=data["log_level"],
        )


def setup_fastly_infra(config: Config):
    logger.info("setting up fastly infra")
    for service_id in config.fastly_config.service_ids:
        # new_version = fastly_api.create_new_version_for_service(service_id)
        new_version = "16"
        logger.info(
            with_suffix(f"new version {new_version} for service created", service_id=service_id)
        )
        # FIXME: remove this horrible hack
        acl_collection_by_action = {"ban": ""}
        for action in acl_collection_by_action:
            acl_count = ceil(config.fastly_config.max_items / ACL_CAPACITY)
            acl_collection_by_action[action] = ACLCollection(
                api=fastly_api, service_id=service_id, version=new_version, action=action
            )
            logger.info(
                with_suffix(
                    f"creating acl collection of {acl_count} acls for {action} action",
                    service_id=service_id,
                )
            )
            acl_collection_by_action[action].create_acls(acl_count)
            logger.info(
                with_suffix(f"created acl collection for {action} action", service_id=service_id)
            )

        service = Service(
            api=fastly_api,
            acl_collection_by_action=acl_collection_by_action,
            autonomoussystems_by_action={"ban": set()},
            countries_by_action={"ban": set()},
            supported_actions=["ban"],
            service_id=service_id,
            version=new_version,
        )
        services.append(service)


def set_logger(config: Config):
    logger.setLevel(config.get_log_level())
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = CustomFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info(f"Starting fastly-bouncer-v{VERSION}")


def run(config: Config):
    crowdsec_client = StreamClient(
        lapi_url=config.crowdsec_config.lapi_url,
        api_key=config.crowdsec_config.lapi_key,
        scopes=["ip", "range", "country", "as"],
        interval=3,
    )

    crowdsec_client.run()
    while True:
        new_state = crowdsec_client.get_current_decisions()
        logger.debug(f"bouncer state {new_state}")
        for service in services:
            service.transform_state(new_state)
        sleep(3)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-c", type=Path, help="Path to configuration file.")
    args = arg_parser.parse_args()
    config = parse_config_file(args.c)
    set_logger(config)
    logger.info("parsed config successfully")
    setup_fastly_api(config.fastly_config)
    setup_fastly_infra(config)
    run()
