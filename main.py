import argparse
import csv
import logging
import sys
from pathlib import Path
from math import ceil
from dataclasses import dataclass
from time import sleep
from typing import Dict, List
from multiprocessing.pool import ThreadPool
import requests

import yaml
from pycrowdsec.client import StreamClient


from fastly_api import ACL_CAPACITY, FastlyAPI
from service import ACLCollection, Service
from utils import with_suffix, SUPPORTED_ACTIONS, DELETE_LIST_FILE

VERSION = "0.0.1"

acl_collections: List[ACLCollection] = []
services: List[Service] = []
logger: logging.Logger = logging.getLogger("")

# TODO: Validate config in post init method
@dataclass
class CrowdSecConfig:
    lapi_key: str
    lapi_url: str = "http://localhost:8080/"


@dataclass
class FastlyServiceConfig:
    id: str
    max_items: int
    recaptcha_site_key: str
    recaptcha_secret_key: str


@dataclass
class FastlyAccountConfig:
    account_token: str
    services: List[FastlyServiceConfig]


@dataclass
class FastlyConfig:
    configs: List[FastlyAccountConfig]

def fastly_config_from_dict(data: Dict) -> FastlyConfig:
    account_configs: List[FastlyAccountConfig] = []
    for account_cfg in data:
        service_configs: List[FastlyServiceConfig] = []
        for service_cfg in account_cfg["services"]:
            service_configs.append(FastlyServiceConfig(**service_cfg))
        account_configs.append(
            FastlyAccountConfig(
                account_token=account_cfg["account_token"], services=service_configs
            )
        )
    return FastlyConfig(account_configs)


@dataclass
class Config:
    log_level: str
    update_frequency: int
    crowdsec_config: CrowdSecConfig
    fastly_account_configs: FastlyConfig

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


def parse_config_file(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Config file at {path} doesn't exist")
    with open(path) as f:
        data = yaml.safe_load(f)
        return Config(
            crowdsec_config=CrowdSecConfig(**data["crowdsec_config"]),
            fastly_account_configs=fastly_config_from_dict(data["fastly_account_configs"]),
            log_level=data["log_level"],
            update_frequency=int(data["update_frequency"]),
        )


def setup_fastly_infra(config: Config):
    logger.info("setting up fastly infra")
    # for account_cfg in config.fastly_account_configs.fastly_account_configs:
    def setup_account(account_cfg: FastlyAccountConfig):
        fastly_api = FastlyAPI(token=account_cfg.account_token)
        for service_cfg in account_cfg.services:
            # new_version = fastly_api.create_new_version_for_service(service_cfg.id)
            new_version = "38"
            logger.info(
                with_suffix(
                    f"new version {new_version} for service created", service_id=service_cfg.id
                )
            )
            acl_collection_by_action = {}
            def setup_action_for_service(action):
            # for action in SUPPORTED_ACTIONS:
                acl_count = ceil(service_cfg.max_items/ ACL_CAPACITY)
                acl_collection_by_action[action] = ACLCollection(
                    api=fastly_api, service_id=service_cfg.id, version=new_version, action=action
                )
                logger.info(
                    with_suffix(
                        f"creating acl collection of {acl_count} acls for {action} action",
                        service_id=service_cfg.id,
                    )
                )
                acl_collection_by_action[action].create_acls(acl_count)
                logger.info(
                    with_suffix(
                        f"created acl collection for {action} action", service_id=service_cfg.id
                    )
                )

            with ThreadPool(len(SUPPORTED_ACTIONS)) as tp:
                tp.map(setup_action_for_service, SUPPORTED_ACTIONS)

            service = Service(
                api=fastly_api,
                recaptcha_secret=service_cfg.recaptcha_secret_key,
                recaptcha_site_key=service_cfg.recaptcha_site_key,
                acl_collection_by_action=acl_collection_by_action,
                service_id=service_cfg.id,
                version=new_version,
            )
            services.append(service)

    with ThreadPool(len(config.fastly_account_configs.configs)) as parent_tp:
        parent_tp.map(setup_account, config.fastly_account_configs.configs)


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
        interval=config.update_frequency,
    )

    crowdsec_client.run()
    while True:
        new_state = crowdsec_client.get_current_decisions()
        with ThreadPool(len(services)) as tp:
            tp.map(lambda service: service.transform_state(new_state), services)
        sleep(config.update_frequency)

def cleanup():
    def perform_delete_req(cols):
        requests.delete(
            url=cols[1],
            headers={"Fastly-Key": cols[0]}
        )
        print("called ", cols[1])

    with open(DELETE_LIST_FILE) as f:
        rows = list(csv.reader(f, delimiter=" "))
        with ThreadPool(len(rows)) as tp:
            tp.map(perform_delete_req, rows)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-c", type=Path, help="Path to configuration file.")
    arg_parser.add_argument("-d", help="Whether to cleanup resources.", action='store_true')
    arg_parser.add_help = True 
    args = arg_parser.parse_args()
    if not args.c:
        if "d" in args :
            cleanup()
            sys.exit(0)
        arg_parser.print_help()
        sys.exit(1)
    config = parse_config_file(args.c)
    set_logger(config)
    logger.info("parsed config successfully")
    setup_fastly_infra(config)
    run(config)
