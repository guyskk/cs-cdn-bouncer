import argparse
import csv
import logging
from logging.handlers import RotatingFileHandler
import sys
from pathlib import Path
from math import ceil
from dataclasses import asdict, dataclass, field
from time import sleep
from typing import Dict, List
from multiprocessing.pool import ThreadPool
from importlib.metadata import version

import yaml
import requests
from pycrowdsec.client import StreamClient


from fastly_bouncer.fastly_api import ACL_CAPACITY, FastlyAPI
from fastly_bouncer.service import ACLCollection, Service
from fastly_bouncer.utils import with_suffix, SUPPORTED_ACTIONS, DELETE_LIST_FILE, are_filled_validator, get_default_logger, CustomFormatter

VERSION = version("cs-fastly-bouncer")

acl_collections: List[ACLCollection] = []
services: List[Service] = []

logger: logging.Logger = get_default_logger()



# TODO: Validate config in post init method
@dataclass
class CrowdSecConfig:
    lapi_key: str
    lapi_url: str = "http://localhost:8080/"

    def __post_init__(self):
        are_filled_validator(
            **{key: getattr(self, key) for key in  asdict(self).keys() }
        )


@dataclass
class FastlyServiceConfig:
    id: str
    recaptcha_site_key: str
    recaptcha_secret_key: str
    max_items: int = 5000

    def __post_init__(self):
        are_filled_validator(
            **{key: getattr(self, key) for key in  asdict(self).keys() }  
        )


@dataclass
class FastlyAccountConfig:
    account_token: str
    services: List[FastlyServiceConfig]


def fastly_config_from_dict(data: Dict) -> List[FastlyAccountConfig]:
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
    return account_configs


@dataclass
class Config:
    log_level: str
    log_mode: str
    log_file: str
    update_frequency: int
    crowdsec_config: CrowdSecConfig
    fastly_account_configs: List[FastlyAccountConfig] = field(default_factory=list)

    def get_log_level(self) -> int:
        log_level_by_str = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
        }
        return log_level_by_str.get(self.log_level.lower())

    def __post_init__(self):
        for i, account_config in enumerate(self.fastly_account_configs):
            if not account_config.account_token:
                raise ValueError(f" {i+1}th has no token specified in config")
            if not account_config.services:
                raise ValueError(f" {i+1}th has no service specified in config")




def parse_config_file(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Config file at {path} doesn't exist")
    with open(path) as f:
        data = yaml.safe_load(f)
        return Config(
            crowdsec_config=CrowdSecConfig(**data["crowdsec_config"]),
            fastly_account_configs=fastly_config_from_dict(data["fastly_account_configs"]),
            log_level=data["log_level"],
            log_mode=data["log_mode"],
            log_file=data["log_file"],
            update_frequency=int(data["update_frequency"]),
        )

def default_config():
    return Config(
        log_level="info",
        log_mode="stdout",
        log_file="/var/log/cs-fastly-bouncer.log",
        crowdsec_config=CrowdSecConfig(
            lapi_key="<LAPI_KEY>"
        ),
        update_frequency="10"
    )

def setup_fastly_infra(config: Config):
    logger.info("setting up fastly infra")
    def setup_account(account_cfg: FastlyAccountConfig):
        fastly_api = FastlyAPI(token=account_cfg.account_token)
        for service_cfg in account_cfg.services:
            # new_version = fastly_api.create_new_version_for_service(service_cfg.id)
            new_version = "38" # REMOVE AFTER DEBUG
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
    global logger
    list(map(logger.removeHandler, logger.handlers))
    logger.setLevel(config.get_log_level())
    if config.log_mode == "stdout":
        handler = logging.StreamHandler(sys.stdout)
    elif config.log_mode == "file":
        handler = RotatingFileHandler(
            config.log_file, mode="a+"
        )
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
        print("called API ", cols[1])

    with open(DELETE_LIST_FILE) as f:
        rows = list(csv.reader(f, delimiter=" "))
        if not rows:
            print("nothing to delete!")
            return
        with ThreadPool(len(rows)) as tp:
            tp.map(perform_delete_req, rows)


def generate_config_for_account(fastly_token:str)-> FastlyAccountConfig:
    api = FastlyAPI(fastly_token)
    all_service_name_by_id = api.get_all_service_name_by_id()
    service_configs: List[FastlyServiceConfig] = []
    for _, service_id in all_service_name_by_id.items():
        service_configs.append(
            FastlyServiceConfig(
                id=service_id,
                recaptcha_site_key="<RECAPTCHA_SITE_KEY>",
                recaptcha_secret_key="<RECAPTCHA_SECRET_KEY>",
            )
        )
    return FastlyAccountConfig(
        account_token=fastly_token,
        services=service_configs
    )

def generate_config(comma_separated_fastly_tokens: str, base_config: Config = default_config()) -> Config:
    fastly_tokens = comma_separated_fastly_tokens.split(",")
    fastly_tokens = list(map(lambda token: token.strip(), fastly_tokens))
    with ThreadPool(len(fastly_tokens)) as tp:
        account_configs = tp.map(generate_config_for_account, fastly_tokens)
    base_config.fastly_account_configs = account_configs
    return yaml.safe_dump(asdict(base_config))

def print_config(cfg, o_arg):
    if not o_arg:
        print(cfg)
    else:
        with open(o_arg, "w") as f:
            f.write(cfg)



def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-c", type=Path, help="Path to configuration file.")
    arg_parser.add_argument("-d", help="Whether to cleanup resources.", action='store_true')
    arg_parser.add_argument("-g", type=str, help="Comma separated tokens to generate config for.")
    arg_parser.add_argument("-o", type=str, help="Path to file to output the generated config.")
    arg_parser.add_help = True 
    args = arg_parser.parse_args()
    if not args.c:
        if args.d :
            cleanup()
            sys.exit(0)
        if args.g:
            gc = generate_config(args.g)
            print_config(gc, args.o)
            sys.exit(0)

        arg_parser.print_help()
        sys.exit(1)
    try:
        config = parse_config_file(args.c)
        set_logger(config)
    except ValueError as e:
        logger.error(f"got error {e} while parsing config at {args.c}")
        sys.exit(1)

    if args.g:
        gc = generate_config(args.g, base_config=config)
        print_config(gc, args.o)
        sys.exit(0)

    logger.info("parsed config successfully")
    setup_fastly_infra(config)
    run(config)

if __name__ == "__main__":
    main()