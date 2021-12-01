import argparse
import csv
import logging
from logging.handlers import RotatingFileHandler
import sys
from pathlib import Path
from math import ceil
from time import sleep
from typing import List
from multiprocessing.pool import ThreadPool
from importlib.metadata import version

import requests
from pycrowdsec.client import StreamClient


from fastly_bouncer.fastly_api import ACL_CAPACITY, FastlyAPI
from fastly_bouncer.service import ACLCollection, Service
from fastly_bouncer.utils import (
    with_suffix,
    SUPPORTED_ACTIONS,
    DELETE_LIST_FILE,
    get_default_logger,
    CustomFormatter,
)
from fastly_bouncer.config import (
    Config,
    FastlyAccountConfig,
    FastlyServiceConfig,
    generate_config,
    parse_config_file,
    print_config,
)


VERSION = version("crowdsec-fastly-bouncer")

acl_collections: List[ACLCollection] = []
services: List[Service] = []

logger: logging.Logger = get_default_logger()


# TODO Avoid nested functions by using starmap
def setup_fastly_infra(config: Config):
    logger.info("setting up fastly infra")

    def setup_account(account_cfg: FastlyAccountConfig):
        fastly_api = FastlyAPI(token=account_cfg.account_token)

        def setup_service(service_cfg: FastlyServiceConfig) -> Service:
            new_version = fastly_api.create_new_version_for_service(service_cfg.id)
            logger.info(
                with_suffix(
                    f"new version {new_version} for service created", service_id=service_cfg.id
                )
            )
            fastly_api.clear_crowdsec_resources(service_cfg.id, new_version)
            acl_collection_by_action = {}

            def setup_action_for_service(action):
                acl_count = ceil(service_cfg.max_items / ACL_CAPACITY)
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

            return Service(
                api=fastly_api,
                recaptcha_secret=service_cfg.recaptcha_secret_key,
                recaptcha_site_key=service_cfg.recaptcha_site_key,
                acl_collection_by_action=acl_collection_by_action,
                service_id=service_cfg.id,
                version=new_version,
            )

        with ThreadPool(len(account_cfg.services)) as service_tp:
            services.extend(list(service_tp.map(setup_service, account_cfg.services)))

    with ThreadPool(len(config.fastly_account_configs)) as account_tp:
        account_tp.map(setup_account, config.fastly_account_configs)


def set_logger(config: Config):
    global logger
    list(map(logger.removeHandler, logger.handlers))
    logger.setLevel(config.get_log_level())
    if config.log_mode == "stdout":
        handler = logging.StreamHandler(sys.stdout)
    elif config.log_mode == "file":
        handler = RotatingFileHandler(config.log_file, mode="a+")
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
        requests.delete(url=cols[1], headers={"Fastly-Key": cols[0]})
        print("called API ", cols[1])

    with open(DELETE_LIST_FILE) as f:
        rows = list(csv.reader(f, delimiter=" "))
        if not rows:
            print("nothing to delete!")
            return
        with ThreadPool(len(rows)) as tp:
            tp.map(perform_delete_req, rows)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-c", type=Path, help="Path to configuration file.")
    arg_parser.add_argument("-d", help="Whether to cleanup resources.", action="store_true")
    arg_parser.add_argument("-g", type=str, help="Comma separated tokens to generate config for.")
    arg_parser.add_argument("-o", type=str, help="Path to file to output the generated config.")
    arg_parser.add_help = True
    args = arg_parser.parse_args()
    if not args.c:
        if args.d:
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
