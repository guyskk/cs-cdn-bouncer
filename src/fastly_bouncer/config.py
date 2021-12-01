import logging
from dataclasses import asdict, dataclass, field
from multiprocessing.pool import ThreadPool
from pathlib import Path
from typing import List, Dict

import yaml

from fastly_bouncer.utils import are_filled_validator
from fastly_bouncer.fastly_api import FastlyAPI


@dataclass
class CrowdSecConfig:
    lapi_key: str
    lapi_url: str = "http://localhost:8080/"

    def __post_init__(self):
        are_filled_validator(**{key: getattr(self, key) for key in asdict(self).keys()})


@dataclass
class FastlyServiceConfig:
    id: str
    recaptcha_site_key: str
    recaptcha_secret_key: str
    max_items: int = 5000

    def __post_init__(self):
        are_filled_validator(**{key: getattr(self, key) for key in asdict(self).keys()})


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
        log_mode="file",
        log_file="/var/log/crowdsec-fastly-bouncer.log",  # FIXME: This needs root permissions
        crowdsec_config=CrowdSecConfig(lapi_key="<LAPI_KEY>"),
        update_frequency="10",
    )


def generate_config_for_account(fastly_token: str) -> FastlyAccountConfig:
    api = FastlyAPI(fastly_token)
    service_ids = api.get_all_service_ids()
    service_configs: List[FastlyServiceConfig] = []
    for service_id in service_ids:
        service_configs.append(
            FastlyServiceConfig(
                id=service_id,
                recaptcha_site_key="<RECAPTCHA_SITE_KEY>",
                recaptcha_secret_key="<RECAPTCHA_SECRET_KEY>",
            )
        )
    return FastlyAccountConfig(account_token=fastly_token, services=service_configs)


def generate_config(
    comma_separated_fastly_tokens: str, base_config: Config = default_config()
) -> Config:
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
