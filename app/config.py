import logging
import os
import sys
from typing import TextIO

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings


class AppSettings(BaseSettings):
    log_level: str = Field(default="INFO")
    crowdsec_lapi_key: str = Field(
        description="crowdsec local api key",
    )
    crowdsec_lapi_url: str = Field(
        default="http://localhost:8080/",
        description="crowdsec local api url",
    )
    crowdsec_stream_interval: int = Field(
        default=10,
        description="crowdsec stream interval",
    )
    tencent_secret_id: str = Field(
        description="tencent cloud secret id",
    )
    tencent_secret_key: str = Field(
        description="tencent cloud secret key",
    )
    tencent_cdn_domain: str | None = Field(
        description="tencent cloud cdn domain",
    )
    tencent_teo_zone_id: str | None = Field(
        description="tencent cloud edgeone zone id",
    )
    tencent_teo_max_rule: int = Field(
        default=10,
        description="tencent cloud edgeone max rule count",
    )


def load_env_config(
    *,
    env_prefix: str,
    default_envfile: str | None = None,
    output: TextIO = sys.stderr,
):
    """
    Load envfile and convert to config model type.
    """
    envfile_path = os.getenv(f"{env_prefix}CONFIG")
    if not envfile_path:
        if default_envfile and os.path.exists(default_envfile):
            envfile_path = default_envfile
    if envfile_path:
        envfile_path = os.path.abspath(os.path.expanduser(envfile_path))
        output.write(f"* Load envfile at {envfile_path}\n")
        load_dotenv(envfile_path)
    return AppSettings(_env_prefix=env_prefix)  # type: ignore


CONFIG = load_env_config(env_prefix="CSCDN_")


LOG_FORMAT = "%(levelname)1.1s %(asctime)s %(name)s:%(lineno)d %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=CONFIG.log_level)
