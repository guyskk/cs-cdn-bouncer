import logging

from app.config import CONFIG

from .decision_handler import CrowdsecDecisionHandler

LOG = logging.getLogger(__name__)

LOG_FORMAT = "%(levelname)1.1s %(asctime)s %(name)s:%(lineno)d %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=CONFIG.log_level)


def main():
    handler = CrowdsecDecisionHandler()
    handler.main()


if __name__ == "__main__":
    main()
