import logging
import sys

from app.config import CONFIG

from .decision_handler import CrowdsecDecisionHandler

LOG = logging.getLogger(__name__)

LOG_FORMAT = "%(levelname)1.1s %(asctime)s %(name)s:%(lineno)d %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=CONFIG.log_level)


def main():
    dryrun = len(sys.argv) >= 2 and sys.argv[1] == "--dryrun"
    is_help = len(sys.argv) >= 2 and sys.argv[1] == "--help"
    if is_help:
        print("Usage: python -m app.main [--dryrun]")
        return
    handler = CrowdsecDecisionHandler()
    handler.main(dryrun=dryrun)


if __name__ == "__main__":
    main()
