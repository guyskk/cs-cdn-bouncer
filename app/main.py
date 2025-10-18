import logging
import sys

from .decision_handler import CrowdsecDecisionHandler

LOG = logging.getLogger(__name__)


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
