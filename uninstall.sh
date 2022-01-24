#!/usr/bin/env bash

BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-fastly-bouncer"
CONFIG_DIR="/etc/crowdsec/crowdsec-fastly-bouncer/"
LOG_FILE="/var/log/crowdsec-fastly-bouncer.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-fastly-bouncer.service"
CACHE_DIR="/var/lib/crowdsec/crowdsec-fastly-bouncer/cache/"

uninstall() {
	systemctl stop crowdsec-fastly-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
	rm -rf "${CACHE_DIR}"
}


if ! [ $(id -u) = 0 ]; then
    echo "Please run the install script as root or with sudo"
    exit 1
fi

uninstall

echo "crowdsec-fastly-bouncer uninstall successfully"