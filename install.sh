#!/usr/bin/env bash

CONFIG_DIR="/etc/crowdsec/bouncers"
LAPI_KEY=""
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-fastly-bouncer"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-fastly-bouncer.service"

BOUNCER_BASH_SCRIPT="#!/usr/bin/env bash
BG='-d'
NAME='--name crowdsec-fastly-bouncer'
if [[ -t 1 ]]; then
    BG=''
    NAME=''
fi
docker run \$BG --rm  \$NAME --network=host \\
    --mount  type=bind,source=$CONFIG_DIR/crowdsec-fastly-bouncer.yaml,target=$CONFIG_DIR/crowdsec-fastly-bouncer.yaml \\
    --mount  type=bind,source=/var/log/crowdsec-fastly-bouncer.log,target=/var/log/crowdsec-fastly-bouncer.log  \\
    fastly_bouncer:latest \$@
trap 'docker kill crowdsec-fastly-bouncer' SIGTERM
if [[ \$BG == '-d' ]]; then 
    sleep infinity
fi
"

if ! [ $(id -u) = 0 ]; then
    echo "Please run the install script as root or with sudo"
    exit 1
fi

function gen_api_key(){
    which cscli > /dev/null
    if [[ $? == 0 ]]; then 
        echo "cscli found, generating bouncer api key."
        SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
        LAPI_KEY=`cscli bouncers add crowdsec-fastly-bouncer-${SUFFIX} -o raw`
    else 
        echo "cscli not found, you will need to generate api key."
    fi
}

function check_docker(){
    which docker > /dev/null
    if [[ $? != 0 ]]; then 
        echo "docker not found. Please install docker and try again"
        exit 1
    fi
}

function install(){
    docker build . -t fastly_bouncer:latest  # After publishing docker image these steps can be shorter
    mkdir -p "$CONFIG_DIR"
    if [[ ! -f "$CONFIG_DIR/crowdsec-fastly-bouncer.yaml" ]]; then
        LAPI_KEY=${LAPI_KEY} envsubst < "./config/config_docker.yaml" > "$CONFIG_DIR/crowdsec-fastly-bouncer.yaml"
    fi
    echo "$BOUNCER_BASH_SCRIPT" > "$BIN_PATH_INSTALLED"
    chmod +x /usr/local/bin/crowdsec-fastly-bouncer
    CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/crowdsec-fastly-bouncer.service > "${SYSTEMD_PATH_FILE}"
    systemctl daemon-reload
}

check_docker
gen_api_key
install