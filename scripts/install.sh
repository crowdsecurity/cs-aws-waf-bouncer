#!/bin/sh

set -e

set_colors() {
    if [ ! -t 0 ]; then
        # terminal is not interactive; no colors
        FG_RED=""
        FG_GREEN=""
        FG_YELLOW=""
        FG_CYAN=""
        RESET=""
    elif tput sgr0 >/dev/null; then
        # terminfo
        FG_RED=$(tput setaf 1)
        FG_GREEN=$(tput setaf 2)
        FG_YELLOW=$(tput setaf 3)
        FG_CYAN=$(tput setaf 6)
        RESET=$(tput sgr0)
    else
        FG_RED=$(printf '%b' '\033[31m')
        FG_GREEN=$(printf '%b' '\033[32m')
        FG_YELLOW=$(printf '%b' '\033[33m')
        FG_CYAN=$(printf '%b' '\033[36m')
        RESET=$(printf '%b' '\033[0m')
    fi
}

set_colors

msg() {
    case "$1" in
        info) echo "${FG_CYAN}$2${RESET}" >&2 ;;
        warn) echo "${FG_YELLOW}$2${RESET}" >&2 ;;
        err) echo "${FG_RED}$2${RESET}" >&2 ;;
        succ) echo "${FG_GREEN}$2${RESET}" >&2 ;;
        *) echo "$1" >&2 ;;
    esac
}

#shellcheck disable=SC2312
if [ "$(id -u)" -ne 0 ]; then
    msg warn "Please run $0 as root or with sudo"
    exit 1
fi

# --------------------------------- #

BOUNCER="crowdsec-aws-waf-bouncer"
SERVICE="$BOUNCER.service"
BIN_PATH_INSTALLED="/usr/local/bin/$BOUNCER"
BIN_PATH="./$BOUNCER"
CONFIG_DIR="/etc/crowdsec/bouncers"
CONFIG_FILE="$BOUNCER.yaml"
CONFIG="$CONFIG_DIR/$CONFIG_FILE"
SYSTEMD_PATH_FILE="/etc/systemd/system/$SERVICE"

API_KEY="<API_KEY>"


gen_apikey() {
    if command -v cscli >/dev/null; then
        msg succ "cscli found, generating bouncer api key."
        unique=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
        bouncer_id="$BOUNCER_PREFIX-$unique"
        API_KEY=$(cscli -oraw bouncers add "$bouncer_id")
        echo "$bouncer_id" > "$CONFIG.id"
        msg info "API Key: $API_KEY"
        READY="yes"
    else
        msg warn "cscli not found, you will need to generate an api key."
        READY="no"
    fi
}

gen_config_file() {
    # shellcheck disable=SC2016
    API_KEY=${API_KEY} envsubst '$API_KEY' <"./config/$CONFIG_FILE" | \
        install -D -m 0600 /dev/stdin "$CONFIG"
}

install_bouncer() {
    if [ ! -f "$BIN_PATH" ]; then
        msg err "$BIN_PATH not found, exiting."
        exit 1
    fi
    if [ -e "$BIN_PATH_INSTALLED" ]; then
        msg warn "$BIN_PATH_INSTALLED is already installed. Exiting"
        exit 1
    fi
    msg info "Installing $BOUNCER"
    install -v -m 0755 -D "$BIN_PATH" "$BIN_PATH_INSTALLED"
    install -D -m 0600 "./config/$CONFIG_FILE" "$CONFIG"
    # shellcheck disable=SC2016
    CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst '$CFG $BIN' <"./config/$SERVICE" >"$SYSTEMD_PATH_FILE"
    systemctl daemon-reload
    gen_apikey
    gen_config_file
    set_local_port
}

# --------------------------------- #

set_colors
install_bouncer

systemctl enable "$SERVICE"
if [ "$READY" = "yes" ]; then
    systemctl start "$SERVICE"
else
    msg warn "service not started. You need to get an API key and configure it in $CONFIG"
fi

msg info "Please configure '$CONFIG'."
msg info "After configuration run the command 'systemctl start $SERVICE' to start the bouncer"
exit 0
