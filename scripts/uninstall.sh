#!/bin/bash

BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-aws-waf-bouncer"
CONFIG_FILE="/etc/crowdsec/bouncers/crowdsec-aws-waf-bouncer.yaml"
LOG_FILE="/var/log/crowdsec-aws-waf-bouncer.log"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-aws-waf-bouncer.service"

uninstall() {
	systemctl stop crowdsec-aws-waf-bouncer
	rm -rf "${CONFIG_DIR}"
	rm -f "${SYSTEMD_PATH_FILE}"
	rm -f "${BIN_PATH_INSTALLED}"
	rm -f "${LOG_FILE}"
}

uninstall

echo "crowdsec-aws-waf-bouncer uninstall successfully"