
#!/bin/sh
BIN_PATH_INSTALLED="/usr/local/bin/crowdsec-aws-waf-bouncer"
BIN_PATH="./crowdsec-aws-waf-bouncer"
CONFIG_DIR="/etc/crowdsec/bouncers/"
SYSTEMD_PATH_FILE="/etc/systemd/system/crowdsec-aws-waf-bouncer.service"

LAPI_KEY=""

gen_apikey() {
    which cscli > /dev/null
    if [ $? -eq 0 ]; then 
        echo "cscli found, generating bouncer api key."
        SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
        LAPI_KEY=`cscli bouncers add crowdsec-aws-waf-bouncer-${SUFFIX} -o raw`
        READY="yes"
    else 
        echo "cscli not found, you will need to generate api key."
        READY="no"
    fi
}

gen_config_file() {
    LAPI_KEY=${LAPI_KEY} envsubst < ./config/crowdsec-aws-waf-bouncer.yaml > "${CONFIG_DIR}crowdsec-aws-waf-bouncer.yaml"
}


install_aws_waf_bouncer() {
	install -v -m 755 -D "${BIN_PATH}" "${BIN_PATH_INSTALLED}"
	mkdir -p "${CONFIG_DIR}"
	cp "./config/crowdsec-aws-waf-bouncer.yaml" "${CONFIG_DIR}crowdsec-aws-waf-bouncer.yaml"
	CFG=${CONFIG_DIR} BIN=${BIN_PATH_INSTALLED} envsubst < ./config/crowdsec-aws-waf-bouncer.service > "${SYSTEMD_PATH_FILE}"
	systemctl daemon-reload
}

install_bouncer(){
    echo "Installing crowdsec-aws-waf-bouncer"
    install_aws_waf_bouncer
    gen_apikey

    gen_config_file
    systemctl enable crowdsec-aws-waf-bouncer.service
}


if ! [ $(id -u) = 0 ]; then
    echo "Please run the install script as root or with sudo"
    exit 1
fi

install_bouncer
echo "Please configure '${CONFIG_DIR}crowdsec-aws-waf-bouncer.yaml'."
echo "After configuration run the command 'systemctl start crowdsec-aws-waf-bouncer.service' to start the bouncer"