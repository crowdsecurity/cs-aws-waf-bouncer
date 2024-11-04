#!/bin/sh

ARGS="$@"
if [ -f "$BOUNCER_CONFIG_FILE" ]; then
	echo "Using config file: $BOUNCER_CONFIG_FILE"
	ARGS="$ARGS -c $BOUNCER_CONFIG_FILE"
fi

echo "Running with args: $ARGS"

exec /crowdsec-aws-waf-bouncer $ARGS