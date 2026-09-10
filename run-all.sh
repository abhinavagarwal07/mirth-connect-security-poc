#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
"$ROOT/sql-selectlimit-injection/poc/run.sh"
"$ROOT/xslt-step-xxe/poc/run.sh"
"$ROOT/xml-batch-xxe/poc/run.sh"
