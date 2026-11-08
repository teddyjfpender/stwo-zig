#!/usr/bin/env bash
# Run on the pod from its synced m7-integrate tree. The producer harness owns
# the GPU lock; do not wrap this script in another GPU flock.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/rv64_gate.py "$@"
