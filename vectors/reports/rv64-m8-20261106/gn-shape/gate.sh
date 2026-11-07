#!/bin/bash
# gn-shape: default gate. usage gate.sh <n> <commit>
S=m8-gn-shape
cd /workspace/m3/src/$S
bash scripts/rv64_gate.sh --stream $S --out /workspace/m3/runs/$S/gate-$1 --source-commit $2 > /workspace/m3/runs/$S/gate-$1.log 2>&1
echo "EXIT $?" >> /workspace/m3/runs/$S/gate-$1.log
