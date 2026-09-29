#!/bin/bash
set -euo pipefail
mkdir -p /workspace/stwo-zig /workspace/inputs /opt/zig
if [ ! -f /opt/zig/zig-x86_64-linux-0.15.2/zig ]; then
 curl -fL https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz -o /workspace/zig.tar.xz
 tar -xJf /workspace/zig.tar.xz -C /opt/zig
fi
if [ -f /workspace/cached-official-verifier ]; then
 echo 'Using snapshot-authenticated cached verifier; no Rust bootstrap required'
elif [ ! -x /root/.cargo/bin/rustup ]; then
 curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /workspace/rustup.sh
 bash /workspace/rustup.sh -y --profile minimal --default-toolchain nightly-2026-01-15
else
 /root/.cargo/bin/rustup toolchain install nightly-2026-01-15 --profile minimal
fi
python3 - <<'PY'
import hashlib, json
from pathlib import Path
r=json.loads(Path('/workspace/snapshot.json').read_text())
for name in ('source.tar.gz','inputs.tar.gz','native-cubins.tar.gz','cuda-units-and-verifier.tar.gz'):
 p=Path('/workspace')/name
 assert hashlib.file_digest(p.open('rb'),'sha256').hexdigest()==r[name]['sha256'],name
PY
tar --no-same-owner -xzf /workspace/source.tar.gz -C /workspace/stwo-zig
tar --no-same-owner -xzf /workspace/inputs.tar.gz -C /workspace/inputs
if [ -f /workspace/cairo-cuda-build-cache.tar.gz ]; then
 tar --no-same-owner -xzf /workspace/cairo-cuda-build-cache.tar.gz -C /workspace
fi
if [ -f /workspace/cuda-units-and-verifier.tar.gz ]; then
 tar --no-same-owner -xzf /workspace/cuda-units-and-verifier.tar.gz -C /workspace
fi
if [ -f /workspace/native-build-cache-v17.tar.gz ]; then
 python3 - <<'PY'
import hashlib, json
from pathlib import Path
ledger=json.loads(Path('/workspace/retained-artifacts.json').read_text())
p=Path('/workspace/native-build-cache-v17.tar.gz')
assert hashlib.file_digest(p.open('rb'),'sha256').hexdigest()==ledger['artifacts'][p.name]
PY
 tar --no-same-owner -xzf /workspace/native-build-cache-v17.tar.gz -C /workspace
fi
if [ -f /workspace/native-cubins.tar.gz ]; then
 tar --no-same-owner -xzf /workspace/native-cubins.tar.gz -C /workspace
fi
nvidia-smi
python3 /workspace/remote.py
