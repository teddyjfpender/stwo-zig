#!/usr/bin/env python3
"""Input adapter for the evmone-class client (our code).

  python3 -I adapter.py --host-binary HOST canonical-input.ssz adapted-input.bin

Untrusted prover-side preparation (bench.py run --input-adapter): runs the
client's native host build on the canonical SSZ input, records every full
secp256k1 recovery it performs (ECRECOVER precompile, EIP-7702 authorities,
transactions without a usable public-key hint) and appends them as hints:

  "STW1" | u64 ssz_len (LE) | canonical SSZ | zero pad to 8 | u64 count |
  count x 232-byte records (z, r, s, Q.x, Q.y, R.y, s^-1 mod n as 32-byte LE,
  recid, 7 zero bytes)

The guest checks each hint (s*w = 1, R on the curve with the right parity,
(z w)G + (r w)Q = R) before using it and falls back to full recovery
otherwise, so hints only change cost, never the result. Deterministic: the
host build is deterministic and records are deduplicated in first-seen order.
"""
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REC = 232


def main(argv):
    if len(argv) != 4 or argv[0] != "--host-binary":
        raise SystemExit("usage: adapter.py --host-binary HOST IN OUT")
    host, src, dst = argv[1], Path(argv[2]), Path(argv[3])
    ssz = src.read_bytes()
    with tempfile.TemporaryDirectory() as td:
        hints_path = Path(td) / "hints.bin"
        env = dict(os.environ, STWO_SECP_HINTS_OUT=str(hints_path))
        r = subprocess.run([host, str(src)], env=env, capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"host client rejected the input: {r.stderr.strip()[-200:]}")
        raw = hints_path.read_bytes() if hints_path.exists() else b""
    if len(raw) % REC:
        raise SystemExit("truncated hint records")
    seen, recs = set(), []
    for i in range(0, len(raw), REC):
        rec = raw[i:i + REC]
        if rec not in seen:
            seen.add(rec)
            recs.append(rec)
    out = bytearray(b"STW1" + struct.pack("<Q", len(ssz)) + ssz)
    out += b"\0" * (-len(out) % 8)
    out += struct.pack("<Q", len(recs)) + b"".join(recs)
    dst.write_bytes(bytes(out))
    print(f"adapted input: {len(ssz)} SSZ bytes, {len(recs)} recovery hints", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
