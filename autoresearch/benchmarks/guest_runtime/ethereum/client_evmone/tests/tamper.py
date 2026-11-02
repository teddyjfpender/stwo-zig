#!/usr/bin/env python3
"""Tamper test for the host build (our code).

Soundness property: for any mutation of the canonical SSZ input, the client
either aborts (exit 2, or SIGABRT from zeg::fatal on the host) or still produces exactly the expected 43-byte output
(the mutation hit data the block never authenticates or uses, e.g. an unused
witness node or an invalid public-key hint that falls back to recovery).
A *different* accepted output (exit 3) is a failure.

Targeted mutations (payload fields, a transaction byte, the parent header, the
request lists, chain id and schema) must abort.

  python3 -I tests/tamper.py HOST_BINARY BLOCK_DIR [--random N] [--seed S]
"""
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def layout(data: bytes) -> dict:
    body = 2
    npr = body + u32(data, body)
    wit = body + u32(data, body + 4)
    pks = body + u32(data, body + 16)
    payload = npr + u32(data, npr)
    vh = npr + u32(data, npr + 4)
    txs = payload + u32(data, payload + 504)
    wds = payload + u32(data, payload + 508)
    hdrs = wit + u32(data, wit + 8)
    state = wit + u32(data, wit)
    codes = wit + u32(data, wit + 4)
    first_tx = txs + u32(data, txs) if wds > txs else None
    first_hdr = hdrs + u32(data, hdrs)
    return {"logs_bloom": payload + 116, "prev_randao": payload + 372, "blob_gas_used": payload + 512,
            "schema": 0, "chain_id": body + 8, "payload": payload, "state_root": payload + 52,
            "receipts_root": payload + 84, "gas_used": payload + 420, "block_hash": payload + 472,
            "extra_off": payload + 436, "fee_recipient": payload + 32, "timestamp": payload + 428,
            "first_tx": first_tx, "parent_beacon": npr + 8, "versioned_hashes": vh, "wds": wds,
            "first_header": first_hdr, "pks": pks, "state": state, "codes": codes, "end": len(data)}


def run(binary, data, expected):
    with tempfile.NamedTemporaryFile(suffix=".ssz") as f:
        f.write(data)
        f.flush()
        r = subprocess.run([binary, f.name, expected], capture_output=True, text=True)
    return r.returncode


def main():
    binary, block = sys.argv[1], Path(sys.argv[2])
    n_random = int(sys.argv[sys.argv.index("--random") + 1]) if "--random" in sys.argv else 200
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
    data = (block / "canonical-input.ssz").read_bytes()
    expected = str(block / "expected-output.bin")
    lay = layout(data)
    assert run(binary, data, expected) == 0, "unmodified input must match"
    must_abort = {k: lay[k] for k in ("schema", "chain_id", "state_root", "receipts_root", "gas_used",
                                       "block_hash", "fee_recipient", "timestamp", "parent_beacon", "logs_bloom",
                                       "prev_randao", "blob_gas_used",
                                       "first_header")}
    if lay["first_tx"] is not None:
        must_abort["first_tx_body"] = lay["first_tx"] + 5
    bad = []
    for name, off in must_abort.items():
        m = bytearray(data)
        m[off + (1 if name == "schema" else 0)] ^= 0x01
        rc = run(binary, bytes(m), expected)
        print(f"targeted {name:16} rc={rc}")
        if rc not in (2, -6):
            bad.append((name, rc))
    rng = random.Random(seed)
    counts = {0: 0, 2: 0, 3: 0}
    for i in range(n_random):
        off = rng.randrange(0, len(data))
        m = bytearray(data)
        m[off] ^= 1 << rng.randrange(8)
        rc = run(binary, bytes(m), expected)
        rc = 2 if rc == -6 else rc
        counts[rc] = counts.get(rc, 0) + 1
        if rc not in (0, 2):
            bad.append((f"random@{off}", rc))
    print(f"random flips: identical-output={counts.get(0,0)} aborted={counts.get(2,0)} "
          f"DIFFERENT-OUTPUT={counts.get(3,0)} other={sum(v for k,v in counts.items() if k not in (0,2,3))}")
    if bad:
        print("FAIL", bad)
        return 1
    print("tamper ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
