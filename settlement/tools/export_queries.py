"""Match native pre-PoW diagnostics to checked-in lifted openings."""

import argparse
import hashlib
import json
import struct
from pathlib import Path


def project(query, domain, tree):
    if tree == 0:
        return 0
    pair = query >> 1
    pair = pair << (tree - domain) if tree > domain else pair >> (domain - tree)
    return (pair << 1) | (query & 1)


def positions(digest, nonce, domain, tree, count):
    nonce_bytes = struct.pack("<Q", nonce)
    prefix = hashlib.blake2s(struct.pack("<I12x32sI", 0x12345678, digest, 20)).digest()
    work = hashlib.blake2s(prefix + nonce_bytes).digest()
    if int.from_bytes(work[:4], "little") & ((1 << 20) - 1):
        raise ValueError("invalid captured nonce")
    mixed = hashlib.blake2s(digest + nonce_bytes).digest()
    raw = []
    for counter in range((count + 7) // 8):
        raw.extend(
            struct.unpack(
                "<8I", hashlib.blake2s(mixed + struct.pack("<IB", counter, 0)).digest()
            )
        )
    mask = (1 << domain) - 1
    return sorted({project(query & mask, domain, tree) for query in raw[:count]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diagnostics", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("openings", type=Path, nargs="+")
    args = parser.parse_args()

    contexts = []
    for line in args.diagnostics.read_text().splitlines():
        if line.startswith("SETTLEMENT_QUERIES "):
            _, root, digest, domain, bits, count, nonce = line.split()
            if (int(bits), int(count)) == (20, 108):
                contexts.append(
                    ("0x" + root, bytes.fromhex(digest), int(domain), int(nonce))
                )

    result = {}
    for path in args.openings:
        opening = json.loads(path.read_text())
        matches = {
            (digest, domain, nonce)
            for root, digest, domain, nonce in contexts
            if root == opening["root"]
            and positions(digest, nonce, domain, opening["depth"], 108)
            == opening["positions"]
        }
        if len(matches) != 1:
            raise ValueError(
                f"{path.name}: expected exactly one transcript, got {len(matches)}"
            )
        digest, domain, nonce = matches.pop()
        result[opening["worker"]] = {
            "workerSha256": opening["workerSha256"],
            "prePowDigest": "0x" + digest.hex(),
            "nonce": str(nonce),
            "domainLog": domain,
        }
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
