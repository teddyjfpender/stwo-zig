#!/usr/bin/env python3
"""Tier-R tamper corpus for native LogUp-GKR v1 sections (stream native-gkr). Python 3 stdlib only.

Every case is a FRESH receiver process (`rv64-native-gkr-tool verify`) on one mutated copy of an honest
section proved on a real v1 roster (census of a dev block). The honest section must be accepted; every
mutation must be rejected with a clean exit 1 (a crash / signal counts as FAIL).
Mutations: each selected u32 word +1 mod p (field words) or ^1 (header words), truncation, extension,
a non-canonical word (= p), and the section of another proof (cross-proof substitution).
"""
import argparse, json, os, random, struct, subprocess, sys, tempfile

P = 2**31 - 1


def run(tool, census, proof, path):
    r = subprocess.run([tool, "verify", census, proof, path], capture_output=True, text=True)
    try:
        out = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        out = {"accepted": None, "reason": "no-json"}
    return r.returncode, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True)
    ap.add_argument("--census", required=True)
    ap.add_argument("--proof", required=True)
    ap.add_argument("--section", required=True)
    ap.add_argument("--other-proof")
    ap.add_argument("--other-section")
    ap.add_argument("--sample", type=int, default=0, help="0 = every word")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    data = open(a.section, "rb").read()
    words = list(struct.unpack(f"<{len(data)//4}I", data))
    cases = []
    tmp = tempfile.mkdtemp(prefix="ngkr-corpus-")

    def case(name, blob, expect_accept=False, proof=None):
        path = os.path.join(tmp, "s.bin")
        open(path, "wb").write(blob)
        code, out = run(a.tool, a.census, proof or a.proof, path)
        ok = (code == 0 and out.get("accepted") is True) if expect_accept else (code == 1 and out.get("accepted") is False)
        cases.append({"case": name, "exit": code, "reason": out.get("reason"), "pass": ok})
        return ok

    case("honest", data, expect_accept=True)
    positions = list(range(len(words)))
    if a.sample and a.sample < len(positions):
        rng = random.Random(0x5eed)
        positions = sorted(set([0, 1, 2, 3] + list(range(4, 12)) + rng.sample(positions, a.sample)))
    for i in positions:
        m = list(words)
        m[i] = m[i] ^ 1 if i < 4 else (m[i] + 1) % P
        case(f"word{i}", struct.pack(f"<{len(m)}I", *m))
    case("truncated", data[:-4])
    case("extended", data + b"\0\0\0\0")
    nc = list(words); nc[len(nc) // 2] = P
    case("noncanonical", struct.pack(f"<{len(nc)}I", *nc))
    if a.other_section:
        case(f"substituted:{a.other_proof}", open(a.other_section, "rb").read())
    passed = sum(c["pass"] for c in cases)
    summary = {"schema": "rv64-native-gkr-corpus/v1", "tier": "R (fresh process per case)", "proof": a.proof,
               "section_words": len(words), "cases": len(cases), "passed": passed,
               "reasons": sorted({c["reason"] for c in cases if c["case"] != "honest"}), "failures": [c for c in cases if not c["pass"]]}
    json.dump(summary, open(a.out, "w"), indent=1)
    print(json.dumps({k: summary[k] for k in ("proof", "section_words", "cases", "passed", "reasons")}))
    sys.exit(0 if passed == len(cases) else 1)


if __name__ == "__main__":
    main()
