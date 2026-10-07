#!/usr/bin/env python3
"""Exercise the distinct first-retarget fold key against saved native proofs.

Run test-bitcoin-retarget-fold-proof and bitcoin-chain-cli first. The saved
proofs cover blocks one and two; the key permits a future height-2016 proof.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]
S31 = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "zig-out/s31/bitcoin-first-retarget-two-step"
CLI = S31 / "zig-out/bin/s31-bitcoin-chain"


def run(*args: object, accepted: bool) -> None:
    result = subprocess.run([str(CLI), *(str(arg) for arg in args)], capture_output=True, text=True)
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"unexpected exit {result.returncode} for {args!r}:\n{result.stdout}{result.stderr}")


def main() -> None:
    required = ("verification-key.json", "verification-key.sha256", "fold0.statement.json",
                "fold0.proof", "fold1.statement.json", "fold1.proof")
    if not CLI.is_file() or any(not (ARTIFACTS / name).is_file() for name in required):
        raise SystemExit("Build bitcoin-chain-cli and run test-bitcoin-retarget-fold-proof first.")
    key = ARTIFACTS / "verification-key.json"
    digest = (ARTIFACTS / "verification-key.sha256").read_text().strip()
    first = ARTIFACTS / "fold0.statement.json"
    second = ARTIFACTS / "fold1.statement.json"
    proof0 = ARTIFACTS / "fold0.proof"
    proof1 = ARTIFACTS / "fold1.proof"
    assert hashlib.sha256(key.read_bytes()).hexdigest() == digest
    run("verify-retarget", key, digest, first, proof0, accepted=True)
    run("verify-retarget", key, digest, second, proof1, accepted=True)
    run("verify-retarget", key, digest, second, proof0, accepted=False)
    run("verify", key, digest, second, proof1, accepted=False)
    wrong_digest = ("0" if digest[0] != "0" else "1") + digest[1:]
    run("verify-retarget", key, wrong_digest, second, proof1, accepted=False)
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        parsed_key = json.loads(key.read_text())
        regenerated = temp / "regenerated-key.json"
        run("keygen-retarget", parsed_key["checkpoint_block_hash"], 2015, regenerated, accepted=True)
        assert regenerated.read_bytes() == key.read_bytes()
        run("keygen-retarget", parsed_key["checkpoint_block_hash"], 2016, temp / "overlong.json", accepted=False)
        source = json.loads(second.read_text())
        times = temp / "times.json"
        times.write_text(json.dumps(source["last_timestamps"]))
        statement = temp / "regenerated-statement.json"
        run("statement-retarget", key, digest, 1, source["current_block_hash"], times, statement, accepted=True)
        assert statement.read_bytes() == second.read_bytes()
        changed_times = list(source["last_timestamps"])
        changed_times[0] ^= 1
        times.write_text(json.dumps(changed_times))
        changed = temp / "changed-time-statement.json"
        run("statement-retarget", key, digest, 1, source["current_block_hash"], times, changed, accepted=True)
        run("verify-retarget", key, digest, changed, proof1, accepted=False)
        tampered = dict(source)
        tampered["public_words"] = list(source["public_words"])
        tampered["public_words"][0] ^= 1
        changed.write_text(json.dumps(tampered))
        run("verify-retarget", key, digest, changed, proof1, accepted=False)
        altered_key = dict(parsed_key)
        altered_key["max_step"] = 2016
        overlong = temp / "altered-key.json"
        overlong.write_text(json.dumps(altered_key))
        run("verify-retarget", overlong, hashlib.sha256(overlong.read_bytes()).hexdigest(), second, proof1, accepted=False)
        damaged = bytearray(proof1.read_bytes())
        damaged[len(damaged) // 2] ^= 1
        bad_proof = temp / "damaged.proof"
        bad_proof.write_bytes(damaged)
        run("verify-retarget", key, digest, second, bad_proof, accepted=False)
    print("Bitcoin first-retarget CLI: two native proofs accepted; wrong v3 profile, key digest, step replay, authenticated timestamp, public claim, over-limit key, and damaged proof rejected")


if __name__ == "__main__":
    main()
