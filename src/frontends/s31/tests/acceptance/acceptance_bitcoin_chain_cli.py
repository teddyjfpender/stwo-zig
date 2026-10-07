#!/usr/bin/env python3
"""Exercise the standalone Bitcoin fold verifier against saved proof artifacts.

First run the opt-in test-bitcoin-chain-fold-proof build step to create the
artifacts in zig-out/s31/bitcoin-chain-two-step.
"""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import json
import hashlib
import pathlib
import subprocess
import sys
import tempfile


ROOT = S31_SOURCE_ROOT.parents[2]
S31 = S31_SOURCE_ROOT
ARTIFACTS = ROOT / "zig-out/s31/bitcoin-chain-two-step"
CLI = S31 / "zig-out/bin/s31-bitcoin-chain"


def run(*args: object, accepted: bool) -> None:
    result = subprocess.run([str(CLI), *(str(arg) for arg in args)], capture_output=True, text=True)
    if (result.returncode == 0) != accepted:
        raise AssertionError(
            f"unexpected exit {result.returncode} for {args!r}:\n{result.stdout}{result.stderr}"
        )


def main() -> None:
    required = ["verification-key.json", "verification-key.sha256", "fold0.statement.json",
                "fold0.proof", "fold1.statement.json", "fold1.proof"]
    if not CLI.is_file() or any(not (ARTIFACTS / name).is_file() for name in required):
        raise SystemExit(
            "Build bitcoin-chain-cli and run test-bitcoin-chain-fold-proof first."
        )
    key = ARTIFACTS / "verification-key.json"
    digest = (ARTIFACTS / "verification-key.sha256").read_text().strip()
    step0 = ARTIFACTS / "fold0.statement.json"
    step1 = ARTIFACTS / "fold1.statement.json"
    proof0 = ARTIFACTS / "fold0.proof"
    proof1 = ARTIFACTS / "fold1.proof"
    run("verify", key, digest, step0, proof0, accepted=True)
    run("verify", key, digest, step1, proof1, accepted=True)
    wrong_digest = ("0" if digest[0] != "0" else "1") + digest[1:]
    run("verify", key, wrong_digest, step1, proof1, accepted=False)
    run("verify", key, digest, step1, proof0, accepted=False)
    statement = json.loads(step1.read_text())
    with tempfile.TemporaryDirectory() as tmp:
        temp = pathlib.Path(tmp)
        regenerated_key = temp / "regenerated-key.json"
        checkpoint = json.loads(key.read_text())["checkpoint_block_hash"]
        run("keygen", checkpoint, 1, regenerated_key, accepted=True)
        assert regenerated_key.read_bytes() == key.read_bytes()
        assert hashlib.sha256(regenerated_key.read_bytes()).hexdigest() == digest
        regenerated_statement = temp / "regenerated.statement.json"
        original = json.loads(step1.read_text())
        times_path = temp / "times.json"
        times_path.write_text(json.dumps(original["last_timestamps"]))
        run("statement", key, digest, 1, original["current_block_hash"],
            times_path, regenerated_statement, accepted=True)
        assert regenerated_statement.read_bytes() == step1.read_bytes()
        changed_hash = ("0" if original["current_block_hash"][0] != "0" else "1") + original["current_block_hash"][1:]
        changed_hash_statement = temp / "changed-hash.statement.json"
        run("statement", key, digest, 1, changed_hash, times_path, changed_hash_statement, accepted=True)
        run("verify", key, digest, changed_hash_statement, proof1, accepted=False)
        changed_times = list(original["last_timestamps"])
        changed_times[1] ^= 1
        times_path.write_text(json.dumps(changed_times))
        changed_time_statement = temp / "changed-time.statement.json"
        run("statement", key, digest, 1, original["current_block_hash"], times_path,
            changed_time_statement, accepted=True)
        run("verify", key, digest, changed_time_statement, proof1, accepted=False)
        times_path.write_text(json.dumps(original["last_timestamps"]))
        alternate_key = temp / "alternate-checkpoint-key.json"
        run("keygen", original["current_block_hash"], 1, alternate_key, accepted=False)
        run("keygen", checkpoint, 2014, temp / "last-first-epoch-key.json", accepted=True)
        run("keygen", checkpoint, 2015, temp / "retarget-key.json", accepted=False)
        overlong_key = json.loads(key.read_text())
        overlong_key["max_step"] = 2015
        overlong_path = temp / "overlong-key.json"
        overlong_path.write_text(json.dumps(overlong_key))
        overlong_digest = hashlib.sha256(overlong_path.read_bytes()).hexdigest()
        run("verify", overlong_path, overlong_digest, step1, proof1, accepted=False)
        changed = temp / "changed.statement.json"
        statement["public_words"][0] ^= 1
        changed.write_text(json.dumps(statement))
        run("verify", key, digest, changed, proof1, accepted=False)
        statement = json.loads(step1.read_text())
        statement["step"] = 2
        changed.write_text(json.dumps(statement))
        run("verify", key, digest, changed, proof1, accepted=False)
        bad_proof = temp / "changed.proof"
        proof_bytes = bytearray(proof1.read_bytes())
        proof_bytes[len(proof_bytes) // 2] ^= 1
        bad_proof.write_bytes(proof_bytes)
        run("verify", key, digest, step1, bad_proof, accepted=False)
        output = temp / "over-limit.statement.json"
        run("statement", key, digest, 2, statement["current_block_hash"], times_path, output, accepted=False)
    print("Bitcoin chain CLI: key and statement regeneration agree; valid steps accepted; wrong checkpoint, retarget boundary, key digest, current hash, timestamp window, replay, claim, proof, and step limit rejected")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
