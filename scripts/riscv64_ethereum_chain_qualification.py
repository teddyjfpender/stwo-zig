#!/usr/bin/env python3
"""Adversarial fresh-process receivers for a pinned real Ethereum prefix.

Also proves a five-instruction synthetic ABI program solely to exercise complete
serialized-chain/terminal-certificate rejection. That program is NOT an Ethereum
validator and supplies no Ethereum block qualification.
"""
import argparse
import copy
import contextlib
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time


def identity(path):
    return {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def toy_config(directory):
    pc, input_start = 4096, 0x10000000
    halt = input_start + (4 << 20)
    words = [0x104000B7, 0x00100113, 0x0020A023, 0x02B00113, 0x0020A223, 0x0000006F]
    code = struct.pack("<6I", *words)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 243, 1, pc, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 5, 256, pc, pc, len(code), len(code), 4)
    elf, witness = directory / "toy.elf", directory / "toy.input"
    elf.write_bytes(header + segment + bytes(256 - len(header) - len(segment)) + code)
    witness.write_bytes(b"synthetic execution ABI test, not Ethereum")
    stack_bottom = halt + 512
    stack_top = stack_bottom + (16 << 20)
    return {"elf": str(elf), "input": str(witness), "elf_sha256": identity(elf)["sha256"], "input_sha256": identity(witness)["sha256"], "expected_output": "00" * 43, "symbols": {"input_start": input_start, "input_end": halt, "halt_flag": halt, "output_len": halt + 4, "output_data": halt + 8, "output_end": stack_bottom, "stack_bottom": stack_bottom, "stack_top": stack_top, "heap_start": stack_top, "heap_end": stack_top + 4096}, "terminal_pc": pc + 20, "batch_steps": 32, "max_steps": 100, "max_batches": 0, "workers": 1, "profile_stages": False, "output_directory": str(directory / "proof")}


def run(binary, mode, config, path, reject=False):
    path.write_text(json.dumps(config))
    start = time.perf_counter_ns()
    result = subprocess.run([str(binary), mode, str(path)], text=True, capture_output=True, timeout=300)
    elapsed = time.perf_counter_ns() - start
    if (result.returncode != 0) != reject:
        raise RuntimeError(f"{mode}: unexpected exit {result.returncode}: {result.stderr[-3000:]}")
    report = json.loads(result.stdout) if not reject else None
    return {"exit_code": result.returncode, "wall_ns": elapsed, "receiver": report, "error": result.stderr.splitlines()[0] if reject and result.stderr else None}


def clone(source, destination):
    """Only immutable proof files are linked; JSON is copied, never symlinked."""
    destination.mkdir()
    for path in source.iterdir():
        if path.suffix == ".proof":
            (destination / path.name).symlink_to(path.resolve())
        elif path.suffix == ".json":
            (destination / path.name).write_bytes(path.read_bytes())


def qualify_resume(binary, workspace, reprove_binary=None):
    """Synthetic ABI only: real state continuation and byte-identical proofs."""
    folder = workspace / "resume"
    folder.mkdir()
    config = toy_config(folder)
    config.update(batch_steps=2, max_batches=1)
    cases = []
    def step(name, mode, value, reject=False):
        result = run(binary, mode, value, folder / (name + ".json"), reject)
        cases.append({"case": "synthetic-resume-" + name, "ethereum_block_proof": False, "rejected": reject, **result})
        return result
    step("prefix-producer", "prove", config)
    prefix = step("prefix-receiver", "verify-prefix", config)
    if prefix["receiver"]["instructions"] != 2:
        raise RuntimeError("synthetic resume seed has wrong coverage")
    config["max_batches"] = 0
    step("continue", "resume", config)
    accepted = step("complete-receiver", "verify", config)
    if not accepted["receiver"]["full_block_proof_verified"] or accepted["receiver"]["instructions"] != 5:
        raise RuntimeError("synthetic resumed chain did not completely verify")
    control = dict(config, output_directory=str(folder / "control"))
    step("single-pass", "prove", control)
    output = Path(config["output_directory"])
    proofs = list(output.glob("*.proof"))
    if len(proofs) != 4:
        raise RuntimeError("synthetic resume proof roster differs")
    for proof in proofs:
        if proof.read_bytes() != (Path(control["output_directory"]) / proof.name).read_bytes():
            raise RuntimeError("resumed proof differs: " + proof.name)
    before = {p.name: identity(p) for p in output.iterdir()}
    step("already-complete", "resume", config, True)
    if before != {p.name: identity(p) for p in output.iterdir()}:
        raise RuntimeError("rejected resume mutated accepted artifacts")
    if reprove_binary is not None:
        replay = dict(config, output_directory=str(folder / "reprove"))
        path = folder / "reprove-config.json"
        path.write_text(json.dumps(replay))
        result = subprocess.run([str(reprove_binary), str(path), str(output), "1"], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("synthetic retained-batch reprove failed: " + result.stderr)
        receipt = json.loads(result.stdout)
        if not receipt["proof_bytes_equal"] or not receipt["baseline_complete_chain_verified"] or receipt["full_block_reproved"]:
            raise RuntimeError("retained-batch reprove evidence differs")
        cases.append({"case": "synthetic-retained-batch-reprove", "ethereum_block_proof": False, "rejected": False, "receipt": receipt})
    return cases


def qualify(binary, config_path, check_batch_budget=False, artifacts=None, check_resume=False, reprove_binary=None):
    config = json.loads(config_path.read_text())
    source = Path(config["output_directory"]).resolve()
    originals = {path: identity(path) for path in source.iterdir() if path.name == "summary.json" or path.name.startswith("batch-") and path.suffix in (".json", ".proof")}
    cases = []
    try:
        if artifacts is not None:
            artifacts.mkdir(parents=True, exist_ok=False)
        manager = contextlib.nullcontext(artifacts) if artifacts is not None else tempfile.TemporaryDirectory(prefix="rv64-ethereum-receiver-")
        with manager as temporary:
            workspace = Path(temporary)
            if artifacts is not None:
                frozen = workspace / "original-prefix"
                frozen.mkdir()
                for path in source.iterdir():
                    if path.suffix in (".json", ".proof"):
                        (frozen / path.name).write_bytes(path.read_bytes())
                source = frozen
            def attack(name, mutation=None, mode="verify-prefix", source_dir=source, source_config=config, reject=True):
                folder = workspace / name
                clone(source_dir, folder)
                local = copy.deepcopy(source_config)
                local["output_directory"] = str(folder)
                meta = folder / "batch-000000.json"
                receipt = json.loads(meta.read_text())
                if mutation:
                    mutation(folder, receipt, local)
                meta.write_text(json.dumps(receipt))
                outcome = run(binary, mode, local, workspace / (name + "-config.json"), reject)
                if not reject and mode == "verify-prefix" and outcome["receiver"]["full_block_proof_verified"]:
                    raise RuntimeError("prefix receiver claimed a complete proof")
                cases.append({"case": name, "rejected": reject, **outcome})
            attack("real-valid-prefix", reject=False)
            if check_batch_budget:
                attack("receiver-batch-budget", lambda f, p, c: c.__setitem__("batch_steps", p["public"]["cpu"]["statement"]["steps"] - 1))

            changes = [
                ("schema", lambda p: p.__setitem__("schema", "rv64-authenticated-ethereum-batch-v999")),
                ("out-of-order-index", lambda p: p.__setitem__("index", 1)),
                ("coverage-gap", lambda p: p.__setitem__("first_step", 1)),
                ("initial-root", lambda p: p["public"]["before"].__setitem__(0, p["public"]["before"][0] ^ 1)),
                ("initial-pc-high64", lambda p: p["public"]["cpu"]["statement"].__setitem__("initial_pc", p["public"]["cpu"]["statement"]["initial_pc"] ^ (1 << 32))),
                ("initial-register", lambda p: p["public"]["cpu"]["statement"]["initial_registers"].__setitem__(31, p["public"]["cpu"]["statement"]["initial_registers"][31] ^ 1)),
                ("final-root", lambda p: p["public"]["after"].__setitem__(0, p["public"]["after"][0] ^ 1)),
                ("keccak-id-gap", lambda p: p["public"]["cpu"].__setitem__("first_call_id", p["public"]["cpu"]["first_call_id"] + 1)),
                ("add-id-gap", lambda p: p["public"]["cpu"]["secp"]["add"].__setitem__("first_id", p["public"]["cpu"]["secp"]["add"]["first_id"] + 1)),
                ("double-id-gap", lambda p: p["public"]["cpu"]["secp"]["double"].__setitem__("first_id", p["public"]["cpu"]["secp"]["double"]["first_id"] + 1)),
                ("producer-rom-injection", lambda p: p["public"]["cpu"]["statement"].__setitem__("program", {"base": 4096, "words": [0x13], "addresses": []})),
                ("unknown-field", lambda p: p.__setitem__("untrusted_root_authority", True)),
                ("proof-digest", lambda p: p.__setitem__("proof_sha256", "00" * 32)),
            ]
            for name, mutate in changes:
                attack(name, lambda folder, p, c, mutate=mutate: mutate(p))
            def duplicate(folder, receipt, local):
                summary = json.loads((folder / "summary.json").read_text())
                summary["verified_batches"] = 2
                (folder / "summary.json").write_text(json.dumps(summary))
                (folder / "batch-000001.json").write_text(json.dumps(receipt))
                (folder / "batch-000001.proof").symlink_to((source / "batch-000000.proof").resolve())
            attack("duplicated-reordered-batch", duplicate)
            def balanced(folder, receipt, local):
                for value, delta in ((receipt["claims"]["cpu"]["cpu"]["state"], 1), (receipt["claims"]["ram"]["callers"]["tables"][1][12], -1)):
                    value["c0"]["a"]["v"] = (value["c0"]["a"]["v"] + delta) % 2147483647
            attack("balanced-cpu-cell-state", balanced)
            def corrupt_wire(folder, receipt, local):
                path = folder / "batch-000000.proof"
                raw = path.read_bytes()[:-1]
                path.unlink()  # Never follow the immutable original symlink.
                path.write_bytes(raw)
                receipt["proof_sha256"] = hashlib.sha256(raw).hexdigest()
            attack("truncated-wire-with-valid-digest", corrupt_wire)
            def completed(folder, receipt, local):
                summary = json.loads((folder / "summary.json").read_text())
                summary["completed"] = True
                (folder / "summary.json").write_text(json.dumps(summary))
            attack("fake-completed-real-prefix", completed, mode="verify")
            # A generic pinned toy ABI test reaches a genuine absorbing endpoint
            # to exercise the terminal branch. No Ethereum validity is claimed.
            toy = workspace / "synthetic"
            toy.mkdir()
            tc = toy_config(toy)
            produced = run(binary, "prove", tc, toy / "config.json")
            accepted = run(binary, "verify", tc, toy / "verify.json")
            if not accepted["receiver"]["full_block_proof_verified"]:
                raise RuntimeError("complete synthetic chain was not accepted")
            cases.append({"case": "synthetic-abi-complete-only", "ethereum_block_proof": False, "rejected": False, **accepted})
            ts = Path(tc["output_directory"])
            def missing_terminal(folder, receipt, local):
                (folder / "terminal.proof").unlink()
            attack("synthetic-missing-terminal", missing_terminal, mode="verify", source_dir=ts, source_config=tc)
            def bad_terminal(folder, receipt, local):
                path = folder / "terminal.proof"
                raw = path.read_bytes()[:-1]
                path.unlink()
                path.write_bytes(raw)
            attack("synthetic-corrupt-terminal", bad_terminal, mode="verify", source_dir=ts, source_config=tc)
            attack("synthetic-wrong-output", lambda f, p, c: c.__setitem__("expected_output", "01" + c["expected_output"][2:]), mode="verify", source_dir=ts, source_config=tc)
            # Input and expected image identity are receiver-owned configuration.
            attack("synthetic-wrong-input-pin", lambda f, p, c: c.__setitem__("input_sha256", "00" * 32), mode="verify", source_dir=ts, source_config=tc)
            if check_resume:
                cases.extend(qualify_resume(binary, workspace, reprove_binary))
            return {"scope": "real-prefix adversarial receiver plus synthetic ABI terminal tests", "ethereum_block_proof": False, "verifier": identity(binary), "batch_budget_checked": check_batch_budget, "real_config_sha256": identity(config_path)["sha256"], "real_prefix_artifacts": {p.name: value for p, value in originals.items()}, "synthetic_producer": produced, "cases": cases}
    finally:
        for path, expected in originals.items():
            if identity(path) != expected:
                raise RuntimeError(f"original artifact changed: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, help="Preserve ignored cloned receipts and synthetic proof artifacts in a NEW directory")
    parser.add_argument("--check-batch-budget", action="store_true", help="Require the current receiver batch resource admission guard; omit for historical frozen controls")
    parser.add_argument("--check-resume", action="store_true", help="Qualify synthetic multi-batch crash-prefix continuation and proof parity")
    parser.add_argument("--reprove-binary", type=Path, help="Also qualify retained-batch benchmark against a complete synthetic chain")
    args = parser.parse_args()
    result = qualify(args.verifier.resolve(), args.config.resolve(), args.check_batch_budget, args.artifacts.resolve() if args.artifacts else None, args.check_resume, args.reprove_binary.resolve() if args.reprove_binary else None)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{len(result['cases'])} serialized-chain receiver cases passed")


if __name__ == "__main__":
    main()
