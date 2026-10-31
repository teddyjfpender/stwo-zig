#!/usr/bin/env python3
"""Build the software RV64 guest; optionally recover/validate one pinned block.

Artifacts and diagnostics are execution preparation, never STARK proof evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
TOOLCHAIN = "nightly-2026-08-08"


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def run(args, cwd, **kwargs):
    subprocess.run(args, cwd=cwd, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--prepare-fixture", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--execution-report", type=Path)
    parser.add_argument("--oracle-report", type=Path)
    parser.add_argument("--guest-profile", choices=("software", "keccak-service-v1", "ethereum-services-v1", "ethereum-services-v2"), default="software")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8:
        parser.error("jobs must be in 1..8")
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    common = ["--locked", "--release", "-j", str(args.jobs)]
    if args.offline:
        common.append("--offline")
    workspace = HERE / "services" if args.guest_profile.startswith("ethereum-services-") else HERE
    env = dict(os.environ, RUSTFLAGS="-C link-arg=-Tlinker.ld")
    service_features = ["--features", "keccak-service"] if args.guest_profile != "software" else []
    if args.guest_profile.startswith("ethereum-services-"):
        service_features = ["--features", "keccak-service,secp-word-service" if args.guest_profile.endswith("v2") else "keccak-service,secp-service"]
        for name in ("linker.ld", "riscv64i-stwo.json"):
            if (workspace / name).read_bytes() != (HERE / name).read_bytes():
                raise ValueError("service workspace runtime contract differs: " + name)
    run(["cargo", "+" + TOOLCHAIN, "build", *common, *service_features, "--target", "riscv64i-stwo.json",
         "-Z", "json-target-spec", "-Z", "build-std=core,alloc", "-Z",
         "build-std-features=compiler-builtins-mem"], workspace, env=env)
    elf = workspace / "target/riscv64i-stwo/release/stwo-ethereum-rv64-guest"
    # Keep the executable source target immutable and publish a separate artifact.
    guest_name = {"software": "ethereum-rv64-software.elf", "keccak-service-v1": "ethereum-rv64-keccak-service-v1.elf", "ethereum-services-v1": "ethereum-rv64-services-v1.elf", "ethereum-services-v2": "ethereum-rv64-services-v2.elf"}[args.guest_profile]
    guest = artifacts / guest_name
    guest.write_bytes(elf.read_bytes())
    report = {"schema": "stwo.rv64.ethereum-software-build.v1", "toolchain": TOOLCHAIN,
              "isa": "RV64IM", "abi": "lp64", "execution_profile": args.guest_profile, "guest": identity(guest),
              "guest_source": identity(HERE / "src/main.rs"),
              "build_script": identity(Path(__file__)),
              "runtime_sources": [identity(HERE / "src/single_thread_atomics.rs"),
                                  identity(workspace / "Cargo.toml"), identity(workspace / "linker.ld"),
                                  identity(HERE / "build.rs")],
              "allocator_source": identity(HERE.parents[1] / "exact_layout_allocator_v2.rs"),
              "target": identity(workspace / "riscv64i-stwo.json"),
              "lockfile": identity(workspace / "Cargo.lock"),
              "host_validation_verified": False, "rv64_execution_verified": False,
              "full_block_proof_verified": False}
    if args.guest_profile != "software":
        report["service_source"] = identity(HERE / "src/keccak_service.rs")
    if args.guest_profile.startswith("ethereum-services-"):
        report["secp_service_sources"] = [identity(HERE / "vendor/k256" / name) for name in
                                          ("Cargo.toml", "src/arithmetic/projective.rs", "src/arithmetic/projective/stwo_service.rs", "src/arithmetic/field.rs")]
        report["secp_upstream_sources"] = identity(HERE / "vendor/k256-source.json")
        report["service_abi_sources"] = [identity(HERE / "service_abi" / name) for name in
                                         ("Cargo.toml", "src/lib.rs")]
    if args.prepare_fixture:
        manifest = json.loads((ROOT / "autoresearch/benchmarks/ethereum_block_mainnet_24628607.json").read_text())
        zisk = manifest["zisk"]
        expected = zisk["fixture"]
        fixture = artifacts / "zisk-input.bin"
        if not fixture.exists():
            if args.offline:
                raise ValueError("offline fixture preparation requires existing zisk-input.bin")
            url = ("https://raw.githubusercontent.com/0xPolygonHermez/zisk-eth-client/"
                   + zisk["ethereum_client"]["commit"] + "/" + expected["path"])
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(expected["bytes"] + 1)
        else:
            with fixture.open("rb") as stream:
                data = stream.read(expected["bytes"] + 1)
        if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("pinned ZisK fixture byte identity mismatch")
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != expected["git_blob"]:
            raise ValueError("pinned ZisK fixture Git blob mismatch")
        fixture.write_bytes(data)
        runtime = HERE.parents[1]
        for package in ("projection", "host_validation"):
            run(["cargo", "+" + TOOLCHAIN, "build", *common], runtime / package)
        projected = artifacts / "fixture"
        if not projected.exists():
            run([str(runtime / "projection/target/release/stwo-ethereum-input-projection"),
                 str(fixture), str(projected)], ROOT)
        # Existing validation joins independent expected hashes and formats.
        import sys
        sys.path.insert(0, str(ROOT))
        from autoresearch.benchmarks import ethereum_block_comparison as comparison
        output = projected / "expected-output.bin"
        candidate = projected / "host-validation-candidate.bin"
        candidate.unlink(missing_ok=True)
        run([str(runtime / "host_validation/target/release/stwo-ethereum-host-validation"),
             str(projected / "canonical-input.ssz"), str(candidate)], ROOT)
        comparison.validate_stwo_projection(projected / "canonical-input.ssz",
                                            projected / "stwo-runner-input.bin", candidate, manifest)
        candidate.replace(output)
        report.update(host_validation_verified=True, canonical_input=identity(projected / "canonical-input.ssz"),
                      input=identity(projected / "stwo-runner-input.bin"),
                      expected_output=identity(output), source_fixture=identity(fixture), source_git_blob=blob,
                      fixture_repository=zisk["ethereum_client"]["repository"],
                      fixture_commit=zisk["ethereum_client"]["commit"])
    if bool(args.execution_report) != bool(args.oracle_report):
        parser.error("execution and oracle reports must be supplied together")
    if args.execution_report:
        if args.guest_profile != "software":
            parser.error("software-only independent oracle linkage does not qualify service profiles")
        if not report["host_validation_verified"]:
            parser.error("execution linkage requires --prepare-fixture host validation")
        native_bytes = args.execution_report.read_bytes()
        native = json.loads(native_bytes)
        independent = json.loads(args.oracle_report.read_text())
        expected_output = output.read_bytes().hex()
        canonical_sha = identity(projected / "canonical-input.ssz")["sha256"]
        if not (native.get("status") == "completed" and native.get("verified_output") is True and
                independent.get("oracle") == "Unicorn2.1.4" and
                independent.get("verified_output") is True and independent.get("completed") is True and
                native.get("elf_sha256") == independent.get("elf_sha256") == report["guest"]["sha256"] and
                native.get("input_sha256") == independent.get("canonical_input_sha256") == canonical_sha and
                native.get("output") == independent.get("output") == expected_output and
                native.get("instructions") == independent.get("exact_steps_verified") and
                native.get("pc") == independent.get("architectural_post_store_pc") and
                native.get("final_registers") == independent.get("final_registers") and
                len(native.get("final_registers", [])) == 32 and
                independent.get("compared_runner_report_sha256") == hashlib.sha256(native_bytes).hexdigest()):
            raise ValueError("native/oracle execution linkage differs from freshly built ELF and validated input/output")
        report.update(rv64_execution_verified=True, native_execution=identity(args.execution_report),
                      independent_execution=identity(args.oracle_report), instructions=native["instructions"],
                      final_registers_pc_output_count_match=True, ram_state_comparison=False)
    destination = artifacts / "build-report.json"
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(destination)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
