#!/usr/bin/env python3
"""Build the pinned ACT4 RV32I/M subset for the stwo-zig zkVM.

The upstream checkout remains byte-clean. This adapter:

* selects only the pinned rv32i/I and rv32i/M test sources;
* builds expected signatures with the exact pinned Sail model/configuration;
* compiles self-checking ELFs against the checked-in zkVM boundary; and
* records every source and ELF digest in a machine-readable receipt.

Run after ``scripts/riscv_formal_tools.py prepare``:

  python3 scripts/riscv_arch_tests.py build \
      --formal-workspace /tmp/stwo-riscv-formal \
      --workdir zig-out/riscv-formal/arch-test
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from riscv_arch_tests_lib.support import (
        EXPECTED_SUITES,
        ROOT,
        ArchTestError,
        adapter_digest as _adapter_digest,
        expected_sources as _expected_sources,
        json_digest as _json_digest,
        load_json_file as _load_json_file,
        materialize_adapter as _materialize_adapter,
        prepend_tool_paths as _prepend_tool_paths,
        require_sha256 as _require_sha256,
        resolve_llvm_nm as _resolve_llvm_nm,
        resolve_riscv_clang as _resolve_riscv_clang,
        run_checked as _run_checked,
        run_json as _run_json,
        sha256_file as _sha256_file,
    )
except ModuleNotFoundError:  # Imported as scripts.riscv_arch_tests in tests.
    from scripts.riscv_arch_tests_lib.support import (
        EXPECTED_SUITES,
        ROOT,
        ArchTestError,
        adapter_digest as _adapter_digest,
        expected_sources as _expected_sources,
        json_digest as _json_digest,
        load_json_file as _load_json_file,
        materialize_adapter as _materialize_adapter,
        prepend_tool_paths as _prepend_tool_paths,
        require_sha256 as _require_sha256,
        resolve_llvm_nm as _resolve_llvm_nm,
        resolve_riscv_clang as _resolve_riscv_clang,
        run_checked as _run_checked,
        run_json as _run_json,
        sha256_file as _sha256_file,
    )

try:
    from scripts import riscv_equivalence as equivalence
    from scripts import riscv_formal_tools as formal
except ImportError:
    import riscv_equivalence as equivalence
    import riscv_formal_tools as formal


def build_arch_tests(
    formal_workspace: Path,
    workdir: Path,
    jobs: int,
) -> dict[str, Any]:
    """Build the complete applicable ACT4 RV32I/M source set."""
    profile = formal.load_profile()
    compiler = formal.resolve_sail_compiler(None, profile.sail_compiler)
    paths = formal.ToolPaths(formal_workspace.resolve())
    formal_receipt = formal.verify(paths, profile, compiler)
    clang = _resolve_riscv_clang()
    _prepend_tool_paths(clang)

    source = paths.arch_test_source
    _require_exact_arch_test(source, profile)
    generated_config = workdir.resolve() / "adapter"
    generated_config.mkdir(parents=True, exist_ok=True)
    _materialize_adapter(generated_config, source, paths, profile, clang)

    # Imported only inside the exact upstream uv environment. The outer CLI
    # re-executes itself there before entering this function.
    from act.build import build
    from act.build_plan import generate_build_plan
    from act.config import CoverageSimulator
    from act.parse_test_constraints import generate_test_dict
    from act.select_tests import prepare_configs_and_select_tests

    test_dir = source / "tests"
    full_test_dict = generate_test_dict(test_dir, ",".join(EXPECTED_SUITES), "")
    prepared = prepare_configs_and_select_tests(
        [generated_config / "test_config.yaml"],
        full_test_dict,
        workdir.resolve(),
        jobs=jobs,
        validate_tools=False,
    )
    if len(prepared) != 1:
        raise ArchTestError("ACT4 returned an unexpected configuration count")
    config, config_params, selected_tests = prepared[0]
    if config_params.get("MXLEN") != 32:
        raise ArchTestError("ACT4 UDB selection did not resolve MXLEN=32")

    expected_sources = _expected_sources(source)
    selected_sources = {metadata.test_path.resolve() for metadata in selected_tests.values()}
    if selected_sources != expected_sources:
        missing = sorted(str(path) for path in expected_sources - selected_sources)
        extra = sorted(str(path) for path in selected_sources - expected_sources)
        raise ArchTestError(
            f"ACT4 applicable source set drifted: missing={missing}, extra={extra}"
        )

    tasks = generate_build_plan(
        config,
        32,
        selected_tests,
        test_dir,
        source / "coverpoints",
        workdir.resolve(),
        False,
        CoverageSimulator.QUESTA,
        fast=True,
    )
    result = build(
        tasks,
        jobs=jobs,
        cache_root=workdir.resolve(),
        keep_going=True,
        verbose=False,
    )
    if result.errors:
        details = "\n".join(
            f"{error.task_name}: {error.output[-2000:]}" for error in result.errors
        )
        raise ArchTestError(
            f"ACT4 build failed ({result.failed} task(s)):\n{details}"
        )

    elf_dir = workdir.resolve() / "stwo-rv32im-zkvm" / "elfs"
    elfs = sorted(elf_dir.rglob("*.elf"))
    if len(elfs) != len(expected_sources):
        raise ArchTestError(
            f"ACT4 emitted {len(elfs)} ELFs for {len(expected_sources)} sources"
        )
    entries = []
    for elf in elfs:
        relative_elf = elf.relative_to(elf_dir)
        source_path = source / "tests" / relative_elf.with_suffix(".S")
        if source_path.resolve() not in expected_sources:
            raise ArchTestError(f"unexpected ACT4 ELF {elf}")
        build_base = (
            workdir.resolve()
            / "stwo-rv32im-zkvm"
            / "build"
            / relative_elf.parent
            / elf.stem
        )
        signature = build_base.with_suffix(".sig")
        signature_elf = build_base.with_suffix(".sig.elf")
        signature_log = build_base.with_suffix(".sig.log")
        for artifact in (signature, signature_elf, signature_log):
            if not artifact.is_file():
                raise ArchTestError(f"ACT4 omitted {artifact}")
        if "SUCCESS" not in signature_log.read_text(encoding="utf-8"):
            raise ArchTestError(f"pinned Sail did not complete {elf.stem}")
        entries.append(
            {
                "name": elf.stem,
                "suite": elf.parent.name,
                "source": str(source_path.relative_to(source)),
                "source_sha256": _sha256_file(source_path),
                "elf": str(elf.relative_to(ROOT) if elf.is_relative_to(ROOT) else elf),
                "elf_sha256": _sha256_file(elf),
                "sail_signature_sha256": _sha256_file(signature),
                "sail_elf_sha256": _sha256_file(signature_elf),
                "sail_log_sha256": _sha256_file(signature_log),
            }
        )

    receipt = {
        "schema": "stwo-riscv-arch-test-build-v1",
        "profile": profile.name,
        "riscv_arch_test_revision": profile.arch_test.revision,
        "sail_revision": profile.sail.revision,
        "sail_compiler": profile.sail_compiler,
        "suites": list(EXPECTED_SUITES),
        "tests": len(entries),
        "adapter_sha256": _adapter_digest(),
        "formal_tools": formal_receipt,
        "elfs": entries,
    }
    receipt_path = workdir.resolve() / "arch-test-build.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def audit_arch_tests(
    formal_workspace: Path,
    workdir: Path,
    trace_bin: Path,
    prover_bin: Path,
    proof_jobs: int,
    max_steps: int,
    metal_bin: Path | None,
) -> dict[str, Any]:
    """Execute, cross-check, prove, and independently verify every ACT4 ELF."""
    profile = formal.load_profile()
    compiler = formal.resolve_sail_compiler(None, profile.sail_compiler)
    paths = formal.ToolPaths(formal_workspace.resolve())
    formal_receipt = formal.verify(paths, profile, compiler)
    equivalence.verify_spike_binary(paths.spike_binary)
    trace_bin = trace_bin.resolve(strict=True)
    prover_bin = prover_bin.resolve(strict=True)
    if proof_jobs <= 0:
        raise ArchTestError("--proof-jobs must be positive")
    if max_steps <= 0:
        raise ArchTestError("--max-steps must be positive")

    build_receipt = _load_build_receipt(workdir, profile)
    audit_dir = workdir.resolve() / "audit"
    proof_dir = audit_dir / "proofs"
    proof_dir.mkdir(parents=True, exist_ok=True)

    executions: list[dict[str, Any]] = []
    execution_by_name: dict[str, dict[str, Any]] = {}
    for raw_entry in build_receipt["elfs"]:
        entry = _validate_build_entry(raw_entry)
        elf = _entry_path(entry["elf"])
        if _sha256_file(elf) != entry["elf_sha256"]:
            raise ArchTestError(f"{elf}: digest changed after the ACT4 build")
        _run_checked(
            [str(trace_bin), "--program-tuples", str(elf)],
            stdout=subprocess.DEVNULL,
            label=f"{entry['name']} program commitment",
        )
        zig_trace = equivalence.run_zig_trace(elf, trace_bin, max_steps, None)
        spike_rows = equivalence.run_spike_commit_trace(
            paths.spike_binary,
            elf,
            zig_trace,
            timeout_seconds=120.0,
        )
        differences = equivalence.compare_spike_commit_trace(spike_rows, zig_trace)
        if differences:
            raise ArchTestError(
                f"{entry['name']}: Spike retirement mismatch:\n"
                + "\n".join(differences)
            )
        public = _run_json(
            [str(trace_bin), "--public-values", str(elf), "--max-steps", str(max_steps)],
            f"{entry['name']} public values",
        )
        _validate_public_diagnostic(public, formal_receipt, entry, zig_trace)
        execution = {
            "name": entry["name"],
            "suite": entry["suite"],
            "elf": entry["elf"],
            "elf_sha256": entry["elf_sha256"],
            "retirements": zig_trace["total_steps"],
            "final_pc": zig_trace["final_pc"],
            "trace_sha256": _json_digest(zig_trace),
            "public_values_sha256": _json_digest(public),
        }
        executions.append(execution)
        execution_by_name[entry["name"]] = {
            "entry": entry,
            "elf": elf,
            "trace": zig_trace,
            "public": public,
        }

    failure_path = _audit_failure_path(
        execution_by_name["M-mulh-00"]["elf"],
        trace_bin,
        audit_dir,
        max_steps,
    )

    started = time.monotonic()
    proof_results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=proof_jobs) as executor:
        futures = {
            executor.submit(
                _prove_and_verify,
                prover_bin,
                proof_dir,
                execution_by_name[execution["name"]],
            ): execution["name"]
            for execution in executions
        }
        try:
            for future in concurrent.futures.as_completed(futures):
                proof_results.append(future.result())
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    proof_results.sort(key=lambda item: item["name"])

    metal = None
    if metal_bin is not None:
        resolved_metal = metal_bin.resolve(strict=True)
        representative = execution_by_name["M-mulh-00"]
        completed = _run_checked(
            [
                str(resolved_metal),
                "--elf",
                str(representative["elf"]),
                # Formerly `--production`; same parameters, honest name (#152/7).
                "--pow24-q70",
                "--profile",
            ],
            label="M-mulh-00 Metal proof",
            timeout=900,
        )
        metal_output = completed.stdout + completed.stderr
        metal = {
            "test": "M-mulh-00",
            "binary_sha256": _sha256_file(resolved_metal),
            "output_sha256": hashlib.sha256(metal_output).hexdigest(),
        }

    corpus_digest = hashlib.sha256()
    for execution in executions:
        corpus_digest.update(execution["name"].encode())
        corpus_digest.update(bytes.fromhex(execution["elf_sha256"]))
        corpus_digest.update(bytes.fromhex(execution["trace_sha256"]))
    receipt = {
        "schema": "stwo-riscv-arch-test-audit-v1",
        "profile": profile.name,
        "formal_tools": formal_receipt,
        "adapter_sha256": build_receipt["adapter_sha256"],
        "trace_binary_sha256": _sha256_file(trace_bin),
        "prover_binary_sha256": _sha256_file(prover_bin),
        "security_policy": "secure",
        "tests": len(executions),
        "retirements": sum(item["retirements"] for item in executions),
        "proofs_verified": len(proof_results),
        "proof_jobs": proof_jobs,
        "proof_wall_seconds": time.monotonic() - started,
        "corpus_sha256": corpus_digest.hexdigest(),
        "failure_path": failure_path,
        "metal": metal,
        "executions": executions,
        "proofs": proof_results,
    }
    audit_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = workdir.resolve() / "arch-test-audit.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def _load_build_receipt(
    workdir: Path,
    profile: formal.FormalProfile,
) -> dict[str, Any]:
    path = workdir.resolve() / "arch-test-build.json"
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ArchTestError(f"{path}: cannot read ACT4 build receipt: {error}") from error
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != "stwo-riscv-arch-test-build-v1"
        or receipt.get("profile") != profile.name
        or receipt.get("riscv_arch_test_revision") != profile.arch_test.revision
        or receipt.get("sail_revision") != profile.sail.revision
        or receipt.get("sail_compiler") != profile.sail_compiler
        or receipt.get("adapter_sha256") != _adapter_digest()
        or receipt.get("tests") != 47
        or not isinstance(receipt.get("elfs"), list)
        or len(receipt["elfs"]) != 47
    ):
        raise ArchTestError(f"{path}: stale or malformed ACT4 build receipt")
    return receipt


def _validate_build_entry(raw: object) -> dict[str, Any]:
    fields = {
        "name",
        "suite",
        "source",
        "source_sha256",
        "elf",
        "elf_sha256",
        "sail_signature_sha256",
        "sail_elf_sha256",
        "sail_log_sha256",
    }
    if not isinstance(raw, dict) or set(raw) != fields:
        raise ArchTestError("ACT4 build entry has a non-canonical shape")
    if raw["suite"] not in EXPECTED_SUITES or not isinstance(raw["name"], str):
        raise ArchTestError("ACT4 build entry has an invalid identity")
    for field in (
        "source_sha256",
        "elf_sha256",
        "sail_signature_sha256",
        "sail_elf_sha256",
        "sail_log_sha256",
    ):
        _require_sha256(raw[field], f"{raw['name']}.{field}")
    return raw


def _entry_path(value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ArchTestError("ACT4 build entry has no ELF path")
    path = Path(value)
    return (path if path.is_absolute() else ROOT / path).resolve(strict=True)


def _validate_public_diagnostic(
    public: object,
    formal_receipt: dict[str, Any],
    entry: dict[str, Any],
    trace: dict[str, Any],
) -> None:
    if not isinstance(public, dict):
        raise ArchTestError(f"{entry['name']}: public diagnostic is not an object")
    if (
        public.get("schema") != "riscv-public-values-diagnostic-v1"
        or public.get("source", {}).get("elf_sha256") != entry["elf_sha256"]
        or public.get("provenance", {}).get("oracle_commit")
        != formal_receipt["sail"]["revision"]
    ):
        raise ArchTestError(f"{entry['name']}: public diagnostic identity drifted")
    data = public.get("public_data")
    if (
        not isinstance(data, dict)
        or data.get("initial_pc") != trace["initial_pc"]
        or data.get("final_pc") != trace["final_pc"]
        or data.get("clock") != trace["total_steps"]
        or data.get("final_regs") != trace["final_regs"]
    ):
        raise ArchTestError(f"{entry['name']}: public diagnostic differs from execution")


def _prove_and_verify(
    prover_bin: Path,
    proof_dir: Path,
    execution: dict[str, Any],
) -> dict[str, Any]:
    entry = execution["entry"]
    name = entry["name"]
    proof_path = proof_dir / f"{name}.proof.json"
    report_path = proof_dir / f"{name}.report.json"
    started = time.monotonic()
    _run_checked(
        [
            str(prover_bin),
            "prove",
            "--elf",
            str(execution["elf"]),
            "--backend",
            "cpu",
            "--protocol",
            "secure",
            "--output",
            str(proof_path),
            "--report-out",
            str(report_path),
        ],
        label=f"{name} secure proof",
        timeout=900,
    )
    artifact = _load_json_file(proof_path, f"{name} proof")
    report = _load_json_file(report_path, f"{name} report")
    expected_public = dict(execution["public"]["public_data"])
    io = expected_public.pop("io_entries")
    expected_public.update(io)
    statement = artifact.get("statement")
    source = artifact.get("source")
    provenance = artifact.get("provenance")
    if (
        artifact.get("artifact_kind") != "stwo_riscv_proof"
        or artifact.get("schema_version") != 4
        or artifact.get("release_status") != "release_gated"
        or artifact.get("air") != "sail_rv32im_zkvm_v1"
        or artifact.get("backend") != "cpu"
        or artifact.get("protocol") != "secure"
        or not isinstance(statement, dict)
        or not isinstance(source, dict)
        or not isinstance(provenance, dict)
        or source != execution["public"]["source"]
        or provenance.get("oracle_repository")
        != "https://github.com/riscv/sail-riscv"
        or provenance.get("oracle_commit")
        != "8c7f2da58de0ba5e4457e4de07e0046f0439f35f"
        or statement.get("public_data") != expected_public
        or statement.get("total_steps") != execution["trace"]["total_steps"]
    ):
        raise ArchTestError(f"{name}: proof artifact is not bound to the audited execution")
    statement_digest = _statement_digest(
        artifact["protocol"], artifact["pcs_config"], source, statement
    )
    if (
        report.get("statement_sha256") != statement_digest
        or report.get("verified_in_process") is not True
        or report.get("experimental") is not False
        or report.get("release_status") != "release_gated"
        or report.get("total_steps") != execution["trace"]["total_steps"]
    ):
        raise ArchTestError(f"{name}: proving report identity drifted")
    verify = _run_json(
        [
            str(prover_bin),
            "verify",
            "--artifact",
            str(proof_path),
            "--elf",
            str(execution["elf"]),
            "--protocol",
            "secure",
            "--expect-statement-digest",
            statement_digest,
        ],
        f"{name} independent verification",
        timeout=900,
    )
    if (
        verify.get("status") != "verified"
        or verify.get("security_policy") != "secure"
        or verify.get("statement_sha256") != statement_digest
    ):
        raise ArchTestError(f"{name}: independent verifier returned an invalid receipt")
    return {
        "name": name,
        "statement_sha256": statement_digest,
        "proof_artifact_sha256": _sha256_file(proof_path),
        "proof_bytes": verify.get("proof_bytes"),
        "proof_sha256": verify.get("proof_sha256"),
        "transcript_state_blake2s": verify.get("transcript_state_blake2s"),
        "seconds": time.monotonic() - started,
    }


def _statement_digest(
    protocol: str,
    pcs_config: dict[str, Any],
    source: dict[str, Any],
    statement: dict[str, Any],
) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"stwo-zig/riscv/expected-statement/v4\0")

    def word(value: object) -> None:
        if type(value) is not int or not 0 <= value <= 0xFFFF_FFFF:
            raise ArchTestError("proof statement contains a non-u32 word")
        hasher.update(struct.pack("<I", value))

    def wide(value: object) -> None:
        if type(value) is not int or not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
            raise ArchTestError("proof statement contains a non-u64 word")
        hasher.update(struct.pack("<Q", value))

    def length(values: object) -> list[Any]:
        if not isinstance(values, list):
            raise ArchTestError("proof statement sequence is not an array")
        word(len(values))
        return values

    def text(value: object) -> None:
        if not isinstance(value, str):
            raise ArchTestError("proof statement digest field is not text")
        encoded = value.encode()
        word(len(encoded))
        hasher.update(encoded)

    def optional(value: object) -> None:
        if value is not None and type(value) is not int:
            raise ArchTestError("proof statement optional word is malformed")
        word(int(value is not None))
        word(0 if value is None else value)

    text(protocol)
    fri_config = pcs_config["fri_config"]
    word(pcs_config["pow_bits"])
    word(fri_config["log_blowup_factor"])
    word(fri_config["log_last_layer_degree_bound"])
    wide(fri_config["n_queries"])
    word(fri_config["fold_step"])
    optional(pcs_config["lifting_log_size"])
    text(source["elf_sha256"])
    text(source["input_sha256"])
    for field in (
        "segment_ordinal",
        "segment_count",
        "initial_pc",
        "final_pc",
        "total_steps",
    ):
        word(statement[field])
    for component in length(statement["components"]):
        for field in (
            "index",
            "family",
            "family_shard_index",
            "family_shard_count",
            "row_offset",
            "log_size",
            "n_rows",
            "n_columns",
            "interaction_batch_count",
        ):
            word(component[field])
    for component in length(statement["infrastructure"]):
        for field in (
            "index",
            "kind",
            "log_size",
            "n_rows",
            "n_columns",
            "claim_count",
        ):
            word(component[field])
    public = statement["public_data"]
    for field in ("initial_pc", "final_pc", "clock"):
        word(public[field])
    for field in ("initial_regs", "final_regs", "reg_last_clock"):
        for value in public[field]:
            word(value)
    for field in ("program_root", "initial_rw_root", "final_rw_root"):
        optional(public[field])
    completion = public["completion"]
    completion_kinds = {"halt_flag": 0, "unretired_self_loop": 1}
    try:
        word(completion_kinds[completion["kind"]])
    except (KeyError, TypeError) as error:
        raise ArchTestError("proof completion kind is unsupported") from error
    for field in ("address", "value", "clock"):
        word(completion[field])
    for field in ("input_start", "input_len"):
        word(public[field])
    for value in length(public["input_words"]):
        word(value)
    for field in ("output_len", "output_len_addr", "output_data_addr"):
        word(public[field])
    for value in length(public["output_words"]):
        for field in ("addr", "value", "clock"):
            word(value[field])
    return hasher.hexdigest()


def _audit_failure_path(
    elf: Path,
    trace_bin: Path,
    audit_dir: Path,
    max_steps: int,
) -> dict[str, Any]:
    nm = _resolve_llvm_nm()
    symbols = subprocess.run(
        [str(nm), "-n", str(elf)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    address = None
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] == "begin_signature":
            address = int(fields[0], 16)
            break
    if address is None:
        raise ArchTestError(f"{elf}: begin_signature symbol is missing")
    image = bytearray(elf.read_bytes())
    offset = _elf32_file_offset(image, address)
    image[offset] ^= 1
    mutated = audit_dir / "M-mulh-00.bad-signature.elf"
    mutated.write_bytes(image)
    completed = subprocess.run(
        [
            str(trace_bin),
            "--elf",
            str(mutated),
            "--max-steps",
            str(max_steps),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    diagnostic = completed.stdout + completed.stderr
    if completed.returncode == 0 or "InstructionAddressMisaligned" not in diagnostic:
        raise ArchTestError("corrupted ACT4 signature did not reach the fail-closed edge")
    return {
        "test": "M-mulh-00",
        "mutation": "begin_signature byte 0 xor 1",
        "expected_error": "InstructionAddressMisaligned",
        "mutated_elf_sha256": _sha256_file(mutated),
    }


def _elf32_file_offset(image: bytes, address: int) -> int:
    if image[:6] != b"\x7fELF\x01\x01":
        raise ArchTestError("ACT4 failure-path fixture is not ELF32 little-endian")
    phoff = struct.unpack_from("<I", image, 28)[0]
    phentsize = struct.unpack_from("<H", image, 42)[0]
    phnum = struct.unpack_from("<H", image, 44)[0]
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, file_offset, vaddr, _, file_size, _ = struct.unpack_from(
            "<IIIIII",
            image,
            offset,
        )
        if p_type == 1 and vaddr <= address < vaddr + file_size:
            return file_offset + address - vaddr
    raise ArchTestError(f"ELF address 0x{address:08x} is not file-backed")


def _require_exact_arch_test(
    source: Path,
    profile: formal.FormalProfile,
) -> None:
    formal._require_head(source, profile.arch_test.revision)
    formal._require_clean(source)


def _reexec_in_act_environment(
    args: argparse.Namespace,
) -> int:
    arch_source = (
        formal.ToolPaths(args.formal_workspace.expanduser().resolve()).arch_test_source
    )
    mise = shutil.which("mise")
    if mise is None:
        raise ArchTestError("mise is required to run the pinned ACT4 environment")
    command = [
        mise,
        "exec",
        "--",
        "uv",
        "run",
        "python",
        str(Path(__file__).resolve()),
        args.command,
        "--formal-workspace",
        str(args.formal_workspace.expanduser().resolve()),
        "--workdir",
        str(args.workdir.expanduser().resolve()),
        "--jobs",
        str(args.jobs),
        "--internal-act-environment",
    ]
    return subprocess.run(command, cwd=arch_source, check=False).returncode


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "audit"))
    parser.add_argument("--formal-workspace", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    parser.add_argument(
        "--trace-bin",
        type=Path,
        default=ROOT / "zig-out" / "bin" / "riscv-trace-dump",
        help="Zig trace/public-values diagnostic executable used by audit",
    )
    parser.add_argument(
        "--prover-bin",
        type=Path,
        default=ROOT / "zig-out" / "bin" / "stwo-zig-riscv-cpu",
        help="CPU prover/verifier executable used by audit",
    )
    parser.add_argument(
        "--metal-bin",
        type=Path,
        help="optional production Metal prover executable for a representative proof",
    )
    parser.add_argument(
        "--proof-jobs",
        type=int,
        default=1,
        help="number of secure CPU proofs to run concurrently",
    )
    parser.add_argument("--max-steps", type=int, default=10_000_000)
    parser.add_argument(
        "--internal-act-environment",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    original_argv = list(sys.argv[1:] if argv is None else argv)
    args = _parser().parse_args(original_argv)
    try:
        if args.jobs <= 0:
            raise ArchTestError("--jobs must be positive")
        if args.command == "build":
            if not args.internal_act_environment:
                return _reexec_in_act_environment(args)
            receipt = build_arch_tests(
                args.formal_workspace.expanduser(),
                args.workdir.expanduser(),
                args.jobs,
            )
        else:
            if args.internal_act_environment:
                raise ArchTestError(
                    "--internal-act-environment is private to the build command"
                )
            receipt = audit_arch_tests(
                args.formal_workspace.expanduser(),
                args.workdir.expanduser(),
                args.trace_bin.expanduser(),
                args.prover_bin.expanduser(),
                args.proof_jobs,
                args.max_steps,
                args.metal_bin.expanduser() if args.metal_bin is not None else None,
            )
    except (
        ArchTestError,
        formal.FormalToolsError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"riscv arch tests: {error}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
