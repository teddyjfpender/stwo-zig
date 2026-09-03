#!/usr/bin/env python3
"""Create and replay sealed ZisK final-proof correctness evidence.

This receipt preserves a retained whole-block VADCOP proof and a separate
fresh-process verification.  Operational rusage is retained for custody, but
the receipt deliberately cannot promote it into the benchmark matrix: ZisK's
single process does not expose the protocol's exclusive timing buckets and a
known concurrent host workload disqualifies the captured wall time.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402


RECEIPT_SCHEMA = "stwo.ethereum.zisk-final-proof-evidence.v1"
EVIDENCE_KIND = "zisk-vadcop-final-proof-evidence-v1"
STATUS = "verified_final_proof_diagnostic_nonpromotable"
PROOF_KIND = "zisk-vadcop-final"
REFERENCE_FIXTURE_ID = "mainnet-24628607-representative-medium"
KEY_FILES = (
    ("global_info", "pilout.globalInfo.json"),
    ("vadcop_final_starkinfo", "zisk/vadcop_final/vadcop_final.starkinfo.json"),
    ("vadcop_final_verifierinfo", "zisk/vadcop_final/vadcop_final.verifierinfo.json"),
    ("vadcop_final_verkey_bin", "zisk/vadcop_final/vadcop_final.verkey.bin"),
    ("vadcop_final_verkey_json", "zisk/vadcop_final/vadcop_final.verkey.json"),
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TIME_LINE = re.compile(r"^(real|user|sys) ([0-9]+(?:\.[0-9]+)?)$", re.MULTILINE)


class ZiskFinalEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ZiskFinalEvidenceError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA256.fullmatch(value), f"{where} differs")
    return value


def _absolute(path: Path, where: str) -> Path:
    path = path.absolute()
    _require(path.is_absolute(), f"{where} path differs")
    return path


def _identity(path: Path, where: str) -> dict[str, Any]:
    path = _absolute(path, where)
    return {"path": str(path), **store.file_identity(path, where)}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"path", "bytes", "sha256"}, where)
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute(),
             f"{where}.path differs")
    _require(type(value["bytes"]) is int and value["bytes"] > 0,
             f"{where}.bytes differs")
    _sha(value["sha256"], f"{where}.sha256")
    store.validate_file_identity(Path(value["path"]), {
        "bytes": value["bytes"], "sha256": value["sha256"],
    }, where)
    return value


def _read_json(path: Path, where: str) -> dict[str, Any]:
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict, f"{where} must be an object")
    return value


def _manifest_projection(path: Path) -> dict[str, Any]:
    path = _absolute(path, "reference manifest")
    manifest = _read_json(path, "reference manifest")
    try:
        protocol_authority = manifest["benchmark_protocol"]
        statement = protocol_authority["statement"]
        block = manifest["block"]
        zisk = manifest["zisk"]
        source = zisk["source"]
        ethereum_client = zisk["ethereum_client"]
        fixture = zisk["fixture"]
        elf = zisk["guest_elf"]
        execution = zisk["execution"]
        global_info = zisk["plan"]["global_info"]
    except (KeyError, TypeError) as error:
        raise ZiskFinalEvidenceError("reference manifest projection is incomplete") from error
    _require(type(protocol_authority["statement_sha256"]) is str
             and SHA256.fullmatch(protocol_authority["statement_sha256"]),
             "reference statement SHA differs")
    expected_block = {
        "chain_id": block["chain_id"],
        "number": block["number"],
        "hash": block["hash"],
        "transaction_count": block["transaction_count"],
        "gas_used": block["gas_used"],
    }
    _require(expected_block == {
        key: statement["block"][key] for key in expected_block
    }, "reference statement block differs")
    return {
        "identity": _identity(path, "reference manifest"),
        "schema": manifest["schema"],
        "statement_sha256": protocol_authority["statement_sha256"],
        "matched_guest_statement_reproduced": statement[
            "matched_guest_statement_reproduced"
        ],
        "block": expected_block,
        "zisk_source": source,
        "ethereum_client": ethereum_client,
        "tool_version": zisk["tools"]["version"],
        "guest_elf": {key: elf[key] for key in ("bytes", "sha256")},
        "input": {key: fixture[key] for key in ("bytes", "sha256")},
        "expected_output": execution["output"],
        "steps": execution["steps"],
        "global_info": global_info,
    }


def _seconds_ns(value: str, where: str) -> int:
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise ZiskFinalEvidenceError(f"{where} differs") from error
    scaled = number * Decimal(1_000_000_000)
    _require(number >= 0 and scaled == scaled.to_integral_value(), f"{where} differs")
    return int(scaled)


def _rusage(path: Path, where: str) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = store.read_regular(path, where, maximum=1024 * 1024)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ZiskFinalEvidenceError(f"{where} is not UTF-8") from error
    matches = TIME_LINE.findall(text)
    _require(len(matches) == 3 and [name for name, _ in matches]
             == ["real", "user", "sys"], f"{where} timing lines differ")

    def resource(label: str) -> int:
        found = re.findall(rf"^\s*([0-9]+)  {re.escape(label)}$", text, re.MULTILINE)
        _require(len(found) == 1, f"{where} {label} differs")
        return int(found[0])

    timing = {
        "wall_ns": _seconds_ns(matches[0][1], f"{where}.real"),
        "user_ns": _seconds_ns(matches[1][1], f"{where}.user"),
        "system_ns": _seconds_ns(matches[2][1], f"{where}.sys"),
    }
    resources = {
        "maximum_resident_set_bytes": resource("maximum resident set size"),
        "peak_memory_footprint_bytes": resource("peak memory footprint"),
        "page_faults": resource("page faults"),
        "involuntary_context_switches": resource("involuntary context switches"),
    }
    return timing, resources


def _prove_semantics(
    path: Path, reference: dict[str, Any], proof_path: Path,
) -> dict[str, Any]:
    raw = store.read_regular(path, "ZisK prove stdout", maximum=16 * 1024 * 1024)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ZiskFinalEvidenceError("ZisK prove stdout is not UTF-8") from error
    block = reference["block"]
    _require(text.count("Block validation succeeded!") == 16,
             "ZisK whole-program execution multiplicity differs")
    for expected in (
        f"Block Hash: {block['hash']}",
        f"Transaction Count: {block['transaction_count']}",
        f"Gas Consumed: {block['gas_used']}",
        "Proof verified successfully.",
        ">>> GENERATE_VADCOP_FINAL_PROOF",
        "<<< GENERATE_VADCOP_FINAL_PROOF",
        f"Proof saved to {proof_path}",
        f"ZisK zkVM {reference['tool_version']}",
    ):
        _require(expected in text, f"ZisK prove stdout lacks {expected!r}")
    summary = re.findall(r"Proof generated in ([0-9]+(?:\.[0-9]+)?)s, steps: ([0-9]+)", text)
    _require(len(summary) == 1 and int(summary[0][1]) == reference["steps"],
             "ZisK prove summary differs")
    final_phase = re.findall(r"<<< GENERATE_VADCOP_FINAL_PROOF \(([0-9]+)ms\)", text)
    inner_phase = re.findall(r"<<< GENERATING_INNER_PROOFS \(([0-9]+)ms\)", text)
    _require(len(final_phase) == 1 and len(inner_phase) == 1,
             "ZisK proof phase observations differ")
    return {
        "execution_multiplicity": 16,
        "steps": int(summary[0][1]),
        "reported_total_ns": _seconds_ns(summary[0][0], "ZisK prove summary"),
        "reported_inner_proof_ns": int(inner_phase[0]) * 1_000_000,
        "reported_final_aggregation_ns": int(final_phase[0]) * 1_000_000,
        "in_process_final_verification": True,
    }


def _verify_semantics(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path, "ZisK fresh verify stdout", maximum=1024 * 1024)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ZiskFinalEvidenceError("ZisK verify stdout is not UTF-8") from error
    _require("Command ZiskVerify" in text and "✓ STARK proof was verified" in text,
             "ZisK fresh verifier verdict differs")
    duration = re.findall(r"time: ([0-9]+) milliseconds", text)
    _require(len(duration) == 1, "ZisK fresh verifier summary differs")
    return {
        "fresh_process": True,
        "verified": True,
        "reported_verification_ns": int(duration[0]) * 1_000_000,
    }


def _key_identities(root: Path) -> list[dict[str, Any]]:
    root = _absolute(root, "ZisK proving-key root")
    store.require_directory(root, "ZisK proving-key root")
    return [
        {"name": name, **_identity(root / relative, f"ZisK proving key {name}")}
        for name, relative in KEY_FILES
    ]


def build(
    *, reference_manifest: Path, tool: Path, elf: Path, input_path: Path,
    proving_key_root: Path, proof: Path, prove_stdout: Path,
    prove_stderr_time: Path, verify_stdout: Path, verify_stderr_time: Path,
    work_directory: Path, timing_disqualifiers: list[str],
) -> dict[str, Any]:
    reference = _manifest_projection(reference_manifest)
    paths = {
        "tool": _identity(tool, "ZisK tool"),
        "elf": _identity(elf, "ZisK guest ELF"),
        "input": _identity(input_path, "ZisK guest input"),
        "proof": _identity(proof, "ZisK final proof"),
        "prove_stdout": _identity(prove_stdout, "ZisK prove stdout"),
        "prove_stderr_time": _identity(prove_stderr_time, "ZisK prove stderr/time"),
        "verify_stdout": _identity(verify_stdout, "ZisK fresh verify stdout"),
        "verify_stderr_time": _identity(
            verify_stderr_time, "ZisK fresh verify stderr/time",
        ),
    }
    _require({key: paths["elf"][key] for key in ("bytes", "sha256")}
             == reference["guest_elf"], "ZisK ELF differs from reference manifest")
    _require({key: paths["input"][key] for key in ("bytes", "sha256")}
             == reference["input"], "ZisK input differs from reference manifest")
    proving_key_root = _absolute(proving_key_root, "ZisK proving-key root")
    keys = _key_identities(proving_key_root)
    _require({key: keys[0][key] for key in ("bytes", "sha256")}
             == reference["global_info"], "ZisK global-info key differs")
    work_directory = _absolute(work_directory, "ZisK work directory")
    store.require_directory(work_directory, "ZisK work directory")
    disqualifiers = sorted(set(timing_disqualifiers))
    _require(disqualifiers and all(type(item) is str and item for item in disqualifiers),
             "ZisK timing disqualifiers differ")
    prove_argv = [
        paths["tool"]["path"], "prove", "--elf", paths["elf"]["path"],
        "--inputs", paths["input"]["path"], "--proving-key", str(proving_key_root),
        "--output", paths["proof"]["path"], "--verify-proof",
    ]
    verify_argv = [paths["tool"]["path"], "verify", "--proof", paths["proof"]["path"]]
    prove_timing, prove_resources = _rusage(
        Path(paths["prove_stderr_time"]["path"]), "ZisK prove stderr/time",
    )
    verify_timing, verify_resources = _rusage(
        Path(paths["verify_stderr_time"]["path"]), "ZisK fresh verify stderr/time",
    )
    return protocol.seal({
        "schema": RECEIPT_SCHEMA,
        "status": STATUS,
        "kind": EVIDENCE_KIND,
        "fixture_id": REFERENCE_FIXTURE_ID,
        "reference": reference,
        "files": {**paths, "proving_key_files": keys},
        "proving_key_root": str(proving_key_root),
        "proving_key_manifest_sha256": protocol.sha256_bytes(
            protocol.canonical_bytes(keys)
        ),
        "processes": {
            "prove": {
                "argv": prove_argv,
                "work_directory": str(work_directory),
                "exit_code": 0,
                "timing": prove_timing,
                "resources": prove_resources,
            },
            "fresh_verify": {
                "argv": verify_argv,
                "work_directory": str(work_directory),
                "exit_code": 0,
                "timing": verify_timing,
                "resources": verify_resources,
            },
        },
        "observations": {
            "prove": _prove_semantics(
                Path(paths["prove_stdout"]["path"]), reference,
                Path(paths["proof"]["path"]),
            ),
            "fresh_verify": _verify_semantics(Path(paths["verify_stdout"]["path"])),
        },
        "claim_boundary": {
            "proof_kind": PROOF_KIND,
            "proof_scope": "one-final-proof-covering-the-entire-block",
            "final_proof_retained": True,
            "fresh_process_verification": True,
            "inner_base_proofs_retained": False,
            "exclusive_stage_timings_available": False,
            "security_target_bits": None,
            "matched_guest_statement_reproduced": False,
            "timing_classification": "diagnostic_nonpromotable",
            "timing_disqualifiers": disqualifiers,
            "matrix_timing_admissible": False,
            "comparison_ready": False,
        },
    })


def validate(path: Path) -> dict[str, Any]:
    path = _absolute(path, "ZisK final-proof receipt")
    raw = store.read_regular(path, "ZisK final-proof receipt", maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "ZisK final-proof receipt is not canonical JSON")
    _require(value.get("content_sha256") == protocol.content_sha256(value),
             "ZisK final-proof receipt content seal differs")
    value = _exact(value, {
        "schema", "status", "kind", "fixture_id", "reference", "files",
        "proving_key_root", "proving_key_manifest_sha256", "processes",
        "observations", "claim_boundary", "content_sha256",
    }, "ZisK final-proof receipt")
    _require(value["schema"] == RECEIPT_SCHEMA and value["status"] == STATUS
             and value["kind"] == EVIDENCE_KIND
             and value["fixture_id"] == REFERENCE_FIXTURE_ID,
             "ZisK final-proof receipt identity differs")
    files = _exact(value["files"], {
        "tool", "elf", "input", "proof", "prove_stdout", "prove_stderr_time",
        "verify_stdout", "verify_stderr_time", "proving_key_files",
    }, "ZisK final-proof files")
    for name in (
        "tool", "elf", "input", "proof", "prove_stdout", "prove_stderr_time",
        "verify_stdout", "verify_stderr_time",
    ):
        _validate_identity(files[name], f"ZisK final-proof {name}")
    keys = files["proving_key_files"]
    _require(type(keys) is list and len(keys) == len(KEY_FILES),
             "ZisK proving-key file count differs")
    for item, (name, relative) in zip(keys, KEY_FILES):
        item = _exact(item, {"name", "path", "bytes", "sha256"},
                      f"ZisK proving-key {name}")
        _require(item["name"] == name
                 and Path(item["path"]) == Path(value["proving_key_root"]) / relative,
                 f"ZisK proving-key {name} path differs")
        _validate_identity({key: item[key] for key in ("path", "bytes", "sha256")},
                           f"ZisK proving-key {name}")
    _sha(value["proving_key_manifest_sha256"], "ZisK proving-key manifest SHA")
    _require(value["proving_key_manifest_sha256"]
             == protocol.sha256_bytes(protocol.canonical_bytes(keys)),
             "ZisK proving-key manifest differs")
    reference_identity = _exact(value["reference"]["identity"],
                                {"path", "bytes", "sha256"},
                                "ZisK reference manifest")
    _validate_identity(reference_identity, "ZisK reference manifest")
    processes = _exact(value["processes"], {"prove", "fresh_verify"},
                       "ZisK final-proof processes")
    prove = _exact(processes["prove"], {
        "argv", "work_directory", "exit_code", "timing", "resources",
    }, "ZisK prove process")
    _require(type(prove["work_directory"]) is str,
             "ZisK prove work directory differs")
    claim = _exact(value["claim_boundary"], {
        "proof_kind", "proof_scope", "final_proof_retained",
        "fresh_process_verification", "inner_base_proofs_retained",
        "exclusive_stage_timings_available", "security_target_bits",
        "matched_guest_statement_reproduced", "timing_classification",
        "timing_disqualifiers", "matrix_timing_admissible", "comparison_ready",
    }, "ZisK final-proof claim boundary")
    expected = build(
        reference_manifest=Path(reference_identity["path"]),
        tool=Path(files["tool"]["path"]), elf=Path(files["elf"]["path"]),
        input_path=Path(files["input"]["path"]),
        proving_key_root=Path(value["proving_key_root"]),
        proof=Path(files["proof"]["path"]),
        prove_stdout=Path(files["prove_stdout"]["path"]),
        prove_stderr_time=Path(files["prove_stderr_time"]["path"]),
        verify_stdout=Path(files["verify_stdout"]["path"]),
        verify_stderr_time=Path(files["verify_stderr_time"]["path"]),
        work_directory=Path(prove["work_directory"]),
        timing_disqualifiers=claim["timing_disqualifiers"],
    )
    _require(value == expected, "ZisK final-proof receipt replay differs")
    return value


def evidence(path: Path) -> dict[str, Any]:
    receipt = validate(path)
    proof = receipt["files"]["proof"]
    return {
        "kind": EVIDENCE_KIND,
        "receipt": _identity(path, "ZisK final-proof receipt"),
        "projection": {
            "fixture_id": receipt["fixture_id"],
            "reference_manifest": {
                key: receipt["reference"]["identity"][key]
                for key in ("bytes", "sha256")
            },
            "statement_sha256": receipt["reference"]["statement_sha256"],
            "block": receipt["reference"]["block"],
            "proof_kind": receipt["claim_boundary"]["proof_kind"],
            "proof_scope": receipt["claim_boundary"]["proof_scope"],
            "proof": {key: proof[key] for key in ("bytes", "sha256")},
            "fresh_process_verification": True,
            "security_target_bits": None,
            "exclusive_stage_timings_available": False,
            "timing_classification": "diagnostic_nonpromotable",
            "matrix_timing_admissible": False,
            "comparison_ready": False,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    for name in (
        "reference-manifest", "tool", "elf", "input", "proving-key-root", "proof",
        "prove-stdout", "prove-stderr-time", "verify-stdout", "verify-stderr-time",
        "work-directory", "output", "staging-directory",
    ):
        create.add_argument(f"--{name}", type=Path, required=True)
    create.add_argument("--timing-disqualifier", action="append", required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--receipt", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "replay":
            validate(arguments.receipt.absolute())
            return 0
        value = build(
            reference_manifest=arguments.reference_manifest,
            tool=arguments.tool, elf=arguments.elf, input_path=arguments.input,
            proving_key_root=arguments.proving_key_root, proof=arguments.proof,
            prove_stdout=arguments.prove_stdout,
            prove_stderr_time=arguments.prove_stderr_time,
            verify_stdout=arguments.verify_stdout,
            verify_stderr_time=arguments.verify_stderr_time,
            work_directory=arguments.work_directory,
            timing_disqualifiers=arguments.timing_disqualifier,
        )
        output = arguments.output.absolute()
        store.require_directory(output.parent, "ZisK receipt parent")
        store.require_directory(arguments.staging_directory.absolute(),
                                "ZisK receipt staging directory", create=True)
        store.publish_new_or_identical(
            output, protocol.canonical_bytes(value),
            staging_directory=arguments.staging_directory.absolute(),
        )
        return 0
    except (ZiskFinalEvidenceError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
