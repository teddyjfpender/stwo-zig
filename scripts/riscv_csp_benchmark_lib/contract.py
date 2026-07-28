"""Authenticated workload contract for the RISC-V EthProofs CSP benchmark."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "vectors" / "riscv_csp" / "manifest-v2.json"
DEFAULT_REPORT = ROOT / "vectors" / "reports" / "riscv_csp_benchmark_report.json"
DEFAULT_CLI = ROOT / "zig-out" / "bin" / "stwo-zig-riscv-cpu"
DEFAULT_TRACE_CLI = ROOT / "zig-out" / "bin" / "riscv-trace-dump"

TARGET_ORDER = ("sha256", "keccak", "poseidon2_m31", "ecdsa_secp256k1")
BYTE_INPUT_SIZES = (128, 256, 512, 1024, 2048)
FIELD_ELEMENT_SIZES = (2, 4, 8, 12, 16)
ECDSA_INPUT_SIZES = (32,)
TARGET_SIZES = {
    "sha256": BYTE_INPUT_SIZES,
    "keccak": BYTE_INPUT_SIZES,
    "poseidon2_m31": FIELD_ELEMENT_SIZES,
    "ecdsa_secp256k1": ECDSA_INPUT_SIZES,
}
CANONICAL_SIZES = tuple(
    sorted({size for sizes in TARGET_SIZES.values() for size in sizes})
)
TARGET_CONTRACTS = {
    "sha256": (
        "u32_le_byte_length_then_message",
        "bytes",
        "csp_canonical",
    ),
    "keccak": (
        "u32_le_byte_length_then_message",
        "bytes",
        "csp_canonical",
    ),
    "poseidon2_m31": (
        "u32_le_element_count_then_m31_le",
        "field_elements",
        "csp_field_native_extension",
    ),
    "ecdsa_secp256k1": (
        "csp_k256_digest_sec1_key_signature",
        "bytes",
        "csp_canonical",
    ),
}
UNSUPPORTED_TARGETS = {"ecdsa_p256", "poseidon", "poseidon2_bn254"}
M31_MODULUS = (1 << 31) - 1
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")

SECURE_PCS_CONFIG = {
    "pow_bits": 26,
    "fri_config": {
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 70,
        "fold_step": 1,
    },
    "lifting_log_size": None,
}


class BenchmarkError(RuntimeError):
    """The suite cannot produce trustworthy benchmark evidence."""


@dataclass(frozen=True)
class Case:
    target: str
    input_size: int
    input_path: Path
    input_sha256: str
    expected_digest: str
    expected_cycles: int
    guest_path: Path
    guest_sha256: str
    guest_bytes: int
    uses_precompile: bool


@dataclass(frozen=True)
class NegativeCase:
    name: str
    target: str
    input_path: Path
    input_sha256: str
    expected_digest: str
    expected_cycles: int
    guest_path: Path


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError(f"JSON repeats field {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > MAX_CAPTURE_BYTES:
        raise BenchmarkError(f"oversized JSON input: {path}")
    try:
        return json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"invalid JSON in {path}: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def repo_path(raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute():
        raise BenchmarkError(f"{label} is not a repository-relative path")
    resolved = (ROOT / raw).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as error:
        raise BenchmarkError(f"{label} escapes the repository") from error
    return resolved


def _exact_fields(
    value: Mapping[str, Any],
    expected: set[str],
    label: str,
) -> None:
    actual = set(value)
    if actual != expected:
        raise BenchmarkError(
            f"{label} fields drifted "
            f"(missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)})"
        )


def _validate_file_binding(
    binding: Any,
    *,
    label: str,
    fields: set[str] = frozenset({"path", "sha256"}),
) -> Mapping[str, Any]:
    if not isinstance(binding, dict):
        raise BenchmarkError(f"{label} binding is invalid")
    _exact_fields(binding, set(fields), label)
    if (
        not isinstance(binding["path"], str)
        or not isinstance(binding["sha256"], str)
        or not HEX_32.fullmatch(binding["sha256"])
    ):
        raise BenchmarkError(f"{label} binding is invalid")
    return binding


def _validate_upstream(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    upstream = manifest["upstream"]
    if not isinstance(upstream, dict):
        raise BenchmarkError("upstream manifest entry is not an object")
    _exact_fields(
        upstream,
        {
            "repository",
            "commit",
            "commit_date",
            "input_generator",
            "size_metadata",
            "rust_toolchain",
            "guest_dependency_revision",
            "extended_input_adapter",
        },
        "CSP upstream",
    )
    if upstream["repository"] != "https://github.com/privacy-ethereum/csp-benchmarks":
        raise BenchmarkError("upstream CSP repository drifted")
    if not isinstance(upstream["commit"], str) or not HEX_40.fullmatch(
        upstream["commit"]
    ):
        raise BenchmarkError("upstream CSP commit is not canonical")
    if (
        not isinstance(upstream["guest_dependency_revision"], str)
        or not HEX_40.fullmatch(upstream["guest_dependency_revision"])
    ):
        raise BenchmarkError("upstream guest dependency revision is not canonical")
    if not isinstance(upstream["commit_date"], str) or not upstream["commit_date"]:
        raise BenchmarkError("upstream CSP commit date is absent")

    generator = _validate_file_binding(
        upstream["input_generator"],
        label="CSP upstream input_generator",
        fields={"path", "sha256", "algorithm"},
    )
    if not isinstance(generator["algorithm"], str) or not generator["algorithm"]:
        raise BenchmarkError("CSP upstream generator algorithm is absent")
    _validate_file_binding(
        upstream["size_metadata"],
        label="CSP upstream size_metadata",
    )
    toolchain = _validate_file_binding(
        upstream["rust_toolchain"],
        label="CSP upstream rust_toolchain",
        fields={"path", "sha256", "channel", "rustc_commit"},
    )
    if (
        toolchain["channel"] != "nightly-2026-03-04"
        or not isinstance(toolchain["rustc_commit"], str)
        or not HEX_40.fullmatch(toolchain["rustc_commit"])
    ):
        raise BenchmarkError("CSP upstream Rust toolchain drifted")
    adapter = _validate_file_binding(
        upstream["extended_input_adapter"],
        label="CSP extended input adapter",
    )
    adapter_path = repo_path(adapter["path"], "CSP extended input adapter path")
    if not adapter_path.is_file() or sha256_file(adapter_path) != adapter["sha256"]:
        raise BenchmarkError("CSP extended input adapter binding drifted")
    return upstream


def _validate_guest(target: str, guest: Any) -> tuple[Path, str, int]:
    if not isinstance(guest, dict):
        raise BenchmarkError(f"{target} guest is not an object")
    _exact_fields(
        guest,
        {"path", "sha256", "bytes", "source_repository", "source_files"},
        f"{target} guest",
    )
    if (
        not isinstance(guest["bytes"], int)
        or isinstance(guest["bytes"], bool)
        or guest["bytes"] <= 0
    ):
        raise BenchmarkError(f"{target} guest byte length is invalid")
    if guest["source_repository"] not in {"csp_upstream", "this_repository"}:
        raise BenchmarkError(f"{target} guest source repository is invalid")
    guest_path = repo_path(guest["path"], f"{target} guest path")
    if not guest_path.is_file():
        raise BenchmarkError(f"missing {target} guest: {guest_path}")
    if guest_path.stat().st_size != guest["bytes"]:
        raise BenchmarkError(f"{target} guest size differs from its manifest")
    guest_digest = sha256_file(guest_path)
    if not isinstance(guest["sha256"], str) or guest_digest != guest["sha256"]:
        raise BenchmarkError(f"{target} guest digest differs from its manifest")

    source_files = guest["source_files"]
    if not isinstance(source_files, list) or not source_files:
        raise BenchmarkError(f"{target} guest has no source-file bindings")
    seen_paths: set[str] = set()
    for source_index, raw_binding in enumerate(source_files):
        binding = _validate_file_binding(
            raw_binding,
            label=f"{target} source binding {source_index}",
        )
        if binding["path"] in seen_paths:
            raise BenchmarkError(f"{target} repeats a source-file binding")
        seen_paths.add(binding["path"])
        if guest["source_repository"] == "this_repository":
            source_path = repo_path(
                binding["path"],
                f"{target} source binding path",
            )
            if (
                not source_path.is_file()
                or sha256_file(source_path) != binding["sha256"]
            ):
                raise BenchmarkError(
                    f"{target} repository source binding drifted: "
                    f"{binding['path']}"
                )
    return guest_path, guest_digest, guest["bytes"]


def _validate_input_frame(
    *,
    target: str,
    input_size: int,
    encoding: str,
    input_bytes: bytes,
) -> None:
    if encoding == "u32_le_byte_length_then_message":
        if (
            len(input_bytes) != input_size + 4
            or struct.unpack("<I", input_bytes[:4])[0] != input_size
        ):
            raise BenchmarkError(f"{target}/{input_size}: byte input framing drifted")
        return
    if encoding == "u32_le_element_count_then_m31_le":
        if (
            len(input_bytes) != 4 + input_size * 4
            or struct.unpack("<I", input_bytes[:4])[0] != input_size
        ):
            raise BenchmarkError(f"{target}/{input_size}: M31 input framing drifted")
        elements = struct.unpack(f"<{input_size}I", input_bytes[4:])
        if any(value >= M31_MODULUS for value in elements):
            raise BenchmarkError(f"{target}/{input_size}: noncanonical M31 input")
        return
    if encoding == "csp_k256_digest_sec1_key_signature":
        if (
            input_size != 32
            or len(input_bytes) != 32 + 65 + 64
            or input_bytes[32] != 0x04
        ):
            raise BenchmarkError(
                f"{target}/{input_size}: secp256k1 input framing drifted"
            )
        return
    raise BenchmarkError(f"{target}: unknown input encoding")


def _validate_cases(
    *,
    target: str,
    spec: Mapping[str, Any],
    guest_path: Path,
    guest_digest: str,
    guest_bytes: int,
    shared_inputs: dict[tuple[str, int], tuple[Path, str]],
) -> list[Case]:
    raw_cases = spec["cases"]
    if not isinstance(raw_cases, list):
        raise BenchmarkError(f"{target} cases are not an array")
    sizes = tuple(
        case.get("input_size") for case in raw_cases if isinstance(case, dict)
    )
    if sizes != TARGET_SIZES[target]:
        raise BenchmarkError(f"{target} does not contain the canonical CSP size sweep")

    cases: list[Case] = []
    for index, raw_case in enumerate(raw_cases):
        if not isinstance(raw_case, dict):
            raise BenchmarkError(f"{target} case {index} is not an object")
        _exact_fields(
            raw_case,
            {
                "input_size",
                "input_path",
                "input_sha256",
                "expected_digest",
                "expected_cycles",
            },
            f"{target} case {index}",
        )
        input_size = raw_case["input_size"]
        expected_cycles = raw_case["expected_cycles"]
        if (
            not isinstance(input_size, int)
            or isinstance(input_size, bool)
            or not isinstance(expected_cycles, int)
            or isinstance(expected_cycles, bool)
            or expected_cycles <= 0
        ):
            raise BenchmarkError(f"{target} case {index} has invalid numeric fields")
        input_path = repo_path(raw_case["input_path"], f"{target} input path")
        if not input_path.is_file():
            raise BenchmarkError(f"missing CSP input: {input_path}")
        input_bytes = input_path.read_bytes()
        encoding = spec["input_encoding"]
        _validate_input_frame(
            target=target,
            input_size=input_size,
            encoding=encoding,
            input_bytes=input_bytes,
        )
        input_digest = sha256_bytes(input_bytes)
        if input_digest != raw_case["input_sha256"]:
            raise BenchmarkError(f"{target}/{input_size}: input digest drifted")
        expected_digest = raw_case["expected_digest"]
        if (
            not isinstance(expected_digest, str)
            or not HEX_32.fullmatch(expected_digest)
        ):
            raise BenchmarkError(
                f"{target}/{input_size}: expected digest is not canonical"
            )
        shared = shared_inputs.setdefault(
            (encoding, input_size),
            (input_path, input_digest),
        )
        if shared != (input_path, input_digest):
            raise BenchmarkError(f"{target}/{input_size}: shared CSP input drifted")
        cases.append(
            Case(
                target=target,
                input_size=input_size,
                input_path=input_path,
                input_sha256=input_digest,
                expected_digest=expected_digest,
                expected_cycles=expected_cycles,
                guest_path=guest_path,
                guest_sha256=guest_digest,
                guest_bytes=guest_bytes,
                uses_precompile=False,
            )
        )
    return cases


def _validate_negative_cases(
    manifest: Mapping[str, Any],
    guests: Mapping[str, Path],
) -> list[NegativeCase]:
    raw_negative = manifest["negative_fixtures"]
    if not isinstance(raw_negative, list) or len(raw_negative) != 1:
        raise BenchmarkError("CSP negative fixture ledger drifted")
    entry = raw_negative[0]
    if not isinstance(entry, dict):
        raise BenchmarkError("negative fixture 0 is invalid")
    _exact_fields(
        entry,
        {
            "name",
            "target",
            "input_path",
            "input_sha256",
            "expected_digest",
            "expected_cycles",
        },
        "negative fixture 0",
    )
    if (
        entry["name"] != "ecdsa_secp256k1_bad_signature"
        or entry["target"] != "ecdsa_secp256k1"
    ):
        raise BenchmarkError("CSP negative fixture identity drifted")
    input_path = repo_path(entry["input_path"], "negative fixture 0 input path")
    if not input_path.is_file():
        raise BenchmarkError("negative fixture 0 input is missing")
    input_bytes = input_path.read_bytes()
    if (
        not isinstance(entry["input_sha256"], str)
        or not HEX_32.fullmatch(entry["input_sha256"])
        or sha256_bytes(input_bytes) != entry["input_sha256"]
        or entry["expected_digest"] != "0" * 64
        or not isinstance(entry["expected_cycles"], int)
        or isinstance(entry["expected_cycles"], bool)
        or entry["expected_cycles"] <= 0
    ):
        raise BenchmarkError("negative fixture 0 binding drifted")
    return [
        NegativeCase(
            name=entry["name"],
            target=entry["target"],
            input_path=input_path,
            input_sha256=entry["input_sha256"],
            expected_digest=entry["expected_digest"],
            expected_cycles=entry["expected_cycles"],
            guest_path=guests[entry["target"]],
        )
    ]


def validate_manifest(
    path: Path = MANIFEST,
) -> tuple[dict[str, Any], list[Case], list[NegativeCase]]:
    manifest = load_json(path)
    if not isinstance(manifest, dict):
        raise BenchmarkError("CSP manifest root is not an object")
    _exact_fields(
        manifest,
        {
            "schema",
            "suite",
            "upstream",
            "targets",
            "negative_fixtures",
            "unsupported_targets",
        },
        "CSP manifest",
    )
    if manifest["schema"] != "stwo_riscv_csp_suite_v2":
        raise BenchmarkError("unsupported CSP manifest schema")
    if manifest["suite"] != "ethproofs_client_side_proving":
        raise BenchmarkError("CSP suite identity drifted")
    _validate_upstream(manifest)

    targets = manifest["targets"]
    if not isinstance(targets, dict) or tuple(targets) != TARGET_ORDER:
        raise BenchmarkError("CSP target order or membership drifted")
    cases: list[Case] = []
    guests: dict[str, Path] = {}
    shared_inputs: dict[tuple[str, int], tuple[Path, str]] = {}
    for target in TARGET_ORDER:
        spec = targets[target]
        if not isinstance(spec, dict):
            raise BenchmarkError(f"{target} target is not an object")
        _exact_fields(
            spec,
            {
                "guest",
                "uses_precompile",
                "input_encoding",
                "input_size_unit",
                "comparison_class",
                "output_encoding",
                "cases",
            },
            f"{target} target",
        )
        if spec["uses_precompile"] is not False:
            raise BenchmarkError(f"{target} must remain an explicit RV32IM workload")
        if (
            spec["input_encoding"],
            spec["input_size_unit"],
            spec["comparison_class"],
        ) != TARGET_CONTRACTS[target]:
            raise BenchmarkError(f"{target} workload contract drifted")
        if not isinstance(spec["output_encoding"], str) or not spec["output_encoding"]:
            raise BenchmarkError(f"{target} output encoding is absent")
        guest_path, guest_digest, guest_bytes = _validate_guest(
            target,
            spec["guest"],
        )
        guests[target] = guest_path
        cases.extend(
            _validate_cases(
                target=target,
                spec=spec,
                guest_path=guest_path,
                guest_digest=guest_digest,
                guest_bytes=guest_bytes,
                shared_inputs=shared_inputs,
            )
        )

    unsupported = manifest["unsupported_targets"]
    if not isinstance(unsupported, dict) or set(unsupported) != UNSUPPORTED_TARGETS:
        raise BenchmarkError("unsupported CSP target ledger drifted")
    if any(
        not isinstance(reason, str) or not reason.strip()
        for reason in unsupported.values()
    ):
        raise BenchmarkError("unsupported CSP target has no reason")
    negative_cases = _validate_negative_cases(manifest, guests)
    return manifest, cases, negative_cases
