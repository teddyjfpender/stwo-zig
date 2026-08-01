"""Validation primitives for the Cairo / RISC-V CSP comparison contract."""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


PUBLIC_STATEMENT_SCHEMA = "stwo_cairo_csp_public_statement_projection_v1"
EXACT_RUNNABLE_SCHEMA_ERROR = (
    "exact_runnable requires a schema upgrade that cryptographically links "
    "the proof, verifier-accepted public statement, program, ProverInput, "
    "canonical output, secure protocol, and independent verifier authority"
)
HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
HEX_20 = re.compile(r"[0-9a-f]{40}\Z")
M31_MODULUS = (1 << 31) - 1
_MASK64 = (1 << 64) - 1
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_KECCAK_ROTATIONS = (
    0,
    1,
    62,
    28,
    27,
    36,
    44,
    6,
    55,
    20,
    3,
    10,
    43,
    25,
    39,
    41,
    45,
    15,
    21,
    8,
    18,
    2,
    61,
    56,
    14,
)


class ComparisonError(ValueError):
    """The comparison contract or one of its authenticated files is invalid."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ComparisonError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ComparisonError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise ComparisonError(f"{path} must contain one JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ComparisonError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _rotate_left_64(value: int, amount: int) -> int:
    if amount == 0:
        return value
    return ((value << amount) | (value >> (64 - amount))) & _MASK64


def _keccak_f1600(state: list[int]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        deltas = [
            columns[(x - 1) % 5] ^ _rotate_left_64(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]

        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                destination_x = y
                destination_y = (2 * x + 3 * y) % 5
                rotated[destination_x + 5 * destination_y] = _rotate_left_64(
                    state[x + 5 * y], _KECCAK_ROTATIONS[x + 5 * y]
                )
        for y in range(5):
            row = rotated[5 * y : 5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & _MASK64
        state[0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Return legacy Keccak-256 (Ethereum suffix 0x01), not NIST SHA3-256."""

    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\0" * ((-len(padded)) % rate))
    padded[-1] |= 0x80

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            start = lane * 8
            state[lane] ^= int.from_bytes(block[start : start + 8], "little")
        _keccak_f1600(state)
    return b"".join(value.to_bytes(8, "little") for value in state)[:32]


def _expect_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ComparisonError(f"{context} must be an object")
    return value


def _expect_keys(value: Mapping[str, Any], keys: Sequence[str], context: str) -> None:
    actual = set(value)
    expected = set(keys)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ComparisonError(
            f"{context} keys drifted (missing={missing}, extra={extra})"
        )


def _require_text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComparisonError(f"{context} must be a nonempty string")
    return value


def _require_int(value: Any, context: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ComparisonError(f"{context} must be an integer")
    if positive and value <= 0:
        raise ComparisonError(f"{context} must be positive")
    return value


def _require_sha256(value: Any, context: str) -> str:
    text = _require_text(value, context)
    if HEX_32.fullmatch(text) is None:
        raise ComparisonError(f"{context} must be lowercase 32-byte hex")
    return text


def _require_commit(value: Any, context: str) -> str:
    text = _require_text(value, context)
    if HEX_20.fullmatch(text) is None:
        raise ComparisonError(f"{context} must be lowercase 20-byte git hex")
    return text


def _repo_path(root: Path, value: Any, context: str) -> Path:
    text = _require_text(value, context)
    posix = PurePosixPath(text)
    if posix.is_absolute() or ".." in posix.parts or "." in posix.parts:
        raise ComparisonError(f"{context} must be a normalized repository path")
    candidate = (root / Path(*posix.parts)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise ComparisonError(f"{context} escapes the repository") from error
    return candidate


def _authenticate_file(
    root: Path,
    descriptor: Mapping[str, Any],
    context: str,
    *,
    path_key: str = "path",
    sha_key: str = "sha256",
    bytes_key: str | None = None,
) -> Path:
    path = _repo_path(root, descriptor.get(path_key), f"{context}.{path_key}")
    expected = _require_sha256(descriptor.get(sha_key), f"{context}.{sha_key}")
    actual = sha256_file(path)
    if actual != expected:
        raise ComparisonError(
            f"{context} digest mismatch: expected {expected}, got {actual}"
        )
    if bytes_key is not None:
        expected_bytes = _require_int(
            descriptor.get(bytes_key), f"{context}.{bytes_key}", positive=True
        )
        try:
            actual_bytes = path.stat().st_size
        except OSError as error:
            raise ComparisonError(f"cannot stat {path}: {error}") from error
        if actual_bytes != expected_bytes:
            raise ComparisonError(
                f"{context} byte length mismatch: expected {expected_bytes}, "
                f"got {actual_bytes}"
            )
    return path


def audit_corelib_checkout(
    corelib_checkout: Path, corelib: Mapping[str, Any]
) -> None:
    checkout = corelib_checkout.resolve()
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=checkout,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ComparisonError(f"cannot inspect Cairo checkout: {error}") from error
    expected_commit = _require_commit(corelib.get("commit"), "corelib.commit")
    if completed.returncode != 0 or completed.stdout.strip() != expected_commit:
        raise ComparisonError("Cairo checkout is not at the pinned corelib commit")
    sources = _expect_object(corelib.get("sources"), "corelib.sources")
    for name, raw_descriptor in sources.items():
        descriptor = _expect_object(raw_descriptor, f"corelib.sources.{name}")
        _expect_keys(descriptor, ("path", "bytes", "sha256"), f"corelib.sources.{name}")
        path = _repo_path(checkout, descriptor["path"], f"corelib.sources.{name}.path")
        actual_sha = sha256_file(path)
        if actual_sha != descriptor["sha256"]:
            raise ComparisonError(f"corelib source {name} digest mismatch")
        if path.stat().st_size != descriptor["bytes"]:
            raise ComparisonError(f"corelib source {name} byte length mismatch")


def _find_riscv_case(
    suite: Mapping[str, Any], target: str, input_size: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    targets = _expect_object(suite.get("targets"), "RISC-V suite.targets")
    target_record = _expect_object(targets.get(target), f"RISC-V target {target}")
    cases = target_record.get("cases")
    if not isinstance(cases, list):
        raise ComparisonError(f"RISC-V target {target}.cases must be a list")
    matches = [
        _expect_object(case, f"RISC-V target {target} case")
        for case in cases
        if isinstance(case, dict) and case.get("input_size") == input_size
    ]
    if len(matches) != 1:
        raise ComparisonError(
            f"RISC-V target {target}/{input_size} must have exactly one case"
        )
    return target_record, matches[0]


def _find_report_measurement(
    report: Mapping[str, Any], target: str, input_size: int
) -> dict[str, Any]:
    measurements = report.get("measurements")
    if not isinstance(measurements, list):
        raise ComparisonError("retained RISC-V report.measurements must be a list")
    matches = [
        _expect_object(row, "retained RISC-V measurement")
        for row in measurements
        if isinstance(row, dict)
        and row.get("target") == target
        and row.get("input_size") == input_size
    ]
    if len(matches) != 1:
        raise ComparisonError(
            f"retained RISC-V report must have exactly one {target}/{input_size} row"
        )
    return matches[0]


def _validate_report_evidence(
    report_row: Mapping[str, Any], row: Mapping[str, Any], expected_output: str
) -> None:
    target = row["target"]
    size = row["input_size"]
    if report_row.get("cycles") != row["expected_cycles"]:
        raise ComparisonError(f"{target}/{size}: retained cycle count drifted")
    if report_row.get("uses_precompile") is not False:
        raise ComparisonError(f"{target}/{size}: retained row unexpectedly uses a precompile")
    evidence = _expect_object(
        report_row.get("evidence"), f"{target}/{size} retained evidence"
    )
    exact = {
        "input_sha256": row["input_sha256"],
        "expected_output_digest": expected_output,
        "output_digest": expected_output,
        "public_values_sha256": row["report_public_values_sha256"],
        "statement_sha256": row["report_statement_sha256"],
        "proof_sha256": row["report_proof_sha256"],
        "status": "verified",
    }
    for key, expected in exact.items():
        if evidence.get(key) != expected:
            raise ComparisonError(f"{target}/{size}: retained evidence {key} drifted")
    receipt = _expect_object(
        evidence.get("retained_verify_receipt"),
        f"{target}/{size} retained verifier receipt",
    )
    if receipt.get("status") != "verified":
        raise ComparisonError(f"{target}/{size}: retained proof is not verified")
    if receipt.get("proof_sha256") != row["report_proof_sha256"]:
        raise ComparisonError(f"{target}/{size}: verifier receipt proof digest drifted")
    if receipt.get("statement_sha256") != row["report_statement_sha256"]:
        raise ComparisonError(f"{target}/{size}: verifier receipt statement drifted")


def _decode_logical_input(
    target: str, encoded: bytes, logical: Mapping[str, Any], context: str
) -> bytes:
    size = _require_int(logical.get("value_size"), f"{context}.value_size", positive=True)
    exact_value = logical.get("exact_value")
    if target in ("sha256", "keccak"):
        if logical.get("container_encoding") != "u32_le_byte_length_then_message":
            raise ComparisonError(f"{context}: byte-message container encoding drifted")
        if logical.get("value_encoding") != "raw_bytes" or exact_value is not None:
            raise ComparisonError(f"{context}: byte-message logical encoding drifted")
        if len(encoded) < 4:
            raise ComparisonError(f"{context}: truncated byte-message container")
        declared = struct.unpack_from("<I", encoded)[0]
        payload = encoded[4:]
        if declared != size or len(payload) != size:
            raise ComparisonError(f"{context}: byte-message length prefix drifted")
        return payload
    if target == "poseidon2_m31":
        if logical.get("container_encoding") != "u32_le_element_count_then_m31_le":
            raise ComparisonError(f"{context}: M31 container encoding drifted")
        if logical.get("value_encoding") != "canonical_m31_u32_le":
            raise ComparisonError(f"{context}: M31 logical encoding drifted")
        if len(encoded) < 4:
            raise ComparisonError(f"{context}: truncated M31 container")
        declared = struct.unpack_from("<I", encoded)[0]
        payload = encoded[4:]
        if declared != size or len(payload) != size * 4:
            raise ComparisonError(f"{context}: M31 element count drifted")
        elements = list(struct.unpack(f"<{size}I", payload))
        if any(value >= M31_MODULUS for value in elements):
            raise ComparisonError(f"{context}: input contains a non-canonical M31 value")
        exact = _expect_object(exact_value, f"{context}.exact_value")
        _expect_keys(exact, ("elements",), f"{context}.exact_value")
        if exact["elements"] != elements:
            raise ComparisonError(f"{context}: exact M31 input elements drifted")
        return payload
    if target == "ecdsa_secp256k1":
        expected_encoding = (
            "digest32_then_uncompressed_sec1_key65_then_compact_signature64"
        )
        if logical.get("container_encoding") != expected_encoding:
            raise ComparisonError(f"{context}: ECDSA container encoding drifted")
        if logical.get("value_encoding") != "secp256k1_ecdsa_verification_tuple":
            raise ComparisonError(f"{context}: ECDSA logical encoding drifted")
        if size != 32 or len(encoded) != 32 + 65 + 64 or encoded[32] != 4:
            raise ComparisonError(f"{context}: ECDSA tuple framing drifted")
        exact = _expect_object(exact_value, f"{context}.exact_value")
        _expect_keys(
            exact,
            ("digest_hex", "public_key_sec1_hex", "signature_rs_hex"),
            f"{context}.exact_value",
        )
        observed = {
            "digest_hex": encoded[:32].hex(),
            "public_key_sec1_hex": encoded[32:97].hex(),
            "signature_rs_hex": encoded[97:].hex(),
        }
        if exact != observed:
            raise ComparisonError(f"{context}: exact ECDSA tuple drifted")
        return encoded
    raise ComparisonError(f"{context}: unsupported target {target}")


def _validate_expected_output(
    target: str,
    logical_bytes: bytes,
    logical: Mapping[str, Any],
    output: Mapping[str, Any],
    context: str,
) -> str:
    _expect_keys(
        output,
        ("canonical_encoding", "hex", "cairo_projection", "exact_value"),
        f"{context}.expected_output",
    )
    output_hex = _require_sha256(output.get("hex"), f"{context}.expected_output.hex")
    raw = bytes.fromhex(output_hex)
    exact = _expect_object(output.get("exact_value"), f"{context}.expected_output.exact_value")
    if target == "sha256":
        if output.get("canonical_encoding") != "raw_32_bytes":
            raise ComparisonError(f"{context}: SHA-256 output encoding drifted")
        if output.get("cairo_projection") != "sha256_u32_words_big_endian_to_raw_bytes":
            raise ComparisonError(f"{context}: SHA-256 Cairo projection drifted")
        if hashlib.sha256(logical_bytes).digest() != raw:
            raise ComparisonError(f"{context}: SHA-256 output is not the input digest")
        _expect_keys(exact, ("u32_be",), f"{context}.expected_output.exact_value")
        if exact["u32_be"] != list(struct.unpack(">8I", raw)):
            raise ComparisonError(f"{context}: SHA-256 word projection drifted")
    elif target == "keccak":
        if output.get("canonical_encoding") != "raw_32_bytes":
            raise ComparisonError(f"{context}: Keccak output encoding drifted")
        if output.get("cairo_projection") != "keccak_u256_little_endian_to_raw_bytes":
            raise ComparisonError(f"{context}: Keccak Cairo projection drifted")
        _expect_keys(exact, ("u256_le_decimal",), f"{context}.expected_output.exact_value")
        if exact["u256_le_decimal"] != str(int.from_bytes(raw, "little")):
            raise ComparisonError(f"{context}: Keccak u256 projection drifted")
        if keccak256(logical_bytes) != raw:
            raise ComparisonError(f"{context}: Keccak-256 output is not the input digest")
    elif target == "poseidon2_m31":
        if output.get("canonical_encoding") != "eight_canonical_m31_u32_le":
            raise ComparisonError(f"{context}: Poseidon2-M31 output encoding drifted")
        if output.get("cairo_projection") != "eight_m31_values_to_u32_little_endian":
            raise ComparisonError(f"{context}: Poseidon2-M31 Cairo projection drifted")
        elements = list(struct.unpack("<8I", raw))
        if any(value >= M31_MODULUS for value in elements):
            raise ComparisonError(f"{context}: output contains a non-canonical M31 value")
        _expect_keys(exact, ("elements",), f"{context}.expected_output.exact_value")
        if exact["elements"] != elements:
            raise ComparisonError(f"{context}: Poseidon2-M31 output elements drifted")
    elif target == "ecdsa_secp256k1":
        if output.get("canonical_encoding") != "validity_true_and_raw_32_byte_digest":
            raise ComparisonError(f"{context}: ECDSA output encoding drifted")
        if output.get("cairo_projection") != "require_true_then_return_digest_bytes":
            raise ComparisonError(f"{context}: ECDSA Cairo projection drifted")
        _expect_keys(
            exact, ("valid", "digest_hex"), f"{context}.expected_output.exact_value"
        )
        if exact.get("valid") is not True or exact.get("digest_hex") != output_hex:
            raise ComparisonError(f"{context}: ECDSA validity/output contract drifted")
        exact_input = _expect_object(
            logical.get("exact_value"), f"{context}.logical_input.exact_value"
        )
        if exact_input.get("digest_hex") != output_hex:
            raise ComparisonError(f"{context}: ECDSA output is not the verified digest")
    else:
        raise ComparisonError(f"{context}: unsupported output target {target}")
    return output_hex


def _validate_artifact_descriptor(
    root: Path, value: Any, context: str
) -> None:
    descriptor = _expect_object(value, context)
    _expect_keys(descriptor, ("path", "bytes", "sha256"), context)
    _authenticate_file(root, descriptor, context, bytes_key="bytes")


def _validate_fixture_state(
    root: Path,
    row: Mapping[str, Any],
    required_bindings: Sequence[str],
    context: str,
) -> None:
    status = row.get("status")
    statement = _expect_object(row.get("public_statement"), f"{context}.public_statement")
    _expect_keys(
        statement,
        ("schema", "input_visibility", "required_bindings", "expected_projection_sha256"),
        f"{context}.public_statement",
    )
    if statement.get("schema") != PUBLIC_STATEMENT_SCHEMA:
        raise ComparisonError(f"{context}: public statement schema drifted")
    if statement.get("input_visibility") != "public":
        raise ComparisonError(f"{context}: logical input must be public")
    if statement.get("required_bindings") != list(required_bindings):
        raise ComparisonError(f"{context}: public statement bindings drifted")

    fixture = _expect_object(row.get("cairo_fixture"), f"{context}.cairo_fixture")
    _expect_keys(
        fixture,
        ("program", "arguments", "prover_input", "expected_vm_steps"),
        f"{context}.cairo_fixture",
    )
    if status == "pending_exact_cairo_fixture":
        if any(value is not None for value in fixture.values()):
            raise ComparisonError(f"{context}: pending row carries unauthenticated fixture data")
        if statement.get("expected_projection_sha256") is not None:
            raise ComparisonError(f"{context}: pending row carries an unverified statement pin")
        pending = _expect_object(row.get("pending"), f"{context}.pending")
        _expect_keys(pending, ("reason_code", "blockers"), f"{context}.pending")
        _require_text(pending.get("reason_code"), f"{context}.pending.reason_code")
        blockers = pending.get("blockers")
        if (
            not isinstance(blockers, list)
            or len(blockers) < 2
            or any(not isinstance(item, str) or not item for item in blockers)
        ):
            raise ComparisonError(f"{context}: pending blockers must be explicit")
        return

    if status != "exact_runnable":
        raise ComparisonError(f"{context}: unknown status {status!r}")
    # The official verifier's v1 verdict authenticates the proof digest,
    # channel, transport, and pinned source revisions.  It does not expose a
    # digest of the verifier-accepted public statement and therefore cannot
    # cryptographically cross-bind that proof to this manifest's program,
    # ProverInput, logical input, output projection, or PCS declaration.  A
    # collection of independently hash-pinned files is not a substitute for
    # that missing edge.  Keep v1 permanently fail-closed until a receipt
    # schema carries and validates the complete linkage.
    raise ComparisonError(f"{context}: {EXACT_RUNNABLE_SCHEMA_ERROR}")


def _validate_negative_gate(
    root: Path,
    suite: Mapping[str, Any],
    report: Mapping[str, Any],
    target: str,
    value: Any,
    context: str,
) -> None:
    if target != "ecdsa_secp256k1":
        if value is not None:
            raise ComparisonError(f"{context}: only ECDSA may declare this negative gate")
        return
    gate = _expect_object(value, f"{context}.negative_gate")
    _expect_keys(
        gate,
        (
            "input_path",
            "input_sha256",
            "input_encoding",
            "expected_output_hex",
            "report_public_values_sha256",
            "required_status",
        ),
        f"{context}.negative_gate",
    )
    if gate.get("input_encoding") != (
        "digest32_then_uncompressed_sec1_key65_then_compact_signature64"
    ):
        raise ComparisonError(f"{context}: ECDSA negative encoding drifted")
    descriptor = {"path": gate.get("input_path"), "sha256": gate.get("input_sha256")}
    negative_path = _authenticate_file(root, descriptor, f"{context}.negative_gate")
    if gate.get("expected_output_hex") != "0" * 64:
        raise ComparisonError(f"{context}: ECDSA negative output must be all zero")
    if gate.get("required_status") != "rejected_as_expected":
        raise ComparisonError(f"{context}: ECDSA negative status drifted")

    suite_cases = suite.get("negative_fixtures")
    report_cases = report.get("negative_validation")
    if not isinstance(suite_cases, list) or not isinstance(report_cases, list):
        raise ComparisonError(f"{context}: negative authority is absent")
    suite_matches = [
        item
        for item in suite_cases
        if isinstance(item, dict) and item.get("name") == "ecdsa_secp256k1_bad_signature"
    ]
    report_matches = [
        item
        for item in report_cases
        if isinstance(item, dict) and item.get("name") == "ecdsa_secp256k1_bad_signature"
    ]
    if len(suite_matches) != 1 or len(report_matches) != 1:
        raise ComparisonError(f"{context}: ECDSA negative fixture is not unique")
    suite_case = suite_matches[0]
    report_case = report_matches[0]
    checks = (
        (suite_case.get("target"), target),
        (suite_case.get("input_path"), gate["input_path"]),
        (suite_case.get("input_sha256"), gate["input_sha256"]),
        (suite_case.get("expected_digest"), gate["expected_output_hex"]),
        (report_case.get("target"), target),
        (report_case.get("input_sha256"), gate["input_sha256"]),
        (report_case.get("output_digest"), gate["expected_output_hex"]),
        (report_case.get("public_values_sha256"), gate["report_public_values_sha256"]),
        (report_case.get("status"), gate["required_status"]),
    )
    if any(actual != expected for actual, expected in checks):
        raise ComparisonError(f"{context}: ECDSA negative authority drifted")
    if len(negative_path.read_bytes()) != 161:
        raise ComparisonError(f"{context}: ECDSA negative tuple length drifted")
