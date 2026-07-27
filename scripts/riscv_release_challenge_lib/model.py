"""Strict parsers for the archived pre-Sail challenge/result formats."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from . import program


CHALLENGE_SCHEMA = "riscv-release-challenge-v1"
RESULT_SCHEMA = "riscv-release-challenge-result-v1"
MAX_LIFETIME_SECONDS = 180
MAX_JSON_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
NONCE_RE = re.compile(r"[0-9a-f]{64}")
TRUSTED_REPOSITORY = "teddyjfpender/stwo-zig"
TRUSTED_REPOSITORY_ID = 1_152_389_958


class ChallengeError(ValueError):
    """The challenge or its execution evidence is invalid."""


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(program.canonical_bytes(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json(path: Path) -> dict[str, Any]:
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ChallengeError(f"{path}: duplicate field {key}")
            result[key] = value
        return result

    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ChallengeError(f"{path}: exceeds {MAX_JSON_BYTES} bytes")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ChallengeError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ChallengeError(f"{path}: root must be an object")
    return value


def atomic_json(path: Path, value: object) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ChallengeError(f"{label} fields drifted")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ChallengeError(f"{label} is not a lowercase SHA-256")
    return value


def _commit(value: object, label: str) -> str:
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        raise ChallengeError(f"{label} is not a full commit SHA")
    return value


def challenge_body(challenge: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in challenge.items() if key != "challenge_id_sha256"}


def validate_challenge(
    challenge: dict[str, Any], *, expected_identity: dict[str, Any] | None = None,
    now: int | None = None,
) -> program.DerivedProgram:
    _exact(challenge, {
        "schema", "challenge_id_sha256", "issued_at_unix", "expires_at_unix",
        "nonce_hex", "identity", "derivation",
    }, "challenge")
    if challenge["schema"] != CHALLENGE_SCHEMA:
        raise ChallengeError("challenge schema drifted")
    issued, expires = challenge["issued_at_unix"], challenge["expires_at_unix"]
    if type(issued) is not int or type(expires) is not int or not issued < expires:
        raise ChallengeError("challenge lifetime is malformed")
    if expires - issued > MAX_LIFETIME_SECONDS:
        raise ChallengeError("challenge lifetime exceeds the fast-gate bound")
    current = int(time.time()) if now is None else now
    if current < issued or current > expires:
        raise ChallengeError("challenge is not currently valid")
    identity = challenge["identity"]
    if expected_identity is not None and identity != expected_identity:
        raise ChallengeError("challenge identity differs from trusted execution context")
    _validate_identity(identity)
    nonce_hex = challenge["nonce_hex"]
    if not isinstance(nonce_hex, str) or NONCE_RE.fullmatch(nonce_hex) is None:
        raise ChallengeError("challenge nonce is not 32-byte lowercase hex")
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as error:
        raise ChallengeError("challenge nonce is not hexadecimal") from error
    derived = program.derive(nonce, identity)
    expected_derivation = {
        "schema": "riscv-release-challenge-derivation-v1",
        "seed_sha256": derived.seed_sha256,
        "program": derived.spec,
        "program_spec_sha256": canonical_sha256(derived.spec),
    }
    if challenge["derivation"] != expected_derivation:
        raise ChallengeError("challenge derivation differs from nonce and bound identity")
    if challenge["challenge_id_sha256"] != canonical_sha256(challenge_body(challenge)):
        raise ChallengeError("challenge identifier digest drifted")
    return derived


def _validate_identity(identity: object) -> None:
    identity = _exact(identity, {"repository", "candidate", "workflow", "anchor"}, "identity")
    repository = _exact(identity["repository"], {"full_name", "id"}, "repository")
    if repository != {"full_name": TRUSTED_REPOSITORY, "id": TRUSTED_REPOSITORY_ID}:
        raise ChallengeError("repository identity is not the canonical trusted repository")
    candidate = _exact(
        identity["candidate"],
        {"commit", "tree_oid", "phase", "executable_sha256", "trace_executable_sha256"},
        "candidate",
    )
    _commit(candidate["commit"], "candidate commit")
    _commit(candidate["tree_oid"], "candidate tree")
    if candidate["phase"] not in ("candidate", "promoted"):
        raise ChallengeError("candidate phase is invalid")
    _digest(candidate["executable_sha256"], "candidate executable")
    _digest(candidate["trace_executable_sha256"], "trace executable")
    workflow = _exact(identity["workflow"], {"commit", "run_id", "attempt"}, "workflow")
    _commit(workflow["commit"], "workflow commit")
    if type(workflow["run_id"]) is not int or workflow["run_id"] <= 0 or \
            type(workflow["attempt"]) is not int or workflow["attempt"] <= 0:
        raise ChallengeError("workflow run identity is malformed")
    anchor = _exact(identity["anchor"], {
        "manifest_sha256", "candidate_commit", "tree_oid", "producer_run_id",
        "oracle_repository", "oracle_commit", "oracle_domain_sha256",
        "oracle_executable_sha256", "verifier_executable_sha256",
    }, "anchor")
    for field in (
        "manifest_sha256", "oracle_domain_sha256", "oracle_executable_sha256",
        "verifier_executable_sha256",
    ):
        _digest(anchor[field], f"anchor {field}")
    _commit(anchor["candidate_commit"], "anchor candidate")
    _commit(anchor["tree_oid"], "anchor tree")
    _commit(anchor["oracle_commit"], "anchor oracle commit")
    if type(anchor["producer_run_id"]) is not int or anchor["producer_run_id"] <= 0 or \
            anchor["oracle_repository"] != "https://github.com/ClementWalter/stark-v":
        raise ChallengeError("anchor identity is malformed")


def issue(identity: dict[str, Any], nonce: bytes, now: int) -> dict[str, Any]:
    _validate_identity(identity)
    derived = program.derive(nonce, identity)
    challenge = {
        "schema": CHALLENGE_SCHEMA,
        "issued_at_unix": now,
        "expires_at_unix": now + MAX_LIFETIME_SECONDS,
        "nonce_hex": nonce.hex(),
        "identity": identity,
        "derivation": {
            "schema": "riscv-release-challenge-derivation-v1",
            "seed_sha256": derived.seed_sha256,
            "program": derived.spec,
            "program_spec_sha256": canonical_sha256(derived.spec),
        },
    }
    challenge["challenge_id_sha256"] = canonical_sha256(challenge)
    return challenge


def claim_replay_slot(ledger: Path, challenge_id: str) -> Path:
    _digest(challenge_id, "challenge id")
    ledger.mkdir(parents=True, exist_ok=True)
    marker = ledger / challenge_id
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ChallengeError("challenge nonce has already been executed") from error
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write("claimed\n")
        handle.flush()
        os.fsync(handle.fileno())
    return marker


def validate_result(
    result: dict[str, Any], challenge: dict[str, Any], evidence_dir: Path,
) -> None:
    validate_challenge(challenge, now=int(time.time()))
    _exact(result, {
        "schema", "status", "challenge_id_sha256", "anchor", "candidate",
        "network_isolation", "comparisons", "files", "timing", "trust_limits",
    }, "result")
    if result["schema"] != RESULT_SCHEMA or result["status"] != "PASS":
        raise ChallengeError("challenge result did not pass")
    if result["challenge_id_sha256"] != challenge["challenge_id_sha256"]:
        raise ChallengeError("result is bound to a different challenge")
    identity = challenge["identity"]
    if result["anchor"] != identity["anchor"] or result["candidate"] != identity["candidate"]:
        raise ChallengeError("result confuses anchor and candidate identities")
    if result["network_isolation"] != "linux-unshare-network-namespace-required":
        raise ChallengeError("trusted execution was not network isolated")
    comparisons = result["comparisons"]
    if comparisons != {
        "independent_verify": "PASS",
        "public_data_exact": "PASS",
        "trace_terminal_state_exact": "PASS",
        "relation_sums_exact": "PASS",
    }:
        raise ChallengeError("independent comparison coverage drifted")
    timing = _exact(result["timing"], {"wall_duration_ns", "commands"}, "timing")
    if type(timing["wall_duration_ns"]) is not int or not 0 <= timing["wall_duration_ns"] <= 180_000_000_000:
        raise ChallengeError("challenge execution exceeded 180 seconds")
    command_names = [
        "candidate-prove", "candidate-public", "candidate-relations",
        "anchor-independent-verify", "pinned-oracle-public", "pinned-oracle-relations",
    ]
    commands = timing["commands"]
    if not isinstance(commands, list) or len(commands) != len(command_names):
        raise ChallengeError("challenge command timing coverage drifted")
    for command, name in zip(commands, command_names, strict=True):
        if not isinstance(command, dict) or set(command) != {
            "name", "duration_ns", "returncode",
        } or command["name"] != name or command["returncode"] != 0 or \
                type(command["duration_ns"]) is not int or command["duration_ns"] < 0:
            raise ChallengeError("challenge command timing record drifted")
    files = result["files"]
    required = {
        "challenge.json", "challenge.elf", "challenge.input", "proof.json",
        "prove-report.json", "verify-receipt.json", "oracle-public.json",
        "candidate-public.json",
        "oracle-relations.txt", "candidate-relations.txt",
    }
    if not isinstance(files, dict) or set(files) != required:
        raise ChallengeError("result file manifest drifted")
    for relative, expected in files.items():
        _digest(expected, f"result file {relative}")
        path = evidence_dir / relative
        if not path.is_file() or path.is_symlink() or sha256_file(path) != expected:
            raise ChallengeError(f"result file digest drifted: {relative}")
    limits = result["trust_limits"]
    if not isinstance(limits, list) or len(limits) < 3 or any(
        not isinstance(item, str) or not item for item in limits
    ):
        raise ChallengeError("challenge trust limits are not explicit")
