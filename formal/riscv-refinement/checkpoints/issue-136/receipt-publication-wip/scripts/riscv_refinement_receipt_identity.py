"""Identity and exact certificate-mapping helpers for refinement receipts."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

if __package__:
    from . import riscv_team_a, riscv_team_b
    from .riscv_refinement_lib import air_program, air_program_contract, codec, render
    from .riscv_refinement_lib.model import (
        FULL_OPCODE_COUNT,
        SCHEMA_VERSION,
        Paths,
        RefinementError,
    )
    from .riscv_refinement_lib.process import _run
    from .riscv_refinement_receipt_constants import (
        APPROVED_LEAN_AXIOMS,
        OPCODE_INDEX_RELATIVE,
        TEAM_A_INDEX_RELATIVE,
        TEAM_B_INDEX_RELATIVE,
    )
else:
    import riscv_team_a
    import riscv_team_b
    from riscv_refinement_lib import air_program, air_program_contract, codec, render
    from riscv_refinement_lib.model import (
        FULL_OPCODE_COUNT,
        SCHEMA_VERSION,
        Paths,
        RefinementError,
    )
    from riscv_refinement_lib.process import _run
    from riscv_refinement_receipt_constants import (
        APPROVED_LEAN_AXIOMS,
        OPCODE_INDEX_RELATIVE,
        TEAM_A_INDEX_RELATIVE,
        TEAM_B_INDEX_RELATIVE,
    )

def _tool(
    name: str,
    version_argv: list[str],
    cwd: Path,
) -> dict[str, str]:
    found = shutil.which(name)
    if found is None:
        raise RefinementError(f"required tool {name!r} is not on PATH")
    binary = Path(found).resolve()
    version = _run([str(binary), *version_argv], cwd).strip().splitlines()[0]
    return {
        "sha256": codec.sha256_file(binary),
        "version": version,
    }


def _toolchain(paths: Paths) -> dict[str, dict[str, str]]:
    python = Path(sys.executable).resolve()
    lean_path = Path(
        _run(["lake", "env", "which", "lean"], paths.formal).strip()
    ).resolve()
    if not lean_path.is_file():
        raise RefinementError("pinned Lean executable could not be resolved")
    return {
        "python": {
            "sha256": codec.sha256_file(python),
            "version": sys.version.split()[0],
        },
        "zig": _tool("zig", ["version"], paths.root),
        "lake": _tool("lake", ["--version"], paths.formal),
        "lean": {
            "sha256": codec.sha256_file(lean_path),
            "version": _run(
                [str(lean_path), "--version"],
                paths.formal,
            ).strip().splitlines()[0],
        },
    }


def _repository_state(paths: Paths) -> tuple[str, list[str]]:
    revision = _run(["git", "rev-parse", "HEAD"], paths.root).strip()
    status = _run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        paths.root,
    )
    receipt_path = paths.receipt.relative_to(paths.root).as_posix()
    dirty_paths = sorted(
        line[3:]
        for line in status.splitlines()
        if line and line[3:] != receipt_path
    )
    return revision, dirty_paths


def _strict_identity(value: object, expected: object) -> bool:
    """Compare JSON values without Python's bool/int numeric coercions."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (
            set(value) == set(expected)
            and all(
                _strict_identity(value[key], expected[key])
                for key in expected
            )
        )
    if isinstance(expected, list):
        return (
            len(value) == len(expected)
            and all(
                _strict_identity(item, expected_item)
                for item, expected_item in zip(value, expected)
            )
        )
    return value == expected


def _sha256_identity(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or air_program_contract.HEX_SHA256.fullmatch(value) is None
    ):
        raise RefinementError(f"{label} is not a sha256 digest")
    return value


def _payload_identity(
    paths: Paths,
    relative: Path,
    *,
    expected_kind: str | None = None,
    expected_schema: object | None = None,
    expected_payload: dict[str, Any] | None = None,
) -> dict[str, object]:
    """Bind both the canonical JSON value and its exact committed bytes."""
    path = paths.root / relative
    if path.is_symlink() or not path.is_file():
        raise RefinementError(
            f"receipt input is absent or not a regular file: {relative}"
        )
    payload = codec.load_json(path)
    if path.read_bytes() != codec.pretty_bytes(payload):
        raise RefinementError(
            f"receipt input is not canonical pretty JSON: {relative}"
        )
    canonical_digest = _sha256_identity(
        payload.get("canonical_digest"),
        f"{relative} canonical_digest",
    )
    if canonical_digest != codec.content_digest(payload):
        raise RefinementError(
            f"receipt input canonical digest is invalid: {relative}"
        )
    if expected_kind is not None and payload.get("kind") != expected_kind:
        raise RefinementError(f"receipt input kind drifted: {relative}")
    if (
        expected_schema is not None
        and not _strict_identity(
            payload.get("schema_version"),
            expected_schema,
        )
    ):
        raise RefinementError(f"receipt input schema drifted: {relative}")
    if expected_payload is not None and payload != expected_payload:
        raise RefinementError(
            f"receipt input payload differs from live evidence: {relative}"
        )
    return {
        "artifact": relative.as_posix(),
        "sha256": codec.sha256_file(path),
        "payload_sha256": codec.sha256_bytes(codec.canonical_bytes(payload)),
        "canonical_digest": canonical_digest,
        "payload": payload,
    }


def _validate_payload_identity(value: object, label: str) -> None:
    required = {
        "artifact",
        "canonical_digest",
        "payload",
        "payload_sha256",
        "sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise RefinementError(f"{label} payload identity schema is invalid")
    artifact = value["artifact"]
    if (
        not isinstance(artifact, str)
        or not artifact
        or Path(artifact).is_absolute()
        or ".." in Path(artifact).parts
    ):
        raise RefinementError(f"{label} artifact identity is invalid")
    for field in ("canonical_digest", "payload_sha256", "sha256"):
        _sha256_identity(value[field], f"{label} {field}")
    payload = value["payload"]
    if (
        not isinstance(payload, dict)
        or payload.get("canonical_digest") != value["canonical_digest"]
        or value["canonical_digest"] != codec.content_digest(payload)
        or value["payload_sha256"]
        != codec.sha256_bytes(codec.canonical_bytes(payload))
        or value["sha256"]
        != codec.sha256_bytes(codec.pretty_bytes(payload))
    ):
        raise RefinementError(f"{label} full payload identity is invalid")


def _certificate_index_identities(
    paths: Paths,
) -> dict[str, dict[str, object]]:
    specs = {
        "team_a": (
            TEAM_A_INDEX_RELATIVE,
            "stwo-riscv-team-a-coverage",
            1,
            136,
            24,
            {
                "canonical_digest",
                "certificates",
                "claim_boundary",
                "families",
                "issue",
                "kind",
                "schema_version",
            },
        ),
        "team_b": (
            TEAM_B_INDEX_RELATIVE,
            "stwo-riscv-team-b-coverage",
            1,
            137,
            22,
            {
                "air_level_counterexample_gate",
                "canonical_digest",
                "certificates",
                "claim_boundary",
                "families",
                "issue",
                "kind",
                "schema_version",
            },
        ),
        "aggregate": (
            OPCODE_INDEX_RELATIVE,
            "stwo-riscv-opcode-coverage",
            1,
            None,
            FULL_OPCODE_COUNT,
            {
                "canonical_digest",
                "certificates",
                "claim_boundary",
                "kind",
                "schema_version",
                "source_indexes",
            },
        ),
    }
    identities: dict[str, dict[str, object]] = {}
    for name, (
        relative,
        kind,
        schema,
        issue,
        count,
        fields,
    ) in specs.items():
        identity = _payload_identity(
            paths,
            relative,
            expected_kind=kind,
            expected_schema=schema,
        )
        payload = identity["payload"]
        certificates = payload.get("certificates")
        if (
            set(payload) != fields
            or (
                issue is not None
                and (
                    type(payload.get("issue")) is not int
                    or payload["issue"] != issue
                )
            )
            or not isinstance(certificates, list)
            or len(certificates) != count
        ):
            raise RefinementError(
                f"receipt {name} certificate index identity drifted"
            )
        identities[name] = identity
    aggregate = identities["aggregate"]["payload"]
    source_indexes = aggregate.get("source_indexes")
    if (
        not isinstance(source_indexes, dict)
        or set(source_indexes) != {"team_a", "team_b"}
        or source_indexes["team_a"]
        != identities["team_a"]["canonical_digest"]
        or source_indexes["team_b"]
        != identities["team_b"]["canonical_digest"]
    ):
        raise RefinementError(
            "aggregate certificate index does not bind both source indexes"
        )
    return identities


def _validate_certificate_mappings(
    mappings: object,
    indexes: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    if not isinstance(mappings, list) or len(mappings) != FULL_OPCODE_COUNT:
        raise RefinementError(
            "receipt must bind exactly 46 opcode certificate mappings"
        )
    team_a_payload = indexes["team_a"]["payload"]
    team_b_payload = indexes["team_b"]["payload"]

    def certificates_by_mnemonic(
        payload: object,
        label: str,
    ) -> dict[str, dict[str, object]]:
        if not isinstance(payload, dict):
            raise RefinementError(
                f"receipt {label} certificate payload is invalid"
            )
        certificates = payload.get("certificates")
        if not isinstance(certificates, list):
            raise RefinementError(
                f"receipt {label} certificate inventory is invalid"
            )
        result: dict[str, dict[str, object]] = {}
        for certificate in certificates:
            if not isinstance(certificate, dict):
                raise RefinementError(
                    f"receipt {label} certificate is not an object"
                )
            mnemonic = certificate.get("mnemonic")
            if (
                not isinstance(mnemonic, str)
                or not mnemonic
                or mnemonic in result
            ):
                raise RefinementError(
                    f"receipt {label} certificate mnemonic is invalid"
                )
            result[mnemonic] = certificate
        return result

    team_a_certificates = certificates_by_mnemonic(
        team_a_payload,
        "Team A",
    )
    team_b_certificates = certificates_by_mnemonic(
        team_b_payload,
        "Team B",
    )
    team_a_names = set(team_a_certificates)
    team_b_names = set(team_b_certificates)
    expected_team_a = {
        mnemonic
        for _, mnemonic, family in air_program_contract.OPCODES
        if family in riscv_team_a.TEAM_A_FAMILIES
    }
    if (
        team_a_names != expected_team_a
        or len(team_a_names) != 24
        or len(team_b_names) != 22
        or team_a_names & team_b_names
        or team_a_names | team_b_names
        != {
            mnemonic
            for _, mnemonic, _ in air_program_contract.OPCODES
        }
    ):
        raise RefinementError(
            "Team A and Team B certificate payloads do not partition 46"
        )
    team_a_sail_fields = {
        "sail_digest",
        "sail_receipt",
        "sail_theorem",
    }
    team_b_source_fields = {
        "family",
        "manifest_id",
        "mnemonic",
        "mutation",
        "mutation_theorem",
        "non_vacuity_theorem",
        "refinement_theorem",
        "sail_binding",
        "state",
        "tuple_theorem",
    }
    theorem_fields = (
        "refinement_theorem",
        "tuple_theorem",
        "non_vacuity_theorem",
        "mutation_theorem",
    )
    theorem_names = {
        field: set()
        for field in (*theorem_fields, "selector_theorem")
    }
    mutation_names: set[str] = set()
    generated_sail_inputs = 0
    normalized_retirements = 0
    reviewed_sail_capsules = 0
    for expected, mapping in zip(
        air_program_contract.OPCODES,
        mappings,
    ):
        manifest_id, mnemonic, family = expected
        if (
            not isinstance(mapping, dict)
            or type(mapping.get("manifest_id")) is not int
            or mapping["manifest_id"] != manifest_id
            or mapping.get("mnemonic") != mnemonic
            or mapping.get("family") != family
            or not isinstance(mapping.get("mutation"), str)
            or not mapping["mutation"]
        ):
            raise RefinementError(
                f"receipt certificate mapping drifted for {mnemonic}"
            )
        _sha256_identity(
            mapping.get("air_digest"),
            f"{mnemonic} AIR digest",
        )
        if mapping["mutation"] in mutation_names:
            raise RefinementError(
                f"receipt reuses opcode mutation {mapping['mutation']}"
            )
        mutation_names.add(mapping["mutation"])
        is_team_a = mnemonic in team_a_names
        source = (
            team_a_certificates[mnemonic]
            if is_team_a
            else team_b_certificates[mnemonic]
        )
        if (
            type(source.get("manifest_id")) is not int
            or source["manifest_id"] != manifest_id
            or source.get("mnemonic") != mnemonic
            or source.get("family") != family
            or not isinstance(source.get("mutation"), str)
            or not source["mutation"]
            or any(
                not isinstance(source.get(field), str)
                or not source[field]
                for field in theorem_fields
            )
        ):
            raise RefinementError(
                f"embedded source certificate drifted for {mnemonic}"
            )
        for field in theorem_fields:
            theorem = source[field]
            if theorem in theorem_names[field]:
                raise RefinementError(
                    f"embedded certificates reuse {field}: {theorem}"
                )
            theorem_names[field].add(theorem)

        if is_team_a:
            expected_source_fields = (
                riscv_team_a.CERTIFICATE_FIELDS
                | team_a_sail_fields
            )
            axioms = source.get("axioms")
            proof_time = source.get("proof_time_ms")
            selector_theorem = source.get("selector_theorem")
            expected_sail_binding = (
                "generated-retirement"
                if mnemonic
                in riscv_team_a.GENERATED_SAIL_RETIREMENT_THEOREMS
                else "generated-clause-input"
            )
            expected_sail_theorem = (
                riscv_team_a.GENERATED_SAIL_RETIREMENT_THEOREMS[mnemonic]
                if expected_sail_binding == "generated-retirement"
                else riscv_team_a.GENERATED_SAIL_INPUT_THEOREMS[mnemonic]
            )
            sail_receipt = source.get("sail_receipt")
            if (
                not isinstance(axioms, list)
                or any(not isinstance(axiom, str) for axiom in axioms)
                or axioms != sorted(set(axioms))
                or not set(axioms) <= APPROVED_LEAN_AXIOMS
            ):
                raise RefinementError(
                    f"Team A receipt axioms drifted for {mnemonic}"
                )
            if (
                set(source) != expected_source_fields
                or source.get("state") != "air-proved"
                or not isinstance(selector_theorem, str)
                or not selector_theorem
                or not isinstance(source.get("proof_target"), str)
                or not source["proof_target"]
                or type(proof_time) is not int
                or proof_time <= 0
                or proof_time > riscv_team_a.MAX_PROOF_TIME_MS
                or source.get("sail_binding") != expected_sail_binding
                or source.get("sail_theorem") != expected_sail_theorem
                or not isinstance(sail_receipt, str)
                or not sail_receipt
                or Path(sail_receipt).is_absolute()
                or ".." in Path(sail_receipt).parts
            ):
                raise RefinementError(
                    f"Team A receipt evidence drifted for {mnemonic}"
                )
            _sha256_identity(
                source.get("air_digest"),
                f"{mnemonic} source AIR digest",
            )
            _sha256_identity(
                source.get("sail_digest"),
                f"{mnemonic} generated Sail digest",
            )
            if selector_theorem in theorem_names["selector_theorem"]:
                raise RefinementError(
                    "embedded certificates reuse selector_theorem: "
                    f"{selector_theorem}"
                )
            theorem_names["selector_theorem"].add(selector_theorem)
            expected_mapping = {
                "air_binding": "exact-generated-local-program",
                "air_digest": source["air_digest"],
                "axioms": axioms,
                "family": family,
                "manifest_id": manifest_id,
                "mnemonic": mnemonic,
                "mutation": source["mutation"],
                "mutation_theorem": source["mutation_theorem"],
                "non_vacuity_theorem":
                    source["non_vacuity_theorem"],
                "proof_time_ms": proof_time,
                "refinement_theorem": source["refinement_theorem"],
                "sail_binding": expected_sail_binding,
                "sail_digest": source["sail_digest"],
                "sail_receipt": sail_receipt,
                "sail_theorem": expected_sail_theorem,
                "selector_theorem": selector_theorem,
                "state": "air-proved",
                "team": "A",
                "tuple_theorem": source["tuple_theorem"],
            }
        else:
            if (
                set(source) != team_b_source_fields
                or source.get("state") != "proved"
                or source.get("sail_binding")
                != riscv_team_b.DEFAULT_SAIL_BINDING
            ):
                raise RefinementError(
                    f"Team B receipt evidence drifted for {mnemonic}"
                )
            expected_mapping = {
                "air_binding": "reviewed-family-capsule",
                "air_digest": mapping["air_digest"],
                "axioms": None,
                "family": family,
                "manifest_id": manifest_id,
                "mnemonic": mnemonic,
                "mutation": source["mutation"],
                "mutation_theorem": source["mutation_theorem"],
                "non_vacuity_theorem":
                    source["non_vacuity_theorem"],
                "proof_time_ms": None,
                "refinement_theorem": source["refinement_theorem"],
                "sail_binding": riscv_team_b.DEFAULT_SAIL_BINDING,
                "selector_theorem": None,
                "state": "proved",
                "team": "B",
                "tuple_theorem": source["tuple_theorem"],
            }
        if not _strict_identity(mapping, expected_mapping):
            raise RefinementError(
                "receipt certificate mapping differs from its embedded "
                f"source certificate for {mnemonic}"
            )
        binding = mapping.get("sail_binding")
        if binding in ("generated-clause-input", "generated-retirement"):
            generated_sail_inputs += 1
        if binding == "generated-retirement":
            normalized_retirements += 1
        if binding == "reviewed-capsule":
            reviewed_sail_capsules += 1
    if (
        generated_sail_inputs != 24
        or normalized_retirements != 24
        or reviewed_sail_capsules != 22
    ):
        raise RefinementError(
            "receipt source-certificate Sail grades do not match the "
            "FV-1/FV-2 input boundary"
        )
    return mappings


def _fixed_table_schemas() -> list[dict[str, object]]:
    return [
        {
            "id": table_id,
            "domain": table_id,
            "arity": arity,
            "log_size": log_size,
            "schema_sha256": air_program.table_schema_digest(
                table_id,
                table_id,
                arity,
                log_size,
            ),
        }
        for table_id, arity, log_size in air_program_contract.FIXED_TABLES
    ]


def _opcode_mutations(
    mappings: list[dict[str, object]],
) -> list[dict[str, object]]:
    return [
        {
            "manifest_id": mapping["manifest_id"],
            "mnemonic": mapping["mnemonic"],
            "mutation": mapping["mutation"],
            "mutation_theorem": mapping["mutation_theorem"],
        }
        for mapping in mappings
    ]


def _team_a_proof_time_diagnostics(
    mappings: list[dict[str, object]],
) -> dict[str, object]:
    measurements = [
        {
            "manifest_id": mapping["manifest_id"],
            "mnemonic": mapping["mnemonic"],
            "proof_time_ms": mapping["proof_time_ms"],
        }
        for mapping in mappings
        if mapping["team"] == "A"
    ]
    if len(measurements) != 24:
        raise RefinementError(
            "receipt has incomplete Team A proof-time diagnostics"
        )
    return {
        "unit": "milliseconds",
        "diagnostic_only": True,
        "semantic_evidence": False,
        "maximum_allowed_ms": riscv_team_a.MAX_PROOF_TIME_MS,
        "measurements": measurements,
    }


def _generated_manifest_identity(paths: Paths) -> dict[str, object]:
    relative = paths.manifest.relative_to(paths.root)
    identity = _payload_identity(
        paths,
        relative,
        expected_kind="stwo-riscv-refinement-generated-manifest",
        expected_schema=SCHEMA_VERSION,
    )
    render.validate_committed_manifest(paths, identity["payload"])
    return identity
