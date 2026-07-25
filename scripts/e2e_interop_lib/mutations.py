"""Independent semantic mutations for the Native proof-exchange schema."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


M31_MODULUS = 2_147_483_647
U64_MODULUS = 1 << 64
REJECTION_CLASS_METADATA = "metadata_policy"
REJECTION_CLASS_VERIFIER = "verifier_semantic"
NATIVE_PROOF_SCHEMA = "proof_exchange_json_wire_v1"
SUPPORTED_EXAMPLES = (
    "blake",
    "plonk",
    "poseidon",
    "xor",
    "state_machine",
    "wide_fibonacci",
)


class MutationError(RuntimeError):
    """The input artifact did not expose the field promised by its schema."""


@dataclass(frozen=True)
class MutationSpec:
    mutation_id: str
    category: str
    field_path: str
    required_rejection_class: str
    apply: Callable[[dict[str, Any], str], None]
    examples: tuple[str, ...] = SUPPORTED_EXAMPLES


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MutationError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise MutationError(f"{label} must be a non-empty array")
    return value


def _proof_wire(artifact: dict[str, Any]) -> dict[str, Any]:
    proof_hex = artifact.get("proof_bytes_hex")
    if not isinstance(proof_hex, str) or not proof_hex:
        raise MutationError("proof_bytes_hex must be a non-empty string")
    try:
        raw = bytes.fromhex(proof_hex)
        wire = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MutationError("proof_bytes_hex is not a JSON proof wire") from error
    return _object(wire, "proof wire")


def _store_proof_wire(artifact: dict[str, Any], wire: dict[str, Any]) -> None:
    encoded = json.dumps(wire, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    artifact["proof_bytes_hex"] = encoded.hex()


def _mutate_hash(value: Any, label: str) -> None:
    digest = _list(value, label)
    first = digest[0]
    if not isinstance(first, int) or not 0 <= first <= 255:
        raise MutationError(f"{label}[0] must be a byte")
    digest[0] = (first + 1) % 256


def _mutate_qm31(value: Any, label: str) -> None:
    limbs = _list(value, label)
    if len(limbs) != 4 or not isinstance(limbs[0], int):
        raise MutationError(f"{label} must contain four integer limbs")
    limbs[0] = (limbs[0] + 1) % M31_MODULUS


def _statement(artifact: dict[str, Any], example: str) -> None:
    statements = {
        "plonk": ("plonk_statement", "log_n_rows"),
        "poseidon": ("poseidon_statement", "log_n_instances"),
        "xor": ("xor_statement", "offset"),
        "wide_fibonacci": ("wide_fibonacci_statement", "sequence_len"),
    }
    if example == "blake":
        statement = _object(artifact.get("blake_statement"), "blake_statement")
        stmt1 = _object(statement.get("stmt1"), "blake_statement.stmt1")
        _mutate_qm31(
            stmt1.get("scheduler_claimed_sum"),
            "blake_statement.stmt1.scheduler_claimed_sum",
        )
        return
    if example == "state_machine":
        statement = _object(artifact.get("state_machine_statement"), "state_machine_statement")
        public_input = _list(statement.get("public_input"), "state_machine_statement.public_input")
        row = _list(public_input[1], "state_machine_statement.public_input[1]")
        row[0] = (int(row[0]) + 1) % M31_MODULUS
        return
    try:
        statement_name, field = statements[example]
    except KeyError as error:
        raise MutationError(f"unsupported Native example {example}") from error
    statement = _object(artifact.get(statement_name), statement_name)
    statement[field] = int(statement.get(field, 0)) + 1


def _plonk_logup_claimed_sum(artifact: dict[str, Any], example: str) -> None:
    if example != "plonk_logup":
        raise MutationError("claimed-sum mutation requires plonk_logup")
    statement = _object(
        artifact.get("plonk_logup_statement"), "plonk_logup_statement"
    )
    _mutate_qm31(statement.get("claimed_sum"), "plonk_logup_statement.claimed_sum")


def _plonk_logup_log_size(artifact: dict[str, Any], example: str) -> None:
    if example != "plonk_logup":
        raise MutationError("log-size mutation requires plonk_logup")
    statement = _object(
        artifact.get("plonk_logup_statement"), "plonk_logup_statement"
    )
    statement["log_n_rows"] = int(statement.get("log_n_rows", 0)) + 1


def _plonk_logup_statement_exclusivity(
    artifact: dict[str, Any], example: str
) -> None:
    if example != "plonk_logup":
        raise MutationError("statement-exclusivity mutation requires plonk_logup")
    if artifact.get("plonk_statement") is not None:
        raise MutationError("plonk_statement is already present")
    statement = _object(
        artifact.get("plonk_logup_statement"), "plonk_logup_statement"
    )
    artifact["plonk_statement"] = {"log_n_rows": int(statement["log_n_rows"])}


def _proof_metadata(artifact: dict[str, Any], _example: str) -> None:
    if not isinstance(artifact.get("prove_mode"), str):
        raise MutationError("prove_mode must be represented for proof metadata coverage")
    artifact["prove_mode"] = "invalid-proof-mode"


def _upstream_metadata(artifact: dict[str, Any], _example: str) -> None:
    artifact["upstream_commit"] = "0" * 40


def _generator_metadata(artifact: dict[str, Any], _example: str) -> None:
    artifact["generator"] = "invalid-generator"


def _outer_config(artifact: dict[str, Any], _example: str) -> None:
    config = _object(artifact.get("pcs_config"), "pcs_config")
    fri = _object(config.get("fri_config"), "pcs_config.fri_config")
    fri["n_queries"] = int(fri.get("n_queries", 0)) + 1


def _outer_fold_step(artifact: dict[str, Any], _example: str) -> None:
    config = _object(artifact.get("pcs_config"), "pcs_config")
    fri = _object(config.get("fri_config"), "pcs_config.fri_config")
    fri["fold_step"] = int(fri.get("fold_step", 1)) + 1


def _outer_lifting_log_size(artifact: dict[str, Any], _example: str) -> None:
    config = _object(artifact.get("pcs_config"), "pcs_config")
    lifting = config.get("lifting_log_size")
    config["lifting_log_size"] = 4 if lifting is None else int(lifting) + 1


def _wire_mutation(
    mutation: Callable[[dict[str, Any]], None],
) -> Callable[[dict[str, Any], str], None]:
    def apply(artifact: dict[str, Any], _example: str) -> None:
        wire = _proof_wire(artifact)
        mutation(wire)
        _store_proof_wire(artifact, wire)

    return apply


def _sampled_value(wire: dict[str, Any]) -> None:
    trees = _list(wire.get("sampled_values"), "sampled_values")
    for tree_index, tree in enumerate(trees):
        if not isinstance(tree, list):
            raise MutationError(f"sampled_values[{tree_index}] must be an array")
        for column_index, values in enumerate(tree):
            if not isinstance(values, list):
                raise MutationError(
                    f"sampled_values[{tree_index}][{column_index}] must be an array"
                )
            if values:
                _mutate_qm31(
                    values[0], f"sampled_values[{tree_index}][{column_index}][0]"
                )
                return
    raise MutationError("sampled_values has no serialized value")


def _commitment(wire: dict[str, Any]) -> None:
    commitments = _list(wire.get("commitments"), "commitments")
    _mutate_hash(commitments[0], "commitments[0]")


def _opening(wire: dict[str, Any]) -> None:
    trees = _list(wire.get("queried_values"), "queried_values")
    for tree_index, tree in enumerate(trees):
        if not isinstance(tree, list):
            raise MutationError(f"queried_values[{tree_index}] must be an array")
        for column_index, values in enumerate(tree):
            if not isinstance(values, list):
                raise MutationError(
                    f"queried_values[{tree_index}][{column_index}] must be an array"
                )
            if values:
                values[0] = (int(values[0]) + 1) % M31_MODULUS
                return
    raise MutationError("queried_values has no serialized opening")


def _trace_decommitment(wire: dict[str, Any]) -> None:
    decommitments = _list(wire.get("decommitments"), "decommitments")
    for index, value in enumerate(decommitments):
        decommitment = _object(value, f"decommitments[{index}]")
        witness = decommitment.get("hash_witness")
        if not isinstance(witness, list):
            raise MutationError(f"decommitments[{index}].hash_witness must be an array")
        if witness:
            _mutate_hash(witness[0], f"decommitments[{index}].hash_witness[0]")
            return
    raise MutationError("decommitments has no serialized hash witness")


def _fri(wire: dict[str, Any]) -> dict[str, Any]:
    return _object(wire.get("fri_proof"), "fri_proof")


def _fri_first_layer(wire: dict[str, Any]) -> dict[str, Any]:
    return _object(_fri(wire).get("first_layer"), "fri_proof.first_layer")


def _fri_commitment(wire: dict[str, Any]) -> None:
    _mutate_hash(_fri_first_layer(wire).get("commitment"), "fri_proof.first_layer.commitment")


def _fri_witness(wire: dict[str, Any]) -> None:
    layer = _fri_first_layer(wire)
    witness = _list(layer.get("fri_witness"), "fri_proof.first_layer.fri_witness")
    _mutate_qm31(witness[0], "fri_proof.first_layer.fri_witness[0]")


def _fri_decommitment(wire: dict[str, Any]) -> None:
    layer = _fri_first_layer(wire)
    decommitment = _object(layer.get("decommitment"), "fri_proof.first_layer.decommitment")
    witness = _list(decommitment.get("hash_witness"), "fri first-layer hash_witness")
    _mutate_hash(witness[0], "fri_proof.first_layer.decommitment.hash_witness[0]")


def _fri_last_layer(wire: dict[str, Any]) -> None:
    polynomial = _list(_fri(wire).get("last_layer_poly"), "fri_proof.last_layer_poly")
    _mutate_qm31(polynomial[0], "fri_proof.last_layer_poly[0]")


def _pow_nonce(wire: dict[str, Any]) -> None:
    nonce = wire.get("proof_of_work")
    if not isinstance(nonce, int) or not 0 <= nonce < U64_MODULUS:
        raise MutationError("proof_of_work must be a u64")
    wire["proof_of_work"] = (nonce + 1) % U64_MODULUS


def _proof_config(wire: dict[str, Any]) -> None:
    config = _object(wire.get("config"), "proof.config")
    fri = _object(config.get("fri_config"), "proof.config.fri_config")
    fri["n_queries"] = int(fri.get("n_queries", 0)) + 1


def _xor_statement_integer(field: str) -> Callable[[dict[str, Any], str], None]:
    def apply(artifact: dict[str, Any], _example: str) -> None:
        statement = _object(artifact.get("xor_statement"), "xor_statement")
        statement[field] = int(statement.get(field, 0)) + 1

    return apply


def _xor_claimed_sum(artifact: dict[str, Any], _example: str) -> None:
    statement = _object(artifact.get("xor_statement"), "xor_statement")
    _mutate_qm31(statement.get("claimed_sum"), "xor_statement.claimed_sum")


def _state_machine_stmt0(field: str) -> Callable[[dict[str, Any], str], None]:
    def apply(artifact: dict[str, Any], _example: str) -> None:
        statement = _object(
            artifact.get("state_machine_statement"), "state_machine_statement"
        )
        stmt0 = _object(statement.get("stmt0"), "state_machine_statement.stmt0")
        stmt0[field] = int(stmt0.get(field, 0)) + 1

    return apply


def _state_machine_claim(field: str) -> Callable[[dict[str, Any], str], None]:
    def apply(artifact: dict[str, Any], _example: str) -> None:
        statement = _object(
            artifact.get("state_machine_statement"), "state_machine_statement"
        )
        stmt1 = _object(statement.get("stmt1"), "state_machine_statement.stmt1")
        _mutate_qm31(stmt1.get(field), f"state_machine_statement.stmt1.{field}")

    return apply


def _state_machine_initial(artifact: dict[str, Any], _example: str) -> None:
    statement = _object(
        artifact.get("state_machine_statement"), "state_machine_statement"
    )
    public_input = _list(
        statement.get("public_input"), "state_machine_statement.public_input"
    )
    initial = _list(public_input[0], "state_machine_statement.public_input[0]")
    initial[0] = (int(initial[0]) + 1) % M31_MODULUS


def _commitment_count_missing(wire: dict[str, Any]) -> None:
    commitments = _list(wire.get("commitments"), "commitments")
    if len(commitments) < 2:
        raise MutationError("commitments must contain at least two entries")
    commitments.pop()


def _commitment_count_extra(wire: dict[str, Any]) -> None:
    commitments = _list(wire.get("commitments"), "commitments")
    commitments.append(copy.deepcopy(commitments[-1]))


ACTIVE_MUTATIONS = (
    MutationSpec("statement", "statement", "<example>_statement", REJECTION_CLASS_VERIFIER, _statement),
    MutationSpec("proof_metadata_prove_mode", "proof_metadata", "prove_mode", REJECTION_CLASS_METADATA, _proof_metadata),
    MutationSpec("artifact_metadata_upstream_commit", "artifact_metadata", "upstream_commit", REJECTION_CLASS_METADATA, _upstream_metadata),
    MutationSpec("artifact_metadata_generator", "artifact_metadata", "generator", REJECTION_CLASS_METADATA, _generator_metadata),
    MutationSpec("transcript_bound_sampled_value", "transcript", "proof.sampled_values[*][*][0]", REJECTION_CLASS_VERIFIER, _wire_mutation(_sampled_value)),
    MutationSpec("merkle_commitment", "merkle_commitment", "proof.commitments[0][0]", REJECTION_CLASS_VERIFIER, _wire_mutation(_commitment)),
    MutationSpec("merkle_opening", "merkle_opening", "proof.queried_values[*][*][0]", REJECTION_CLASS_VERIFIER, _wire_mutation(_opening)),
    MutationSpec("merkle_trace_decommitment", "merkle_decommitment", "proof.decommitments[*].hash_witness[0][0]", REJECTION_CLASS_VERIFIER, _wire_mutation(_trace_decommitment)),
    MutationSpec("fri_commitment", "fri", "proof.fri_proof.first_layer.commitment[0]", REJECTION_CLASS_VERIFIER, _wire_mutation(_fri_commitment)),
    MutationSpec("fri_witness", "fri", "proof.fri_proof.first_layer.fri_witness[0][0]", REJECTION_CLASS_VERIFIER, _wire_mutation(_fri_witness)),
    MutationSpec("fri_decommitment", "fri", "proof.fri_proof.first_layer.decommitment.hash_witness[0][0]", REJECTION_CLASS_VERIFIER, _wire_mutation(_fri_decommitment)),
    MutationSpec("fri_last_layer_polynomial", "fri", "proof.fri_proof.last_layer_poly[0][0]", REJECTION_CLASS_VERIFIER, _wire_mutation(_fri_last_layer)),
    MutationSpec("pow_nonce", "proof_of_work", "proof.proof_of_work", REJECTION_CLASS_VERIFIER, _wire_mutation(_pow_nonce)),
    MutationSpec("artifact_pcs_config", "protocol_config", "pcs_config.fri_config.n_queries", REJECTION_CLASS_VERIFIER, _outer_config),
    MutationSpec("outer_fold_step", "protocol_config", "pcs_config.fri_config.fold_step", REJECTION_CLASS_VERIFIER, _outer_fold_step),
    MutationSpec("outer_lifting_log_size", "protocol_config", "pcs_config.lifting_log_size", REJECTION_CLASS_VERIFIER, _outer_lifting_log_size),
    MutationSpec("proof_pcs_config", "protocol_config", "proof.config.fri_config.n_queries", REJECTION_CLASS_VERIFIER, _wire_mutation(_proof_config)),
    MutationSpec("xor_statement_log_size", "statement", "xor_statement.log_size", REJECTION_CLASS_VERIFIER, _xor_statement_integer("log_size"), ("xor",)),
    MutationSpec("xor_statement_log_step", "statement", "xor_statement.log_step", REJECTION_CLASS_VERIFIER, _xor_statement_integer("log_step"), ("xor",)),
    MutationSpec("xor_statement_claimed_sum", "statement", "xor_statement.claimed_sum", REJECTION_CLASS_VERIFIER, _xor_claimed_sum, ("xor",)),
    MutationSpec("xor_commitment_count_missing", "proof_shape", "proof.commitments", REJECTION_CLASS_VERIFIER, _wire_mutation(_commitment_count_missing), ("xor",)),
    MutationSpec("xor_commitment_count_extra", "proof_shape", "proof.commitments", REJECTION_CLASS_VERIFIER, _wire_mutation(_commitment_count_extra), ("xor",)),
    MutationSpec("state_machine_stmt0_n", "statement", "state_machine_statement.stmt0.n", REJECTION_CLASS_VERIFIER, _state_machine_stmt0("n"), ("state_machine",)),
    MutationSpec("state_machine_stmt0_m", "statement", "state_machine_statement.stmt0.m", REJECTION_CLASS_VERIFIER, _state_machine_stmt0("m"), ("state_machine",)),
    MutationSpec("state_machine_initial_state", "statement", "state_machine_statement.public_input[0][0]", REJECTION_CLASS_VERIFIER, _state_machine_initial, ("state_machine",)),
    MutationSpec("state_machine_x_axis_claimed_sum", "statement", "state_machine_statement.stmt1.x_axis_claimed_sum", REJECTION_CLASS_VERIFIER, _state_machine_claim("x_axis_claimed_sum"), ("state_machine",)),
    MutationSpec("state_machine_y_axis_claimed_sum", "statement", "state_machine_statement.stmt1.y_axis_claimed_sum", REJECTION_CLASS_VERIFIER, _state_machine_claim("y_axis_claimed_sum"), ("state_machine",)),
    MutationSpec("state_machine_commitment_count_missing", "proof_shape", "proof.commitments", REJECTION_CLASS_VERIFIER, _wire_mutation(_commitment_count_missing), ("state_machine",)),
    MutationSpec("state_machine_commitment_count_extra", "proof_shape", "proof.commitments", REJECTION_CLASS_VERIFIER, _wire_mutation(_commitment_count_extra), ("state_machine",)),
)

PLONK_LOGUP_ORACLE_MUTATIONS = (
    MutationSpec(
        "plonk_logup_claimed_sum",
        "statement",
        "plonk_logup_statement.claimed_sum",
        REJECTION_CLASS_VERIFIER,
        _plonk_logup_claimed_sum,
    ),
    MutationSpec(
        "plonk_logup_log_size",
        "statement",
        "plonk_logup_statement.log_n_rows",
        REJECTION_CLASS_VERIFIER,
        _plonk_logup_log_size,
    ),
    MutationSpec(
        "plonk_logup_statement_exclusivity",
        "statement_shape",
        "plonk_statement",
        REJECTION_CLASS_VERIFIER,
        _plonk_logup_statement_exclusivity,
    ),
    MutationSpec(
        "plonk_logup_proof_commitment",
        "proof_bytes",
        "proof.commitments[0][0]",
        REJECTION_CLASS_VERIFIER,
        _wire_mutation(_commitment),
    ),
)


def mutations_for_example(example: str) -> tuple[MutationSpec, ...]:
    if example not in SUPPORTED_EXAMPLES:
        raise MutationError(f"unsupported Native example {example}")
    return tuple(spec for spec in ACTIVE_MUTATIONS if example in spec.examples)


NOT_APPLICABLE_COVERAGE = (
    {
        "mutation_id": "serialized_transcript_challenge",
        "category": "transcript_challenge",
        "field_path": None,
        "status": "not_applicable",
        "reason": (
            "The Native v1 proof wire serializes transcript-bound sampled values but no "
            "Fiat-Shamir transcript state or derived challenge. Both verifiers reconstruct "
            "those challenges internally, so there is no independent challenge field to mutate."
        ),
    },
)


def mutate_artifact(src: Path, dst: Path, spec: MutationSpec, *, example: str) -> None:
    try:
        before = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MutationError(f"failed to parse source artifact {src}") from error
    artifact = copy.deepcopy(_object(before, "artifact"))
    spec.apply(artifact, example)
    if artifact == before:
        raise MutationError(f"mutation {spec.mutation_id} did not change the artifact")
    dst.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def coverage_manifest(examples: tuple[str, ...] | list[str]) -> dict[str, Any]:
    selected = list(examples)
    unknown = sorted(set(selected) - set(SUPPORTED_EXAMPLES))
    if unknown:
        raise MutationError(f"unsupported examples in coverage manifest: {unknown}")
    applicable = []
    required_cases = 0
    for spec in ACTIVE_MUTATIONS:
        applicable_examples = [
            example for example in selected if example in spec.examples
        ]
        if not applicable_examples:
            continue
        applicable.append(
            {
                "mutation_id": spec.mutation_id,
                "category": spec.category,
                "field_path": spec.field_path,
                "status": "required",
                "required_rejection_class": spec.required_rejection_class,
                "examples": applicable_examples,
                "directions": ["rust_to_zig", "zig_to_rust"],
            }
        )
        required_cases += len(applicable_examples) * 2
    not_applicable = [dict(item, examples=selected) for item in NOT_APPLICABLE_COVERAGE]
    return {
        "proof_schema": NATIVE_PROOF_SCHEMA,
        "applicable": applicable,
        "not_applicable": not_applicable,
        "required_cases": required_cases,
    }


def plonk_logup_oracle_coverage_manifest() -> dict[str, Any]:
    return {
        "proof_schema": NATIVE_PROOF_SCHEMA,
        "applicable": [
            {
                "mutation_id": spec.mutation_id,
                "category": spec.category,
                "field_path": spec.field_path,
                "status": "required",
                "required_rejection_class": spec.required_rejection_class,
                "examples": ["plonk_logup"],
                "directions": ["zig_to_rust"],
            }
            for spec in PLONK_LOGUP_ORACLE_MUTATIONS
        ],
        "not_applicable": [],
        "required_cases": len(PLONK_LOGUP_ORACLE_MUTATIONS),
    }
