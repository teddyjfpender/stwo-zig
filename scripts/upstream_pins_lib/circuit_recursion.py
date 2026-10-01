"""Pin, provenance and fixture validation for the circuit recursion lane.

The lane's Rust oracle (`tools/stwo-circuit-oracle-rs`) depends on StarkWare's
`proving` repository by git URL and revision. Its checkpoints live under
`vectors/circuit/`, authenticated by `vectors/circuit/provenance.json`, which
binds every fixture to its bytes, SHA-256, generating command, and the digest of
the oracle source that produced it. Editing the oracle without regenerating the
fixtures, or editing a fixture by hand, is therefore rejected.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import tomllib
from pathlib import Path

from .circuit_projection import (  # noqa: F401  (re-exported for the lane's callers)
    PROJECTION_MAGIC,
    PROJECTION_VERSION,
    ProjectionError,
    parse_projection,
)
from .official_cairo_air import (
    BUNDLE_FORMAT,
    EVAL_PROGRAM_ABI,
    bundle_summary,
    check_bundle_geometry,
    parse_bundle_header,
)


ORACLE = "tools/stwo-circuit-oracle-rs"
MANIFEST = f"{ORACLE}/Cargo.toml"
LOCK = f"{ORACLE}/Cargo.lock"
TOOLCHAIN = f"{ORACLE}/rust-toolchain.toml"
AUTHORITY_SOURCE = f"{ORACLE}/src/checkpoint.rs"
# The trace digest source shared with `tools/stwo-cairo-trace-oracle`, compiled in with `#[path]`.
TRACE_DIGEST = "tools/stwo-trace-digest"
VECTORS = "vectors/circuit"
README = f"{VECTORS}/README.md"
PROVENANCE = f"{VECTORS}/provenance.json"
PROVENANCE_SCHEMA = "stwo-circuit-oracle-provenance-v1"
CHECKPOINT_SCHEMA = "stwo-circuit-oracle-checkpoint-v1"
METADATA_TABLE = "circuit-recursion-oracle"
PROVING_ROOT_PLACEHOLDER = "<proving checkout at the pinned revision>"

# (fixture, rung, oracle subcommand, reads upstream data)
ORACLE_ARTIFACTS = (
    (f"{VECTORS}/r0/primitives.json", "r0", "primitives", False),
    (f"{VECTORS}/r10/prove_lifted_example.json", "r10-lift", "prove-lifted-example", False),
    (f"{VECTORS}/r2/gadgets.json", "r1-r2", "gadgets", False),
    (f"{VECTORS}/r3/components.json", "r3", "components", True),
    (f"{VECTORS}/r3/statement_trace.json", "r3", "statement-trace", True),
    (f"{VECTORS}/official/compiled_air_constraints_v1.bin", "r3", "project-air", True),
    (f"{VECTORS}/r4/verifier_stages.json", "r4", "verifier-stages", True),
    (f"{VECTORS}/r5/finalize.json", "r5", "finalize", False),
    (f"{VECTORS}/r6/topology.json", "r6", "topology", True),
    (f"{VECTORS}/r7/prove_small.json", "r7", "prove-small", False),
    (f"{VECTORS}/r7/prove_profiles.json", "r7", "prove-profiles", False),
    (f"{VECTORS}/official/circuit_air.air_programs_v1.bin", "r7", "air-programs", False),
    (f"{VECTORS}/r6/cairo_statement.json", "r6", "cairo-statement", True),
    (f"{VECTORS}/r9/fold_tree.json", "r9", "fold-tree", True),
)
# (fixture, rung, adapted ProverInput under the repository root, registry in the proving
# checkout) for `prove-cairo`, the leaf-lane Cairo proofs (R10c). The inputs are the
# stwo-cairo 82f2125 fixtures authenticated by vectors/cairo/official provenance.
# The leaf simple bootloader's input in upstream `test_golden_four_leaves_e2e`
# (`crates/stwo_run_and_prove_recursive_tree/src/tests.rs`, `leaf_bl_input_json`): one
# `simple_output` task with output [11, 13, 17]. (task program, task output, golden
# hashed-output preimage the run must dump), paths in the proving checkout.
SIMPLE_OUTPUT_TASK = (
    "crates/stwo_run_and_prove_recursive_tree/test_data/simple_output_compiled.json",
    (11, 13, 17),
    "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/leaf_preimage.json",
)
LEAF_BOOTLOADER_INPUT_PLACEHOLDER = "<leaf bootloader input written by the generator>"
PREIMAGE_DUMP_PLACEHOLDER = "<hashed-output preimage dump, outside the tree>"
# (fixture, rung, compiled program in the proving checkout, bootloader task or None) for
# `adapt-program`: the leaf prover's own VM run and adapter (prove_leaf.rs steps 1-2), emitted as
# ProverInput JSON.
ADAPTED_PROGRAMS = (
    (
        f"{VECTORS}/r10/use_all_opcodes_and_builtins.prover_input.json",
        "r10c",
        "crates/leaf_prover/tests/data/use_all_opcodes_and_builtins_compiled.json",
        None,
    ),
    (
        f"{VECTORS}/r10/leaf_simple_bootloader.prover_input.json",
        "r8b",
        "crates/stwo_run_and_prove_recursive_tree/test_data/leaf_simple_bootloader_compiled.json",
        SIMPLE_OUTPUT_TASK,
    ),
)


def leaf_bootloader_input(task: tuple, proving_root: str, dump_path: str) -> dict:
    """`leaf_bl_input_json` of upstream's e2e test for `task` (a `SIMPLE_OUTPUT_TASK`)."""
    program, output, _preimage = task
    return {
        "tasks": [
            {
                "type": "RunProgramTask",
                "path": f"{proving_root}/{program}",
                "program_input": {"output": list(output)},
                "program_hash_function": "blake",
            }
        ],
        "fact_topologies_path": None,
        "single_page": True,
        "output_preimage_dump_path": dump_path,
    }
CAIRO_PROOF_REGISTRY = "crates/leaf_prover/tests/data/circuit_registry_canonical_small.json"
# The last field overrides the registry's lifting policy (None keeps it): small programs
# never lift under AtLeastPreprocessed, so `fixed:22` covers the lifted Cairo trees.
CAIRO_PROOF_ARTIFACTS = tuple(
    (
        f"{VECTORS}/r10/{name}.prove_cairo.json",
        "r10c",
        f"vectors/cairo/official/{name}.prover_input.json",
        CAIRO_PROOF_REGISTRY,
        None,
    )
    for name in ("all_opcodes", "all_builtins")
) + (
    (
        f"{VECTORS}/r10/use_all_opcodes_and_builtins.prove_cairo.json",
        "r10c",
        ADAPTED_PROGRAMS[0][0],
        CAIRO_PROOF_REGISTRY,
        None,
    ),
    (
        f"{VECTORS}/r10/all_opcodes.fixed_22.prove_cairo.json",
        "r10c",
        "vectors/cairo/official/all_opcodes.prover_input.json",
        CAIRO_PROOF_REGISTRY,
        "fixed:22",
    ),
)
# `multiverifier-inputs`: the checkpoint pins the circuit-prover inputs of
# test_data/circuit_multiverifier/proof.bin, a 179 MB `STWZCIRC/1` file kept outside the tree.
MULTIVERIFIER_INPUTS = f"{VECTORS}/r7/multiverifier_inputs.json"
MULTIVERIFIER_INPUTS_FILE_PLACEHOLDER = "<multiverifier inputs file, outside the tree>"
# `verify-circuit` verdicts of upstream `verify_circuit` on proofs the Zig circuit prover wrote
# (`STWO_CIRCUIT_R7_EMIT_DIR` of `zig build circuit-parity-r7` and
# `circuit-parity-r7-multiverifier`, src/integrations/circuit_cpu).
ZIG_EMIT_DIR_PLACEHOLDER = "<STWO_CIRCUIT_R7_EMIT_DIR of the Zig circuit-parity-r7 steps>"
VERIFY_VERDICTS = tuple(
    (f"{VECTORS}/r7/verify/{label}.json", label)
    for label in (
        "internal-blake_g_gate",
        "internal-fibonacci",
        "multiverifier",
        "small-blake_g_gate",
        "small-fibonacci",
        "small-m31_to_u32",
        "small-triple_xor",
    )
)
# R11 acceptance and tamper: upstream `verify_circuit`'s verdicts on the proofs and requests the
# Zig `circuit-parity-r11` step writes (`STWO_CIRCUIT_R11_EMIT_DIR`, src/integrations/circuit_cpu):
# three proofs, each untouched and after each tampering.
R11_EMIT_DIR_PLACEHOLDER = "<STWO_CIRCUIT_R11_EMIT_DIR of the Zig circuit-parity-r11 step>"
R11_BASES = ("leaf", "multiverifier", "small-fibonacci")
R11_TAMPERS = (
    "none",
    "output_digest",
    "preprocessed_root",
    "circuit_hash",
    "claimed_sum",
    "channel_salt",
    "pow_nonce",
    "interaction_pow_nonce",
    "fri_witness",
)
R11_VERDICTS = tuple(
    (f"{VECTORS}/r11/verify/{base}-{tamper}.json", f"{base}-{tamper}")
    for base in R11_BASES
    for tamper in R11_TAMPERS
)
PROJECTION = f"{VECTORS}/official/compiled_air_constraints_v1.bin"
PRIMITIVES = f"{VECTORS}/r0/primitives.json"
# The Zig test that inlines the R0 `fri` vector of `PRIMITIVES`.
R0_FRI_ZIG_TEST = "src/frontends/circuit/builder/tests/r0_fri_test.zig"
R0_FRI_ZIG_TEST_NAME = "R0: FRI fold_step 4 folds match the oracle digests"
COMPONENTS = f"{VECTORS}/r3/components.json"
TOPOLOGY = f"{VECTORS}/r6/topology.json"
AIR_PROGRAMS = f"{VECTORS}/official/circuit_air.air_programs_v1.bin"
# The circuit AIR's components, in `ComponentList` order.
CIRCUIT_AIR_COMPONENTS = 11
# (fixture, path in the proving checkout) for files copied verbatim.
UPSTREAM_COPIES = (
    (
        f"{VECTORS}/official/compiled_casm_air.sample_evaluations.json",
        "outputs/compiled_casm_air/sample_evaluations.json",
    ),
    (
        f"{VECTORS}/official/compiled_circuit_air.sample_evaluations.json",
        "outputs/compiled_circuit_air/sample_evaluations.json",
    ),
    (
        f"{VECTORS}/official/registries/leaf_prover_canonical_small.json",
        "crates/leaf_prover/tests/data/circuit_registry_canonical_small.json",
    ),
    (
        f"{VECTORS}/official/programs/use_all_opcodes_and_builtins_compiled.json",
        "crates/leaf_prover/tests/data/use_all_opcodes_and_builtins_compiled.json",
    ),
    (
        f"{VECTORS}/official/registries/recursive_tree_test.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json",
    ),
    # Wire-format goldens (M3): circuit proofs, leaf and tree outputs.
    (
        f"{VECTORS}/official/registries/privacy_large_proofs.json",
        "crates/privacy_circuit_verify/large_proofs_circuit_registry.json",
    ),
    (
        f"{VECTORS}/official/circuit_multiverifier/proof.bin",
        "test_data/circuit_multiverifier/proof.bin",
    ),
    (
        f"{VECTORS}/official/circuit_multiverifier/proof_cairo.bin",
        "test_data/circuit_multiverifier/proof_cairo.bin",
    ),
    (
        f"{VECTORS}/official/circuit_multiverifier/backward_compatibility_cairo_proof.bin",
        "test_data/circuit_multiverifier/backward_compatibility_cairo_proof.bin",
    ),
    (
        f"{VECTORS}/official/leaf_prover/expected_output.json",
        "crates/leaf_prover/tests/data/expected_output.json",
    ),
    (
        f"{VECTORS}/official/programs/leaf_simple_bootloader_compiled.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/leaf_simple_bootloader_compiled.json",
    ),
    (
        f"{VECTORS}/official/registry_definitions/canonical_small/definition.json",
        "circuit_registry_definitions/canonical_small/definition.json",
    ),
    (
        f"{VECTORS}/official/registry_definitions/canonical_small/cairo_prover_params.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/cairo_prover_params.json",
    ),
    (
        f"{VECTORS}/official/registry_definitions/canonical_small/circuit_fri_config.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/circuit_fri_config.json",
    ),
    (
        f"{VECTORS}/official/registry_definitions/leaf_prover_canonical_small/definition.json",
        "crates/leaf_prover/tests/data/circuit_registry_definition_canonical_small.json",
    ),
    (
        f"{VECTORS}/official/registry_definitions/leaf_prover_canonical_small/cairo_prover_params.json",
        "crates/leaf_prover/tests/data/cairo_prover_params_canonical_small.json",
    ),
    (
        f"{VECTORS}/official/registry_definitions/leaf_prover_canonical_small/circuit_fri_config.json",
        "crates/leaf_prover/tests/data/circuit_fri_config_canonical_small.json",
    ),
    (
        f"{VECTORS}/official/programs/simple_output_compiled.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/simple_output_compiled.json",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/leaf_preimage.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/leaf_preimage.json",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/leaf.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/leaf.json",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/root.proof",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root.proof",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/root_outputs.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root_outputs.json",
    ),
    (
        f"{VECTORS}/official/recursive_tree/four_leaves/root_packed.json",
        "crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root_packed.json",
    ),
)
MANAGED = (
    tuple(path for path, *_ in ORACLE_ARTIFACTS)
    + (MULTIVERIFIER_INPUTS,)
    + tuple(path for path, _ in VERIFY_VERDICTS)
    + tuple(path for path, _ in R11_VERDICTS)
    + tuple(path for path, *_ in ADAPTED_PROGRAMS)
    + tuple(path for path, *_ in CAIRO_PROOF_ARTIFACTS)
    + tuple(path for path, _ in UPSTREAM_COPIES)
)


def adapt_program_command(path: str, program: str, task: tuple | None = None) -> list[str]:
    """The recorded `adapt-program` invocation of an adapted ProverInput fixture."""
    program_input = ["--program-input", LEAF_BOOTLOADER_INPUT_PLACEHOLDER] if task else []
    return [
        "stwo-circuit-oracle",
        "adapt-program",
        "--proving-root",
        PROVING_ROOT_PLACEHOLDER,
        "--program",
        program,
        *program_input,
        "--output",
        path,
    ]


def multiverifier_inputs_command(
    path: str,
    proving_root: str = PROVING_ROOT_PLACEHOLDER,
    inputs_output: str = MULTIVERIFIER_INPUTS_FILE_PLACEHOLDER,
) -> list[str]:
    """The `multiverifier-inputs` invocation of the multiverifier input checkpoint."""
    return [
        "stwo-circuit-oracle",
        "multiverifier-inputs",
        "--proving-root",
        proving_root,
        "--inputs-output",
        inputs_output,
        "--output",
        path,
    ]


def verify_circuit_command(path: str, label: str, emit_dir: str = ZIG_EMIT_DIR_PLACEHOLDER) -> list[str]:
    """The `verify-circuit` invocation of a verdict on a Zig-emitted proof."""
    return [
        "stwo-circuit-oracle",
        "verify-circuit",
        "--proof",
        f"{emit_dir}/{label}.proof",
        "--request",
        f"{emit_dir}/{label}.request.json",
        "--output",
        path,
    ]


def cairo_proof_command(
    path: str, prover_input: str, registry: str, policy: str | None, proving_root: str = PROVING_ROOT_PLACEHOLDER
) -> list[str]:
    """The `prove-cairo` invocation of a leaf-lane Cairo proof fixture (recorded with the
    placeholder checkout; the generator passes the real one)."""
    override = ["--lifting-size-policy", policy] if policy else []
    return [
        "stwo-circuit-oracle",
        "prove-cairo",
        "--prover-input",
        prover_input,
        "--params",
        registry,
        "--proving-root",
        proving_root,
        *override,
        "--output",
        path,
    ]

INPUTS_DOMAIN = b"STWO_CIRCUIT_ORACLE_INPUTS_V1\0"


def lock_source(repository: str, revision: str) -> str:
    return f"git+{repository}?rev={revision}#{revision}"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def oracle_sources(root: Path) -> list[str]:
    """The files that determine the oracle binary, as sorted repository paths.

    Besides the oracle crate, the oracle compiles the shared evaluation-program ABI sources
    (`tools/stwo-eval-program-abi`) and trace digest source (`tools/stwo-trace-digest`) in with
    `#[path]`.
    """
    oracle = root / ORACLE
    files = [oracle / "Cargo.toml", oracle / "Cargo.lock", oracle / "rust-toolchain.toml"]
    files.extend(sorted((oracle / "src").rglob("*.rs")))
    files.extend(sorted((root / EVAL_PROGRAM_ABI / "src").rglob("*.rs")))
    files.extend(sorted((root / TRACE_DIGEST / "src").rglob("*.rs")))
    return sorted(path.relative_to(root).as_posix() for path in files)


def oracle_source_sha256(root: Path) -> str:
    """SHA-256 over `path NUL sha256 LF` lines of every oracle source, in path order."""
    lines = "".join(
        f"{path}\0{sha256_file(root / path)}\n" for path in oracle_sources(root)
    )
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def inputs_aggregate(records: list[dict]) -> str:
    """The oracle's aggregate digest of the upstream inputs it read (`src/upstream.rs`)."""
    digest = hashlib.sha256(INPUTS_DOMAIN)
    for record in sorted(records, key=lambda item: item["path"]):
        digest.update(record["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(struct.pack("<Q", record["bytes"]))
        digest.update(bytes.fromhex(record["sha256"]))
    return digest.hexdigest()


def _load_toml(root: Path, relative: str) -> tuple[dict | None, list[str]]:
    try:
        with (root / relative).open("rb") as handle:
            return tomllib.load(handle), []
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, [f"{relative}: unable to parse: {error}"]


def _check_manifest(root: Path, repository: str, revision: str, toolchain: str) -> list[str]:
    manifest, errors = _load_toml(root, MANIFEST)
    if manifest is None:
        return errors
    metadata = manifest.get("package", {}).get("metadata", {}).get(METADATA_TABLE, {})
    expected = {
        "checkpoint-schema": CHECKPOINT_SCHEMA,
        "proving-repository": repository,
        "proving-revision": revision,
        "rust-toolchain": toolchain,
    }
    errors = [
        f"{MANIFEST}: metadata {key!r} is {metadata.get(key)!r}, expected {value!r}"
        for key, value in expected.items()
        if metadata.get(key) != value
    ]
    pinned = 0
    for name, value in manifest.get("dependencies", {}).items():
        if isinstance(value, dict) and "path" in value:
            errors.append(f"{MANIFEST}: path dependency {name!r} is forbidden")
        if isinstance(value, dict) and "git" in value:
            pinned += 1
            if value.get("git") != repository or value.get("rev") != revision:
                errors.append(
                    f"{MANIFEST}: dependency {name!r} is {value.get('git')!r}@"
                    f"{value.get('rev')!r}, expected {repository!r}@{revision!r}"
                )
    if pinned == 0:
        errors.append(f"{MANIFEST}: no dependency on {repository}")
    for key in ("patch", "replace"):
        if key in manifest:
            errors.append(f"{MANIFEST}: [{key}] is forbidden")
    return errors


def _check_lock_and_toolchain(root: Path, repository: str, revision: str, toolchain: str) -> list[str]:
    lock, errors = _load_toml(root, LOCK)
    if lock is not None:
        sources = {
            package["source"]
            for package in lock.get("package", [])
            if isinstance(package.get("source"), str)
            and package["source"].startswith("git+")
        }
        if sources != {lock_source(repository, revision)}:
            errors.append(
                f"{LOCK}: git sources are {sorted(sources)!r}, expected only "
                f"{lock_source(repository, revision)!r}"
            )
    config, toolchain_errors = _load_toml(root, TOOLCHAIN)
    errors.extend(toolchain_errors)
    if config is not None and config.get("toolchain", {}).get("channel") != toolchain:
        errors.append(f"{TOOLCHAIN}: channel is not {toolchain!r}")
    try:
        source = (root / AUTHORITY_SOURCE).read_text(encoding="utf-8")
    except OSError as error:
        return errors + [f"{AUTHORITY_SOURCE}: unable to read: {error}"]
    for constant, value in (("PROVING_REPOSITORY", repository), ("PROVING_REVISION", revision)):
        line = f'pub const {constant}: &str = "{value}";'
        if source.count(f"pub const {constant}:") != 1 or line not in source:
            errors.append(f"{AUTHORITY_SOURCE}: {constant} is not {value!r}")
    return errors


def _check_checkpoint(root: Path, path: str, rung: str, subcommand: str, revision: str) -> list[str]:
    try:
        document = json.loads((root / path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{path}: unable to parse checkpoint: {error}"]
    expected = {
        "schema": CHECKPOINT_SCHEMA,
        "rung": rung,
        "subcommand": subcommand,
    }
    errors = [
        f"{path}: {key} is {document.get(key)!r}, expected {value!r}"
        for key, value in expected.items()
        if document.get(key) != value
    ]
    if document.get("authority", {}).get("revision") != revision:
        errors.append(f"{path}: authority revision is not {revision}")
    return errors


def _check_projection(root: Path, revision: str) -> list[str]:
    try:
        summary = parse_projection((root / PROJECTION).read_bytes())
        components = json.loads((root / COMPONENTS).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ProjectionError, UnicodeDecodeError) as error:
        return [f"{PROJECTION}: {error}"]
    errors = []
    if summary["revision"] != revision:
        errors.append(f"{PROJECTION}: revision is {summary['revision']!r}, expected {revision!r}")
    if summary["inputs_sha256"] != inputs_aggregate(components.get("inputs", [])):
        errors.append(f"{PROJECTION}: upstream inputs differ from {COMPONENTS}")
    body = components.get("body", {})
    slots = {
        "cairo": body.get("cairo_slots"),
        "circuit": body.get("circuit_components"),
    }
    for label, expected_slots in slots.items():
        source = summary["sources"].get(label)
        if source is None or source["slots"] != expected_slots:
            errors.append(f"{PROJECTION}: {label} slots differ from {COMPONENTS}")
    return errors


def _check_provenance(root: Path, repository: str, revision: str, toolchain: str) -> list[str]:
    try:
        provenance = json.loads((root / PROVENANCE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{PROVENANCE}: unable to parse: {error}"]
    errors = []
    if provenance.get("schema") != PROVENANCE_SCHEMA:
        errors.append(f"{PROVENANCE}: schema is not {PROVENANCE_SCHEMA}")
    if provenance.get("upstream") != {"repository": repository, "revision": revision}:
        errors.append(f"{PROVENANCE}: upstream is not {repository}@{revision}")
    oracle = provenance.get("oracle", {})
    if oracle.get("toolchain") != toolchain or oracle.get("manifest") != MANIFEST:
        errors.append(f"{PROVENANCE}: oracle manifest or toolchain drifted")
    if oracle.get("lock") != LOCK or oracle.get("lock_sha256") != _sha256_or_none(root / LOCK):
        errors.append(f"{PROVENANCE}: oracle lock digest drifted")
    # Provenance names only host-independent inputs: the toolchain, the lock and the sources.
    if "host" in provenance:
        errors.append(f"{PROVENANCE}: 'host' is host-dependent; provenance must not record it")
    if oracle.get("source_sha256") != oracle_source_sha256(root):
        errors.append(
            f"{PROVENANCE}: oracle source digest drifted; regenerate with "
            "scripts/generate_circuit_oracle_vectors.py"
        )
    artifacts = provenance.get("artifacts", [])
    by_path = {artifact.get("path"): artifact for artifact in artifacts}
    if len(by_path) != len(artifacts) or set(by_path) != set(MANAGED):
        errors.append(f"{PROVENANCE}: artifact set is not exactly {sorted(MANAGED)}")
    for path, artifact in by_path.items():
        if path not in MANAGED:
            continue
        try:
            data = (root / path).read_bytes()
        except OSError as error:
            errors.append(f"{path}: unable to read fixture: {error}")
            continue
        if artifact.get("bytes") != len(data) or artifact.get("sha256") != hashlib.sha256(data).hexdigest():
            errors.append(f"{path}: fixture bytes differ from {PROVENANCE}")
    for path, rung, subcommand, reads_upstream in ORACLE_ARTIFACTS:
        command = ["stwo-circuit-oracle", subcommand]
        if reads_upstream:
            command += ["--proving-root", PROVING_ROOT_PLACEHOLDER]
        artifact = by_path.get(path, {})
        if artifact.get("command") != command + ["--output", path]:
            errors.append(f"{path}: provenance command is not {command}")
        if path.endswith(".json"):
            errors.extend(_check_checkpoint(root, path, rung, subcommand, revision))
    for path, _rung, program, task in ADAPTED_PROGRAMS:
        command = adapt_program_command(path, program, task)
        if by_path.get(path, {}).get("command") != command:
            errors.append(f"{path}: provenance command is not {command}")
        if task:
            expected_input = leaf_bootloader_input(task, PROVING_ROOT_PLACEHOLDER, PREIMAGE_DUMP_PLACEHOLDER)
            if by_path.get(path, {}).get("program_input") != expected_input:
                errors.append(f"{path}: provenance program_input is not {expected_input}")
    for path, rung, prover_input, registry, policy in CAIRO_PROOF_ARTIFACTS:
        command = cairo_proof_command(path, prover_input, registry, policy)
        if by_path.get(path, {}).get("command") != command:
            errors.append(f"{path}: provenance command is not {command}")
        errors.extend(_check_checkpoint(root, path, rung, "prove-cairo", revision))
    if by_path.get(MULTIVERIFIER_INPUTS, {}).get("command") != multiverifier_inputs_command(MULTIVERIFIER_INPUTS):
        errors.append(f"{MULTIVERIFIER_INPUTS}: provenance command is not multiverifier-inputs")
    errors.extend(_check_checkpoint(root, MULTIVERIFIER_INPUTS, "r7", "multiverifier-inputs", revision))
    for path, label in VERIFY_VERDICTS:
        if by_path.get(path, {}).get("command") != verify_circuit_command(path, label):
            errors.append(f"{path}: provenance command is not verify-circuit on {label}")
        errors.extend(_check_checkpoint(root, path, "r7", "verify-circuit", revision))
    for path, label in R11_VERDICTS:
        command = verify_circuit_command(path, label, emit_dir=R11_EMIT_DIR_PLACEHOLDER)
        if by_path.get(path, {}).get("command") != command:
            errors.append(f"{path}: provenance command is not verify-circuit on {label}")
        errors.extend(_check_checkpoint(root, path, "r7", "verify-circuit", revision))
        try:
            accepted = json.loads((root / path).read_text(encoding="utf-8"))["body"]["accepted"]
        except (OSError, json.JSONDecodeError, KeyError) as error:
            errors.append(f"{path}: unable to read the verdict: {error}")
            continue
        if accepted != label.endswith("-none"):
            errors.append(f"{path}: upstream must accept exactly the untampered proofs")
    for path, upstream_path in UPSTREAM_COPIES:
        if by_path.get(path, {}).get("upstream_path") != upstream_path:
            errors.append(f"{path}: provenance upstream path is not {upstream_path}")
    present = {
        path.relative_to(root).as_posix()
        for path in (root / VECTORS).rglob("*")
        if path.is_file()
    }
    for unlisted in sorted(present - set(MANAGED) - {README, PROVENANCE}):
        errors.append(f"{unlisted}: fixture is not listed in {PROVENANCE}")
    return errors


def _sha256_or_none(path: Path) -> str | None:
    try:
        return sha256_file(path)
    except OSError:
        return None


def _check_upstream_copies(root: Path) -> list[str]:
    """Copies of files the oracle read must equal the bytes it recorded reading."""
    recorded: dict[str, str] = {}
    errors = []
    for path, _rung, _subcommand, reads_upstream in ORACLE_ARTIFACTS:
        if not reads_upstream or not path.endswith(".json"):
            continue
        try:
            checkpoint = json.loads((root / path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{path}: unable to parse: {error}")
            continue
        for record in checkpoint.get("inputs", []):
            if recorded.setdefault(record["path"], record["sha256"]) != record["sha256"]:
                errors.append(f"{path}: records {record['path']} with a different digest")
    for path, *_ in CAIRO_PROOF_ARTIFACTS:
        try:
            proof = json.loads((root / path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{path}: unable to parse: {error}")
            continue
        for record in proof.get("inputs", []):
            if recorded.setdefault(record["path"], record["sha256"]) != record["sha256"]:
                errors.append(f"{path}: records {record['path']} with a different digest")
    for path, upstream_path in UPSTREAM_COPIES:
        if upstream_path in recorded and (root / path).is_file():
            if sha256_file(root / path) != recorded[upstream_path]:
                errors.append(f"{path}: differs from the {upstream_path} the oracle read")
    return errors


def _check_air_programs(root: Path) -> list[str]:
    """The circuit AIR bundle: `STWZEVA/1` geometry and plan hash, as for the Cairo bundles."""
    try:
        encoded = (root / AIR_PROGRAMS).read_bytes()
        provenance = json.loads((root / PROVENANCE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{AIR_PROGRAMS}: {error}"]
    header = parse_bundle_header(encoded)
    if header is None:
        return [f"{AIR_PROGRAMS}: invalid AIR program header"]
    artifact = next(
        (item for item in provenance.get("artifacts", []) if item.get("path") == AIR_PROGRAMS),
        {},
    )
    errors = check_bundle_geometry(encoded, header, artifact, AIR_PROGRAMS)
    if artifact.get("format") != BUNDLE_FORMAT:
        errors.append(f"{AIR_PROGRAMS}: AIR program format drifted")
    if header["component_count"] != CIRCUIT_AIR_COMPONENTS:
        errors.append(
            f"{AIR_PROGRAMS}: {header['component_count']} components, "
            f"expected {CIRCUIT_AIR_COMPONENTS}"
        )
    return errors


def _registry_words(words: list[str]) -> list[int]:
    return [int(word, 16) for word in words]


def _check_topology(root: Path) -> list[str]:
    """The fold roots and hashes the oracle rebuilt equal the committed registry copies."""
    try:
        topology = json.loads((root / TOPOLOGY).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{TOPOLOGY}: unable to parse: {error}"]
    copies = {upstream_path: path for path, upstream_path in UPSTREAM_COPIES}
    errors = []
    folds = topology.get("body", {}).get("folds", [])
    if not folds:
        errors.append(f"{TOPOLOGY}: no fold records")
    for fold in folds:
        copy = copies.get(fold.get("registry"))
        if copy is None:
            errors.append(f"{TOPOLOGY}: registry {fold.get('registry')!r} has no committed copy")
            continue
        try:
            registry = json.loads((root / copy).read_text(encoding="utf-8"))
            (multiverifier,) = registry["multiverifiers"]
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as error:
            errors.append(f"{copy}: {error}")
            continue
        for key in ("preprocessed_root", "circuit_hash"):
            if fold.get(key) != _registry_words(multiverifier.get(key, [])):
                errors.append(f"{TOPOLOGY}: {copy} multiverifier {key} differs")
    return errors


def _zig_test_body(source: str, name: str) -> str | None:
    """The body of the Zig `test "<name>" { ... }` block (top-level, closed by `\n}`)."""
    start = source.find(f'test "{name}" {{')
    if start < 0:
        return None
    end = source.find("\n}", start)
    return None if end < 0 else source[start:end]


def _check_r0_fri_inline(root: Path) -> list[str]:
    """The Zig test's inlined R0 `fri` constants equal the committed `primitives.json` vector.

    The test pins, in order, the input digest and every per-fold output digest, the per-layer
    alphas and the last-layer value; regenerating the fixture with different FRI output without
    updating the test is rejected here rather than passing against stale constants.
    """
    try:
        fri = json.loads((root / PRIMITIVES).read_text(encoding="utf-8"))["body"]["fri"]
        source = (root / R0_FRI_ZIG_TEST).read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError, KeyError) as error:
        return [f"{R0_FRI_ZIG_TEST}: unable to compare with {PRIMITIVES}: {error}"]
    body = _zig_test_body(source, R0_FRI_ZIG_TEST_NAME)
    if body is None:
        return [f"{R0_FRI_ZIG_TEST}: missing test {R0_FRI_ZIG_TEST_NAME!r}"]
    errors = []
    expected_digests = [fri["input_sha256"]] + [
        fold["values_sha256"] for layer in fri["layers"] for fold in layer["folds"]
    ]
    if re.findall(r'"([0-9a-f]{64})"', body) != expected_digests:
        errors.append(f"{R0_FRI_ZIG_TEST}: inlined R0 fri digests differ from {PRIMITIVES}")
    quadruples = [
        [int(limb) for limb in match]
        for match in re.findall(
            r"QM31\.fromU32Unchecked\((\d+), (\d+), (\d+), (\d+)\)", body
        )
    ]
    expected_quadruples = [layer["layer_alpha"] for layer in fri["layers"]] + [fri["last_layer"]]
    if quadruples != expected_quadruples:
        errors.append(
            f"{R0_FRI_ZIG_TEST}: inlined R0 fri alphas or last layer differ from {PRIMITIVES}"
        )
    for key, pattern in (("log_size", r"const log_size: u32 = (\d+);"),):
        match = re.search(pattern, body)
        if match is None or int(match.group(1)) != fri[key]:
            errors.append(f"{R0_FRI_ZIG_TEST}: inlined R0 fri {key} differs from {PRIMITIVES}")
    return errors


def check(root: Path, *, repository: str, revision: str, toolchain: str) -> list[str]:
    errors = _check_manifest(root, repository, revision, toolchain)
    errors.extend(_check_lock_and_toolchain(root, repository, revision, toolchain))
    errors.extend(_check_provenance(root, repository, revision, toolchain))
    errors.extend(_check_projection(root, revision))
    errors.extend(_check_upstream_copies(root))
    errors.extend(_check_air_programs(root))
    errors.extend(_check_topology(root))
    errors.extend(_check_r0_fri_inline(root))
    return errors
