"""Validation and reconstruction of committed Sail evidence."""

from __future__ import annotations

import re
from pathlib import Path

from . import codec, sail_lean_bridge, sail_translation
from .model import (
    Paths,
    RefinementError,
    SAIL_REPOSITORY,
    SAIL_REVISION,
    SAIL_VERSION,
)
from .sail_contract import (
    BASE_CONFIGURATION,
    CARRIED_EVIDENCE,
    CARRIED_INPUTS,
    COMMITTED_CAPSULE,
    COMMITTED_CONFIGURATION,
    COMMITTED_DEFINITIONS,
    COMMITTED_MONAD_BRIDGE_RECEIPT,
    COMMITTED_TRANSLATION_RECEIPT,
    EXACT_CONFIGURATION,
    GENERATED_DEFINITION_HASHES,
    GENERATED_FILE,
    LEGACY_NORMALIZATION,
    LIVE_EVIDENCE,
    MODEL_ENTRY,
    NORMALIZATION,
    SOURCE_FILE,
    SOURCE_SLICE_HASHES,
    SailEvidence,
    _extract_definition,
    _profile,
    _translation_receipt,
    _validate_semantic_shapes,
    _verify_translation_receipt,
)

def _carried_digest(carried: dict[str, object], key: str) -> str:
    value = carried.get(key)
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RefinementError(
            f"committed Sail provenance {key} is not a sha256 digest"
        )
    return value


def _carried_base_pins(carried: dict[str, object]) -> None:
    """Check immutable provenance shared by normal reuse and capture."""
    pinned: dict[str, object] = {
        "repository": SAIL_REPOSITORY,
        "revision": SAIL_REVISION,
        "compiler_version": SAIL_VERSION,
        "architectural_profile": "rv32im-zkvm-v1",
        "validated_isa_string": "rv32im",
        "model_entry": MODEL_ENTRY.as_posix(),
        "base_configuration": BASE_CONFIGURATION.as_posix(),
        "exact_configuration": EXACT_CONFIGURATION.as_posix(),
        "source_file": SOURCE_FILE.as_posix(),
        "generated_backend_file": GENERATED_FILE.as_posix(),
        "generated_definition_sha256": GENERATED_DEFINITION_HASHES,
        "source_slice_sha256": SOURCE_SLICE_HASHES,
    }
    for key, expected in pinned.items():
        if carried.get(key) != expected:
            raise RefinementError(
                f"committed Sail provenance {key} does not match the pin in "
                f"scripts/riscv_refinement_lib/sail.py: "
                f"{carried.get(key)!r} != {expected!r}"
            )
    if carried.get("checkout_state") not in ("clean", "rvfi-transport-patch-only"):
        raise RefinementError(
            "committed Sail provenance names an unknown checkout state"
        )
    if carried.get("evidence_source", LIVE_EVIDENCE) not in (
        LIVE_EVIDENCE,
        CARRIED_EVIDENCE,
    ):
        raise RefinementError(
            "committed Sail provenance names an unknown evidence source"
        )


def _carried_pins(carried: dict[str, object]) -> None:
    """Every reusable field is pinned or re-derived, never trusted from JSON."""
    _carried_base_pins(carried)
    pinned: dict[str, object] = {
        "normalization": NORMALIZATION,
        "generated_monad_normalization_theorem": True,
        "generated_step_loop_framing_theorem": False,
    }
    for key, expected in pinned.items():
        if carried.get(key) != expected:
            raise RefinementError(
                f"committed Sail provenance {key} does not match the pin in "
                f"scripts/riscv_refinement_lib/sail.py: "
                f"{carried.get(key)!r} != {expected!r}"
            )
    translation = carried.get("generated_ast_translation_receipt")
    if (
        not isinstance(translation, dict)
        or translation.get("artifact")
        != COMMITTED_TRANSLATION_RECEIPT.as_posix()
        or translation.get("schema_version")
        != sail_translation.SCHEMA_VERSION
        or translation.get("parser_version")
        != sail_translation.PARSER_VERSION
    ):
        raise RefinementError(
            "committed Sail provenance translation receipt does not match "
            "the pinned artifact/schema/parser"
        )
    bridge = carried.get("generated_monad_bridge_receipt")
    if (
        not isinstance(bridge, dict)
        or bridge.get("artifact")
        != COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()
        or bridge.get("schema_version")
        != sail_lean_bridge.SCHEMA_VERSION
    ):
        raise RefinementError(
            "committed Sail provenance monad bridge receipt does not match "
            "the pinned artifact/schema"
        )


def _carried_inputs(paths: Paths, carried: dict[str, object]) -> dict[str, str]:
    """Re-hash every Sail input the committed provenance names in this repo."""
    digests = carried.get("profile_file_sha256")
    expected = {relative.as_posix() for relative in CARRIED_INPUTS}
    if not isinstance(digests, dict) or set(digests) != expected:
        raise RefinementError(
            "committed Sail provenance names an unexpected profile input set"
        )
    rehashed: dict[str, str] = {}
    for relative in CARRIED_INPUTS:
        path = paths.root / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(
                f"{relative.as_posix()}: Sail input named by the committed "
                "provenance is absent; reused evidence cannot be checked"
            )
        actual = codec.sha256_file(path)
        if actual != digests[relative.as_posix()]:
            raise RefinementError(
                f"{relative.as_posix()}: Sail input changed since the committed "
                f"provenance ({actual} != {digests[relative.as_posix()]}); "
                "re-derive the evidence with the live Sail toolchain"
            )
        rehashed[relative.as_posix()] = actual
    return rehashed


def _carried_configuration(
    paths: Paths,
    manifest: dict[str, object],
    carried: dict[str, object],
) -> bytes:
    """The reused exact configuration is the committed artifact, byte for byte."""
    path = paths.formal / COMMITTED_CONFIGURATION
    if path.is_symlink() or not path.is_file():
        raise RefinementError(
            f"{COMMITTED_CONFIGURATION.as_posix()}: committed exact Sail "
            "configuration is absent; reused evidence cannot be checked"
        )
    configuration = path.read_bytes()
    digest = codec.sha256_bytes(configuration)
    if digest != _carried_digest(carried, "exact_configuration_sha256"):
        raise RefinementError(
            f"{COMMITTED_CONFIGURATION.as_posix()}: committed exact Sail "
            "configuration does not match the committed provenance digest"
        )
    artifacts = manifest.get("artifacts")
    if (
        not isinstance(artifacts, dict)
        or artifacts.get(COMMITTED_CONFIGURATION.as_posix()) != digest
    ):
        raise RefinementError(
            f"{COMMITTED_CONFIGURATION.as_posix()}: committed manifest artifact "
            "digest does not match the committed exact Sail configuration"
        )
    return configuration


def _carried_translation(
    paths: Paths,
    manifest: dict[str, object],
) -> tuple[dict[str, str], dict[str, object]]:
    """Re-hash definition slices and re-derive their checked receipt."""
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RefinementError(
            "committed manifest has no generated artifact digest map"
        )
    definitions: dict[str, str] = {}
    for name, relative in COMMITTED_DEFINITIONS.items():
        path = paths.formal / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(
                f"{relative.as_posix()}: committed generated Sail definition "
                "slice is absent; reused evidence cannot be checked"
            )
        try:
            definitions[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RefinementError(
                f"{relative.as_posix()}: generated Sail definition is unreadable"
            ) from exc
        digest = codec.sha256_bytes(definitions[name].encode("utf-8"))
        if (
            digest != GENERATED_DEFINITION_HASHES[name]
            or artifacts.get(relative.as_posix()) != digest
        ):
            raise RefinementError(
                f"{relative.as_posix()}: generated Sail definition digest "
                "does not match the pinned backend and manifest"
            )
    receipt_path = paths.formal / COMMITTED_TRANSLATION_RECEIPT
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise RefinementError(
            f"{COMMITTED_TRANSLATION_RECEIPT.as_posix()}: committed Sail "
            "translation receipt is absent; reused evidence cannot be checked"
        )
    receipt = codec.load_json(receipt_path)
    if receipt_path.read_bytes() != codec.pretty_bytes(receipt):
        raise RefinementError(
            f"{COMMITTED_TRANSLATION_RECEIPT.as_posix()}: committed Sail "
            "translation receipt is not canonical pretty JSON"
        )
    digest = codec.sha256_file(receipt_path)
    if artifacts.get(COMMITTED_TRANSLATION_RECEIPT.as_posix()) != digest:
        raise RefinementError(
            f"{COMMITTED_TRANSLATION_RECEIPT.as_posix()}: translation receipt "
            "digest does not match the committed manifest"
        )
    return definitions, _verify_translation_receipt(receipt, definitions)


def _carried_monad_bridge(
    paths: Paths,
    manifest: dict[str, object],
    generated_backend_sha256: str,
) -> dict[str, object]:
    """Validate the committed cross-project Lean proof receipt."""
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RefinementError(
            "committed manifest has no generated artifact digest map"
        )
    receipt_path = paths.formal / COMMITTED_MONAD_BRIDGE_RECEIPT
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise RefinementError(
            f"{COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()}: committed "
            "generated Sail monad bridge receipt is absent"
        )
    receipt = codec.load_json(receipt_path)
    if receipt_path.read_bytes() != codec.pretty_bytes(receipt):
        raise RefinementError(
            f"{COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()}: committed "
            "generated Sail monad bridge receipt is not canonical pretty JSON"
        )
    digest = codec.sha256_file(receipt_path)
    if artifacts.get(COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()) != digest:
        raise RefinementError(
            f"{COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()}: monad bridge "
            "receipt digest does not match the committed manifest"
        )
    return sail_lean_bridge.validate_carried(
        paths,
        receipt,
        generated_backend_sha256,
    )


def _render_capsule(evidence: SailEvidence) -> bytes:
    from . import render  # deferred: render imports this module at load time

    definitions = evidence.translation_receipt["definitions"]
    return (
        render.SAIL_LEAN_TEMPLATE.replace(
            "__UTYPE_DIGEST__",
            evidence.definition_hashes["execute_UTYPE"],
        )
        .replace(
            "__ITYPE_DIGEST__",
            evidence.definition_hashes["execute_ITYPE"],
        )
        .replace(
            "__RTYPE_DIGEST__",
            evidence.definition_hashes["execute_RTYPE"],
        )
        .replace(
            "__TRANSLATION_RECEIPT_DIGEST__",
            str(evidence.translation_receipt["canonical_digest"]),
        )
        .replace(
            "__UTYPE_AST_DIGEST__",
            str(definitions["execute_UTYPE"]["ast_sha256"]),
        )
        .replace(
            "__ITYPE_AST_DIGEST__",
            str(definitions["execute_ITYPE"]["ast_sha256"]),
        )
        .replace(
            "__RTYPE_AST_DIGEST__",
            str(definitions["execute_RTYPE"]["ast_sha256"]),
        )
        .encode("utf-8")
    )


def _refuse_minting_sail_artifacts(paths: Paths, evidence: SailEvidence) -> None:
    """Reused evidence may reproduce the Sail artifacts and nothing else."""
    rendered_artifacts = {
        COMMITTED_CONFIGURATION: evidence.exact_configuration,
        COMMITTED_CAPSULE: _render_capsule(evidence),
        COMMITTED_TRANSLATION_RECEIPT:
            codec.pretty_bytes(evidence.translation_receipt),
        COMMITTED_MONAD_BRIDGE_RECEIPT:
            codec.pretty_bytes(evidence.monad_bridge_receipt),
        **{
            relative: evidence.definition_slices[name].encode("utf-8")
            for name, relative in COMMITTED_DEFINITIONS.items()
        },
    }
    for relative, rendered in rendered_artifacts.items():
        path = paths.formal / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(
                f"{relative.as_posix()}: committed Sail artifact is absent; "
                "reused evidence can only reproduce existing Sail output"
            )
        if path.read_bytes() != rendered:
            raise RefinementError(
                f"{relative.as_posix()}: reusing the committed Sail evidence "
                "would rewrite this artifact; only the live Sail toolchain may "
                "mint new Sail output"
            )


def capture_pinned_generated_evidence(
    paths: Paths,
    generated_file: Path,
) -> SailEvidence:
    """Capture slices from the exact backend already bound by the manifest.

    This is a narrow bootstrap for adding translation artifacts to an older
    committed manifest. It does not run Sail and therefore remains carried
    evidence: the supplied backend must be byte-identical to the backend digest
    previously minted by a live pinned-toolchain run.
    """
    manifest = codec.load_json(paths.manifest)
    if (
        manifest.get("kind") != "stwo-riscv-refinement-generated-manifest"
        or manifest.get("canonical_digest") != codec.content_digest(manifest)
    ):
        raise RefinementError(
            "committed refinement manifest identity is invalid; exact backend "
            "slices cannot be captured"
        )
    carried = manifest.get("sail")
    if not isinstance(carried, dict):
        raise RefinementError(
            "committed refinement manifest has no Sail provenance block"
        )
    _carried_base_pins(carried)
    if (
        carried.get("normalization") not in {
            LEGACY_NORMALIZATION,
            NORMALIZATION,
        }
        or not isinstance(
            carried.get("generated_monad_normalization_theorem"),
            bool,
        )
    ):
        raise RefinementError(
            "committed Sail normalization boundary is not eligible for "
            "translation-artifact capture"
        )
    profile_file_sha256 = _carried_inputs(paths, carried)
    _profile(paths.root)
    configuration = _carried_configuration(paths, manifest, carried)
    generated = generated_file.resolve()
    if generated_file.is_symlink() or not generated.is_file():
        raise RefinementError(
            "translation capture requires a regular generated backend file"
        )
    expected_backend_digest = _carried_digest(
        carried,
        "generated_backend_file_sha256",
    )
    actual_backend_digest = codec.sha256_file(generated)
    if actual_backend_digest != expected_backend_digest:
        raise RefinementError(
            "supplied generated Sail backend does not match the backend "
            f"already bound by the committed manifest "
            f"({actual_backend_digest} != {expected_backend_digest})"
        )
    try:
        generated_text = generated.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RefinementError(
            "supplied generated Sail backend is unreadable"
        ) from exc
    definitions = {
        name: _extract_definition(generated_text, name)
        for name in GENERATED_DEFINITION_HASHES
    }
    definition_hashes = {
        name: codec.sha256_bytes(text.encode("utf-8"))
        for name, text in definitions.items()
    }
    if definition_hashes != GENERATED_DEFINITION_HASHES:
        raise RefinementError(
            "supplied backend definitions do not match the pinned hashes"
        )
    _validate_semantic_shapes(definitions)
    translation_receipt = _translation_receipt(definitions)
    monad_bridge_receipt = sail_lean_bridge.verify(
        paths,
        generated,
        actual_backend_digest,
    )
    return SailEvidence(
        source_root=None,
        compiler=None,
        compiler_sha256=None,
        simulator_sha256=None,
        generated_file=generated,
        generated_file_sha256=actual_backend_digest,
        source_file_sha256=_carried_digest(carried, "source_file_sha256"),
        model_entry_sha256=_carried_digest(carried, "model_entry_sha256"),
        base_configuration_sha256=_carried_digest(
            carried,
            "base_configuration_sha256",
        ),
        exact_configuration=configuration,
        exact_configuration_sha256=codec.sha256_bytes(configuration),
        profile_file_sha256=profile_file_sha256,
        checkout_state=str(carried["checkout_state"]),
        definition_hashes=definition_hashes,
        definition_slices=definitions,
        source_slice_hashes=dict(SOURCE_SLICE_HASHES),
        translation_receipt=translation_receipt,
        monad_bridge_receipt=monad_bridge_receipt,
        evidence_source=CARRIED_EVIDENCE,
    )


def carried_evidence(paths: Paths) -> SailEvidence:
    """Rebuild the Sail evidence from committed provenance, never from a tool.

    Nothing here can invent Sail output. Every field is either pinned in this
    module, re-hashed from a file in this repository, or copied verbatim out of
    the committed manifest and then required to round-trip back to it; and
    every Sail artifact must already exist with exactly the reproduced bytes.
    The result is labelled `carried-committed-sail-evidence` in the manifest and
    is refused by `toolchain`, so no release receipt can rest on it.
    """
    manifest = codec.load_json(paths.manifest)
    if (
        manifest.get("kind") != "stwo-riscv-refinement-generated-manifest"
        or manifest.get("canonical_digest") != codec.content_digest(manifest)
    ):
        raise RefinementError(
            "committed refinement manifest identity is invalid; its Sail "
            "provenance cannot be reused"
        )
    carried = manifest.get("sail")
    if not isinstance(carried, dict):
        raise RefinementError(
            "committed refinement manifest has no Sail provenance block"
        )
    _carried_pins(carried)
    profile_file_sha256 = _carried_inputs(paths, carried)
    _profile(paths.root)
    configuration = _carried_configuration(paths, manifest, carried)
    definitions, translation_receipt = _carried_translation(paths, manifest)
    generated_backend_sha256 = _carried_digest(
        carried,
        "generated_backend_file_sha256",
    )
    monad_bridge_receipt = _carried_monad_bridge(
        paths,
        manifest,
        generated_backend_sha256,
    )
    evidence = SailEvidence(
        source_root=None,
        compiler=None,
        compiler_sha256=None,
        simulator_sha256=None,
        generated_file=None,
        generated_file_sha256=generated_backend_sha256,
        source_file_sha256=_carried_digest(carried, "source_file_sha256"),
        model_entry_sha256=_carried_digest(carried, "model_entry_sha256"),
        base_configuration_sha256=_carried_digest(
            carried,
            "base_configuration_sha256",
        ),
        exact_configuration=configuration,
        exact_configuration_sha256=codec.sha256_bytes(configuration),
        profile_file_sha256=profile_file_sha256,
        checkout_state=str(carried["checkout_state"]),
        definition_hashes=dict(GENERATED_DEFINITION_HASHES),
        definition_slices=definitions,
        source_slice_hashes=dict(SOURCE_SLICE_HASHES),
        translation_receipt=translation_receipt,
        monad_bridge_receipt=monad_bridge_receipt,
        evidence_source=CARRIED_EVIDENCE,
    )
    reconstructed = provenance(evidence)
    reconstructed.pop("evidence_source")
    if reconstructed != {
        key: value for key, value in carried.items() if key != "evidence_source"
    }:
        raise RefinementError(
            "reused Sail evidence does not reproduce the committed provenance "
            "block; re-derive it with the live Sail toolchain"
        )
    _refuse_minting_sail_artifacts(paths, evidence)
    return evidence


def provenance(evidence: SailEvidence) -> dict[str, object]:
    return {
        "repository": SAIL_REPOSITORY,
        "revision": SAIL_REVISION,
        "checkout_state": evidence.checkout_state,
        "compiler_version": SAIL_VERSION,
        "architectural_profile": "rv32im-zkvm-v1",
        "profile_file_sha256": evidence.profile_file_sha256,
        "model_entry": MODEL_ENTRY.as_posix(),
        "model_entry_sha256": evidence.model_entry_sha256,
        "base_configuration": BASE_CONFIGURATION.as_posix(),
        "base_configuration_sha256": evidence.base_configuration_sha256,
        "exact_configuration": EXACT_CONFIGURATION.as_posix(),
        "exact_configuration_sha256": evidence.exact_configuration_sha256,
        "validated_isa_string": "rv32im",
        "source_file": SOURCE_FILE.as_posix(),
        "source_file_sha256": evidence.source_file_sha256,
        "generated_backend_file": GENERATED_FILE.as_posix(),
        "generated_backend_file_sha256": evidence.generated_file_sha256,
        "generated_definition_sha256": evidence.definition_hashes,
        "source_slice_sha256": evidence.source_slice_hashes,
        "normalization": NORMALIZATION,
        "generated_ast_translation_receipt": {
            "artifact": COMMITTED_TRANSLATION_RECEIPT.as_posix(),
            "schema_version": sail_translation.SCHEMA_VERSION,
            "parser_version": sail_translation.PARSER_VERSION,
            "canonical_digest":
                evidence.translation_receipt["canonical_digest"],
            "definition_ast_sha256": {
                name: evidence.translation_receipt["definitions"][name][
                    "ast_sha256"
                ]
                for name in sorted(GENERATED_DEFINITION_HASHES)
            },
        },
        "generated_monad_bridge_receipt": {
            "artifact": COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix(),
            "schema_version": sail_lean_bridge.SCHEMA_VERSION,
            "canonical_digest":
                evidence.monad_bridge_receipt["canonical_digest"],
            "theorems": evidence.monad_bridge_receipt["theorems"],
            "claim_boundary":
                evidence.monad_bridge_receipt["claim_boundary"],
        },
        "generated_monad_normalization_theorem": True,
        "generated_step_loop_framing_theorem": False,
        "evidence_source": evidence.evidence_source,
    }


def toolchain(evidence: SailEvidence) -> dict[str, object]:
    """Platform-local binaries recorded in the receipt, not portable inputs."""
    if evidence.evidence_source != LIVE_EVIDENCE:
        raise RefinementError(
            "the semantic toolchain record requires live Sail evidence; "
            f"{evidence.evidence_source} carries no compiler or simulator digest"
        )
    return {
        "compiler": {
            "version": SAIL_VERSION,
            "sha256": evidence.compiler_sha256,
        },
        "simulator": {
            "sha256": evidence.simulator_sha256,
        },
    }
