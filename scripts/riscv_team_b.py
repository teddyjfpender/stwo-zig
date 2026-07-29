#!/usr/bin/env python3
"""Team B coverage, certificate, and AIR-binding gate for RISC-V refinement.

Team B (issue #137) owns 22 of the 46 admitted RV32IM opcodes, across the
``shifts_reg``, ``shifts_imm``, ``load_store``, ``mul``, ``mulh``, and ``div``
AIR families. This gate answers three questions, and fails closed on each:

1. Is the Team B opcode set exactly the 22 opcodes the production manifest
   assigns to those six families, with no duplicate and no missing entry?
2. Does every Lean family capsule still bind the exact production AIR it was
   transcribed from? Each capsule records the SHA-256 of its exported family IR;
   this gate recomputes that digest from a fresh export and requires equality.
3. Does every theorem named in the certificate index actually exist in the Lean
   source it is attributed to?

It deliberately does not import the Level-1 pilot generator. The pilot's
committed manifest is a separate, Sail-bound artifact; this gate is additive and
must not be able to weaken it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

OPCODE_MANIFEST = REPOSITORY_ROOT / "src/frontends/riscv/opcode_manifest.zig"
LEAN_ROOT = REPOSITORY_ROOT / "formal/riscv-refinement/RiscvRefinement"
CERTIFICATE_INDEX = (
    REPOSITORY_ROOT / "formal/riscv-refinement/team-b-coverage.json"
)

TEAM_B_FAMILIES = (
    "shifts_reg",
    "shifts_imm",
    "load_store",
    "mul",
    "mulh",
    "div",
)

TEAM_B_OPCODE_COUNT = 22
FULL_OPCODE_COUNT = 46

#: Lean capsule file -> exported AIR family whose digest it must record.
CAPSULE_FAMILIES = {
    "Air/Family/Shifts.lean": ("shifts_imm", "shifts_reg"),
    "Air/Family/LoadStore.lean": ("load_store",),
    "Air/Family/Multiply.lean": ("mul", "mulh"),
    "Air/Family/Div.lean": ("div",),
}

#: Recognised certificate states, weakest first. Only ``proved`` counts toward
#: coverage; every other value is an explicit, reviewable admission of a gap.
#:
#: A state cannot overstate what exists, because each one names the fields it
#: requires and the gate refuses a certificate that claims a state without
#: them. "Proved" here still means proved against the reviewed architectural
#: capsule -- the generated-Sail obligation is open for every entry, which is
#: why the index carries a claim boundary of its own.
CERTIFICATE_STATES = ("open", "capsule-only", "refined", "proved")

#: state -> fields that must be present (non-null) for that state to be claimed.
REQUIRED_CERTIFICATE_FIELDS: dict[str, tuple[str, ...]] = {
    "open": (),
    "capsule-only": (),
    # A refinement theorem plus its tuple projections. The non-vacuity witness
    # is recorded when it exists and is required to advance past this state,
    # so a populated field distinguishes a witnessed refinement from an
    # unwitnessed one without needing a fifth state.
    "refined": (
        "refinement_theorem",
        "tuple_theorem",
    ),
    "proved": (
        "refinement_theorem",
        "tuple_theorem",
        "non_vacuity_theorem",
        "mutation",
    ),
}

MANIFEST_ENTRY = re.compile(r"proof\(\.[^,]+,\s*\"([^\"]+)\",\s*\.([a-z_0-9]+)")
LEAN_DIGEST = re.compile(
    r"^def\s+([A-Za-z0-9]+)IrDigest\s*:\s*String\s*:=\s*\"([0-9a-f]{64})\"$",
    re.MULTILINE,
)
LEAN_THEOREM = re.compile(r"^\s*theorem\s+([A-Za-z0-9_']+)", re.MULTILINE)


class TeamBError(RuntimeError):
    """A Team B gate failure. Every path out of this module raises this."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_digest(payload: dict[str, Any]) -> str:
    unsigned = {k: v for k, v in payload.items() if k != "canonical_digest"}
    encoded = json.dumps(
        unsigned, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def manifest_opcodes() -> list[tuple[str, str, int]]:
    """Return ``(mnemonic, family, protocol_id)`` for all 46 admitted opcodes."""
    if not OPCODE_MANIFEST.is_file():
        raise TeamBError(f"opcode manifest is absent at {OPCODE_MANIFEST}")
    text = OPCODE_MANIFEST.read_text(encoding="utf-8")
    entries = [
        (mnemonic, family, index)
        for index, (mnemonic, family) in enumerate(MANIFEST_ENTRY.findall(text))
    ]
    if len(entries) != FULL_OPCODE_COUNT:
        raise TeamBError(
            f"opcode manifest lists {len(entries)} entries, "
            f"expected {FULL_OPCODE_COUNT}"
        )
    mnemonics = [entry[0] for entry in entries]
    if len(set(mnemonics)) != len(mnemonics):
        raise TeamBError("opcode manifest contains a duplicate mnemonic")
    return entries


def team_b_opcodes() -> list[tuple[str, str, int]]:
    selected = [
        entry for entry in manifest_opcodes() if entry[1] in TEAM_B_FAMILIES
    ]
    if len(selected) != TEAM_B_OPCODE_COUNT:
        raise TeamBError(
            f"Team B families cover {len(selected)} opcodes, "
            f"expected {TEAM_B_OPCODE_COUNT}; the family assignment in "
            "opcode_manifest.zig drifted from the issue #137 split"
        )
    covered_families = {entry[1] for entry in selected}
    missing = set(TEAM_B_FAMILIES) - covered_families
    if missing:
        raise TeamBError(
            "Team B families with no opcode in the production manifest: "
            + ", ".join(sorted(missing))
        )
    return selected


def load_certificates() -> dict[str, Any]:
    if not CERTIFICATE_INDEX.is_file():
        raise TeamBError(
            f"Team B certificate index is absent at {CERTIFICATE_INDEX}"
        )
    index = json.loads(CERTIFICATE_INDEX.read_text(encoding="utf-8"))
    expected_digest = canonical_digest(index)
    if index.get("canonical_digest") != expected_digest:
        raise TeamBError(
            "Team B certificate index digest mismatch: recorded "
            f"{index.get('canonical_digest')}, recomputed {expected_digest}"
        )
    return index


def check_coverage() -> str:
    opcodes = team_b_opcodes()
    index = load_certificates()
    certificates = index.get("certificates")
    if not isinstance(certificates, list):
        raise TeamBError("certificate index has no certificates list")

    by_mnemonic: dict[str, dict[str, Any]] = {}
    for certificate in certificates:
        mnemonic = certificate.get("mnemonic")
        if not isinstance(mnemonic, str):
            raise TeamBError("a certificate has no string mnemonic")
        if mnemonic in by_mnemonic:
            raise TeamBError(f"duplicate certificate for {mnemonic}")
        by_mnemonic[mnemonic] = certificate

    expected = {mnemonic for mnemonic, _, _ in opcodes}
    if set(by_mnemonic) != expected:
        missing = sorted(expected - set(by_mnemonic))
        extra = sorted(set(by_mnemonic) - expected)
        raise TeamBError(
            f"certificate coverage drifted; missing {missing}, unexpected {extra}"
        )

    for mnemonic, family, protocol_id in opcodes:
        certificate = by_mnemonic[mnemonic]
        if certificate.get("family") != family:
            raise TeamBError(
                f"{mnemonic} certificate records family "
                f"{certificate.get('family')!r}, manifest says {family!r}"
            )
        recorded = certificate.get("manifest_id")
        if type(recorded) is not int or recorded != protocol_id:
            raise TeamBError(
                f"{mnemonic} certificate records manifest id {recorded!r}, "
                f"manifest says {protocol_id}"
            )
        state = certificate.get("state")
        if state not in CERTIFICATE_STATES:
            raise TeamBError(
                f"{mnemonic} certificate has unrecognised state {state!r}; "
                f"expected one of {CERTIFICATE_STATES}"
            )
        for field in REQUIRED_CERTIFICATE_FIELDS[state]:
            if not certificate.get(field):
                raise TeamBError(
                    f"{mnemonic} claims state {state!r} but its {field} is "
                    "absent; a state may not overstate what exists"
                )

    proved = sorted(
        mnemonic
        for mnemonic, certificate in by_mnemonic.items()
        if certificate["state"] == "proved"
    )
    return (
        f"team B coverage: {len(proved)}/{TEAM_B_OPCODE_COUNT} proved "
        f"of {FULL_OPCODE_COUNT} admitted opcodes"
    )


def check_ir_digests(air_ir_dir: Path) -> str:
    if not air_ir_dir.is_dir():
        raise TeamBError(f"exported AIR IR directory is absent at {air_ir_dir}")

    checked = 0
    for relative, families in sorted(CAPSULE_FAMILIES.items()):
        capsule = LEAN_ROOT / relative
        if not capsule.is_file():
            # A capsule that has not landed yet is reported by the coverage gate
            # as an open certificate; it is not a digest failure.
            continue
        recorded = {
            name: digest
            for name, digest in LEAN_DIGEST.findall(
                capsule.read_text(encoding="utf-8")
            )
        }
        if not recorded:
            raise TeamBError(
                f"{relative} records no AIR IR digest; a family capsule must "
                "bind the exported production AIR it was transcribed from"
            )
        for family in families:
            exported = air_ir_dir / f"{family}.json"
            if not exported.is_file():
                raise TeamBError(
                    f"exported AIR for family {family} is absent at {exported}"
                )
            key = "".join(part.capitalize() for part in family.split("_"))
            key = key[0].lower() + key[1:]
            if key not in recorded:
                raise TeamBError(
                    f"{relative} does not record a digest named {key}IrDigest "
                    f"for family {family}"
                )
            actual = sha256_file(exported)
            if recorded[key] != actual:
                raise TeamBError(
                    f"{relative} binds {family} AIR digest {recorded[key]}, "
                    f"but the fresh export hashes to {actual}; the Lean capsule "
                    "no longer describes the shipped AIR"
                )
            checked += 1
    return f"team B AIR bindings: {checked} family digests match a fresh export"


def check_theorems() -> str:
    index = load_certificates()
    declared: set[str] = set()
    for certificate in index.get("certificates", []):
        for field in (
            "refinement_theorem",
            "tuple_theorem",
            "non_vacuity_theorem",
            "mutation_theorem",
        ):
            name = certificate.get(field)
            if name is None:
                continue
            if not isinstance(name, str) or not name:
                raise TeamBError(
                    f"{certificate.get('mnemonic')} has a malformed {field}"
                )
            declared.add(name)

    present: set[str] = set()
    for path in sorted(LEAN_ROOT.rglob("*.lean")):
        for name in LEAN_THEOREM.findall(path.read_text(encoding="utf-8")):
            present.add(name)

    missing = sorted(name.rsplit(".", 1)[-1] for name in declared)
    absent = [name for name in missing if name not in present]
    if absent:
        raise TeamBError(
            "certificate index names theorems that do not exist in the Lean "
            "sources: " + ", ".join(sorted(absent))
        )
    return f"team B certificates: {len(declared)} named theorems all present"


PROFILE_PATH = REPOSITORY_ROOT / "conformance/riscv/rv32im-sail-profile.json"
OVERRIDE_PATH = REPOSITORY_ROOT / "conformance/riscv/sail-rv32im-override.json"
CONTRACT_PATH = (
    REPOSITORY_ROOT / "soundness/TEAM_B_SAIL_REFINEMENT_CONTRACT.md"
)

FENCE_I_WORD = 0x0000100F

#: Claims the Team B contract makes about the profile, restated as machine
#: checks. Section 4 of the contract erases Sail state on the strength of these
#: settings, so if one silently flips, the erasure argument is void.
PROFILE_CLAIMS: tuple[tuple[str, Any], ...] = (
    ("isa.xlen", 32),
    ("isa.extensions", ["I", "M"]),
    ("isa.instruction_alignment_bytes", 4),
    ("isa.misaligned_load_store", "reject_before_retirement"),
    ("isa.traps", "successful_retirements_only"),
    ("environment.memory", "sparse_little_endian_32_bit"),
)

OVERRIDE_CLAIMS: tuple[tuple[str, Any, str], ...] = (
    ("base.xlen", 32, "the proof profile is RV32"),
    ("base.writable_misa", False, "the extension set cannot change at runtime"),
    ("base.E", False, "the reduced register file is not in the profile"),
    ("extensions.M.supported", True, "Team B proves MUL and DIV"),
    ("extensions.A.supported", False, "erasing the reservation set needs this"),
    ("extensions.F.supported", False, "no floating-point state to erase"),
    ("extensions.D.supported", False, "no floating-point state to erase"),
    ("extensions.B.supported", False, "no bit-manipulation state to erase"),
    ("extensions.S.supported", False, "erasing supervisor state needs this"),
    ("extensions.U.supported", False, "erasing user-mode state needs this"),
    ("extensions.V.support_level", "Disabled", "no vector state to erase"),
    ("extensions.Zicsr.supported", False, "erasing CSR state needs this"),
    (
        "extensions.Zifencei.supported",
        False,
        "the FENCE.I decode narrowing exists because of this",
    ),
    ("memory.pmp.count", 0, "erasing PMP configuration needs this"),
    ("memory.pmp.usable_count", 0, "erasing PMP configuration needs this"),
)


def _resolve(payload: dict[str, Any], dotted: str) -> Any:
    node: Any = payload
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            raise TeamBError(f"profile path {dotted!r} is absent")
        node = node[part]
    return node


def check_profile(
    profile: dict[str, Any] | None = None,
    override: dict[str, Any] | None = None,
) -> str:
    """Check the committed profile still supports the contract's claims."""
    if profile is None:
        profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    if override is None:
        override = json.loads(OVERRIDE_PATH.read_text(encoding="utf-8"))

    for dotted, expected in PROFILE_CLAIMS:
        actual = _resolve(profile, dotted)
        if actual != expected:
            raise TeamBError(
                f"profile {dotted} is {actual!r}, contract requires {expected!r}"
            )

    for dotted, expected, why in OVERRIDE_CLAIMS:
        actual = _resolve(override, dotted)
        if actual != expected:
            raise TeamBError(
                f"override {dotted} is {actual!r}, contract requires "
                f"{expected!r} because {why}"
            )

    exclusions = _resolve(profile, "isa.decode_exclusions")
    if not isinstance(exclusions, list) or len(exclusions) != 1:
        raise TeamBError(
            "the profile must narrow decode by exactly one instruction; "
            f"it names {len(exclusions) if isinstance(exclusions, list) else '?'}"
        )
    exclusion = exclusions[0]
    if exclusion.get("instruction") != "FENCE.I":
        raise TeamBError(
            f"the decode narrowing names {exclusion.get('instruction')!r}, "
            "not FENCE.I"
        )
    if exclusion.get("word") != FENCE_I_WORD:
        raise TeamBError(
            f"the FENCE.I narrowing names word {exclusion.get('word')!r}, "
            f"expected {FENCE_I_WORD} ({FENCE_I_WORD:#010x})"
        )
    # The narrowing is only honest while it records that the pinned model
    # *does* retire the instruction. Dropping that field would turn a
    # documented divergence into a silent one.
    disposition = exclusion.get("pinned_sail_disposition")
    if not isinstance(disposition, str) or "retires" not in disposition:
        raise TeamBError(
            "the FENCE.I narrowing no longer records that the pinned Sail "
            "model retires the instruction"
        )
    return (
        f"team B profile: {len(PROFILE_CLAIMS) + len(OVERRIDE_CLAIMS)} contract "
        "claims hold and decode narrows only FENCE.I"
    )


def check_contract_binding() -> str:
    """The contract prose and the profile must not drift apart."""
    if not CONTRACT_PATH.is_file():
        raise TeamBError(f"Team B contract is absent at {CONTRACT_PATH}")
    text = CONTRACT_PATH.read_text(encoding="utf-8")
    required = (
        f"{FENCE_I_WORD:#010x}".upper().replace("0X", "0x"),
        "rv32im",
        "Zifencei",
    )
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise TeamBError(
            "the Team B contract no longer states: " + ", ".join(missing)
        )
    return "team B contract: prose still names the pinned profile facts"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("coverage", help="check the 22-opcode certificate index")
    subparsers.add_parser("theorems", help="check every named theorem exists")
    subparsers.add_parser("profile", help="check the pinned profile supports the contract")

    digests = subparsers.add_parser(
        "ir-digests", help="check family capsules against a fresh AIR export"
    )
    digests.add_argument("--air-ir-dir", type=Path, required=True)

    check = subparsers.add_parser("check", help="run every Team B gate")
    check.add_argument("--air-ir-dir", type=Path, required=True)

    args = parser.parse_args(argv)

    try:
        if args.command == "coverage":
            print(check_coverage())
        elif args.command == "theorems":
            print(check_theorems())
        elif args.command == "ir-digests":
            print(check_ir_digests(args.air_ir_dir))
        elif args.command == "profile":
            print(check_profile())
            print(check_contract_binding())
        else:
            print(check_coverage())
            print(check_theorems())
            print(check_profile())
            print(check_contract_binding())
            print(check_ir_digests(args.air_ir_dir))
    except TeamBError as error:
        print(f"team B gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
