"""Source and package contract for experimental circuit random-row blinding.

This policy is an integrity check, not a zero-knowledge security argument or a
trust anchor. The native verifier independently reconstructs the sealed circuit.
"""

from __future__ import annotations

POLICY = {"scheme": "upstream_random_rows_v1", "rounds": 80,
          "queries": 70, "extra_openings": 10}
PROFILE = "circuit-blinded-v1"
KEY_SCHEMA = "s31-verification-key-blinded-v1"
RECURSIVE_ARTIFACTS = {"recursive-verification-key.json",
                       "recursive-verification-key-level2.json",
                       "fixed-fold-verification-key.json",
                       "state-fold-verification-key.json"}


def policy_for(source: dict, lowering: str, fold_step: int) -> dict | None:
    mode = source.get("proof_mode", "transparent")
    if mode not in ("transparent", "blinded"):
        raise ValueError("proof_mode must be transparent or blinded")
    if mode == "transparent":
        return None
    if lowering != "gate" or type(fold_step) is not int or fold_step != 1:
        raise ValueError("blinded circuits require gate lowering and FRI fold step 1")
    return POLICY.copy()


def matches_policy(value: object, expected: dict) -> bool:
    return (isinstance(value, dict) and value == expected and
            all(type(value.get(name)) is int for name in ("rounds", "queries", "extra_openings")))


def validate_package(source: dict, manifest: dict, key: dict, report: dict) -> None:
    expected = policy_for(source, manifest.get("lowering"), manifest.get("fri_fold_step", 1))
    if expected is None:
        if (manifest.get("proof_mode", "transparent") != "transparent" or
                any(item.get("proof_privacy") is not None for item in (manifest, key, report)) or
                key.get("schema") == KEY_SCHEMA or key.get("profile") == PROFILE):
            raise ValueError("transparent source cannot request a blinded package policy")
        return
    if (manifest.get("proof_mode") != "blinded" or
            key.get("schema") != KEY_SCHEMA or key.get("profile") != PROFILE or
            any(not matches_policy(item.get("proof_privacy"), expected)
                for item in (manifest, key, report))):
        raise ValueError("blinded package policy does not match source and pinned query budget")
    if (RECURSIVE_ARTIFACTS.intersection(manifest["artifacts"]) or
            manifest.get("capabilities") or "recursive_fri_fold_step" in manifest):
        raise ValueError("blinded packages do not support recursion or folding")
