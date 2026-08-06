"""Reviewed H-009/H-010 arm and deterministic-vector identity pins."""

from __future__ import annotations

from dataclasses import dataclass


ARTIFACT_DIGEST = (
    "5ead00cfcb8cfd396836be9cc3a79ed80bfb0b8bc7913a1c6ab38dbcff879494"
)
VECTOR_CALL_DIGESTS = {
    10: "c149cb04c9604a9702484f4cdc52712d8cbdd92e7ec5d5055b8066207f42826c",
    14: "c1cbc8b1f135c6e2ac71f0a17fa545714a5adefadef52a993b19fd4b0416613a",
    18: "255b80dc74b2cd1cf528ab12d9240ff98247db8807a3bdefe624ae7a8f30ad97",
}
VECTOR_SEALS = {
    10: "27be0de8a88a36ac9cb686c40da6442abdd18950bc4cb45a93773f45de4fb113",
    14: "b9ce7ca07edee474d0ca9da8e2a4dcdd24d300b6a99c1a1c5305a90da9a3c11d",
    18: "026856cb253075be1cc3671cff75a9e974bf384bcff359e903bd1c2e4f357f08",
}
VECTOR_ARTIFACT_DIGESTS = {
    10: "2d90fa647d55758f1fdf7be46de5232ee006ac3682ab0371ec1108c95c8f14ee",
    14: "b2f84aa4ecc9f017932a2ca81fd89060d1fccb8bfaf90c9843ac9013cb6f83d8",
    18: "97c24095ff33d0150a69da5cc9e108065b3f68e204ea10d6f0a21d19dce604b4",
}
VECTOR_OUTPUT_DIGESTS = {
    10: "08478c8bede13d09402a3ad5688d9581f3ee45e11455a46f23814387435c73ae",
    14: "5b0a3a47bba89e6ffa0314b0d5a64ce9f0d8fe560cb63e1b2803c3011ebb2454",
    18: "f687cc5b81a20b10a2200190dd0449271ac488ea5db9e581fb9fe463d811c1fa",
}
VECTOR_TRACE_DIGESTS = {
    10: (
        "972f3071150f299a9054363b8e27a63354bf2d18d93752476af546742fecab39",
        "c85fe25a7a9132c1d41fafb423252f4e62ff0a26f2e24f4012bbbda33a07c6ad",
        "c05bbe69456d010ec8a8318a5a0682f76326f774cab08a834d0ac011e6e5ed90",
        "669bae41567c5ef7be2bfe9be0e65c281b437f346d482c3907205cd6578b821d",
    ),
    14: (
        "9fa0b291e70bcbf637c4605d002e7fd6040bbf1b3803f8feba9b5c294b3827a7",
        "2e8a3424f62e33e908e69be3e0f04159e71e28953454fd090bb7d50ba9137ad2",
        "79511831f3a2b3a7bd09a95ce8614a2d4ca81b9186cb53d29b4ea2daa75fc332",
        "5a626e0a415caa06e2ee3e5a479b1c25061ccb5e61bb620a8e6d9243236ab4c2",
    ),
    18: (
        "dba86497b97ae4213564822d6945b9fdb708173f73e7c0b921595e83392235a5",
        "6fca9b92fa3014f12596bc34e92180a0ba4dc5c7d62c9d1d1ebc00912b08179d",
        "601fdcd3af1202f6f7ee66881709215ae0309c238a1ef342cfcbd9cdfbac5095",
        "34085fd56f4732d1caf5ed9e32f884e5b81cb7f82a4c3a71961021a796d42db7",
    ),
}


@dataclass(frozen=True)
class ArmPin:
    arm: str
    frontier_ordinal: int | None
    proposal_digest: str
    cut_digest: str
    selection_class: str
    quantile_numerator: int | None
    quantile_denominator: int | None
    sorted_rank: int | None
    removed_value_id: int | None
    added_value_id: int | None
    parent_cut_digest: str | None


BASELINE_CUT = "b10cb7f66e3519788ecec6edc4095541a24eaf642a3ed8877fbe87c85e8ba9c5"
ARM_PINS = (
    ArmPin(
        "compat-seed",
        None,
        "7a585031ef8710d62adac55d1c2d8072c0b2a6ce82a562b4862d4329623a23ef",
        BASELINE_CUT,
        "compatibility_seed",
        None,
        None,
        None,
        None,
        None,
        None,
    ),
    ArmPin(
        "removed-q0",
        85,
        "997d7236203de34953b8479ea2773a0772737d6e7f81c08537f8bd744f5ccd44",
        "96f45498a15b2313ca83a9f5bc8a38f74c620f2712ca219bf440cb30dbe1e788",
        "removed_value_id_quantile",
        0,
        1,
        0,
        266,
        240,
        BASELINE_CUT,
    ),
    ArmPin(
        "removed-q50",
        92,
        "ae33d31eab62c10a8be6826a6e739c6e30dddf154eec22d10194e3583fa37e23",
        "0f339a827261aa19693617a6d782d8b02a49a6930fd75ea512c9bb62a59ea90e",
        "removed_value_id_quantile",
        1,
        2,
        62,
        1_517,
        1_485,
        BASELINE_CUT,
    ),
    ArmPin(
        "removed-q100",
        60,
        "662338db02cbb0e7e1e4eb7f486b2f6a05087e96f8d3597ca50dd667faa9ae6a",
        "a2b77acaaf4977012e6dfc17fed31856b906c1e221999d4d52932922cd425f20",
        "removed_value_id_quantile",
        1,
        1,
        125,
        2_039,
        2_007,
        BASELINE_CUT,
    ),
)
