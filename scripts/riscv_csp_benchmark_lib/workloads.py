"""Authenticated full-guest coverage, including typed ECDSA acceleration."""
from .contract import BenchmarkError
from .precompile import validate_manifest


def require_execution_mode(mode: str) -> None:
    if mode not in ("software", "precompile"):
        raise BenchmarkError(f"unknown execution mode: {mode}")
    if mode == "precompile":
        validate_manifest()


def workload_inventory(cases) -> dict:
    manifest = validate_manifest()
    return {
        "software": {
            "status": "available", "proof_scope": "riscv_guest", "uses_precompile": False,
            "cases": [{"target": case.target, "input_size": case.input_size,
                       "guest_sha256": case.guest_sha256} for case in cases],
        },
        "precompile": {
            "status": "available", "proof_scope": "riscv_guest",
            "target": "ecdsa_secp256k1", "implementation": manifest["implementation"],
            "guests": manifest["guests"],
            "fallback": "full software guest proof for unsupported inputs and other targets",
        },
    }
