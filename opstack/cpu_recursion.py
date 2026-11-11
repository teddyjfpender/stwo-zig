"""CPU execution-root production and strict fresh admission for the CPU harness.

The native and recursive producers are timed together, before any independent
receiver or corruption trials. A native-only result cannot satisfy this path.
"""

import json
import time
from pathlib import Path

from opstack.recursive_transition import OUTER_DOMAINS, admit_receipt

DEFAULT_OUTER = "m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1"
FOLD_ARITIES = {
    DEFAULT_OUTER: 3,
    "m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1": 4,
    "m7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1": 4,
}


def add_arguments(parser):
    parser.add_argument("--recursive-runner", type=Path)
    parser.add_argument("--recursive-profile", choices=OUTER_DOMAINS, default=DEFAULT_OUTER)
    parser.add_argument("--recursive-workers", type=int)
    parser.add_argument("--recursive-live-bytes", type=int, default=52 << 30)
    parser.add_argument("--recursive-receiver-bytes", type=int, default=32 << 30)


def validate_arguments(args, parser):
    if args.recursive_runner is None:
        if (
            args.recursive_workers is not None
            or args.recursive_profile != DEFAULT_OUTER
            or args.recursive_live_bytes != 52 << 30
            or args.recursive_receiver_bytes != 32 << 30
        ):
            parser.error("recursive options require --recursive-runner")
        return
    if args.transition_statement is not None:
        parser.error("this execution-root benchmark does not admit an anchored OD/OP join")
    if args.recursive_workers is not None and not 1 <= args.recursive_workers <= 32:
        parser.error("recursive workers must be in 1..32")
    if not all(1 <= n <= 64 << 30 for n in (
        args.recursive_live_bytes, args.recursive_receiver_bytes
    )):
        parser.error("recursive admissions must be in 1..64 GiB")


def run(args, config, root, fixed_bytes, env, measure, record_stage):
    """Return only after independently receiving the complete physical tree.

    Producer output is diagnostic. `admit_receipt` requires fresh native
    verification, complete leaf/fold coverage, exact output and pinned profiles.
    The external verifier establishes source authority; Python does not supply it.
    """
    if fixed_bytes > min(args.recursive_live_bytes, args.recursive_receiver_bytes):
        raise ValueError("fixed-key admission must fit inside both recursive live limits")
    request = root / "recursive-request.json"
    recursive_config = dict(config)
    recursive_config["workers"] = args.recursive_workers or args.workers
    request.write_text(json.dumps(recursive_config, indent=2) + "\n")
    selected = args.recursive_profile
    recursive_env = dict(env, STWO_RV64_OUTER_PROFILE=selected)
    recursive_env["STWO_RV64_FOLD_ARITY"] = str(FOLD_ARITIES.get(selected, 2))
    if selected.startswith("m7_"):
        recursive_env["STWO_RV64_OUTER_GKR_NATIVE"] = "1"
    command = [args.recursive_runner.resolve(), "--security-profile", args.native_profile]
    produce = measure(
        [*command, "recurse-candidate", request, root / "proof", fixed_bytes,
         args.recursive_live_bytes],
        root / "recursive-produce", args.timeout, recursive_env, True,
    )
    root_ready_ns = time.monotonic_ns()
    record_stage("recursive_produce", produce)
    if produce["returncode"] or produce["timed_out"]:
        raise RuntimeError("CPU recursive production failed; see recursive-produce.stderr")
    # A new process independently reconstructs authority. No producer setup
    # cache or assignment is passed, and missing proofs must not be regenerated.
    receive = measure(
        [*command, "verify-recursion-candidate", request, root / "proof", fixed_bytes,
         args.recursive_receiver_bytes],
        root / "recursive-receive", args.timeout, recursive_env, True,
    )
    record_stage("recursive_receive", receive)
    if receive["returncode"] or receive["timed_out"]:
        raise RuntimeError("CPU recursive reception failed; see recursive-receive.stderr")
    report = json.loads((root / "recursive-receive.stdout").read_text())
    admitted = admit_receipt(
        report, bytes.fromhex(config["expected_output"]), selected, args.native_profile
    )
    return {
        "receiver": report,
        "admitted": admitted,
        "root_ready_monotonic_ns": root_ready_ns,
        "workers": recursive_config["workers"],
        "producer_requested_live_bytes": args.recursive_live_bytes,
        "receiver_requested_live_bytes": args.recursive_receiver_bytes,
        "fixed_setup_bytes_inside_live_limits": fixed_bytes,
        "outer_profile": selected,
    }
