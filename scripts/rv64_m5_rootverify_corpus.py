#!/usr/bin/env python3
"""RV64 M5 rootverify: the negative corpus against the ROOT-ONLY receiver.

Runs ON the pod, CPU only (never holds the GPU lock). Reuses every runnable
case of scripts/rv64_m5_negative_corpus.py (binding note section 7) verbatim,
but runs the receiver as `verify-root-candidate CONFIG OUT TABLE ...` with a
receiver-local VK table, and adds table/profile cases (RV*) that only exist
for the root-only path.

  python3 rv64_m5_rootverify_corpus.py run --run RUN --donor DONOR_RUN --table TABLE --donor-table DONOR_TABLE \
      --receiver BIN --out OUT [--jobs 3] [--cases ID,..]

Expectations under root-only. The root-only receiver reads the bundle metadata
and recursion-om31/root.proof only; it neither verifies nor reads native proofs
(beyond the bundle's own file-hash load check) or child recursion proofs. A
mutation of a byte it does not consume therefore cannot change its statement:
such cases are `reject_or_same_statement` (accepting is a pass only with the
control's exact statement: output, root digest, root identity, profiles). Every
case that changes what the statement or the root proof says must be rejected.
"""
import argparse
import concurrent.futures as cf
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rv64_m5_negative_corpus as N  # noqa: E402

SCHEMA = "rv64-m5-rootverify-corpus/v1"
HOST_BYTES = 34359738368
# Cases whose mutated bytes the root-only receiver never consumes.
NOT_CONSUMED = {
    "S02-drop-leaf": "child recursion proof (bound in-circuit by its parent fold)",
    "S04-dup-leaf": "child recursion proof",
    "S06-permute-leaves": "child recursion proofs",
    "V01-cross-class-fold": "child recursion proof",
    "V02-cross-block-fold": "child recursion proof",
    "V03-cross-block-leaf": "child recursion proof",
    "R06-leaf-proof-flip": "child recursion proof",
    "R07-coherent-native-flip": "native proof body (verified in-circuit by its leaf); bundle hash rewritten",
    "R08-coherent-native-head-flip": "native proof body; bundle hash rewritten",
    "R09-coherent-truth-flip": "native proof body; bundle hash rewritten",
    "K01-tree-leaf-count": "producer tree.json (receiver re-derives the tree)",
    "K03-tree-drop-node": "producer tree.json",
}


# ------------------------------------------------------------------ table helpers (mirror root_verify.zig)

def u32(v):
    return int(v).to_bytes(4, "little")


def table_root(t):
    h = hashlib.blake2s(digest_size=32)
    h.update(b"rv64-vk-receiver-table/v0/root\x00")
    hd = t["header"]
    for part in (hd["profile"], hd["native_profile"], hd["outer_domain"], hd["image"]):
        b = part.encode()
        h.update(len(b).to_bytes(8, "little"))
        h.update(b)
    kinds = {"leaf": 0, "fold": 1}
    for e in sorted(t["entries"], key=lambda e: (kinds[e["kind"]], bytes.fromhex(e["key"]))):
        vk = e["vk"]
        h.update(bytes([kinds[e["kind"]]]))
        h.update(bytes.fromhex(e["key"]))
        h.update(bytes.fromhex(vk["columns"]))
        for v in vk["log_sizes"] + vk["logs"] + [vk["n_outputs"], vk["total_constraints"], vk["max_evaluation_log_size"]]:
            h.update(u32(v))
        h.update(bytes.fromhex(vk["fixed_root"]))
        h.update(bytes.fromhex(vk["identity"]))
    return h.hexdigest()


def coherent(fn):
    """Mutate the table and re-seal its root so the semantic check must reject."""
    def apply(t):
        fn(t)
        t["entries"].sort(key=lambda e: ({"leaf": 0, "fold": 1}[e["kind"]], bytes.fromhex(e["key"])))
        t["table_root"] = table_root(t)
    return apply


def flip_hex(text, at=0):
    b = bytearray(bytes.fromhex(text))
    b[at] ^= 1
    return b.hex()


def rotate_leaf_vks(t):
    """Every leaf class gets the next class's VK (keys kept): each leaf of the
    block now maps to some other honest leaf circuit."""
    leaves = [e for e in t["entries"] if e["kind"] == "leaf"]
    vks = [e["vk"] for e in leaves]
    for e, vk in zip(leaves, vks[1:] + vks[:1]):
        e["vk"] = vk


def first(t, kind):
    return next(e for e in t["entries"] if e["kind"] == kind)


# RV cases: (id, family, expect, what, table_fn(table_json) | None, special)
RV_CASES = [
    dict(id="RV01-store-supplied-table", family="table-policy", what="VK table placed inside the producer's proof directory",
         special="in_proof_dir"),
    dict(id="RV02-unknown-profile", family="profile", what="table profile id rv64-m4-fold-v2-compat/v1 (unknown), root re-sealed",
         table=coherent(lambda t: t["header"].__setitem__("profile", "rv64-m4-fold-v2-compat/v1"))),
    dict(id="RV03-unimplemented-profile", family="profile", what="table profile id rv64-m5-canon/v1 (named, not implemented yet)",
         table=coherent(lambda t: t["header"].__setitem__("profile", "rv64-m5-canon/v1"))),
    dict(id="RV04-other-receiver", family="table-policy", what="table claims derivation by another receiver binary (sha changed), root re-sealed",
         table=coherent(lambda t: t["header"].__setitem__("receiver_sha256", flip_hex(t["header"]["receiver_sha256"])))),
    dict(id="RV05-other-image", family="table-policy", what="table image id changed, root re-sealed",
         table=coherent(lambda t: t["header"].__setitem__("image", flip_hex(t["header"]["image"])))),
    dict(id="RV06-native-profile", family="profile", what="table native profile label changed, root re-sealed",
         table=coherent(lambda t: t["header"].__setitem__("native_profile", t["header"]["native_profile"] + "-x"))),
    dict(id="RV07-leaf-vk-root", family="child-vk", what="every leaf VK FIXED root flipped (one bit), root re-sealed",
         table=coherent(lambda t: [e["vk"].__setitem__("fixed_root", flip_hex(e["vk"]["fixed_root"])) for e in t["entries"] if e["kind"] == "leaf"])),
    dict(id="RV08-leaf-vk-identity", family="child-vk", what="every leaf VK identity flipped, root re-sealed",
         table=coherent(lambda t: [e["vk"].__setitem__("identity", flip_hex(e["vk"]["identity"], 5)) for e in t["entries"] if e["kind"] == "leaf"])),
    dict(id="RV09-fold-vk-root", family="child-vk", what="every fold VK FIXED root flipped, root re-sealed",
         table=coherent(lambda t: [e["vk"].__setitem__("fixed_root", flip_hex(e["vk"]["fixed_root"])) for e in t["entries"] if e["kind"] == "fold"])),
    dict(id="RV10-fold-vk-logs", family="child-vk", what="every fold VK component log + 1 (root VK geometry changed), root re-sealed",
         table=coherent(lambda t: [e["vk"].__setitem__("logs", [v + 1 for v in e["vk"]["logs"]]) for e in t["entries"] if e["kind"] == "fold"])),
    dict(id="RV11-missing-leaf-class", family="child-vk", what="all leaf entries removed, root re-sealed",
         table=coherent(lambda t: t.__setitem__("entries", [e for e in t["entries"] if e["kind"] != "leaf"]))),
    dict(id="RV12-missing-fold-class", family="child-vk", what="all fold entries removed, root re-sealed",
         table=coherent(lambda t: t.__setitem__("entries", [e for e in t["entries"] if e["kind"] != "fold"]))),
    dict(id="RV13-table-root-tamper", family="table-policy", what="one fold VK constraint count changed WITHOUT re-sealing the root",
         table=lambda t: first(t, "fold")["vk"].__setitem__("total_constraints", first(t, "fold")["vk"]["total_constraints"] + 1)),
    dict(id="RV14-donor-only-table", family="child-vk", what="table derived from the OTHER dev block only (classes of this block absent)",
         special="donor_table"),
    dict(id="RV15-leaf-vk-rotate", family="child-vk", what="leaf VKs rotated across leaf classes (keys kept: every leaf maps to another honest leaf circuit), root re-sealed",
         table=coherent(lambda t: rotate_leaf_vks(t))),
]


def statement(stdout):
    return {k: stdout.get(k) for k in ("output", "root_digest", "root_identity", "native_profile", "outer_profile", "table_profile")}


def run_case(case, ctx, mode):
    work = ctx["work"] / case["id"]
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    proof = work / "proof"
    shutil.copytree(ctx["proof"], proof)
    request = json.loads(ctx["request_path"].read_text())
    request["output_directory"] = str(work / "capture")
    argv = {"profile": ctx["profile"]}
    env = N.environment()
    (work / "gpu-disabled").mkdir()
    env["STWO_RV64_GPU_WORKDIR"] = str(work / "gpu-disabled")
    table = work / "vk-table.json"
    shutil.copyfile(ctx["table"], table)
    if mode == "rv" and case.get("special") == "donor_table":
        shutil.copyfile(ctx["donor_table"], table)
    expect = case.get("expect", "reject")
    if mode == "m3" and case["id"] in NOT_CONSUMED:
        expect = "reject_or_same_statement"
    result = {"id": case["id"], "family": case["family"], "expect": expect, "what": case["what"]}
    if mode == "m3" and case["id"] in NOT_CONSUMED:
        result["root_only_note"] = "mutates bytes the root-only receiver does not consume: " + NOT_CONSUMED[case["id"]]
    try:
        if mode == "m3":
            detail = case["mutate"]({"proof": proof, "donor": ctx["donor"], "request": request, "env": env, "argv": argv})
            if isinstance(detail, int):
                result["mutation_detail"] = {"flipped_byte_offset": detail}
        elif case.get("table"):
            value = json.loads(table.read_text())
            case["table"](value)
            table.write_text(json.dumps(value, indent=1))
        if mode == "rv" and case.get("special") == "in_proof_dir":
            inside = proof / "vk-table.json"
            shutil.copyfile(table, inside)
            table = inside
    except Exception as error:
        result.update(status="harness_error", error=f"mutation failed: {error!r}", passed=False)
        shutil.rmtree(work, ignore_errors=True)
        return result
    request_path = work / "receiver-request.json"
    request_path.write_text(json.dumps(request, indent=1))
    command = ["nice", "-n", "10", str(ctx["receiver"]), "--security-profile", argv["profile"], "verify-root-candidate",
               str(request_path), str(proof), str(table), str(ctx["fixed_setup_bytes"]), str(HOST_BYTES)]
    started = time.monotonic()
    timed_out = False
    with open(work / "stdout", "wb") as out, open(work / "stderr", "wb") as err:
        try:
            returncode = subprocess.run(command, stdout=out, stderr=err, env=env, cwd=ctx["cwd"], timeout=900).returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, None
    wall = time.monotonic() - started
    stderr = (work / "stderr").read_text(errors="replace").splitlines()
    first_error = next((line for line in stderr if line.startswith("error") or "error:" in line[:40]), None)
    accepted, same = False, None
    try:
        stdout = json.loads((work / "stdout").read_text())
        accepted = returncode == 0 and stdout.get("accepted") is True and stdout.get("completed_ethereum_block") is True
        if accepted:
            same = statement(stdout) == ctx["control_statement"]
            result["verify_per_block_s"] = round(stdout["verify_per_block_ns"] / 1e9, 3)
    except Exception:
        pass
    crashed = timed_out or returncode is None or returncode < 0 or any(m in line for line in stderr for m in N.CRASH_MARKERS)
    verdict = "accept" if accepted else ("crash" if crashed else "reject")
    if expect == "accept":
        passed = accepted and same is True
    elif expect == "reject":
        passed = verdict == "reject"
    else:
        passed = verdict == "reject" or (accepted and same is True)
    result.update(status="timeout" if timed_out else "ran", verdict=verdict, exit_code=returncode, wall_s=round(wall, 2),
                  first_error=first_error, reject_class=N.reject_class(first_error) if verdict == "reject" else None,
                  same_statement_as_control=same, passed=passed)
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({k: result.get(k) for k in ("id", "expect", "verdict", "passed", "wall_s", "first_error")}, default=str), flush=True)
    return result


def control(ctx):
    """C00 under root-only: establishes the control statement every case is compared with."""
    case = {"id": "C00-control", "family": "control", "what": "unmodified proof dir, receiver-local table", "expect": "accept"}
    ctx = dict(ctx, control_statement=None)
    work = ctx["work"] / "C00-probe"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    request = json.loads(ctx["request_path"].read_text())
    request["output_directory"] = str(work / "capture")
    (work / "req.json").write_text(json.dumps(request))
    env = N.environment()
    command = [str(ctx["receiver"]), "--security-profile", ctx["profile"], "verify-root-candidate", str(work / "req.json"),
               str(ctx["proof"]), str(ctx["table"]), str(ctx["fixed_setup_bytes"]), str(HOST_BYTES)]
    proc = subprocess.run(command, capture_output=True, env=env, cwd=ctx["cwd"], timeout=900)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode(errors="replace")[-3000:])
        raise SystemExit("root-only control rejected")
    stdout = json.loads(proc.stdout)
    shutil.rmtree(work, ignore_errors=True)
    return case, statement(stdout), stdout


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    for name in ("--run", "--donor", "--table", "--donor-table", "--receiver", "--out"):
        r.add_argument(name, required=True)
    r.add_argument("--jobs", type=int, default=3)
    r.add_argument("--cases")
    r.add_argument("--work", default="/workspace/m3/scratch/m5-rootverify/corpus")
    args = p.parse_args()
    run, donor_run = Path(args.run), Path(args.donor)
    plan, job, proof = N.proof_dir(run)
    _, djob, donor_proof = N.proof_dir(donor_run)
    if job["block"] not in N.DEV_BLOCKS or djob["block"] not in N.DEV_BLOCKS or job["block"] == djob["block"]:
        raise SystemExit("run and donor must be the two different dev blocks")
    recv_dir, _ = N.accepted_receiver_dir(run)  # harness receive (workers=16, same request shape)
    request_path = recv_dir / "receiver-request.json"
    ctx = {"proof": proof, "donor": donor_proof, "request_path": request_path, "profile": plan["profile"], "receiver": Path(args.receiver),
           "fixed_setup_bytes": job["resources"]["fixed_setup_bytes"], "cwd": plan.get("producer_cwd") or "/", "table": Path(args.table),
           "donor_table": Path(args.donor_table), "work": Path(args.work) / str(job["block"])}
    ctx["work"].mkdir(parents=True, exist_ok=True)
    c00, control_statement, control_stdout = control(ctx)
    ctx["control_statement"] = control_statement
    wanted = set(args.cases.split(",")) if args.cases else None
    m3 = [c for c in N.CASES if c["today"] == "m3" and (wanted is None or c["id"] in wanted)]
    rv = [c for c in RV_CASES if wanted is None or c["id"] in wanted]
    load = os.getloadavg()[0]
    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda c: run_case(c, ctx, "m3"), m3)) + list(pool.map(lambda c: run_case(c, ctx, "rv"), rv))
    receipt = {"schema": SCHEMA, "measured": True, "date": time.strftime("%Y-%m-%dT%H:%M:%S"), "block": job["block"], "donor_block": djob["block"],
               "mode": "verify-root-candidate (root-only)", "receiver": str(ctx["receiver"]), "receiver_sha256": N.sha(ctx["receiver"]),
               "table": str(ctx["table"]), "table_sha256": N.sha(ctx["table"]), "control_statement": control_statement,
               "control_verify_per_block_s": round(control_stdout["verify_per_block_ns"] / 1e9, 3),
               "receiver_env": {"CUDA_VISIBLE_DEVICES": "", "STWO_RV64_GPU_PCS_HELPER": "/bin/false", "STWO_ZIG_RV64_SETUP_CACHE": "unset"},
               "jobs": args.jobs, "loadavg_1m_start": load, "loadavg_1m_end": os.getloadavg()[0], "wall_s": round(time.time() - started, 1),
               "ran": len(results), "passed": sum(1 for x in results if x.get("passed")),
               "rejected_where_reject_expected": sum(1 for x in results if x["expect"] == "reject" and x.get("verdict") == "reject"),
               "reject_expected": sum(1 for x in results if x["expect"] == "reject"),
               "accepted_same_statement": [x["id"] for x in results if x.get("verdict") == "accept" and x.get("same_statement_as_control")],
               "unexpected_accepts": [x["id"] for x in results if x.get("verdict") == "accept" and not x.get("passed")],
               "crashes": [x["id"] for x in results if x.get("verdict") == "crash"],
               "nonsemantic_rejects": {x["id"]: x["reject_class"] for x in results if x.get("reject_class") not in (None, "semantic")},
               "results": results}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=1, default=str))
    print(json.dumps({k: receipt[k] for k in ("block", "ran", "passed", "reject_expected", "rejected_where_reject_expected", "accepted_same_statement", "unexpected_accepts", "crashes", "wall_s")}))
    sys.exit(0 if receipt["passed"] == receipt["ran"] else 1)


if __name__ == "__main__":
    main()
