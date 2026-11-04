#!/usr/bin/env python3
"""RV64 M5/M7 negative corpus: spec + CPU harness against a fresh receiver.

Spec: design/riscv-proving-stack/rv64-m5-binding.md section 7 (case ids are stable).
Runs ON the pod. Each case copies an accepted proof directory, applies ONE
mutation, and runs a fresh, separate, cache-disabled, GPU-disabled receiver
process exactly as `rv64_m3_pod.py receive` does (same argv shape and env).

  python3 rv64_m5_negative_corpus.py spec                      # print the full spec (incl. pending M5/M7 cases)
  python3 rv64_m5_negative_corpus.py run --run RUN_DIR --donor DONOR_RUN_DIR --out OUT [--jobs 3] [--cases ID,..]

RUN_DIR is a harness run directory (plan.json + an accepted receiver-*/ dir)
of a dev block (26235156 or 24628607). DONOR_RUN_DIR is an accepted run of the
OTHER dev block (cross-block substitutions). Pending cases (format does not
exist yet) are listed in the receipt with status "pending" and never run.

Verdict rule: a case PASSES when the receiver's verdict equals the expectation.
  reject                 : exit != 0, or stdout accepted/completed not both true.
  accept                 : exit 0 and accepted and completed_ethereum_block (controls).
  reject_or_same_statement: producer-advisory metadata the receiver re-derives.
                           Accepting is allowed only if the receiver's statement
                           (output, root digest, root authority, manifest) equals
                           the control's; otherwise it must reject.
Standard library only; no GPU; never holds the GPU lock.
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

SCHEMA = "rv64-m5-negative-corpus/v1"
DEV_BLOCKS = {26235156, 24628607}
HOST_BYTES = 34359738368


def rec(*names):
    return [f"recursion-om31/{n}" for n in names]


def flip(path, where):
    data = bytearray(path.read_bytes())
    offset = {"head": min(64, len(data) - 1), "mid": len(data) // 2, "tail": len(data) - 9}[where]
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))
    return offset


def swap(a, b):
    tmp = a.with_suffix(a.suffix + ".swap")
    a.rename(tmp)
    b.rename(a)
    tmp.rename(b)


def json_edit(path, fn):
    value = json.loads(path.read_text())
    fn(value)
    path.write_text(json.dumps(value))


def root_node(tree):
    return max(tree["nodes"], key=lambda n: n.get("leaf_count", 0))


def digest_list(path):
    return list(hashlib.sha256(path.read_bytes()).digest())


def bundle(proof, fn):
    json_edit(proof / "bundle.json", fn)


def coherent_swap(proof, kind, a, b):
    """Swap two segment files AND their bundle entries (declaration, request, claims, proof hash) together."""
    files = {"cpus": "cpu", "truths": "truth"}[kind]
    swap(proof / f"{files}-{a}.bin", proof / f"{files}-{b}.bin")
    bundle(proof, lambda v: v[kind].__setitem__(slice(None), [v[kind][b] if i == a else v[kind][a] if i == b else e for i, e in enumerate(v[kind])]))


def coherent_drop_last_cpu(proof):
    last = None

    def edit(v):
        nonlocal last
        last = len(v["cpus"]) - 1
        v["cpus"].pop()
    bundle(proof, edit)
    (proof / f"cpu-{last}.bin").unlink()


def coherent_dup_cpu(proof, src, dst):
    shutil.copyfile(proof / f"cpu-{src}.bin", proof / f"cpu-{dst}.bin")
    bundle(proof, lambda v: v["cpus"].__setitem__(dst, json.loads(json.dumps(v["cpus"][src]))))


def coherent_flip(proof, name, setter):
    offset = flip(proof / name, "mid")
    h = digest_list(proof / name)
    bundle(proof, lambda v: setter(v, h))
    return offset


# Each case: id, family (spec section 7), expect, today ("m3" runnable now | "m5"/"m7" pending), what, mutate(ctx).
# ctx: proof (Path, mutable copy), donor (Path, read-only), request (dict, mutable), env (dict, mutable), argv (dict, mutable)
CASES = [
    dict(id="C00-control", family="control", expect="accept", today="m3", what="unmodified accepted proof directory",
         mutate=lambda c: None),
    # Segment chain: dropped / duplicated / permuted
    dict(id="S01-drop-native-segment", family="segment-chain", expect="reject", today="m3",
         what="delete the last CPU native segment proof (cpu-3.bin)", mutate=lambda c: (c["proof"] / "cpu-3.bin").unlink()),
    dict(id="S02-drop-leaf", family="segment-chain", expect="reject", today="m3",
         what="delete leaf-000003.proof", mutate=lambda c: (c["proof"] / rec("leaf-000003.proof")[0]).unlink()),
    dict(id="S03-dup-native-segment", family="segment-chain", expect="reject", today="m3",
         what="cpu-2.bin copied over cpu-3.bin (segment 2 claimed twice, segment 3 absent)",
         mutate=lambda c: shutil.copyfile(c["proof"] / "cpu-2.bin", c["proof"] / "cpu-3.bin")),
    dict(id="S04-dup-leaf", family="segment-chain", expect="reject", today="m3",
         what="leaf-000002.proof copied over leaf-000003.proof",
         mutate=lambda c: shutil.copyfile(c["proof"] / rec("leaf-000002.proof")[0], c["proof"] / rec("leaf-000003.proof")[0])),
    dict(id="S05-permute-native-segments", family="segment-chain", expect="reject", today="m3",
         what="swap cpu-1.bin and cpu-2.bin", mutate=lambda c: swap(c["proof"] / "cpu-1.bin", c["proof"] / "cpu-2.bin")),
    dict(id="S06-permute-leaves", family="segment-chain", expect="reject", today="m3",
         what="swap leaf-000000.proof and leaf-000001.proof",
         mutate=lambda c: swap(c["proof"] / rec("leaf-000000.proof")[0], c["proof"] / rec("leaf-000001.proof")[0])),
    dict(id="S07-permute-truth", family="segment-chain", expect="reject", today="m3",
         what="swap truth-0.bin and truth-1.bin (service/truth family order)",
         mutate=lambda c: swap(c["proof"] / "truth-0.bin", c["proof"] / "truth-1.bin")),
    # Coherent variants: the producer also rewrites bundle.json (file hashes, declarations, claims)
    # so the byte-level WideBundleFileChanged check cannot be what rejects.
    dict(id="S08-coherent-permute-native", family="segment-chain", expect="reject", today="m3",
         what="swap cpu-1/cpu-2 files AND their bundle.json entries (order permuted consistently)",
         mutate=lambda c: coherent_swap(c["proof"], "cpus", 1, 2)),
    dict(id="S09-coherent-drop-native", family="segment-chain", expect="reject", today="m3",
         what="drop cpu-3.bin AND its bundle.json entry (kappa 4 -> 3, consistent bundle)",
         mutate=lambda c: coherent_drop_last_cpu(c["proof"])),
    dict(id="S10-coherent-dup-native", family="segment-chain", expect="reject", today="m3",
         what="cpu-3 := cpu-2 in files AND bundle.json (segment 2 duplicated consistently)",
         mutate=lambda c: coherent_dup_cpu(c["proof"], 2, 3)),
    dict(id="S11-coherent-permute-truth", family="segment-chain", expect="reject", today="m3",
         what="swap truth-0/truth-1 files AND bundle.json entries",
         mutate=lambda c: coherent_swap(c["proof"], "truths", 0, 1)),
    # kappa (leaf count) / producer metadata the receiver must re-derive
    dict(id="K01-tree-leaf-count", family="kappa", expect="reject_or_same_statement", today="m3",
         what="tree.json: root node leaf_count - 1 (producer-claimed kappa)",
         mutate=lambda c: json_edit(c["proof"] / "recursion-om31/tree.json", lambda t: root_node(t).__setitem__("leaf_count", root_node(t)["leaf_count"] - 1))),
    dict(id="K02-report-cpu-proofs", family="kappa", expect="reject_or_same_statement", today="m3",
         what="report.json: cpu_proofs - 1 (producer-claimed segment count)",
         mutate=lambda c: json_edit(c["proof"] / "report.json", lambda r: r.__setitem__("cpu_proofs", r["cpu_proofs"] - 1))),
    dict(id="K03-tree-drop-node", family="kappa", expect="reject_or_same_statement", today="m3",
         what="tree.json: remove the first leaf node", mutate=lambda c: json_edit(c["proof"] / "recursion-om31/tree.json", lambda t: t["nodes"].pop(0))),
    # child VK / rung / class
    dict(id="V01-cross-class-fold", family="child-vk", expect="reject", today="m3",
         what="fold-000005.proof copied over fold-000002.proof (different child classes)",
         mutate=lambda c: shutil.copyfile(c["proof"] / rec("fold-000005.proof")[0], c["proof"] / rec("fold-000002.proof")[0])),
    dict(id="V02-cross-block-fold", family="child-vk", expect="reject", today="m3",
         what="donor block fold-000002.proof in place of fold-000002.proof",
         mutate=lambda c: shutil.copyfile(c["donor"] / rec("fold-000002.proof")[0], c["proof"] / rec("fold-000002.proof")[0])),
    dict(id="V03-cross-block-leaf", family="child-vk", expect="reject", today="m3",
         what="donor block leaf-000000.proof (other native VK, same family/position)",
         mutate=lambda c: shutil.copyfile(c["donor"] / rec("leaf-000000.proof")[0], c["proof"] / rec("leaf-000000.proof")[0])),
    dict(id="V04-cross-block-root", family="child-vk", expect="reject", today="m3",
         what="donor block root.proof in place of root.proof",
         mutate=lambda c: shutil.copyfile(c["donor"] / rec("root.proof")[0], c["proof"] / rec("root.proof")[0])),
    dict(id="V05-cross-block-native", family="child-vk", expect="reject", today="m3",
         what="donor block cpu-0.bin in place of cpu-0.bin (wrong native segment, other block)",
         mutate=lambda c: shutil.copyfile(c["donor"] / "cpu-0.bin", c["proof"] / "cpu-0.bin")),
    # tampered bytes (native roots, outer proofs)
    dict(id="R01-native-head-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit at byte 64 of cpu-0.bin (commitment/header region)", mutate=lambda c: flip(c["proof"] / "cpu-0.bin", "head")),
    dict(id="R02-native-mid-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit mid cpu-0.bin", mutate=lambda c: flip(c["proof"] / "cpu-0.bin", "mid")),
    dict(id="R03-truth-mid-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit mid truth-0.bin", mutate=lambda c: flip(c["proof"] / "truth-0.bin", "mid")),
    dict(id="R04-root-proof-flip", family="outer-bytes", expect="reject", today="m3",
         what="flip one bit mid root.proof", mutate=lambda c: flip(c["proof"] / rec("root.proof")[0], "mid")),
    dict(id="R05-root-proof-truncate", family="outer-bytes", expect="reject", today="m3",
         what="truncate root.proof by 32 bytes",
         mutate=lambda c: (lambda p: p.write_bytes(p.read_bytes()[:-32]))(c["proof"] / rec("root.proof")[0])),
    dict(id="R06-leaf-proof-flip", family="outer-bytes", expect="reject", today="m3",
         what="flip one bit mid leaf-000004.proof", mutate=lambda c: flip(c["proof"] / rec("leaf-000004.proof")[0], "mid")),
    dict(id="R07-coherent-native-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit mid cpu-0.bin AND rewrite its bundle.json sha256 (proof itself must fail)",
         mutate=lambda c: coherent_flip(c["proof"], "cpu-0.bin", lambda v, h: v["cpus"][0]["proof"].__setitem__("sha256", h))),
    dict(id="R08-coherent-native-head-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit at byte 64 of cpu-0.bin AND rewrite its bundle.json sha256",
         mutate=lambda c: (lambda o: (bundle(c["proof"], lambda v: v["cpus"][0]["proof"].__setitem__("sha256", digest_list(c["proof"] / "cpu-0.bin"))), o)[1])(flip(c["proof"] / "cpu-0.bin", "head"))),
    dict(id="R09-coherent-truth-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit mid truth-0.bin AND rewrite its bundle.json sha256",
         mutate=lambda c: coherent_flip(c["proof"], "truth-0.bin", lambda v, h: v["truths"][0]["proof"].__setitem__("sha256", h))),
    # chi / global stage
    dict(id="X01-stage-one-flip", family="chi", expect="reject", today="m3",
         what="flip one bit mid stage-one.bin (global stage: MAIN roots that chi is drawn from)",
         mutate=lambda c: flip(c["proof"] / "stage-one.bin", "mid")),
    dict(id="X02-cells-flip", family="chi", expect="reject", today="m3",
         what="flip one bit mid cells.bin (global GKR cells)", mutate=lambda c: flip(c["proof"] / "cells.bin", "mid")),
    dict(id="X03-coherent-stage-one-flip", family="chi", expect="reject", today="m3",
         what="flip one bit mid stage-one.bin AND rewrite bundle.json stage_one.sha256",
         mutate=lambda c: coherent_flip(c["proof"], "stage-one.bin", lambda v, h: v["stage_one"].__setitem__("sha256", h))),
    dict(id="X04-coherent-cells-flip", family="chi", expect="reject", today="m3",
         what="flip one bit mid cells.bin AND rewrite bundle.json cells_sha256",
         mutate=lambda c: coherent_flip(c["proof"], "cells.bin", lambda v, h: v.__setitem__("cells_sha256", h))),
    # statement / profile (receiver policy)
    dict(id="T01-wrong-output", family="statement", expect="reject", today="m3",
         what="receiver request expected_output: last byte changed (claimed block output differs)",
         mutate=lambda c: c["request"].__setitem__("expected_output", c["request"]["expected_output"][:-2] + ("00" if c["request"]["expected_output"][-2:] != "00" else "01"))),
    dict(id="P01-wrong-native-profile", family="profile", expect="reject", today="m3",
         what="receiver selects proven_beta2_q256_p0_fold4 for conjectured128 proofs",
         mutate=lambda c: c["argv"].__setitem__("profile", "proven_beta2_q256_p0_fold4")),
    # Pending: formats that do not exist until M5 / M7 (spec only; never run).
    dict(id="P02-wrong-outer-profile", family="profile", expect="reject", today="m5",
         what="receiver selects outer m3_b4_q51_p26 for r1 proofs (needs recsize merged into the receiver)"),
    dict(id="N01-forged-null-slot", family="null-slot", expect="reject", today="m5",
         what="k-ary fold: real child slot re-tagged null (child dropped while kappa kept)"),
    dict(id="N02-null-with-payload", family="null-slot", expect="reject", today="m5",
         what="null-tagged slot carrying a non-zero child digest"),
    dict(id="N03-null-not-trailing", family="null-slot", expect="reject", today="m5",
         what="null slot followed by a real slot (canonical null placement violated)"),
    dict(id="K04-root-kappa", family="kappa", expect="reject", today="m5",
         what="root statement kappa != receiver-derived segment count"),
    dict(id="G01-wrong-rung", family="child-vk", expect="reject", today="m5",
         what="leaf proof of rung r' presented at a chain position whose native segment has rung r"),
    dict(id="G02-vkfold-mismatch", family="child-vk", expect="reject", today="m5",
         what="root vk_fold public input != receiver-derived constant"),
    dict(id="G03-child-vk-not-in-table", family="child-vk", expect="reject", today="m5",
         what="fold child VK neither in the leaf VK table nor equal to vk_fold"),
    dict(id="G04-native-vk-not-in-table", family="child-vk", expect="reject", today="m5",
         what="leaf guesses a native VK with a valid-looking but non-member Merkle path"),
    dict(id="B01-bus-balance", family="bus", expect="reject", today="m5",
         what="root bus-balance sum != 0 (one segment's claimed sum shifted, chain re-hashed)"),
    dict(id="X05-chi-root-mismatch", family="chi", expect="reject", today="m5",
         what="root statement chi != H(statement || MAIN roots sorted by segment index)"),
    dict(id="M01-gkr-sumcheck-tamper", family="outer-gkr", expect="reject", today="m7",
         what="outer LogUp-GKR: one sumcheck round polynomial coefficient changed"),
    dict(id="M02-gkr-claim-tamper", family="outer-gkr", expect="reject", today="m7",
         what="outer LogUp-GKR: final layer claim inconsistent with the committed columns"),
    dict(id="M03-compress-profile", family="compress", expect="reject", today="m7",
         what="C2 proof verified under C1 profile (or fold-step 3 vs 4)"),
    dict(id="M04-compress-inner-root", family="compress", expect="reject", today="m7",
         what="C1/C2 proof wrapping a different root statement digest"),
]


def spec():
    return [{k: v for k, v in case.items() if k != "mutate"} for case in CASES]


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def proof_dir(run):
    plan = json.loads((run / "plan.json").read_text())
    job = plan["jobs"][0]
    hits = sorted((Path(job["target"]) / "batch").glob(f"trial-0/{job['block']}/proof"))
    if not hits:
        raise SystemExit(f"no proof dir under {run}")
    return plan, job, hits[0]


def accepted_receiver_dir(run):
    dirs = sorted(run.glob("receiver-*"))
    for d in reversed(dirs):
        out = d / "strict-receiver.stdout"
        try:
            value = json.loads(out.read_text())
            if value.get("accepted") is True and value.get("completed_ethereum_block") is True:
                return d, value
        except Exception:
            continue
    raise SystemExit(f"no accepted receiver-* under {run}; run the harness receive first")


def statement(stdout):
    r = stdout.get("recursive", {})
    return {"output": stdout.get("output"), "root_digest": r.get("root_digest"), "root_authority": r.get("root_authority"),
            "manifest": r.get("manifest"), "native_profile": stdout.get("native_profile"), "outer_profile": stdout.get("outer_profile")}


def environment():
    env = {k: v for k, v in os.environ.items() if not k.startswith("STWO_RV64_GPU_")}
    env.pop("STWO_ZIG_RV64_SETUP_CACHE", None)
    env.update(CUDA_VISIBLE_DEVICES="", STWO_RV64_GPU_PCS_HELPER="/bin/false", STWO_RV64_FOLD_CLASS_CACHE="0")
    return env


def run_case(case, ctx):
    work = ctx["work"] / case["id"]
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    proof = work / "proof"
    shutil.copytree(ctx["proof"], proof)
    request = json.loads(ctx["request_path"].read_text())
    request["output_directory"] = str(work / "capture")
    argv = {"profile": ctx["profile"]}
    env = environment()
    (work / "gpu-disabled").mkdir()
    env["STWO_RV64_GPU_WORKDIR"] = str(work / "gpu-disabled")
    mctx = {"proof": proof, "donor": ctx["donor"], "request": request, "env": env, "argv": argv}
    result = {"id": case["id"], "family": case["family"], "expect": case["expect"], "what": case["what"]}
    try:
        detail = case["mutate"](mctx)
        if isinstance(detail, int):
            result["mutation_detail"] = {"flipped_byte_offset": detail}
    except Exception as error:
        result.update(status="harness_error", error=f"mutation failed: {error!r}", passed=False)
        shutil.rmtree(work, ignore_errors=True)
        return result
    request_path = work / "receiver-request.json"
    request_path.write_text(json.dumps(request, indent=1))
    command = ["nice", "-n", "10", str(ctx["receiver"]), "--security-profile", argv["profile"], "verify-recursion-candidate",
               str(request_path), str(proof), str(ctx["fixed_setup_bytes"]), str(HOST_BYTES)]
    started = time.monotonic()
    with open(work / "stdout", "wb") as out, open(work / "stderr", "wb") as err:
        proc = subprocess.run(command, stdout=out, stderr=err, env=env, cwd=ctx["cwd"], timeout=1800)
    wall = time.monotonic() - started
    stderr = (work / "stderr").read_text(errors="replace").splitlines()
    first_error = next((line for line in stderr if line.startswith("error") or "error:" in line[:40]), None)
    accepted = False
    same = None
    try:
        stdout = json.loads((work / "stdout").read_text())
        accepted = proc.returncode == 0 and stdout.get("accepted") is True and stdout.get("completed_ethereum_block") is True
        if accepted:
            same = statement(stdout) == ctx["control_statement"]
    except Exception:
        pass
    verdict = "accept" if accepted else "reject"
    if case["expect"] == "accept":
        passed = accepted and same is True
    elif case["expect"] == "reject":
        passed = not accepted
    else:  # reject_or_same_statement
        passed = (not accepted) or same is True
    result.update(status="ran", verdict=verdict, exit_code=proc.returncode, wall_s=round(wall, 2), first_error=first_error,
                  last_stderr=stderr[-1] if stderr else None, same_statement_as_control=same, passed=passed)
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({k: result.get(k) for k in ("id", "verdict", "passed", "exit_code", "wall_s", "first_error")}, default=str), flush=True)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("spec")
    r = sub.add_parser("run")
    r.add_argument("--run", required=True)
    r.add_argument("--donor", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--receiver")
    r.add_argument("--jobs", type=int, default=3)
    r.add_argument("--cases")
    r.add_argument("--work", default="/workspace/m3/scratch/m4-profiles/corpus")
    args = p.parse_args()
    if args.cmd == "spec":
        print(json.dumps({"schema": SCHEMA, "cases": spec()}, indent=1))
        return
    run, donor_run = Path(args.run), Path(args.donor)
    plan, job, proof = proof_dir(run)
    _, djob, donor_proof = proof_dir(donor_run)
    if job["block"] not in DEV_BLOCKS or djob["block"] not in DEV_BLOCKS or job["block"] == djob["block"]:
        raise SystemExit("run and donor must be the two different dev blocks (26235156, 24628607)")
    recv_dir, control_stdout = accepted_receiver_dir(run)
    receiver = Path(args.receiver or plan["assets"]["recursive_receiver"])
    ctx = {"proof": proof, "donor": donor_proof, "request_path": recv_dir / "receiver-request.json", "profile": plan["profile"],
           "receiver": receiver, "fixed_setup_bytes": job["resources"]["fixed_setup_bytes"], "cwd": plan.get("producer_cwd") or "/",
           "control_statement": statement(control_stdout), "work": Path(args.work) / str(job["block"])}
    ctx["work"].mkdir(parents=True, exist_ok=True)
    wanted = set(args.cases.split(",")) if args.cases else None
    runnable = [c for c in CASES if c["today"] == "m3" and (wanted is None or c["id"] in wanted)]
    pending = [{k: v for k, v in c.items() if k != "mutate"} | {"status": "pending"} for c in CASES if c["today"] != "m3"]
    load = os.getloadavg()[0]
    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda c: run_case(c, ctx), runnable))
    receipt = {"schema": SCHEMA, "measured": True, "date": time.strftime("%Y-%m-%dT%H:%M:%S"), "block": job["block"],
               "donor_block": djob["block"], "run": str(run), "proof_dir": str(proof), "donor_proof_dir": str(donor_proof),
               "receiver": str(receiver), "receiver_sha256": sha(receiver), "native_profile": plan["profile"],
               "receiver_env": {"CUDA_VISIBLE_DEVICES": "", "STWO_RV64_GPU_PCS_HELPER": "/bin/false",
                                "STWO_ZIG_RV64_SETUP_CACHE": "unset", "STWO_RV64_FOLD_CLASS_CACHE": "0"},
               "control_statement": ctx["control_statement"], "jobs": args.jobs, "loadavg_1m_start": load,
               "loadavg_1m_end": os.getloadavg()[0], "wall_s": round(time.time() - started, 1),
               "ran": len(results), "passed": sum(1 for x in results if x.get("passed")),
               "unexpected_accepts": [x["id"] for x in results if x.get("verdict") == "accept" and x["expect"] == "reject"],
               "results": results, "pending": pending}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=1, default=str))
    print(json.dumps({k: receipt[k] for k in ("block", "ran", "passed", "unexpected_accepts", "wall_s")}))
    sys.exit(0 if receipt["passed"] == receipt["ran"] else 1)


if __name__ == "__main__":
    main()
