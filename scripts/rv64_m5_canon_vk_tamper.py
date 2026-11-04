#!/usr/bin/env python3
"""canon-vk (M5) adversarial tamper cases for the opt-in recursion formats.

Runs extra cases on top of scripts/rv64_m5_negative_corpus.py (same receiver
argv, same fresh GPU-disabled process per case, same verdict rules). The
corpus runs every receiver with STWO_RV64_FOLD_CLASS_CACHE=0; these cases also
cover the receiver DEFAULT (=1, in-process fold-class reuse), because under a
uniform outer shape every fold shares ONE verification key and the output
digest check is the only barrier between two folds.

  python3 scripts/rv64_m5_canon_vk_tamper.py --run <E6 canonical run> --donor <other block canonical run> \
      --base-env STWO_RV64_OUTER_PROFILE=m5_outer_canonical_r1_b2_q108_p20_fold4_v1 --set canonical --out <receipt>

Sets: canonical (proofs under the named canonical profile), uniform (r1 domain, uniform-v1 shape),
set-v2 (r1 domain, set-v2 shape). Every case except the controls must be rejected cleanly.
"""
import argparse
import concurrent.futures as cf
import json
import os
from pathlib import Path
import shutil
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rv64_m5_negative_corpus as K  # noqa: E402

SCHEMA = "rv64-m5-canon-vk-tamper/v1"
CANON = "m5_outer_canonical_r1_b2_q108_p20_fold4_v1"
CANON_M3 = "m5_outer_canonical_m3_b4_q51_p26_fold4_v1"
R = "recursion-om31"


def env_set(**values):
    def mutate(c):
        for key, value in values.items():
            if value is None:
                c["env"].pop(key, None)
            else:
                c["env"][key] = value
    return mutate


def copy_node(src, dst, donor=False, **env):
    def mutate(c):
        base = c["donor"] if donor else c["proof"]
        shutil.copyfile(base / R / src, c["proof"] / R / dst)
        env_set(**env)(c)
    return mutate


def coherent_root(src, top, **env):
    """Replace the top fold AND root.proof with another fold's proof (same fold VK under a uniform shape)."""
    def mutate(c):
        shutil.copyfile(c["proof"] / R / src, c["proof"] / R / top)
        shutil.copyfile(c["proof"] / R / src, c["proof"] / R / "root.proof")
        env_set(**env)(c)
    return mutate


def both(*fns):
    def mutate(c):
        for fn in fns:
            fn(c)
    return mutate


def case(id, what, mutate, expect="reject"):
    return dict(id=id, family="canon-vk", expect=expect, today="m5", what=what, mutate=mutate)


# 26235156 (11 leaves): binary plan ids fold-000002 = (0,1), fold-000005 = (2,3), fold-000006 = (2,5),
# fold-000019 = left subtree, fold-000020 = root. Under a uniform shape every fold has the same VK.
SETS = {
    "canonical": [
        case("CV00-control-cache0", "unmodified, STWO_RV64_FOLD_CLASS_CACHE=0", env_set(STWO_RV64_FOLD_CLASS_CACHE="0"), "accept"),
        case("CV01-control-cache1", "unmodified, receiver default fold-class reuse (=1)", env_set(STWO_RV64_FOLD_CLASS_CACHE="1"), "accept"),
        case("CV02-same-vk-fold-copy-cache-hit", "fold-000002 copied over fold-000005 (same fold VK); cache=1 so fold-000005 takes the class-hit restore path",
             copy_node("fold-000002.proof", "fold-000005.proof", STWO_RV64_FOLD_CLASS_CACHE="1")),
        case("CV03-same-vk-fold-copy-cache0", "fold-000002 copied over fold-000005 (same fold VK), cache=0",
             copy_node("fold-000002.proof", "fold-000005.proof", STWO_RV64_FOLD_CLASS_CACHE="0")),
        case("CV04-cross-block-fold-cache-hit", "donor block fold-000005 (same fold VK across blocks) over fold-000005, cache=1",
             copy_node("fold-000005.proof", "fold-000005.proof", donor=True, STWO_RV64_FOLD_CLASS_CACHE="1")),
        case("CV05-coherent-root-cache-hit", "fold-000019 over fold-000020 AND root.proof (root replaced by an inner fold of the same VK), cache=1",
             coherent_root("fold-000019.proof", "fold-000020.proof", STWO_RV64_FOLD_CLASS_CACHE="1")),
        case("CV06-leaf-over-fold", "leaf-000004 over fold-000005 (same S_OUT_V1 shape, different circuit)",
             copy_node("leaf-000004.proof", "fold-000005.proof")),
        case("CV07-fold-over-leaf", "fold-000002 over leaf-000003 (same S_OUT_V1 shape, different circuit)",
             copy_node("fold-000002.proof", "leaf-000003.proof")),
        case("CV08-receiver-r1-uniform", "receiver r1 + STWO_RV64_OUTER_SHAPE=uniform-v1 (same PCS and shape, other domain)",
             env_set(STWO_RV64_OUTER_PROFILE="r1_b2_q108_p20_fold4", STWO_RV64_OUTER_SHAPE="uniform-v1")),
        case("CV09-receiver-canonical-exact", "receiver canonical + STWO_RV64_OUTER_SHAPE=exact (must refuse cleanly)",
             env_set(STWO_RV64_OUTER_SHAPE="exact")),
        case("CV10-receiver-canonical-set-v2", "receiver canonical + STWO_RV64_OUTER_SHAPE=set-v2 (must refuse cleanly)",
             env_set(STWO_RV64_OUTER_SHAPE="set-v2")),
        case("CV11-receiver-arity-3", "receiver canonical + STWO_RV64_FOLD_ARITY=3", env_set(STWO_RV64_FOLD_ARITY="3")),
        case("CV12-receiver-arity-4", "receiver canonical + STWO_RV64_FOLD_ARITY=4", env_set(STWO_RV64_FOLD_ARITY="4")),
        case("CV13-receiver-canonical-m3", "receiver selects the canonical m3 profile", env_set(STWO_RV64_OUTER_PROFILE=CANON_M3)),
        case("CV14-receiver-arity-garbage", "STWO_RV64_FOLD_ARITY=2x (clean error, no panic)", env_set(STWO_RV64_FOLD_ARITY="2x")),
    ],
    "uniform": [
        case("CU00-control", "unmodified uniform-v1 proofs, r1 receiver with uniform-v1", env_set(), "accept"),
        case("CU01-receiver-canonical", "receiver canonical r1 (same PCS + shape, canonical domain)",
             env_set(STWO_RV64_OUTER_PROFILE=CANON, STWO_RV64_OUTER_SHAPE=None)),
        case("CU02-receiver-set-v2", "receiver r1 set-v2", env_set(STWO_RV64_OUTER_SHAPE="set-v2")),
        case("CU03-receiver-exact-cache1", "receiver r1 exact, cache=1", env_set(STWO_RV64_OUTER_SHAPE=None, STWO_RV64_FOLD_CLASS_CACHE="1")),
        case("CU04-same-vk-fold-copy-cache-hit", "fold-000002 over fold-000005 (same VK), cache=1",
             copy_node("fold-000002.proof", "fold-000005.proof", STWO_RV64_FOLD_CLASS_CACHE="1")),
    ],
    "set-v2": [
        case("CS00-control", "unmodified set-v2 proofs, r1 receiver with set-v2", env_set(), "accept"),
        case("CS01-receiver-uniform", "receiver r1 uniform-v1", env_set(STWO_RV64_OUTER_SHAPE="uniform-v1")),
        case("CS02-receiver-exact", "receiver r1 exact", env_set(STWO_RV64_OUTER_SHAPE=None)),
        case("CS03-same-class-fold-copy-cache-hit", "fold-000002 over fold-000005 (same set-v2 class), cache=1",
             copy_node("fold-000002.proof", "fold-000005.proof", STWO_RV64_FOLD_CLASS_CACHE="1")),
    ],
}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--run", required=True)
    p.add_argument("--donor", required=True)
    p.add_argument("--set", required=True, choices=sorted(SETS))
    p.add_argument("--base-env", action="append", default=[], help="KEY=VALUE for the producer policy (also the receiver default)")
    p.add_argument("--out", required=True)
    p.add_argument("--receiver")
    p.add_argument("--jobs", type=int, default=3)
    p.add_argument("--cases")
    p.add_argument("--cwd", help="receiver cwd (default: the plan's producer_cwd)")
    p.add_argument("--work", default="/workspace/m3/scratch/m5-canon-vk/tamper")
    args = p.parse_args()
    for item in args.base_env:
        key, _, value = item.partition("=")
        os.environ[key] = value
    run, donor_run = Path(args.run), Path(args.donor)
    plan, job, proof = K.proof_dir(run)
    _, djob, donor_proof = K.proof_dir(donor_run)
    if job["block"] not in K.DEV_BLOCKS or djob["block"] not in K.DEV_BLOCKS or job["block"] == djob["block"]:
        raise SystemExit("run and donor must be the two different dev blocks")
    recv_dir, control_stdout = K.accepted_receiver_dir(run)
    receiver = Path(args.receiver or plan["assets"]["recursive_receiver"])
    ctx = {"proof": proof, "donor": donor_proof, "request_path": recv_dir / "receiver-request.json", "profile": plan["profile"],
           "receiver": receiver, "fixed_setup_bytes": job["resources"]["fixed_setup_bytes"], "cwd": args.cwd or plan.get("producer_cwd") or "/",
           "control_statement": K.statement(control_stdout), "work": Path(args.work) / f"{job['block']}-{args.set}"}
    ctx["work"].mkdir(parents=True, exist_ok=True)
    wanted = set(args.cases.split(",")) if args.cases else None
    cases = [c for c in SETS[args.set] if wanted is None or c["id"] in wanted]
    load = os.getloadavg()[0]
    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda c: K.run_case(c, ctx), cases))
    receipt = {"schema": SCHEMA, "measured": True, "date": time.strftime("%Y-%m-%dT%H:%M:%S"), "set": args.set, "block": job["block"],
               "donor_block": djob["block"], "run": str(run), "donor_run": str(donor_run), "receiver": str(receiver),
               "receiver_sha256": K.sha(receiver), "base_env": args.base_env,
               "receiver_env_overrides": "per case (see what); corpus baseline CUDA_VISIBLE_DEVICES='' STWO_RV64_FOLD_CLASS_CACHE=0",
               "control_statement": ctx["control_statement"], "jobs": args.jobs, "loadavg_1m_start": load,
               "loadavg_1m_end": os.getloadavg()[0], "wall_s": round(time.time() - started, 1), "ran": len(results),
               "passed": sum(1 for x in results if x.get("passed")),
               "unexpected_accepts": [x["id"] for x in results if x.get("verdict") == "accept" and x["expect"] == "reject"],
               "crashes": [x["id"] for x in results if x.get("verdict") == "crash"], "results": results}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=1, default=str))
    print(json.dumps({k: receipt[k] for k in ("set", "block", "ran", "passed", "unexpected_accepts", "crashes", "wall_s")}))
    sys.exit(0 if receipt["passed"] == receipt["ran"] else 1)


if __name__ == "__main__":
    main()
