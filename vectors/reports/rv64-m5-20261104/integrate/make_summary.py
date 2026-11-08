#!/usr/bin/env python3
"""M5 integrate: build vectors/reports/rv64-m5-20261104/summary.json from the receipts in this directory
(copied back from /workspace/m3/runs/m5-integrate and /workspace/m3/scratch/m5-integrate) and, with --ledger,
append progress rows to vectors/reports/progress/integrate.jsonl (run --ledger exactly once per data set).

Configs:
  (a)  proof-neutral, old format (r1 exact binary outer, flat native digest): byte-identical to M4 (= M3)
  (a22) same with STWO_RV64_DEVICE_ARENA=22G
  (b)  M5 format available today: canonical outer profile m5_outer_canonical_r1_b2_q108_p20_fold4_v1
       (uniform-v1 shape, one fold VK), receiver = derive-vk-tables once + root-only verify pinned with --table-root."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
M3 = json.load(open(REPO / "vectors/reports/rv64-m3-20261104/summary.json"))
M4 = json.load(open(REPO / "vectors/reports/rv64-m4-20261104/summary.json"))
COMMIT = sys.argv[sys.argv.index("--commit") + 1] if "--commit" in sys.argv else "HEAD"
DATE = "2026-11-04"
RECEIVER_V2_COMMIT = "573a85445"  # root-only receiver v2 (P03 fix); producer binaries + receiver v1 from --commit
BLOCKS = (26235156, 24628607)
# Plan section 5: M5 row of the cumulative trajectory (24628607) and the M5 exit gate.
PLAN_M5 = {"request_s": "22-26", "capture_s": "1.5", "setup_s": "<=0.5 (block independent +-10%)", "native_s": "8-9",
           "recursion_s": "15-18", "verifier_s": "<=1.5 per block", "derive_vk_tables_once_s": "<=30",
           "rss_request_private_gib": "8-10", "proof": "about 700 KB", "host_prep_per_node_s": "<=0.1",
           "distinct_leaf_topologies": "<= families x rungs"}
PLAN_M7_FINAL = {"request_s": "6-8", "capture_s": "0.4-0.6", "setup_s": "<=0.5", "native_s": "1.0-1.5",
                 "recursion_s": "2.5-4", "verifier_s": "<=1", "rss_request_private_gib": "3-5", "proof": "90-110 KB"}


def load(name):
    p = HERE / name
    return json.load(open(p)) if p.is_file() else None


def gib(b):
    return round(b / 2**30, 2) if b else None


def daemon_rows(name, config):
    r = load(name)
    if r is None:
        return []
    verdicts = {(v["block"], v.get("trial")): v for v in r.get("receivers", [])}
    peaks = (r.get("physical_gpu_memory") or {}).get("peak_used_bytes") or {}
    out = []
    for q in r["requests"]:
        s = q["stages"]
        v = verdicts.get((q["block"], q["trial"]))
        par = q.get("parity_vs_m3") or {}
        out.append({"receipt": name, "config": config, "block": q["block"], "position": q["ordinal"], "trial": q["trial"],
                    "request_s": s["request_wall_s"], "capture_s": s["capture_s"], "setup_s": s["setup_s"],
                    "native_s": s["native_prove_s"], "recursion_s": s["recursion_s"],
                    "verifier_s": round(v["process"]["wall_ns"] / 1e9, 1) if v else None,
                    "verifier_kind": "full-tree receiver (verify-recursion-candidate)" if v else None,
                    "receiver_accepted": v["accepted"] if v else None,
                    "service_rss_peak_gib": gib(r["producer_process"].get("peak_rss_bytes")),
                    "device_peak_gb": round(max(peaks.values()) / 1e9, 2) if peaks else None,
                    "proof_bytes": q.get("proof_bytes_root"),
                    "byte_identical_to_m3": bool(par.get("byte_identical")),
                    "service_start_s": r.get("service_start_s"), "loadavg_1m": round(r["load_avg_before"][0], 1)})
    return out


def oneshot_row(name, config):
    v = load(name)
    if v is None:
        return None
    s = v["stages"]
    c = v.get("counters") or {}
    corr = v["correctness"]
    fp = corr.get("fingerprint_vs_reference") or {}
    rec = corr.get("receiver") or {}
    return {"receipt": name, "config": config, "block": v["block"], "request_s": s["request_s"], "capture_s": s["capture_s"],
            "setup_s": s["setup_s"], "native_s": s["native_s"], "recursion_s": s["recursion_s"],
            "fold_tail_after_last_leaf_s": s.get("fold_tail_after_last_leaf_s"),
            "verifier_s": (v.get("verifier") or {}).get("verify_per_block_s"),
            "receiver_accepted": rec.get("accepted"),
            "rss_peak_gib": (v.get("ram") or {}).get("rss_peak_daemon_gib"),
            "rss_request_private_gib": (v.get("ram") or {}).get("rss_peak_request_private_gib"),
            "device_peak_gb": max((v.get("device_memory") or {}).get("device_peak_gb", {}).values() or [None]),
            "proof_bytes": (v.get("proof_size") or {}).get("proof_bytes_root"),
            "byte_identical_to_m3": bool(fp.get("identical")) if fp else None, "hashes_compared": fp.get("compared"),
            "syncs": c.get("sync_total"), "launches": c.get("kernel_launches"), "pool_mallocs": c.get("pool_mallocs"),
            "library_loads": c.get("library_loads"), "pageable_copies": c.get("pageable_copies"),
            "pageable_copy_gb": round(c["pageable_copy_bytes"] / 1e9, 1) if c.get("pageable_copy_bytes") else (0.0 if c else None),
            "loadavg_1m": v["loadavg"]["start"]["1m"]}


def rootonly(tag):
    d = HERE / f"rootonly-{tag}"
    if not d.is_dir():
        return None
    out = {"dir": d.name}
    rss = lambda n: (lambda p: round(int(p.read_text()) / 2**20, 2) if p.is_file() else None)(d / f"out/{n}.stderr.rss")
    walls, loads = {}, {}
    log = d / "gate-broot.log"
    if log.is_file():
        name = None
        for line in log.read_text().splitlines():
            if line.startswith("== ") and " load=" in line:
                name = line[3:].split(" load=")[0].strip()
                loads[name] = float(line.split(" load=")[1].split()[0])
            elif line.startswith("exit=") and name and " wall=" in line:
                walls[name] = float(line.split(" wall=")[1].split()[0])
    out["process_wall_s"] = walls
    out["loadavg_1m_at_start"] = loads
    derive = {}
    for n in ("derive-26235156", "derive-24628607", "derive-both"):
        j = load(f"{d.name}/out/{n}.json")
        if j:
            derive[n] = {"derive_once_s": round(j["derive_once_ns"] / 1e9, 2), "entries": j["entries"],
                         "new_leaf_classes": j["new_leaf_classes"], "new_fold_classes": j["new_fold_classes"],
                         "root_identity": j["root_identity"], "table_root": j["table_root"],
                         "root_only_self_check": j["root_only_self_check"], "audit_accepted": j["audit_accepted"],
                         "maxrss_gib": rss(n), "process_wall_s": walls.get(n)}
    out["derive"] = derive
    verify = []
    for b in BLOCKS:
        for rep in (1, 2):
            n = f"verify-pinned-{b}-r{rep}"
            j = load(f"{d.name}/out/{n}.json")
            if j:
                verify.append({"block": b, "rep": rep, "accepted": j["accepted"], "table_root_pinned": j["table_root_pinned"],
                               "verify_per_block_s": round(j["verify_per_block_ns"] / 1e9, 2), "process_wall_s": walls.get(n),
                               "loadavg_1m": loads.get(n), "proofs_verified": j["proofs_verified"],
                               "root_identity": j["root_identity"], "root_digest": j["root_digest"],
                               "breakdown_s": {k: round(v / 1e9, 3) for k, v in (j.get("breakdown") or {}).items()},
                               "maxrss_gib": rss(n)})
    out["verify_root_only"] = verify
    audit = []
    for b in BLOCKS:
        j = load(f"{d.name}/out/audit-{b}.json")
        if j:
            audit.append({"block": b, "accepted": j["accepted"], "audit": j.get("audit"),
                          "verify_per_block_s": round(j["verify_per_block_ns"] / 1e9, 2), "maxrss_gib": rss(f"audit-{b}"),
                          "process_wall_s": walls.get(f"audit-{b}")})
    out["audit"] = audit
    corp = {}
    for b in BLOCKS:
        for kind in ("rv", "pc"):
            j = load(f"{d.name}/{kind}-corpus-{b}.json")
            if j:
                failed = [c["id"] for c in j.get("results", []) if not c.get("passed")]
                corp[f"{kind}-{b}"] = {"ran": j["ran"], "passed": j["passed"], "unexpected_accepts": j["unexpected_accepts"],
                                       "crashes": j["crashes"], "failed": failed,
                                       "receiver_sha256": j.get("receiver_sha256")}
    out["corpus"] = corp
    return out


MERGED = {"platform": "f6c4f3d4c (fast-forward)", "capture": "26a18f94c", "profiles": "9fe0ae381", "canon-vk": "aa0761d4e",
          "rootverify": "955445de6 (build files unioned; adapted to canon-vk A2: protocol.domain -> domainName())",
          "outer-gkr": "c6a9659dc (new files; section not wired into any prover/receiver)",
          "blake-gadget": "72a77871e (AIR + fill kernel; proof-neutral shadow/check flag only)"}
NOT_MERGED = {"canon-native": "3ab539067: review left A1 (high) unfixed -- chi-chain vkhash hashes the segment's own declaration "
                              "vector while T_nat hashes the rung vector, so no T_nat leaf can hold it; needs a v2/re-freeze + fresh "
                              "acceptance. Carried to M6."}
INTEGRATION_FIXES = [
    "root_verify{,_main}.zig: Om31.protocol.domain (renamed r1_domain by canon-vk A2) -> protocol.domainName() for class/leaf keys "
    "and the table header outer_domain (canonical tables now say m5-canonical-q108-p20-fold4) [M]",
    "root-only entry (derive-vk-tables / verify-root-candidate) is dispatched before gkr_main.runArguments, so canon-vk's "
    "checkPolicyEnv never ran: corpus P03 crashed (exit -6) on both blocks with receiver 0babaf7e; now calls "
    "execution_wrap.checkPolicyEnv() first; receiver v2 7c8e05f0 rejects P03 cleanly [M]",
    "corpus C01 (explicit-profile control) follows the caller's STWO_RV64_OUTER_PROFILE (an explicit r1 receiver correctly "
    "rejects canonical proofs with VkTableOuterProfileMismatch [M]); unchanged for r1 runs",
    "default config set in code: scripts/rv64_m3_pod.py DEFAULT_PRODUCER_ENV applied by prove/bench/daemon (--no-default-env "
    "opts out); daemon-a6-default.json byte-identical",
]
DEFAULT = {
    "producer": "config (a): old proof format (outer r1_b2_q108_p20_fold4, exact shape, binary folds, flat native manifest "
                "digest) + DEFAULT_PRODUCER_ENV {NARROW_RUNS=1, CPU_REPLAY=1, CORE_SINGLE_STREAM=1, DEVICE_ARENA=1 (auto)}; "
                "pinned staging and arena are on by code default (platform)",
    "why_not_b": "canonical outer profile costs +7-13% recursion and +5.6% proof bytes on 24628607 [M]; its constant fold VK "
                 "does not shorten the verifier today (root-only works on old-format proofs too: rootverify 10.0-14.9 s on M4 "
                 "proofs); root-only acceptance under table profile rv64-m4-fold-v2-compat/v0 rests on the leaf-class premise. "
                 "Promote once canonical leaves + fold v3 land.",
    "arena": "auto (31.5 GB/GPU); 22G (27.81 GB/GPU, byte-identical) stays opt-in: platform A/B measured +0.5-1 s/request on 607",
    "receiver": "full-tree receiver is the acceptance path; derive-vk-tables + verify-root-candidate --table-root <pin> available "
                "(accepted every honest proof, corpora pass); STWO_RV64_FOLD_CLASS_CACHE=1 judged admissible (receiver-built, "
                "requireDigest holds on the hit path per canon-vk review N3) but the acceptance harness still forces it off",
}
PLAN_GATES = {
    "verifier_per_block_le_1.5s": "NOT met: root-only 9.5-13.8 s; OM31 root verify 12 ms, the rest is native keys (5.0-7.4 s) + "
                                  "native FIXED authority (3.2-4.7 s) for receiver-side admission",
    "derive_vk_tables_le_30s": "NOT met: 30.7 s (26235156), 45.2 s (24628607), merge 45.0 s",
    "setup_block_independent_10pct": "NOT met by construction: warm hit path 0.127-0.155 s, 607 vs 156 gap 12-15% (a) / 5-9% (b); "
                                     "seed 4.74 vs 5.43 s; native class set is per block until canon-native strict roster",
    "distinct_leaf_topologies_le_families_x_rungs": "NOT met: 27 leaf classes for 28 leaves; fold classes constant (1) under canonical",
    "host_prep_le_0.1s_per_node": "NOT met (canon-vk: folds 0.47-0.66 s, leaves ~2 s)",
    "audit_agrees": "met on both blocks (same root digest + authority)",
    "negative_corpus_all_rejected": "met for every runnable (R-tier) case; 57 in-circuit M5/M7 cases pending (formats not wired)",
}
M6_ENTRY = [
    "canon-native first: fix A1 (strict roster so vkhash == T_nat leaf), re-freeze/bump chi-chain, fresh acceptance + corpus, merge; "
    "unlocks block-independent setup, the native VK table (-8..-12 s on the root-only verifier [D]) and canonical leaves",
    "fold v3 in circuit (canon-vk): T_rec membership, NS interval chain (seg_lo range check), PCD self-VK -> root-only becomes "
    "acceptance without --audit",
    "wire outer-GKR + fused Blake (named M7 profiles; OG2 / blake-gadget 8.4b), one fused instance per node, ship together",
    "M6 pipeline (no protocol change): remove the canon-vk class-PP RSS regression (+5.4 GiB service peak), 22 GiB carve once "
    "concurrent nodes need it, terminal-fence timing reads; 223k launches/request is the CUDA-graph / hint-tape lever",
    "capture 2.1-2.7 s vs 1.5: walk init + batch-0 traced walk + serial ledger; M7 traced emitter",
]


def main():
    rows = {
        "a_seed_fresh_store": daemon_rows("daemon-a1-seed.json", "(a) service, empty store (cold setup)"),
        "a_warm_boot": daemon_rows("daemon-a2-warm.json", "(a) service, store reuse, --warm boot"),
        "a22_warm_boot": daemon_rows("daemon-a3-warm22.json", "(a22) service, --warm boot, STWO_RV64_DEVICE_ARENA=22G"),
        "a_default_env": daemon_rows("daemon-a6-default.json", "(a) service, --warm boot, harness DEFAULT_PRODUCER_ENV (no --env)"),
        "a_nsys": daemon_rows("daemon-a5-nsys.json", "(a) service, --warm boot, under nsys (timing not quotable)"),
        "b_warm_boot": daemon_rows("daemon-b2-canon-warm.json", "(b) service, --warm boot, canonical outer profile"),
        "a_counters": [x for x in (oneshot_row(f"{b}-a4-counters.json", "(a) one-shot, no store, counter shim + smaps")
                                   for b in BLOCKS) if x],
        "b_bench": [x for x in (oneshot_row(f"{b}-b1-canon-bench.json", "(b) one-shot, no store, canonical outer profile")
                                for b in BLOCKS) if x],
        "scale_probe": [x for x in [oneshot_row("24697070-s1-scale.json", "default config, one-shot, no store (cold)")] if x],
    }
    nsys = load("daemon-a5-nsys-per-request.json") or []
    ro = rootonly("b1-canon-rv2")
    ro_v1 = rootonly("b1-canon")
    head = {}
    for block in BLOCKS:
        m3 = next(r for r in M3["rows"] if r["block"] == block)
        m4 = M4["headline"][str(block)]
        aw = [r for r in rows["a_warm_boot"] if r["block"] == block]
        bw = [r for r in rows["b_warm_boot"] if r["block"] == block]
        a22 = [r for r in rows["a22_warm_boot"] if r["block"] == block]
        seed = [r for r in rows["a_seed_fresh_store"] if r["block"] == block]
        cnt = next((r for r in rows["a_counters"] if r["block"] == block), {})
        ns = next((r for r in nsys if r["block"] == block), None)
        ver = [v["process_wall_s"] for v in (ro or {}).get("verify_root_only", []) if v["block"] == block]
        head[str(block)] = {
            "m3": {k: m3[k] for k in ("request_s", "capture_s", "setup_s", "native_prove_s", "recursion_s", "receiver_wall_s",
                                       "producer_peak_rss_gib")},
            "m4_warm_first": {k: m4["m4_warm_first"][k] for k in ("request_s", "capture_s", "setup_s", "native_s", "recursion_s",
                                                                   "verifier_s", "service_rss_peak_gib", "device_peak_gb",
                                                                   "proof_bytes")},
            "m4_counters": m4["counters_per_request"],
            "m5_a_warm": aw, "m5_a22_warm": a22, "m5_b_warm": bw, "m5_a_seed": seed,
            "m5_a_counters": {k: cnt.get(k) for k in ("syncs", "launches", "pool_mallocs", "library_loads", "pageable_copies",
                                                      "pageable_copy_gb", "rss_peak_gib", "rss_request_private_gib",
                                                      "device_peak_gb")},
            "m5_b_root_only_verify_s": ver,
            "nsys_per_request_in_service": ns,
            "speedup_request_vs_m3_a_first": round(m3["request_s"] / aw[0]["request_s"], 2) if aw else None,
            "speedup_request_vs_m4_a_first": round(m4["m4_warm_first"]["request_s"] / aw[0]["request_s"], 2) if aw else None,
            "speedup_verifier_vs_m4_b": round(m4["m4_warm_first"]["verifier_s"] / min(ver), 2) if ver else None,
        }
    summary = {
        "schema": "rv64-m5-summary/v1", "date": DATE, "source_commit": COMMIT, "branch": "codex/rv64-m5-integrate",
        "assets": {k: (load("build.json") or {}).get(k) for k in ("driver_sha256", "library_sha256", "receiver_sha256")},
        "receiver_v2_sha256": (load("receiver-v2.json") or {}).get("receiver_sha256"),
        "label": "measured single observations [M] unless noted; pod 1-min load 9-37 (protocol quiet bar is 8): not quiet-host quotable",
        "merged_streams": MERGED, "not_merged": NOT_MERGED, "integration_fixes": INTEGRATION_FIXES,
        "default_config": DEFAULT, "plan_m5_exit_gates": PLAN_GATES, "m6_entry": M6_ENTRY,
        "full_tree_corpus_canonical": {b: (lambda j: j and {"ran": j["ran"], "passed": j["passed"],
                                                            "unexpected_accepts": j["unexpected_accepts"], "crashes": j["crashes"]})(
                                           load(f"fullcorpus-b1-canon/pc-full-corpus-{b}.json")) for b in BLOCKS},
        "summary_md_note": "SUMMARY.md not written: file writes of .md reports are blocked in this agent context; this JSON "
                           "plus the commit message and the PR #314 comment carry the summary",
        "plan_m5_targets_24628607": PLAN_M5, "plan_m7_final_24628607": PLAN_M7_FINAL,
        "headline": head, "root_only": ro, "root_only_receiver_v1_pre_p03_fix": ro_v1 and ro_v1["corpus"], "rows": rows,
        "tests": (HERE / "tests.log").read_text().splitlines() if (HERE / "tests.log").is_file() else None,
    }
    json.dump(summary, open(HERE.parent / "summary.json", "w"), indent=1)
    print(json.dumps({b: {"a": [r["request_s"] for r in h["m5_a_warm"]], "b": [r["request_s"] for r in h["m5_b_warm"]],
                          "verify_root_only": h["m5_b_root_only_verify_s"]} for b, h in head.items()}))
    if "--ledger" in sys.argv:
        out = REPO / "vectors/reports/progress/integrate.jsonl"
        with open(out, "a") as f:
            for key, rs in rows.items():
                for r in rs:
                    row = {"date": DATE, "commit": COMMIT, "stream": "integrate", "milestone": "M5", "block": r["block"],
                           "gpus": 2, "label": "M", "config": f"{key}: {r['config']}",
                           "receipt": f"vectors/reports/rv64-m5-20261104/integrate/{r['receipt']}",
                           "loadavg_1m": r["loadavg_1m"],
                           "byte_identical_to": "M3 integrate scale receipt (= M4)" if r.get("byte_identical_to_m3") else None}
                    for k in ("request_s", "capture_s", "setup_s", "native_s", "recursion_s", "verifier_s", "receiver_accepted",
                              "device_peak_gb", "proof_bytes", "syncs", "launches", "pool_mallocs", "library_loads",
                              "pageable_copies", "rss_request_private_gib"):
                        if r.get(k) is not None:
                            row[k] = r[k]
                    rss = r.get("rss_peak_gib", r.get("service_rss_peak_gib"))
                    if rss is not None:
                        row["rss_peak_gib"] = rss
                    f.write(json.dumps(row) + "\n")
            if ro:
                for v in ro["verify_root_only"]:
                    f.write(json.dumps({"date": DATE, "commit": RECEIVER_V2_COMMIT, "stream": "integrate", "milestone": "M5", "block": v["block"],
                                        "gpus": 2, "label": "M", "config": "(b) root-only verify-root-candidate --table-root (fresh CPU-only process)",
                                        "receipt": f"vectors/reports/rv64-m5-20261104/integrate/{ro['dir']}",
                                        "verifier_s": v["process_wall_s"], "receiver_accepted": v["accepted"],
                                        "rss_peak_gib": v["maxrss_gib"],
                                        "loadavg_1m": v["loadavg_1m"], "notes": f"rep {v['rep']}; CPU-only fresh receiver of the 2-GPU canonical proof; derive-vk-tables once reported separately"}) + "\n")


if __name__ == "__main__":
    main()
