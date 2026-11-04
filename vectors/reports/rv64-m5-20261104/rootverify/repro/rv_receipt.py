#!/usr/bin/env python3
"""Assemble rootverify receipts (one per dev block) from the pod outputs."""
import hashlib, json, re, sys
from pathlib import Path
S = Path("/workspace/m3/scratch/m5-rootverify")
RUNS = Path("/workspace/m3/runs/m5-rootverify")
OUT = RUNS / "receipts"; OUT.mkdir(exist_ok=True)
R = Path("/workspace/m3/build/m5-rootverify/zig-out/bin/rv64-word16-ethereum-recursion-receiver")
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(p): return json.loads(Path(p).read_text())
log = (RUNS / "go-all.log").read_text()
walls = {m.group(1): (float(m.group(3)) if m.group(3) else None, float(m.group(2))) for m in re.finditer(r"== (\S+) load=([\d.]+) [\d:]+\nexit=0 wall=([\d.]*)", log)}
commit = (Path("/workspace/m3/src/m5-rootverify/.m3-commit").read_text().strip())
for b in ("26235156", "24628607"):
    base = load(RUNS / f"{b}-2gpu-m4base/receipt.json")
    proc = base["receiver"]["process"]
    verify = [load(S / f"out/verify-{b}-r{i}.json") for i in (1, 2)]
    audit = load(S / f"out/audit-{b}.json")
    derive = load(S / f"out/derive-{b}.json")
    corpus = load(RUNS / f"corpus-{b}.json") if (RUNS / f"corpus-{b}.json").exists() else None
    pv3 = load(RUNS / f"profiles-v3-m5root-{b}.json") if (RUNS / f"profiles-v3-m5root-{b}.json").exists() else None
    receipt = {
        "schema": "rv64-m5-rootverify-receipt/v1", "label": "measured", "stream": "rootverify", "milestone": "M5", "block": int(b),
        "commit": commit, "receiver_sha256": sha(R), "proof_source": "M4 integrate binaries a9acb639 (driver) / 5886e2a5 (lib); format unchanged",
        "proof_dir": str(next((RUNS / f"{b}-2gpu-m4base/case/batch/trial-0/{b}").glob("proof"))), "root_proof_bytes": (next((RUNS / f"{b}-2gpu-m4base/case/batch/trial-0/{b}").glob("proof")) / "recursion-om31/root.proof").stat().st_size,
        "table": {"path": str(S / "tables/vk-both.json"), "sha256": sha(S / "tables/vk-both.json"), "profile": "rv64-m4-fold-v2-compat/v0", "bytes": (S / "tables/vk-both.json").stat().st_size, "entries": load(S / "tables/vk-both.json")["entries"].__len__()},
        "root_only": [{"process_wall_s": walls.get(f"verify-{b}-r{i+1}", (None, None))[0], "loadavg_1m_start": walls.get(f"verify-{b}-r{i+1}", (None, None))[1],
                       "verify_per_block_s": round(v["verify_per_block_ns"] / 1e9, 3), "breakdown_s": {k[:-3]: round(x / 1e9, 4) for k, x in v["breakdown"].items()},
                       "proofs_verified": v["proofs_verified"], "leaves": v["leaves"], "folds": v["folds"], "root_digest": v["root_digest"], "root_identity": v["root_identity"], "output": v["output"]} for i, v in enumerate(verify)],
        "audit": {"process_wall_s": walls.get(f"audit-{b}", (None, None))[0], "loadavg_1m_start": walls.get(f"audit-{b}", (None, None))[1], "agrees": audit["audit"]["agrees"],
                  "native_verify_s": round(audit["audit"]["native_verify_ns"] / 1e9, 3), "recursion_s": round(audit["audit"]["recursion_ns"] / 1e9, 3)},
        "baseline_m4_receiver": {"binary_sha256": base["receiver"]["receiver_sha256"], "mode": "verify-recursion-candidate (harness receive)", "process_wall_s": round(proc["wall_ns"] / 1e9, 3),
                                 "user_s": proc["user_seconds"], "peak_rss_gib": round(proc["peak_rss_bytes"] / 2**30, 2), "accepted": base["receiver"]["accepted"]},
        "derive_once": {"process_wall_s": walls.get(f"derive-{b}", (None, None))[0], "derive_once_s": round(derive["derive_once_ns"] / 1e9, 3), "new_leaf_classes": derive["new_leaf_classes"], "new_fold_classes": derive["new_fold_classes"],
                        "fold_reimplementation_cross_checks": derive["fold_reimplementation_cross_checks"], "breakdown_s": {k[:-3]: round(x / 1e9, 3) for k, x in derive["breakdown"].items()}},
        "corpus": None if corpus is None else {k: corpus[k] for k in ("ran", "passed", "reject_expected", "rejected_where_reject_expected", "accepted_same_statement", "unexpected_accepts", "crashes", "nonsemantic_rejects", "control_verify_per_block_s", "loadavg_1m_start", "wall_s")},
        "profiles_corpus_v3_m5_root": None if pv3 is None else {k: pv3.get(k) for k in ("schema", "ran", "passed", "unexpected_accepts", "crashes", "nonsemantic_rejects", "wall_s", "loadavg_1m_start")},
        "stale_table_refused": "VkTableNotDerivedByThisReceiver (table of receiver 48ba61f9 offered to f5f7ec5e)",
        "gate": {"verify_per_block_le_1_5_s": False, "audit_agrees": audit["audit"]["agrees"], "negative_corpus_all_pass": None if corpus is None else corpus["passed"] == corpus["ran"], "profiles_corpus_all_pass": None if pv3 is None else pv3.get("passed") == pv3.get("ran")},
    }
    (OUT / f"{b}-rootonly.json").write_text(json.dumps(receipt, indent=1))
    print(b, json.dumps({"root_only": [r["verify_per_block_s"] for r in receipt["root_only"]], "audit": receipt["audit"]["process_wall_s"], "base": receipt["baseline_m4_receiver"]["process_wall_s"], "corpus": receipt["corpus"] and (receipt["corpus"]["passed"], receipt["corpus"]["ran"]), "pv3": receipt["profiles_corpus_v3_m5_root"] and (receipt["profiles_corpus_v3_m5_root"]["passed"], receipt["profiles_corpus_v3_m5_root"]["ran"])}))
