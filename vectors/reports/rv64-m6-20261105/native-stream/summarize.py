"""Summarize native-stream daemon runs (pod): per request stages, byte identity, native schedule spans,
retained/replayed CPU workers, and the native-window H2D bytes from GPU_STAGING_SUMMARY deltas.

  python3 summarize.py RUN_DIR [RUN_DIR...] > out.json
"""
import json, re, sys
from pathlib import Path

STAGING = re.compile(r"^GPU_STAGING_SUMMARY .*?staged_h2d_bytes=(\d+)")


def spans(proof):
    s = json.loads((proof / "schedule.json").read_text())
    out = {}
    for phase in ("stage1", "stage2"):
        rows = s.get(phase) or []
        if not rows:
            continue
        out[phase + "_span_s"] = round(max(r["finished_ns"] for r in rows) / 1e9, 3)
        dev = {}
        for i, r in enumerate(rows):
            dev.setdefault(i % 2, 0)
            dev[i % 2] += r["finished_ns"] - r["started_ns"]
        out[phase + "_worker_s_by_device"] = {str(k): round(v / 1e9, 3) for k, v in dev.items()}
        out[phase + "_lanes"] = sorted({r["lane"] for r in rows})
    return out


def requests_log(run):
    """Split producer.stderr into per-request chunks at GPU_RESIDENT_BLOCK markers (printed at request end)."""
    chunks, cur = [], []
    for line in (run / "producer.stderr").read_text(errors="replace").splitlines():
        cur.append(line)
        if line.startswith("GPU_RESIDENT_BLOCK "):
            chunks.append(cur)
            cur = []
    return chunks


def main():
    out = []
    for arg in sys.argv[1:]:
        run = Path(arg)
        receipt = json.loads((run / "receipt.json").read_text())
        chunks = requests_log(run)
        env = receipt.get("environment", {})
        for q, chunk in zip(receipt["requests"], chunks):
            proof = Path(q["proof"]) / "proof" if (Path(q["proof"]) / "proof").is_dir() else Path(q["proof"])
            native = [l for l in chunk if "pipelined recursion:" in l]
            cut = chunk.index(native[0]) if native else len(chunk)
            pre = chunk[:cut]
            staged = [int(m.group(1)) for l in pre if (m := STAGING.match(l))]
            row = {"run": run.name, "block": q["block"], "trial": q["trial"], "stages": q["stages"],
                   "byte_identical_to_m3_m5": (q.get("parity_vs_m3") or {}).get("byte_identical"),
                   "proof_bytes_root": q.get("proof_bytes_root"),
                   "retained_cpu_workers": sum(l.startswith("GPU_CPU_REPLAY_RETAIN") for l in pre),
                   "replayed_cpu_workers": sum(l.startswith("GPU_CPU_REPLAY_RESTORED") for l in pre),
                   "cpu_projection_uploads": sum(l.startswith("GPU_CPU_PROJECTION") for l in pre),
                   "staging_h2d_summary_bytes_seen": staged[-4:] if staged else [],
                   "schedule": receipt.get("schedule") or None,
                   "env": {k: v for k, v in env.items() if k.startswith("STWO_RV64_") and "LIBRARY" not in k and "CACHE" not in k and "STORE" not in k}}
            try:
                row.update(spans(proof))
            except Exception as error:  # spool pruned
                row["spans_error"] = repr(error)
            out.append(row)
        out.append({"run": run.name, "load_avg_before": receipt.get("load_avg_before"), "load_avg_after": receipt.get("load_avg_after"),
                    "service_start_s": receipt.get("service_start_s"), "producer_peak_rss_gib": round(receipt["producer_process"]["peak_rss_bytes"] / 2**30, 2),
                    "assets": receipt.get("assets"), "source_commit": receipt.get("source_commit")})
    json.dump(out, sys.stdout, indent=1)


main()
