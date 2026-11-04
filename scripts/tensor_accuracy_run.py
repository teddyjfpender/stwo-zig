#!/usr/bin/env python3
"""Reproduces the tensor-frontend accuracy study (design/tensor-frontend/accuracy.md).

  python3 -I scripts/tensor_accuracy_run.py --cache ~/Coding/ge-cache/accuracy \
      --out vectors/reports/tensor-frontend-20261103/accuracy

Expects (downloaded beforehand, data only):
  <cache>/stories260K/{stories260K.bin,tok512.bin}   huggingface.co/karpathy/tinyllamas (stories260K/)
  <cache>/corpus/tinystories-valid-head.txt          first 2,000,000 bytes of TinyStories-valid.txt
                                                     (huggingface.co/datasets/roneneldan/TinyStories)
and src/tensor built (zig build -Doptimize=ReleaseSafe: zig-out/bin/tensor-accuracy).
Every heavy step runs under memguard.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ACC = os.path.join(HERE, "tensor_accuracy.py")
ZIG = os.path.join(ROOT, "src", "tensor", "zig-out", "bin", "tensor-accuracy")
MG = os.path.expanduser("~/Coding/ge-ops/bin/memguard")

EVAL_CONFIGS = ["lmcal-h1", "matched-s8-h0", "matched-s13-h0", "matched-s13-h1", "emu-s13-r16-h0", "emu-a12-s13-r16-h0", "emu-a16-s13-r16-h0"]


def run(cmd, gb=3, label="acc"):
    full = [MG, "run", "--gb", str(gb), "--label", label, "--"] + cmd
    p = subprocess.run(full, capture_output=True, text=True)
    if p.returncode != 0:
        sys.stderr.write(p.stdout + p.stderr)
        raise SystemExit(f"failed: {' '.join(cmd)}")
    return p.stdout


def py(*args, gb=3):
    return run([sys.executable, "-I", ACC] + list(args), gb=gb)


def last_json(s):
    return json.loads([l for l in s.splitlines() if l.startswith("{")][-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--prove", type=int, default=4)
    a = ap.parse_args()
    cache = os.path.expanduser(a.cache)
    d = os.path.join(cache, "run")
    os.makedirs(a.out, exist_ok=True)
    if not os.path.exists(os.path.join(d, "windows.npz")):
        py("prepare", "--ckpt", os.path.join(cache, "stories260K", "stories260K.bin"), "--tok", os.path.join(cache, "stories260K", "tok512.bin"),
           "--corpus", os.path.join(cache, "corpus", "tinystories-valid-head.txt"), "--out", d)
    summary = {"zig": {}, "eval": {}}
    # --- Zig: lm.calibrate plan for the naive path; replay + bit-identity checks
    for cfg, zcal in [("lmcal-h1", True), ("lmcal-s13-h1", True), ("matched-s13-h0", False)]:
        py("export", "--dir", d, "--config", cfg, *(["--no-plan"] if zcal else []))
        model = os.path.join(d, f"{cfg}.model.bin")
        zout = os.path.join(d, f"zig-{cfg}.out.bin")
        cmd = [ZIG, model, os.path.join(d, "eval.win.bin"), zout]
        plan = os.path.join(d, f"zig-{cfg}.plan.bin")
        if zcal:
            cmd += ["--calibrate", os.path.join(d, "calib.win.bin"), plan, "1"]
        r = {"replay": last_json(run(cmd, gb=4, label="acc-zig"))}
        r["compare"] = last_json(py("compare", "--dir", d, "--config", cfg, "--zig", zout, "--n", "256", *(["--plan", plan] if zcal else [])))
        if a.prove:
            # prove + verify the first requests of the eval set (T = 64, one greedy token each)
            w8 = os.path.join(d, "eval8.win.bin")
            with open(os.path.join(d, "eval.win.bin"), "rb") as fi:
                raw = fi.read()
            import struct
            n, T = struct.unpack("<II", raw[:8])
            with open(w8, "wb") as fo:
                fo.write(struct.pack("<II", 8, T) + raw[8:8 + 8 * T * 4])
            r["prove"] = last_json(run([ZIG, model, w8, os.path.join(d, f"zig-{cfg}.prove.bin"), "--prove", str(a.prove)] + cmd[4:], gb=6, label="acc-prove"))
        summary["zig"][cfg] = r
    # --- metrics (numpy emulation, bit-identical to the Zig forward where implemented)
    for cfg in EVAL_CONFIGS + ["lmcal-s13-h1"]:
        out = os.path.join(a.out, f"{cfg}.json")
        extra = ["--plan", os.path.join(d, f"zig-{cfg}.plan.bin")] if cfg.startswith("lmcal") else []
        py("eval", "--dir", d, "--config", cfg, "--out", out, *extra)
        e = json.load(open(out))["eval"]
        summary["eval"][cfg] = {k: e.get(k) for k in ("windows", "refused_windows", "positions", "top1_agree", "top1_agree_last_pos", "top1_agree_all_windows", "top1_agree_last_pos_all_windows", "top5_overlap",
                                                       "float_top1_in_int_top5", "kl_float_int_nats", "logit_cosine_centered", "xent_float_nats",
                                                       "xent_int_nats", "next_token_acc_float", "next_token_acc_int")}
        summary["eval"][cfg]["resid_rel_l2_per_layer"] = [x["resid_rel_l2"] for x in e.get("per_layer", [])]
    shutil.copy(os.path.join(d, "meta.json"), os.path.join(a.out, "meta.json"))
    json.dump(summary, open(os.path.join(a.out, "summary.json"), "w"), indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
