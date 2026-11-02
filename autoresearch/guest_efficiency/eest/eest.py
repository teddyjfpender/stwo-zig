#!/usr/bin/env python3
"""EEST blockchain tests against both RV64 Ethereum guests.

  python3 -I eest.py fetch    --cache C               pinned fixtures (download + sha256 + extract)
  python3 -I eest.py build    --cache C               generator, host builds, executor, guest ELFs
  python3 -I eest.py convert  --cache C --work W      EEST blocks -> canonical SSZ StatelessInput
  python3 -I eest.py host     --cache C --work W      tier 1: both clients natively
  python3 -I eest.py guest    --cache C --work W      tier 2: both guests on rv64-ethereum-execution
  python3 -I eest.py receipt  --cache C --work W --out RECEIPT.json
  python3 -I eest.py all      --cache C --work W --out RECEIPT.json

Options: --jobs N (default 6, max 12), --clients evmone,rust, --evmone-profile {v3,admitted}, --filter SUBSTR (fixture paths), --guest-sample
{all,per-file} (tier 2 runs every input, or the first valid and first invalid
input of each fixture file). See README.md for the route and the categories.
Only the Python standard library is used; downloads go to --cache.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
EFF = HERE.parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(EFF))
import bench  # noqa: E402  (guest_efficiency harness: ELF ABI symbols, guest build)

FIXTURES = {
    "release": "tests@v21.0.2",
    "url": "https://github.com/ethereum/execution-specs/releases/download/tests%40v21.0.2/fixtures.tar.gz",
    "bytes": 939189561,
    "sha256": "e2fa7ea2ea516459f9ab92284b2927892f318f4e1f78ca802cb05a6c3b479ed9",
}
# Fixture directories whose networks reach the ElectraFulu request shape both
# guests accept (Prague, Osaka, BPO1, BPO2). Everything else in the release is
# out of scope (see README: pre-Prague forks, Amsterdam and its BPO variants).
IN_SCOPE_DIRS = ["for_prague", "for_osaka", "for_bpo1", "for_bpo2", "for_praguetoosakaattime15k",
                 "for_osakatobpo1attime15k", "for_bpo1tobpo2attime15k", "for_cancuntopragueattime15k"]
STATELESS = {"url": "https://github.com/paradigmxyz/stateless.git",
             "commit": "a134a621bad7229ff7f980e42dfca8e22d101491"}
EVMONE = ROOT / "autoresearch/benchmarks/guest_runtime/ethereum/client_evmone"
RUST_PROFILE = "ethereum-services-v2-lean"
CLIENTS = ("evmone", "rust")  # narrowed by --clients
MAX_JOBS = 12
# evmone guest profile -> (build.py --profile, ELF name, executor execution_profile)
EVMONE_PROFILES = {
    "admitted": ("admitted", "client-evmone-admitted-eest.elf", "ethereum_services_v2"),
    "v3": ("v3", "client-evmone-v3-eest.elf", "ethereum_services_v3"),
}
EVMONE_PROFILE = "v3"  # set from --evmone-profile
RUST_EXEC_PROFILE = "ethereum_services_v2"


def run(cmd, cwd=None, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], cwd=cwd, check=True, **kw)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def paths(cache: Path) -> dict:
    return {
        "tarball": cache / "fixtures" / "fixtures.tar.gz",
        "fixtures": cache / "fixtures" / "x" / "fixtures",
        "stateless": cache / "stateless",
        "target": cache / "target",
        "gen": cache / "target" / "release" / "stwo-eest-witness-gen",
        "rust_host": cache / "target-rust-host" / "release" / "stwo-eest-rust-host",
        "evmone_out": cache / "evmone",
        "evmone_host": cache / "evmone" / "client-evmone-host-eest",
        "evmone_elf": cache / "evmone" / EVMONE_PROFILES[EVMONE_PROFILE][1],
        "rust_elf": cache / "rust-elf" / f"ethereum-rv64-{RUST_PROFILE.replace('ethereum-', '')}.elf",
        "exec": cache / "exec" / "bin" / "rv64-ethereum-execution",
    }


# ------------------------------------------------------------------ fetch ---
def cmd_fetch(a):
    p = paths(a.cache)
    tb = p["tarball"]
    tb.parent.mkdir(parents=True, exist_ok=True)
    if not tb.exists() or tb.stat().st_size != FIXTURES["bytes"]:
        run(["curl", "-sSfL", "--max-filesize", str(FIXTURES["bytes"] + 1), "-o", tb, FIXTURES["url"]])
    got = sha256_file(tb)
    if got != FIXTURES["sha256"]:
        raise SystemExit(f"fixture sha256 mismatch: {got}")
    marker = p["fixtures"].parent / ".extracted"
    if not marker.exists():
        dest = p["fixtures"].parent
        dest.mkdir(parents=True, exist_ok=True)
        wanted = tuple(f"fixtures/{kind}/{d}/" for kind in ("blockchain_tests", "blockchain_tests_engine")
                       for d in IN_SCOPE_DIRS) + ("fixtures/.meta/",)
        with tarfile.open(tb, "r:gz") as t:
            members = [m for m in t.getmembers() if m.name.startswith(wanted)
                       and (m.isfile() or m.isdir()) and ".." not in Path(m.name).parts]
            t.extractall(dest, members=members, filter="data")
        marker.write_text(FIXTURES["sha256"])
    print(f"fixtures ok: {p['fixtures']}")


# ------------------------------------------------------------------ build ---
def cmd_build(a):
    p = paths(a.cache)
    jobs = str(min(a.jobs, MAX_JOBS))
    # 1. Generator: our crate inside the pinned stateless workspace.
    st = p["stateless"]
    if not (st / ".git").exists():
        st.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "-q"], st)
        run(["git", "remote", "add", "origin", STATELESS["url"]], st)
    head = subprocess.run(["git", "-C", st, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != STATELESS["commit"]:
        run(["git", "fetch", "-q", "--depth", "1", "origin", STATELESS["commit"]], st)
        run(["git", "checkout", "-q", "--force", "FETCH_HEAD"], st)
    member = st / "testing" / "stwo-eest-witness-gen"
    if member.exists():
        shutil.rmtree(member)
    shutil.copytree(HERE / "witness_gen", member)
    ws = st / "Cargo.toml"
    text = ws.read_text()
    if "testing/stwo-eest-witness-gen" not in text:
        text = text.replace('    "testing/stateless-validator",\n',
                            '    "testing/stateless-validator",\n    "testing/stwo-eest-witness-gen",\n', 1)
        ws.write_text(text)
    env = dict(os.environ, CARGO_TARGET_DIR=str(p["target"]))
    run(["cargo", "+stable", "build", "--release", "-p", "stwo-eest-witness-gen", "-j", jobs], st, env=env)
    # 2. Rust host tier: the guest's validation core with the guest's [patch] set.
    if "rust" in CLIENTS:
        env = dict(os.environ, CARGO_TARGET_DIR=str(p["rust_host"].parents[1]))
        run(["cargo", "+" + "nightly-2026-08-08", "build", "--release", "--locked", "-j", jobs], HERE / "rust_host",
            env=env)
    # 3. evmone host and guest, EEST conformance variant (fork from schema id).
    if "evmone" in CLIENTS:
        cache = a.evmone_cache or (p["evmone_out"] / "cache")
        for extra in (["--host"], ["--profile", EVMONE_PROFILES[EVMONE_PROFILE][0]]):
            run([sys.executable, "-I", EVMONE / "build.py", "--out", p["evmone_out"], "--cache", cache, "--eest",
                 "--jobs", jobs, *extra], ROOT)
    # 4. Rust guest (unchanged production profile) and the execution tool.
    if "rust" in CLIENTS:
        run([sys.executable, "-I", EFF / "bench.py", "build-guest", "--out", p["rust_elf"].parent,
             "--profile", RUST_PROFILE, "--jobs", "4"], ROOT)
    run([sys.executable, "-I", EFF / "bench.py", "build-exec", "--out", p["exec"].parents[1]], ROOT)


# ---------------------------------------------------------------- convert ---
def fixture_files(cache: Path, flt: str | None) -> list[Path]:
    base = paths(cache)["fixtures"] / "blockchain_tests"
    out = sorted(q for d in IN_SCOPE_DIRS for q in (base / d).rglob("*.json"))
    return [q for q in out if not flt or flt in str(q)]


def fid_of(rel: str) -> str:
    return hashlib.sha256(rel.encode()).hexdigest()[:16]


def convert_one(gen: Path, fx: Path, base: Path, work: Path, env: dict) -> tuple[str, int]:
    rel = str(fx.relative_to(base))
    fid = fid_of(rel)
    eng = base.parent / "blockchain_tests_engine" / rel
    outdir = work / "inputs" / fid
    jl = work / "gen" / f"{fid}.jsonl"
    if jl.exists() and (work / "gen" / f"{fid}.done").exists():
        return rel, 0
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)
    t0 = time.time()
    try:
        r = subprocess.run([gen, "--fixture", fx, "--engine", eng, "--out", outdir, "--reference", "--control"],
                           capture_output=True, text=True, timeout=3600, env=env)
        lines = r.stdout
        if r.returncode != 0:
            lines += json.dumps({"test": None, "block": 0, "status": "gen_fail",
                                 "reason": f"generator exit {r.returncode}: {r.stderr[-400:]}"}) + "\n"
    except subprocess.TimeoutExpired:
        lines = json.dumps({"test": None, "block": 0, "status": "gen_fail", "reason": "generator timeout"}) + "\n"
    recs = []
    for line in lines.splitlines():
        if line.strip():
            rec = json.loads(line)
            rec["fixture"] = rel
            recs.append(json.dumps(rec, sort_keys=True))
    jl.write_text("\n".join(recs) + ("\n" if recs else ""))
    (work / "gen" / f"{fid}.done").write_text(f"{time.time() - t0:.2f}")
    return rel, len(recs)


def cmd_convert(a):
    p = paths(a.cache)
    base = p["fixtures"] / "blockchain_tests"
    (a.work / "gen").mkdir(parents=True, exist_ok=True)
    files = fixture_files(a.cache, a.filter)
    env = dict(os.environ)
    if a.tmpdir:
        # reth's per-test databases live in TMPDIR. Their many small commits
        # are fsync-bound on macOS (F_FULLFSYNC); a RAM disk is ~8x faster.
        a.tmpdir.mkdir(parents=True, exist_ok=True)
        env["TMPDIR"] = str(a.tmpdir)
    t0 = time.time()
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(a.jobs, MAX_JOBS)) as pool:
        for rel, n in pool.map(lambda f: convert_one(p["gen"], f, base, a.work, env), files):
            done += 1
            if done % 200 == 0:
                print(f"convert {done}/{len(files)} {time.time() - t0:.0f}s", flush=True)
    (a.work / "convert-seconds.txt").write_text(f"{time.time() - t0:.1f}")
    print(f"converted {len(files)} fixture files in {time.time() - t0:.0f}s")


def load_records(work: Path, flt: str | None = None) -> list[dict]:
    recs = []
    for jl in sorted((work / "gen").glob("*.jsonl")):
        for line in jl.read_text().splitlines():
            r = json.loads(line)
            if not flt or flt in r["fixture"]:
                recs.append(r)
    return recs


def input_path(work: Path, r: dict) -> Path:
    return work / "inputs" / fid_of(r["fixture"]) / r["input"]


# ------------------------------------------------------------------- host ---
HOST_RSS_LIMIT_KB = 4 * 1024 * 1024  # the native evmone build has no heap cap


def host_evmone(exe: Path, inp: Path) -> dict:
    # Watchdog: kill the native run above 4 GiB RSS (macOS has no enforced
    # address-space rlimit). One EEST case otherwise grows to ~38 GB.
    proc = subprocess.Popen([exe, inp], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    t0, killed = time.time(), None
    while proc.poll() is None:
        try:
            proc.wait(timeout=0.2)
            break
        except subprocess.TimeoutExpired:
            pass
        rss = subprocess.run(["ps", "-o", "rss=", "-p", str(proc.pid)], capture_output=True, text=True).stdout.strip()
        if rss.isdigit() and int(rss) > HOST_RSS_LIMIT_KB:
            killed = "memory"
        elif time.time() - t0 > 600:
            killed = "timeout"
        if killed:
            proc.kill()
    out, err = proc.communicate()
    if killed == "timeout":
        return {"verdict": "timeout"}
    if killed == "memory":
        return {"verdict": "reject", "reason": "host RSS above 4 GiB (killed)"}
    r = subprocess.CompletedProcess(proc.args, proc.returncode, out, err)
    if r.returncode == 0:
        out = [ln for ln in r.stdout.splitlines() if len(ln) == 86]
        return {"verdict": "output", "output": "0x" + out[-1] if out else None}
    why = [ln.split(":", 1)[1].strip() for ln in r.stderr.splitlines()
           if ln.startswith(("guest abort:", "guest:"))]
    return {"verdict": "reject", "reason": (why[-1] if why else f"exit {r.returncode}: {r.stderr[-200:]}")}


def host_rust_batch(exe: Path, inps: list[Path]) -> dict:
    out = {}
    try:
        r = subprocess.run([exe, *inps], capture_output=True, text=True, timeout=3600)
        lines = r.stdout.splitlines()
    except subprocess.TimeoutExpired:
        lines = []
    for ln in lines:
        path, _, rest = ln.partition(" ")
        if rest.startswith("ABORT"):
            out[path] = {"verdict": "reject", "reason": "panic"}
        elif rest.startswith("REJECT"):
            out[path] = {"verdict": "reject", "reason": "successful_validation=false"}
        elif len(rest) == 86:
            out[path] = {"verdict": "output", "output": "0x" + rest}
    for i in inps:  # a crash of the batch process: rerun singly
        if str(i) not in out:
            try:
                r = subprocess.run([exe, i], capture_output=True, text=True, timeout=600)
                rest = r.stdout.partition(" ")[2].strip()
                if len(rest) == 86:
                    out[str(i)] = {"verdict": "output", "output": "0x" + rest}
                else:
                    out[str(i)] = {"verdict": "reject", "reason": rest or f"process exit {r.returncode}"}
            except subprocess.TimeoutExpired:
                out[str(i)] = {"verdict": "timeout"}
    return out


def cmd_host(a):
    p = paths(a.cache)
    recs = [r for r in load_records(a.work, a.filter) if r["status"] == "input"]
    res_dir = a.work / "host"
    res_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    by_fixture = collections.defaultdict(list)
    for r in recs:
        by_fixture[r["fixture"]].append(r)

    def one(item):
        rel, rs = item
        f = res_dir / f"{fid_of(rel)}.json"
        if f.exists():
            return
        inps = [input_path(a.work, r) for r in rs]
        rust = host_rust_batch(p["rust_host"], inps) if "rust" in CLIENTS else {}
        res = {}
        for r, i in zip(rs, inps):
            res[r["input"]] = {}
            if "evmone" in CLIENTS:
                res[r["input"]]["evmone"] = host_evmone(p["evmone_host"], i)
            if "rust" in CLIENTS:
                res[r["input"]]["rust"] = rust[str(i)]
        f.write_text(json.dumps(res, sort_keys=True))

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(a.jobs, MAX_JOBS)) as pool:
        list(pool.map(one, sorted(by_fixture.items())))
    (a.work / "host-seconds.txt").write_text(f"{time.time() - t0:.1f}")
    print(f"host tier: {len(recs)} inputs in {time.time() - t0:.0f}s")


# ------------------------------------------------------------------ guest ---
def guest_run(exe: Path, elf: Path, elf_sha: str, abi: dict, profile: str, inp: Path, expected: str | None,
              tmp: Path) -> dict:
    data = inp.read_bytes()
    cfg = {"elf": str(elf), "elf_sha256": elf_sha, "input": str(inp),
           "input_sha256": hashlib.sha256(data).hexdigest(),
           # Invalid blocks have no expected output: a completed run then fails
           # the comparison (EthereumOutputMismatch) and counts as acceptance.
           "expected_output": (expected or "0x" + "00" * 43)[2:], "symbols": abi,
           "execution_profile": profile, "max_steps": 10_000_000_000}
    tmp.write_text(json.dumps(cfg))
    try:
        r = subprocess.run([exe, tmp], capture_output=True, text=True, timeout=a_timeout)
    except subprocess.TimeoutExpired:
        return {"verdict": "timeout"}
    if r.returncode != 0:
        err = (r.stderr.strip().splitlines() or ["?"])[-1]
        if "EthereumOutputMismatch" in r.stderr:
            return {"verdict": "output_mismatch" if expected else "accepted_invalid", "error": err}
        return {"verdict": "executor_error", "error": err}
    j = json.loads(r.stdout)
    v = {"instructions": j.get("instructions"), "keccak_calls": j.get("keccak_calls", 0),
         "secp_calls": j.get("secp_add_calls", 0) + j.get("secp_double_calls", 0)}
    if j.get("status") == "completed" and j.get("verified_output"):
        v.update(verdict="output", output="0x" + j["output"])
    elif j.get("status") == "trap":
        v.update(verdict="reject", reason=j.get("stop_error"))
    else:
        v.update(verdict=j.get("status"), reason=j.get("stop_error"))
    return v


a_timeout = 1800


def cmd_guest(a):
    global a_timeout
    a_timeout = a.timeout
    p = paths(a.cache)
    recs = [r for r in load_records(a.work, a.filter) if r["status"] == "input"]
    if a.guest_sample == "per-file":
        pick, seen = [], set()
        for r in recs:
            k = (r["fixture"], r["negative"])
            if k not in seen:
                seen.add(k)
                pick.append(r)
        recs = pick
    elfs = {}
    for c, key, prof in (("evmone", "evmone_elf", EVMONE_PROFILES[EVMONE_PROFILE][2]),
                         ("rust", "rust_elf", RUST_EXEC_PROFILE)):
        if c not in CLIENTS:
            continue
        raw = p[key].read_bytes()
        abi, _ = bench.elf_symbols(raw)
        elfs[c] = (p[key], hashlib.sha256(raw).hexdigest(), abi, prof)
    out_dir = a.work / "guest"
    (out_dir / "cfg").mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    by_fixture = collections.defaultdict(list)
    for r in recs:
        by_fixture[r["fixture"]].append(r)
    counter = [0]

    def one(item):
        rel, rs = item
        fid = fid_of(rel)
        f = out_dir / f"{fid}.json"
        res = json.loads(f.read_text()) if f.exists() else {}
        changed = False
        for r in rs:
            if r["input"] in res:
                continue
            inp = input_path(a.work, r)
            res[r["input"]] = {c: guest_run(p["exec"], *elfs[c], inp, r.get("expected_output"),
                                            out_dir / "cfg" / f"{fid}-{c}.json") for c in CLIENTS}
            changed = True
        if changed:
            f.write_text(json.dumps(res, sort_keys=True))
        counter[0] += 1
        if counter[0] % 200 == 0:
            print(f"guest {counter[0]}/{len(by_fixture)} files {time.time() - t0:.0f}s", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(a.jobs, MAX_JOBS)) as pool:
        list(pool.map(one, sorted(by_fixture.items())))
    (a.work / "guest-seconds.txt").write_text(f"{time.time() - t0:.1f}")
    print(f"guest tier: {len(recs)} inputs in {time.time() - t0:.0f}s")


# ---------------------------------------------------------------- receipt ---
def category(rec: dict, v: dict | None) -> str:
    """Per-block verdict of one client on one tier."""
    if rec["status"] == "out_of_scope":
        return "OUT_OF_SCOPE"
    if rec["status"] == "na":
        return "NA_NEG" if rec["negative"] else "NA_POS"
    if rec["status"] == "gen_fail":
        return "GEN_FAIL"
    if v is None:
        return "NOT_RUN"
    verdict = v["verdict"]
    if rec["negative"]:
        if verdict in ("reject",):
            return "PASS_NEG"
        if verdict in ("output", "accepted_invalid"):
            return "FAIL_NEG"
        return "ERROR"  # timeout, step limit, executor error: not a rejection
    if verdict == "output":
        return "PASS" if v.get("output") == rec["expected_output"] else "FAIL"
    if verdict in ("reject", "output_mismatch"):
        return "FAIL"
    return "ERROR"


def fixture_dir(rel: str) -> str:
    return rel.split("/")[0]


def cmd_receipt(a):
    recs = load_records(a.work, a.filter)
    host, guest = {}, {}
    for d, tgt in ((a.work / "host", host), (a.work / "guest", guest)):
        if d.exists():
            for f in d.glob("*.json"):
                tgt[f.stem] = json.loads(f.read_text())
    counts = {t: {c: collections.defaultdict(collections.Counter) for c in CLIENTS} for t in ("host", "guest")}
    totals = {t: {c: collections.Counter() for c in CLIENTS} for t in ("host", "guest")}
    gen = collections.Counter()
    oos = collections.Counter()
    na = collections.Counter()
    gen_fail = []
    failures = []
    disagreements = []
    reference = collections.Counter()
    control = {t: {c: collections.Counter() for c in CLIENTS} for t in ("host", "guest")}
    guest_instr = collections.defaultdict(int)
    neg_reasons = collections.Counter()
    for r in recs:
        if r.get("control"):
            fid = fid_of(r["fixture"])
            for tier, src in (("host", host), ("guest", guest)):
                per = src.get(fid, {}).get(r.get("input")) if r["status"] == "input" else None
                for c in CLIENTS:
                    cat = category(r, per.get(c) if per else None)
                    control[tier][c][cat] += 1
                    if cat in ("FAIL", "ERROR"):
                        failures.append({"tier": tier, "client": c, "category": "CONTROL_" + cat,
                                         "fixture": r["fixture"], "test": r["test"], "block": r["block"],
                                         "input": r.get("input"), "result": per.get(c) if per else None})
            continue
        gen[r["status"]] += 1
        if r["status"] == "out_of_scope":
            oos[r.get("reason", "?")] += 1
        if r["status"] == "na":
            na[("neg " if r["negative"] else "pos ") + r.get("reason", "?").split(" (")[0]] += 1
        if r["status"] == "gen_fail":
            gen_fail.append({k: r.get(k) for k in ("fixture", "test", "block", "reason", "negative")})
        fid = fid_of(r["fixture"])
        if r["status"] == "input" and "reference_output" in r:
            ref = r["reference_output"]
            if r["negative"]:
                reference["neg_rejected" if ref[66:68] == "00" else "neg_ACCEPTED"] += 1
            else:
                reference["pos_match" if ref == r["expected_output"] else "pos_MISMATCH"] += 1
        key = (fixture_dir(r["fixture"]), r.get("fork", "?"))
        if r["status"] == "input" and r["negative"]:
            v = host.get(fid, {}).get(r["input"], {}).get("evmone")
            if v and v.get("verdict") == "reject":
                neg_reasons[" ".join(w for w in v["reason"].split() if not any(ch.isdigit() for ch in w))[:90]] += 1
        for tier, src in (("host", host), ("guest", guest)):
            per = src.get(fid, {}).get(r.get("input")) if r["status"] == "input" else None
            cats = {}
            for c in CLIENTS:
                v = per.get(c) if per else None
                cat = category(r, v)
                if tier == "guest" and cat == "NOT_RUN":
                    continue
                cats[c] = cat
                counts[tier][c][f"{key[0]}|{key[1]}"][cat] += 1
                totals[tier][c][cat] += 1
                if tier == "guest" and v and v.get("instructions"):
                    guest_instr[c] += v["instructions"]
                if cat in ("FAIL", "FAIL_NEG", "ERROR"):
                    failures.append({"tier": tier, "client": c, "category": cat, "fixture": r["fixture"],
                                     "test": r["test"], "block": r["block"], "fork": r.get("fork"),
                                     "negative": r["negative"], "expect_exception": r.get("expect_exception"),
                                     "input": r.get("input"), "input_sha256": r.get("input_sha256"),
                                     "result": v})
            if len(cats) == 2 and len(set(cats.values())) > 1:
                disagreements.append({"tier": tier, "fixture": r["fixture"], "test": r["test"],
                                      "block": r["block"], "categories": cats})
    fx = paths(a.cache)
    meta = {}
    for name in ("gen", "rust_host", "evmone_host", "evmone_elf", "rust_elf", "exec"):
        if fx[name].exists():
            meta[name] = {"path": str(fx[name].relative_to(a.cache)), "sha256": sha256_file(fx[name])}
    secs = {n: (a.work / f"{n}-seconds.txt").read_text() if (a.work / f"{n}-seconds.txt").exists() else None
            for n in ("convert", "host", "guest")}
    receipt = {
        "schema": "stwo.rv64.eest-guests.v1",
        "clients_run": list(CLIENTS),
        "evmone_guest_profile": {"build": EVMONE_PROFILES[EVMONE_PROFILE][0],
                                 "execution_profile": EVMONE_PROFILES[EVMONE_PROFILE][2]},
        "date": time.strftime("%Y-%m-%d"),
        "fixtures": {**FIXTURES, "in_scope_dirs": IN_SCOPE_DIRS,
                     "formats": ["blockchain_tests", "blockchain_tests_engine"],
                     "fixture_files": len({r["fixture"] for r in recs}),
                     "tests": len({(r["fixture"], r["test"]) for r in recs}), "blocks": len(recs)},
        "route": "reth replay (stateless@a134a621 workspace, ef-tests flow) -> per-block canonical-mode witness; "
                 "payload request from the engine fixture; invalid blocks get a full parent-state witness",
        "stateless_revision": STATELESS,
        "artifacts": meta,
        "clients": {"evmone": f"client_evmone, EEST variant (build.py --eest: fork/blob schedule from schema id); "
                              f"guest build.py --profile {EVMONE_PROFILES[EVMONE_PROFILE][0]}",
                    "rust": f"stateless-validator-reth a134a621 with the {RUST_PROFILE} [patch] set "
                            "(host: no RV64 services; guest: production ELF, unchanged)"},
        "conversion": {"status": dict(gen), "out_of_scope": dict(oos), "not_applicable": dict(na),
                       "generator_failures": gen_fail[:200], "generator_failure_count": len(gen_fail),
                       "upstream_reference_validator": dict(reference)},
        "tiers": {t: {c: {"totals": dict(totals[t][c]),
                          "by_dir_fork": {k: dict(v) for k, v in sorted(counts[t][c].items())}}
                      for c in CLIENTS} for t in ("host", "guest")},
        "full_state_witness_control": {t: {c: dict(control[t][c]) for c in CLIENTS} for t in ("host", "guest")},
        "evmone_host_invalid_block_reject_reasons": dict(neg_reasons.most_common()),
        "guest_instructions_total": dict(guest_instr),
        "failures": failures,
        "client_disagreements": disagreements,
        "seconds": secs,
    }
    if a.annotations and Path(a.annotations).exists():
        receipt["failure_classification"] = json.loads(Path(a.annotations).read_text())
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=1, sort_keys=False) + "\n")
    print(json.dumps({t: {c: dict(totals[t][c]) for c in CLIENTS} for t in ("host", "guest")}, indent=1))
    print("conversion:", dict(gen), "reference:", dict(reference))
    print("full-state-witness control:", {t: {c: dict(control[t][c]) for c in CLIENTS} for t in ("host", "guest")})
    print(f"failures: {len(failures)} disagreements: {len(disagreements)} -> {out}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("fetch", "build", "convert", "host", "guest", "receipt", "all"))
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--work", type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "vectors/reports/rv64-ethereum-20261101/eest-guests-v1.json")
    ap.add_argument("--jobs", type=int, default=MAX_JOBS)
    ap.add_argument("--filter", default=None)
    ap.add_argument("--guest-sample", choices=("all", "per-file"), default="all")
    ap.add_argument("--tmpdir", type=Path, default=None,
                    help="TMPDIR for the generator's throwaway reth databases (a RAM disk is much faster)")
    ap.add_argument("--timeout", type=int, default=1800, help="per guest execution, seconds")
    ap.add_argument("--evmone-cache", type=Path, default=None, help="pinned evmone/ziskethone source cache")
    ap.add_argument("--clients", default="evmone,rust", help="comma list of clients to build/run (evmone, rust)")
    ap.add_argument("--evmone-profile", choices=tuple(EVMONE_PROFILES), default="v3",
                    help="evmone RV64 guest: v3 = ethereum_services_v3 (default service set), admitted = v2")
    ap.add_argument("--annotations", default=str(HERE / "failure-classification.json"))
    a = ap.parse_args(argv)
    global CLIENTS, EVMONE_PROFILE
    CLIENTS = tuple(c for c in ("evmone", "rust") if c in a.clients.split(","))
    if not CLIENTS or set(a.clients.split(",")) - {"evmone", "rust"}:
        ap.error("--clients takes evmone and/or rust")
    EVMONE_PROFILE = a.evmone_profile
    a.cache = a.cache.resolve()
    if a.work:
        a.work = a.work.resolve()
    if not 1 <= a.jobs <= MAX_JOBS:
        ap.error(f"--jobs must be in 1..{MAX_JOBS}")
    if a.cmd not in ("fetch", "build") and not a.work:
        ap.error("--work is required")
    steps = {"fetch": [cmd_fetch], "build": [cmd_build], "convert": [cmd_convert], "host": [cmd_host],
             "guest": [cmd_guest], "receipt": [cmd_receipt],
             "all": [cmd_fetch, cmd_build, cmd_convert, cmd_host, cmd_guest, cmd_receipt]}[a.cmd]
    for s in steps:
        s(a)


if __name__ == "__main__":
    main()
