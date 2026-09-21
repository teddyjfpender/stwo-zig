from pathlib import Path
import datetime, hashlib, json, os, subprocess, sys, time
repo=Path.cwd(); out=repo/".git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/metal-field5-block-v1"
plan=json.loads((out/"prepared-launch-v2.json").read_text()); snapshot=Path(plan["cwd"])
def sha(p):
    with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
for e in plan["controller_sources"]:
    if sha(snapshot/e["path"])!=e["sha256"]:raise SystemExit("Frozen source mismatch")
for e in [plan["prover"],plan["verifier"],*plan["aot_files"]]:
    if sha(Path(e["path"]))!=e["sha256"]:raise SystemExit("Executable/AOT mismatch")
accounting=json.loads((out/"import-accounting-v1.json").read_text())
if sorted(e["segment_index"] for e in accounting["imports"]) != [9,120]:raise SystemExit("Missing accepted imports")
for e in accounting["imports"]:
    if sha(out/(e["artifact_sha256"]+".bin"))!=e["artifact_sha256"]:raise SystemExit("Imported proof mismatch")
startpath=out/"controller-start-v2.json"
if startpath.exists():raise SystemExit("Campaign already launched")
env=os.environ.copy();env.update(plan["environment"])
for key in ("STWO_ZIG_STAGE101_REFERENCE_ARTIFACT","STWO_ZIG_STAGE101_BENCHMARK_ADMISSION_V2"):env.pop(key,None)
(out/"controller-run-v2.py").write_bytes(Path(__file__).read_bytes())
started=time.monotonic_ns()
with (out/"controller-stdout-v2.json").open("xb") as stdout, (out/"controller-stderr-v2.log").open("xb") as stderr:
    process=subprocess.Popen(plan["argv"],cwd=snapshot,env=env,stdout=stdout,stderr=stderr)
    start={"version":2,"pid":process.pid,"runner_pid":os.getpid(),"started_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"argv":plan["argv"],"cwd":plan["cwd"],"environment":plan["environment"],"prepared_launch_sha256":sha(out/"prepared-launch-v2.json"),"controller_source_manifest_sha256":plan["source_manifest_sha256"],"import_accounting_sha256":sha(out/"import-accounting-v1.json"),"shared_lock_scope":"Each heavy child; no controller-wide lock","memory_policy":"Admission budgets; no automatic process RSS/footprint stop","status":"running","full_block_verified":False}
    with startpath.open("x") as f:json.dump(start,f,indent=2);f.write("\n")
    print(json.dumps(start),flush=True)
    code=process.wait()
receipt={"exit_code":code,"elapsed_ns":time.monotonic_ns()-started,"finished_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"controller_stdout_sha256":sha(out/"controller-stdout-v2.json"),"controller_stderr_sha256":sha(out/"controller-stderr-v2.log"),"bundle_status_requires_terminal_verifier_receipt":True}
(out/"controller-terminal-v2.json").write_text(json.dumps(receipt,indent=2)+"\n")
print(json.dumps(receipt),flush=True);sys.exit(code)
