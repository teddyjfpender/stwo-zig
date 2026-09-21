import fcntl,hashlib,json,pathlib,subprocess,sys,time
repo=pathlib.Path.cwd();out=repo/".git/local-ethereum/selected-real-metal-leaf-fresh-v1"
base=repo/".git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907"
exe=repo/".git/local-ethereum/selected-real-cpu-leaf-fresh-v2/verifier.bin"
proof=base/"metal-field4-segment9-selected-v3/segment-000009.stwief04"
metadata=proof.with_name("segment-000009.metadata.json")
materialization=base/"authority/materialization-v2.json"
def sha(p):
 with p.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
pins={str(exe):json.loads((out/"binary-retention.json").read_text())["sha256"],str(proof):"43aa15db272bfb6fdac201c5bf682dbc0887444ada440d9721afe5d099a2c2d8",str(metadata):"3d0775148bd5055e6d22c9cafabd3f6bd0a82086bf8d18456bf222b6e4c67bc8",str(materialization):"e9d9ba5619d5780155bf7f23e3475a1af0aae85ec74a0660b837c0cdbb237f4e"}
assert all(sha(pathlib.Path(p))==h for p,h in pins.items())
command=[str(exe),"verify-leaf",str(proof),str(metadata),str(materialization),pins[str(materialization)],"--workers","1"]
with open("/tmp/stwo-zig-build.lock","a+") as lock:
 print("waiting for shared lock",flush=True);fcntl.flock(lock,fcntl.LOCK_EX);print("acquired shared lock",flush=True)
 assert all(sha(pathlib.Path(p))==h for p,h in pins.items())
 (out/"plan.json").write_text(json.dumps({"command":command,"input_sha256":pins,"python":sys.executable,"python_version":sys.version,"endpoint":"verified_native_selected_leaf","producer_process_destroyed":True,"full_block_coverage":False},indent=2)+"\n")
 started=time.monotonic_ns()
 with (out/"stdout.json").open("xb") as stdout,(out/"stderr.log").open("xb") as stderr:
  result=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=1200)
 elapsed=time.monotonic_ns()-started
 unchanged=all(sha(pathlib.Path(p))==h for p,h in pins.items())
 parsed=json.loads((out/"stdout.json").read_text()) if result.returncode==0 else None
 passed=result.returncode==0 and unchanged and parsed["endpoint"]=="verified_native_selected_leaf" and parsed["segment_index"]==9 and parsed["segment_count"]==121 and parsed["worker_count"]==1 and parsed["proof_bytes"]==62552044 and parsed["retained_admission_destroyed_before_proof"]
 receipt={"passed":passed,"exit_code":result.returncode,"elapsed_ns":elapsed,"producer_process_destroyed":True,"inputs_and_binary_unchanged":unchanged,"verification":parsed,"full_block_coverage":False}
 (out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n");print(json.dumps(receipt),flush=True)
 sys.exit(0 if passed else 1)
