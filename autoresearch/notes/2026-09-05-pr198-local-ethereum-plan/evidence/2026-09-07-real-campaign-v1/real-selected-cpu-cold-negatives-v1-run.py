import fcntl,hashlib,json,pathlib,struct,subprocess,sys,time
repo=pathlib.Path.cwd();out=repo/".git/local-ethereum/selected-real-cpu-leaf-cold-negatives-v1"
positive=repo/".git/local-ethereum/selected-real-cpu-leaf-fresh-v2"
assert json.loads((positive/"receipt.json").read_text())["passed"]
plan=json.loads((positive/"plan.json").read_text());pins=plan["input_sha256"];command=plan["command"]
def sha(p):
 with pathlib.Path(p).open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
assert all(sha(p)==v for p,v in pins.items())
original=pathlib.Path(command[2]).read_bytes();leaf=json.loads(pathlib.Path(command[3]).read_text())
assert original[:8]==b"STWIEF04" and struct.unpack_from("<HHIQ",original,8)==(4,2,0,len(original))
lengths=struct.unpack_from("<6Q",original,24);assert 72+sum(lengths)+32==len(original)
statement=original[72:72+lengths[0]];signature=struct.pack("<III",70,2,1);matches=[];start=0
while (index:=statement.find(signature,start))>=0:
 if index>=4 and index+4*struct.unpack_from("<I",statement,index-4)[0]+32==len(statement):matches.append(index)
 start=index+1
assert len(matches)==1
cases=[]
for name in ["changed-clock-resealed-transport","changed-proof-original-seal"]:
 directory=out/name;directory.mkdir();changed=bytearray(original)
 if name.startswith("changed-clock"):
  # RawV2 fixed_layout.entry_register_clocks=516, register1 uses words518/519.
  offset=72+matches[0]+4*518
  struct.pack_into("<II",changed,offset,65535,65535)
  changed[-32:]=hashlib.sha256(b"stwo.ethereum.incremental-full-leaf-proof.v4\x00"+changed[:-32]).digest()
  expected="BoundaryClockOutOfRange"
 else:
  offset=72+sum(lengths[:5])+lengths[5]//2;changed[offset]^=1
  expected="IncrementalFullLeafProofArtifactContentMismatchV4"
 proof=directory/"proof.stwief04";proof.write_bytes(changed)
 metadata=dict(leaf);metadata["proof_sha256"]=list(hashlib.sha256(changed).digest());metadata["proof_bytes"]=len(changed)
 sidecar=directory/"leaf.json";sidecar.write_text(json.dumps(metadata,indent=2)+"\n")
 cmd=command[:];cmd[2]=str(proof);cmd[3]=str(sidecar)
 cases.append({"name":name,"command":cmd,"expected_error":expected,"changed_offset":offset,"proof_sha256":sha(proof),"metadata_sha256":sha(sidecar),"transport_seal_recomputed":name.startswith("changed-clock")})
(out/"plan.json").write_text(json.dumps({"original_pins":pins,"positive_receipt_sha256":sha(positive/"receipt.json"),"cases":cases},indent=2)+"\n")
with open("/tmp/stwo-zig-build.lock","a+") as lock:
 print("waiting for shared lock",flush=True);fcntl.flock(lock,fcntl.LOCK_EX);print("acquired shared lock",flush=True)
 results=[]
 for case in cases:
  directory=out/case["name"];started=time.monotonic_ns()
  with (directory/"stdout.log").open("xb") as stdout,(directory/"stderr.log").open("xb") as stderr:
   result=subprocess.run(case["command"],stdout=stdout,stderr=stderr,timeout=300)
  message=(directory/"stderr.log").read_text();passed=result.returncode==1 and ("error: "+case["expected_error"]) in message
  results.append({"name":case["name"],"passed":passed,"exit_code":result.returncode,"elapsed_ns":time.monotonic_ns()-started,"expected_error":case["expected_error"],"stderr_sha256":sha(directory/"stderr.log")})
 unchanged=all(sha(p)==v for p,v in pins.items());passed=unchanged and all(c["passed"] for c in results)
 receipt={"passed":passed,"genuine_positive_precedes_negatives":True,"originals_and_verifier_unchanged":unchanged,"cases":results}
 (out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n");print(json.dumps(receipt),flush=True);sys.exit(0 if passed else 1)
