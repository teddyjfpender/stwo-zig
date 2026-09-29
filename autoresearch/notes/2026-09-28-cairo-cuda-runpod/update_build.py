"""Stage only recorded changed sources, update provenance, then build on the rental."""
import argparse,hashlib,json,shlex,subprocess,tarfile
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument("version",type=int);parser.add_argument("files",nargs="+");args=parser.parse_args()
notes=Path(__file__).resolve().parent;repo=notes.parents[2]
ssh=["ssh","-i",str(Path.home()/".runpod/ssh/runpodctl-ssh-key"),"-p","11338","-o","BatchMode=yes","root@87.120.211.208"]
scp=["scp","-i",str(Path.home()/".runpod/ssh/runpodctl-ssh-key"),"-P","11338","-o","BatchMode=yes"]
base=json.loads((notes/f"source-snapshot-v{args.version-1}.json").read_text())
by_path={x["path"]:x for x in base["source_files"]}
archive=repo/f"zig-out/cairo-cuda-runpod-20260928/update-v{args.version}.tar.gz"
with tarfile.open(archive,"w:gz") as tar:
 for filename in args.files:
  path=repo/filename;data=path.read_bytes();by_path[filename]={"path":filename,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
  tar.add(path,arcname=filename,recursive=False)
base["source_files"]=sorted(by_path.values(),key=lambda x:x["path"])
digest=hashlib.sha256(json.dumps(base["source_files"],sort_keys=True,separators=(",",":")).encode()).hexdigest()
base["closure_sha256"]=digest;(notes/f"source-snapshot-v{args.version}.json").write_text(json.dumps(base,indent=2)+"\n")
subprocess.run([*scp,str(archive),"root@87.120.211.208:/workspace/"],check=True)
subprocess.run([*ssh,f"tar --no-same-owner -xzf /workspace/{archive.name} -C /workspace/stwo-zig"],check=True)
command=json.loads((notes/"build-arguments-v4.json").read_text())["args"]
command=["-Dimplementation-dirty-content-sha256="+digest if x.startswith("-Dimplementation-dirty-content-sha256=") else x for x in command]
(notes/f"build-arguments-v{args.version}.json").write_text(json.dumps({"args":command,"environment":{"STWO_CUDA_ARCHIVE_CACHE":"/workspace/cuda-archive-cache"}},indent=2)+"\n")
remote_script="import os,subprocess\nfrom pathlib import Path\nargs="+repr(command)+"\nenv=dict(os.environ,STWO_CUDA_ARCHIVE_CACHE='/workspace/cuda-archive-cache')\nlog=Path('/workspace/cairo-cuda-build-v"+str(args.version)+".log')\nwith log.open('w') as stream: result=subprocess.run(args,cwd='/workspace/stwo-zig',env=env,stdout=stream,stderr=subprocess.STDOUT)\nprint('\\n'.join(log.read_text().splitlines()[-25:]))\nraise SystemExit(result.returncode)\n"
remote="python3 -c "+shlex.quote(remote_script)
raise SystemExit(subprocess.run([*ssh,remote]).returncode)
