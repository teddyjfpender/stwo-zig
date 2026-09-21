from pathlib import Path
import subprocess,tempfile,os,hashlib,json,gzip
root=Path.cwd();out=root/'vectors/reports/recursive-product-20260921/typed-recursion-final-qualified-v1'
snapshot=json.loads((out/'qualified-source-snapshot.json').read_text())
assert all(hashlib.sha256((root/p).read_bytes()).hexdigest()==sha for p,sha in snapshot.items())
base=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
with tempfile.TemporaryDirectory(prefix='pr198-source-replay-') as d:
 env=dict(os.environ);env['GIT_INDEX_FILE']=str(Path(d)/'export-index')
 subprocess.run(['git','read-tree',base],env=env,check=True)
 subprocess.run(['git','add','-A','--','build.zig','build.zig.zon','build_support','src','scripts','design','conformance'],env=env,check=True)
 patch=subprocess.check_output(['git','diff','--cached','--binary',base,'--','build.zig','build.zig.zon','build_support','src','scripts','design','conformance'],env=env)
 with gzip.open(out/'source.patch.gz','wb') as f:f.write(patch)
 env['GIT_INDEX_FILE']=str(Path(d)/'replay-index')
 subprocess.run(['git','read-tree',base],env=env,check=True)
 subprocess.run(['git','apply','--cached','--binary','-'],input=patch,env=env,check=True)
 tree=subprocess.check_output(['git','write-tree'],env=env,text=True).strip()
 batch=subprocess.Popen(['git','cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
 try:
  for path,expected in snapshot.items():
   batch.stdin.write((tree+':'+path+'\n').encode());batch.stdin.flush()
   header=batch.stdout.readline().split();assert len(header)==3 and header[1]==b'blob',path
   body=batch.stdout.read(int(header[2]));assert batch.stdout.read(1)==b'\n'
   assert hashlib.sha256(body).hexdigest()==expected,path
 finally:
  batch.stdin.close();batch.wait()
 assert batch.returncode==0
(out/'source-replay.json').write_text(json.dumps({'passed':True,'base_head':base,'verified_source_files':len(snapshot),'source_patch_sha256':hashlib.sha256((out/'source.patch.gz').read_bytes()).hexdigest(),'user_index_modified':False,'independent_build':False},indent=2)+'\n')
print(f'Replayed {len(snapshot)} source files without changing user index.')
