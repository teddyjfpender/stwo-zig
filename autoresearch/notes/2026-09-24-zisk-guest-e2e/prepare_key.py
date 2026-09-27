import hashlib,json,tarfile
from pathlib import Path
h=Path(__file__).resolve().parent;p=Path('/tmp/stwo-zisk-guest-e2e-20260924/provingkey-blake3.tar.gz')
md5=hashlib.md5();sha=hashlib.sha256()
with p.open('rb') as f:
 while chunk:=f.read(16<<20):md5.update(chunk);sha.update(chunk)
assert md5.hexdigest()==p.with_suffix(p.suffix+'.md5').read_text().split()[0]
total=0;members=0
with tarfile.open(p,mode='r|*') as t:
 for member in t:
  total+=member.size;members+=1
  if total>120*(1<<30):raise RuntimeError('expanded key exceeds 120 GiB research budget')
  t.extract(member,path=p.parent,filter='data')
(h/'peer-key.json').write_text(json.dumps({'archive':str(p),'sha256':sha.hexdigest(),'upstream_md5':md5.hexdigest(),'extracted_bytes':total,'members':members},indent=2)+'\n')
print(total,members,flush=True)
