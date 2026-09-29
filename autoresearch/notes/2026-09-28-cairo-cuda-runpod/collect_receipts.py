import tarfile
from pathlib import Path
root=Path('/workspace')
files=set(root.glob('cairo-cuda-*.log'))|set(root.glob('proof-driver-*.log'))|set(root.glob('*smoke-driver.log'))
for pattern in ['qualification-v*','cairo-component-smokes','cairo-pcs-smokes']:
 for d in root.glob(pattern):
  if d.is_dir():
   files.update(x for x in d.iterdir() if x.suffix in ('.json','.log','.envelope'))
files.update(root.glob('stwo-zig/zig-out/**/build-receipt*.json'))
with tarfile.open('/workspace/cairo-final-receipts.tar.gz','w:gz') as t:
 for f in sorted(files):t.add(f,arcname=f.relative_to(root),recursive=False)
print('files',len(files),'archive_bytes',Path('/workspace/cairo-final-receipts.tar.gz').stat().st_size)
