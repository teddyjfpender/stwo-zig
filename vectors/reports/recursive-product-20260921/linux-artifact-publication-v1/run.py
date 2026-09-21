from pathlib import Path
import os,stat,gzip,subprocess,json,hashlib
p=Path('/tmp/pr198-linux-publication-v1');root=p/'overlay';data=bytearray()
def entry(name,mode,body,ino):
 fields=[ino,mode,0,0,1,0,len(body),0,0,0,0,len(name.encode())+1,0]
 data.extend(('070701'+''.join(f'{v:08x}' for v in fields)).encode());data.extend(name.encode()+b'\0');data.extend(b'\0'*(-len(data)%4));data.extend(body);data.extend(b'\0'*(-len(data)%4))
for i,f in enumerate(sorted(root.rglob('*')),1):
 mode=f.lstat().st_mode
 body=os.readlink(f).encode() if stat.S_ISLNK(mode) else f.read_bytes() if f.is_file() else b''
 entry(str(f.relative_to(root)),mode,body,i)
entry('TRAILER!!!',0,b'',0)
(p/'guest-initramfs.gz').write_bytes((p/'initramfs-virt').read_bytes()+gzip.compress(data))
with (p/'disk.raw').open('wb') as f:f.truncate(256*1024*1024)
args=['qemu-system-x86_64','-machine','q35,accel=tcg','-cpu','max','-smp','2','-m','1024','-kernel',str(p/'vmlinuz-virt'),'-initrd',str(p/'guest-initramfs.gz'),'-append','console=ttyS0 rdinit=/init panic=1','-drive',f'file={p}/disk.raw,format=raw,if=virtio','-nographic','-monitor','none','-nic','none','-no-reboot']
(p/'command.json').write_text(json.dumps(args,indent=2)+'\n')
with (p/'guest.log').open('w') as log:r=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=180)
s=(p/'guest.log').read_text();assert r.returncode==0,r.returncode;assert 'ARTIFACT_STORE_LINUX_COMPLETE' in s,s[-5000:]
print('Linux tmpfs and ext4 artifact-store suites passed.')
