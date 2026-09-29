import os,subprocess
from pathlib import Path
subprocess.run(['tar','--no-same-owner','-xzf','/workspace/source.tar.gz','-C','/workspace/stwo-zig'],check=True)
a=['/opt/zig/zig-x86_64-linux-0.15.2/zig', 'build', 'stwo-cairo-cuda', '-Doptimize=ReleaseFast', '-Dimplementation-commit=7e95ce3017c16be868f9c0ea883c3c5c112723d8', '-Dimplementation-dirty=true', '-Dimplementation-dirty-content-sha256=fb8f2d6f996748cc3b18d3c1d83681c267fa0297ebe725a8729bc713ac52b7c8', '-Dcuda-nvcc=/usr/local/cuda/bin/nvcc', '-Dcuda-host-cxx=/usr/bin/g++', '-Dcuda-host-runtime=/usr/lib/x86_64-linux-gnu/libstdc++.so.6', '-Dcuda-host-unwind-runtime=/usr/lib/x86_64-linux-gnu/libgcc_s.so.1', '-Dcuda-ar=/usr/bin/ar', '-Dcuda-home=/usr/local/cuda', '-Dcuda-library-dir=/usr/local/cuda/lib64', '-Dcuda-arch=sm_90', '-Dcuda-build-jobs=8', '-j2', '--summary', 'all', '-Dimplementation-tree=8643e2a01b54874f7a738d20e68f27a958cea75d']
p=Path('/workspace/cairo-cuda-build-v1.log')
with p.open('w') as f:r=subprocess.run(a,cwd='/workspace/stwo-zig',env=dict(os.environ,STWO_CUDA_ARCHIVE_CACHE='/workspace/cuda-archive-cache'),stdout=f,stderr=subprocess.STDOUT)
print('\n'.join(p.read_text().splitlines()[-35:]))
raise SystemExit(r.returncode)
