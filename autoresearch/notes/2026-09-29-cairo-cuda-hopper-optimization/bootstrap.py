"""Prepare the funded host while immutable inputs upload; no GPU benchmarks."""
from pathlib import Path
import hashlib
import subprocess
import tarfile
import urllib.request

def run(args):
    subprocess.run(args, check=True, timeout=240)

zig = Path('/opt/zig')
zig.mkdir(exist_ok=True)
archive = zig / 'zig.tar.xz'
urllib.request.urlretrieve('https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz', archive)
index = __import__('json').loads(urllib.request.urlopen('https://ziglang.org/download/index.json').read())
assert hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() == index['0.15.2']['x86_64-linux']['shasum']
with tarfile.open(archive) as item:
    item.extractall(zig, filter='data')
run(['apt-get', 'update', '-qq'])
run(['apt-get', 'install', '-y', '--no-install-recommends', 'gnupg', 'ca-certificates', 'libtinfo6'])
key = urllib.request.urlopen('https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/7fa2af80.pub').read()
subprocess.run(['gpg', '--dearmor', '--yes', '-o', '/usr/share/keyrings/nvidia-devtools-keyring.gpg'], input=key, check=True)
Path('/etc/apt/sources.list.d/nvidia-devtools.list').write_text('deb [signed-by=/usr/share/keyrings/nvidia-devtools-keyring.gpg] https://developer.download.nvidia.com/devtools/repos/ubuntu2404/amd64/ /\n')
run(['apt-get', 'update', '-qq'])
run(['apt-get', 'install', '-y', '--no-install-recommends', 'nsight-systems-cli'])
run(['nsys', '--version'])
run(['/usr/local/cuda/bin/nvcc', '--version'])
