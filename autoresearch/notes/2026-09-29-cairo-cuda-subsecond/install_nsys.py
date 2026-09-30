"""Install Nsight Systems CLI on the ephemeral H200 benchmark host."""

from pathlib import Path
import subprocess
import urllib.request


def run(args):
    subprocess.run(args, check=True, timeout=300)


run(['apt-get', 'update', '-qq'])
run(['apt-get', 'install', '-y', '--no-install-recommends', 'gnupg', 'ca-certificates', 'libtinfo6'])
key = urllib.request.urlopen('https://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/7fa2af80.pub').read()
subprocess.run(['gpg', '--dearmor', '--yes', '-o', '/usr/share/keyrings/nvidia-devtools-keyring.gpg'], input=key, check=True)
Path('/etc/apt/sources.list.d/nvidia-devtools.list').write_text('deb [signed-by=/usr/share/keyrings/nvidia-devtools-keyring.gpg] https://developer.download.nvidia.com/devtools/repos/ubuntu2404/amd64/ /\n')
run(['apt-get', 'update', '-qq'])
run(['apt-get', 'install', '-y', '--no-install-recommends', 'nsight-systems-cli'])
run(['nsys', '--version'])
