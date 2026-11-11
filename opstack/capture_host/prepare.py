#!/usr/bin/env python3
"""Apply the pinned host-only patch in a NEW owned detached worktree.

This prepares source only. It never builds, runs a client, installs dependencies,
reads credentials, or touches the repository's guest/prover sources.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_tree(root, pin):
    for name, expected in pin['original_files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or not relative.parts:
            raise ValueError('unsafe pinned source path')
        path = root
        for part in relative.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError('upstream source hash mismatch')
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            raise ValueError('upstream source hash mismatch')


def prepare(source, destination):
    pin = json.loads((HERE / 'pin.json').read_bytes())
    patch = HERE / 'disable_optional_prefetch.patch'
    if digest(patch.read_bytes()) != pin['patch_sha256']:
        raise ValueError('host patch digest mismatch')
    revision = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'], check=True, capture_output=True, text=True).stdout.strip()
    if revision != pin['revision'] or destination.exists() or destination.is_symlink():
        raise ValueError('source revision or new-worktree destination mismatch')
    validate_tree(source, pin)
    subprocess.run(['git', '-C', str(source), 'worktree', 'add', '--detach', str(destination), revision], check=True, capture_output=True, timeout=120)
    validate_tree(destination, pin)
    subprocess.run(['git', '-C', str(destination), 'apply', '--check', str(patch)], check=True, capture_output=True)
    subprocess.run(['git', '-C', str(destination), 'apply', str(patch)], check=True, capture_output=True)
    for name, expected in pin['patched_files'].items():
        if digest((destination / name).read_bytes()) != expected:
            raise ValueError('patched source hash mismatch')
    result = {'revision': revision, 'patch_sha256': pin['patch_sha256'], 'host_only': True,
              'patched_files': {name: digest((destination / name).read_bytes()) for name in pin['original_files']},
              'built': False, 'client_executed': False}
    (destination / '.stwo-capture-host.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        print(json.dumps(prepare(a.source.resolve(), a.output.absolute()), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'host_prepare_failed', 'error_type': type(error).__name__}))
        raise SystemExit(1) from None
