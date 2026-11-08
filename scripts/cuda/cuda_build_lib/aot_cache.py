"""Source/flags/toolchain-bound cubins shared across whole-archive rebuilds."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(source: Path, sm: int, plan: dict, command: list[str], producer: dict | None = None) -> str:
    # Include conservative authority/native-header closures, not unrelated
    # product selection or runtime implementation changes. Generated Cairo
    # sources inline their field support; any source-side headers also bind.
    headers = [{k: entry[k] for k in ('path', 'sha256')}
               for entry in plan['native_runtime_files']
               if str(entry['path']).endswith(('.h', '.cuh'))]
    companions = [{'path': p.relative_to(source.parent).as_posix(), 'sha256': digest(p)}
                  for p in sorted(source.parent.rglob('*'))
                  if p.is_file() and p.suffix in ('.h', '.cuh')]
    flags = command[1:command.index(str(source))]
    payload = {'schema': 'stwo-cuda-cubin-unit-v1', 'source_sha256': digest(source),
               'sm': sm, 'flags': flags, 'authority': plan['source_closure_sha256'],
               'native_headers': headers, 'source_headers': companions,
               'tools': {key: plan['tools'][key] for key in ('nvcc', 'host_cxx')}}
    if producer is not None:
        payload["tools"] = {"imported_native_cuda_producer": producer}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def restore(cache: Path, key: str, destination: Path) -> bool:
    artifact, stamp = cache / (key + '.cubin'), cache / (key + '.json')
    try:
        record = json.loads(stamp.read_text())
        if record.get('identity') != key or record.get('sha256') != digest(artifact) or artifact.stat().st_size == 0:
            return False
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_copy(artifact, destination)
        return True
    except (OSError, ValueError):
        return False


def publish(cache: Path, key: str, source: Path) -> None:
    if not source.is_file() or source.stat().st_size == 0:
        raise ValueError('cannot cache an empty cubin')
    cache.mkdir(parents=True, exist_ok=True)
    artifact, stamp = cache / (key + '.cubin'), cache / (key + '.json')
    atomic_copy(source, artifact)
    payload = json.dumps({'identity': key, 'sha256': digest(artifact)}, sort_keys=True).encode()
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
        stream.write(payload)
        staging = Path(stream.name)
    os.replace(staging, stamp)


def atomic_copy(source: Path, destination: Path) -> None:
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
        staging = Path(stream.name)
    try:
        shutil.copyfile(source, staging)
        os.replace(staging, destination)
    finally:
        staging.unlink(missing_ok=True)
