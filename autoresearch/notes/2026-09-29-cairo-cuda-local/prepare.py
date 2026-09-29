"""Snapshot only prover sources, authenticated vectors and the four adapted inputs."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

root = Path.cwd()
out = root / 'zig-out/cairo-cuda-completion/current'
out.mkdir(parents=True, exist_ok=True)
excluded = {'.git', '.zig-cache', 'zig-out', 'target', '__pycache__'}
files = [root / 'build.zig', root / 'build.zig.zon']
for directory in ('src', 'build_support', 'scripts', 'conformance', 'vectors/cairo', 'tests/cuda', 'third_party/bzip2',
                  'tools/stwo-cairo-official-verifier-rs'):
    files += [p for p in (root / directory).rglob('*') if p.is_file()
              and not p.is_symlink() and not excluded.intersection(p.relative_to(root).parts)]
def content_hash(items):
    digest = hashlib.sha256()
    for name, payload in sorted(items):
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, 'little')); digest.update(encoded)
        digest.update(len(payload).to_bytes(8, 'little')); digest.update(payload)
    return digest.hexdigest()

# Reuse only our saved Linux verifier built from precisely the same project
# sources. Pin the binary separately; a source edit invalidates this shortcut.
verifier_prefix = 'tools/stwo-cairo-official-verifier-rs/'
verifier_identity = content_hash((p.relative_to(root).as_posix(), p.read_bytes())
                                for p in files if p.relative_to(root).as_posix().startswith(verifier_prefix))
cached = out / 'cached-official-verifier'
cached_stamp = out / 'cached-official-verifier.json'
if not cached_stamp.exists() and (out / 'source.tar.gz').exists():
    with tarfile.open(out / 'source.tar.gz') as archive:
        old_identity = content_hash((m.name, archive.extractfile(m).read()) for m in archive
                                    if m.isfile() and m.name.startswith(verifier_prefix))
    if old_identity == verifier_identity:
        with tarfile.open(out / 'cuda-units-and-verifier.tar.gz') as archive:
            payload = archive.extractfile('stwo-zig/' + verifier_prefix + 'target/release/stwo-cairo-official-verifier').read()
        cached.write_bytes(payload)
        cached_stamp.write_text(json.dumps({'source_sha256': verifier_identity,
                                            'binary_sha256': hashlib.sha256(payload).hexdigest()}) + '\n')
cached_identity = json.loads(cached_stamp.read_text()) if cached_stamp.exists() else None
if cached_identity and (cached_identity['source_sha256'] != verifier_identity or
                        hashlib.file_digest(cached.open('rb'), 'sha256').hexdigest() != cached_identity['binary_sha256']):
    cached_identity = None

source_hash = hashlib.sha256()
with tarfile.open(out / 'source.tar.gz', 'w:gz', compresslevel=2) as archive:
    for path in sorted(set(files), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        encoded = relative.encode()
        source_hash.update(len(encoded).to_bytes(8, 'little'))
        source_hash.update(encoded)
        source_hash.update(len(payload).to_bytes(8, 'little'))
        source_hash.update(payload)
        archive.add(path, arcname=relative, recursive=False)
if not (out / 'inputs.tar.gz').exists():
 with tarfile.open(out / 'inputs.tar.gz', 'w:gz', compresslevel=2) as archive:
    for number in range(1, 5):
        archive.add(root / f'zig-out/cairo-completion-20260927/sn-pie-{number}.cpi',
                    arcname=f'sn-pie-{number}.cpi', recursive=False)
receipt = {'schema': 'stwo-zig-cuda-source-snapshot-v1',
           'implementation_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
           'implementation_tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
           'implementation_dirty': True, 'dirty_content_sha256': source_hash.hexdigest(),
           'digest_algorithm': 'SHA256 of sorted snapshot files, little-endian u64 path length/path/byte length/bytes',
           'source_file_count': len(set(files))}
receipt['cached_official_verifier'] = cached_identity
for name in ('source.tar.gz', 'inputs.tar.gz', 'native-cubins.tar.gz', 'cuda-units-and-verifier.tar.gz'):
    path = out / name
    receipt[name] = {'sha256': hashlib.file_digest(path.open('rb'), 'sha256').hexdigest(), 'bytes': path.stat().st_size}
(out / 'snapshot.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
