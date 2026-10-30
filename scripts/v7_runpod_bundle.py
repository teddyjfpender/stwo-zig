#!/usr/bin/env python3
"""Build an explicit, hashed Lab source/corpus export; never provision or upload."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
import tarfile
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = Path('vectors/reports/block-v7-real-window-v2-20261030')
CORPUS = Path('vectors/reports/block-v7-real-window-corpus-20261029')
EXTENSIONS = {'.zig', '.zon', '.py', '.json', '.cu', '.cuh', '.h', '.c', '.cpp', '.m', '.metal', '.cairo', '.lean', '.txt', '.patch'}
SKIP_DIRS = {'__pycache__', 'zig-out', 'node_modules', 'target', 'build'}
FORBIDDEN_NAMES = {'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519'}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked(path: Path) -> Path:
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('path must be inside the Lab checkout')
    current = ROOT
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('symlink not permitted in export: ' + str(path))
    if not current.is_file():
        raise ValueError('missing regular file: ' + str(path))
    return current


def source_paths() -> list[Path]:
    paths = [Path('build.zig'), Path('build.zig.zon')]
    for directory in ('src', 'build_support', 'scripts'):
        for path in (ROOT / directory).rglob('*'):
            relative = path.relative_to(ROOT)
            if any(part.startswith('.') or part in SKIP_DIRS for part in relative.parts):
                continue
            if path.is_file() and path.suffix in EXTENSIONS:
                if path.name.lower() in FORBIDDEN_NAMES:
                    raise ValueError('credential-like filename in source export: ' + str(relative))
                paths.append(relative)
    # The existing CUDA tools graph eagerly declares canonical Cairo AOT inputs
    # even when selecting its native archive. They are explicit build inputs.
    paths.extend(path.relative_to(ROOT) for path in (ROOT / 'vectors/cairo/official').rglob('*') if path.is_file())
    paths.append(Path('vectors/cairo/sn_pie_2_witness_programs.bin'))
    return sorted(set(paths))


def snapshot_identity(raw: bytes) -> str:
    if len(raw) < 148 or raw[:8] != b'B7WIN001':
        raise ValueError('invalid snapshot encoding')
    count = struct.unpack_from('<Q', raw, 140)[0]
    if count > 8_000_000 or len(raw) != 148 + 8 * count:
        raise ValueError('snapshot length exceeds declared bounded corpus')
    h = hashlib.sha256(b'stwo-v7-real-window-state-v1')
    for value, in struct.iter_unpack('<I', raw[8:140]):
        h.update(struct.pack('<Q', value))
    h.update(struct.pack('<Q', count))
    previous = -1
    for address, value in struct.iter_unpack('<II', raw[148:]):
        if address % 4 or address <= previous:
            raise ValueError('noncanonical snapshot addresses')
        previous = address
        h.update(struct.pack('<QQ', address, value))
    return h.hexdigest()


def corpus_paths() -> tuple[list[Path], list[dict]]:
    prepared = json.loads(checked(REPORT / 'prepared-corpus.json').read_text())
    paths = [REPORT / 'prepared-corpus.json', CORPUS / 'source/guest.elf', CORPUS / 'source/input.bin', CORPUS / 'source/expected-output.bin']
    cases = []
    for case in prepared['cases']:
        directory = Path(case['directory'])
        capture = directory / 'capture.json'
        if sha(checked(capture).read_bytes()) != case['capture_manifest_sha256']:
            raise ValueError('capture pin mismatch: ' + case['case'])
        paths.append(capture)
        capsules = {}
        for boundary in ('incoming', 'outgoing'):
            path = directory / (boundary + '.b7win.gz')
            compressed = checked(path).read_bytes()
            raw = gzip.decompress(compressed)
            if snapshot_identity(raw) != case[boundary + '_sha256']:
                raise ValueError('decompressed capsule pin mismatch: ' + case['case'])
            paths.append(path)
            capsules[boundary] = {'path': str(path), 'compressed_sha256': sha(compressed), 'compressed_bytes': len(compressed), 'decompressed_file_sha256': sha(raw), 'state_identity_sha256': case[boundary + '_sha256'], 'decompressed_bytes': len(raw)}
        cases.append({'case': case['case'], 'window': case['window'], 'capture': str(capture), 'capture_sha256': case['capture_manifest_sha256'], 'capsules': capsules})
    paths.extend(sorted(REPORT.glob('features-*/initialization-selection.json')))
    elf = checked(CORPUS / 'source/guest.elf').read_bytes()
    if any(sha(elf) != case['elf_sha256'] for case in prepared['cases']):
        raise ValueError('ELF pin mismatch')
    source_input = checked(CORPUS / 'source/input.bin').read_bytes()
    if sha(source_input) != '737368031bfec21aa2bd557a3a71d2cbf253ec730199f7ec4c3bccd628df8e82':
        raise ValueError('original input pin mismatch')
    return sorted(set(paths)), cases


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--archive', type=Path, help='Optional deterministic tar.gz; writes local artifact only')
    parser.add_argument('--corpus-only', action='store_true')
    args = parser.parse_args()
    corpus, cases = corpus_paths()
    sources = [] if args.corpus_only else source_paths()
    paths = sorted(set(sources + corpus))
    rows = []
    for path in paths:
        data = checked(path).read_bytes()
        rows.append({'path': str(path), 'bytes': len(data), 'sha256': sha(data)})
    source_set = set(map(str, sources))
    source_rows = [row for row in rows if row['path'] in source_set]
    manifest = {'schema': 'stwo-v7-runpod-export-v1', 'scope': 'Declared nonterminal real Ethereum windows; externally selected incoming state, skipped prefixes and full block not proved.',
                'source_kind': 'explicit dirty-worktree source snapshot' if sources else None,
                'source_tree_sha256': sha(json.dumps(source_rows, sort_keys=True, separators=(',', ':')).encode()) if sources else None,
                'source_file_count': len(sources), 'cases': cases, 'files': rows,
                'logical_payload_bytes': sum(row['bytes'] for row in rows),
                'excluded': ['git metadata/history', 'hidden files', 'build/cache outputs', 'other workspaces', 'audit records', 'credentials', 'host binaries'],
                'cuda_prebuilt_included': False, 'gpu_execution_qualified': False}
    encoded = (json.dumps(manifest, indent=2) + '\n').encode()
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(encoded)
    if args.archive:
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        with args.archive.open('wb') as output, gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|') as tar:
            def add(name: str, data: bytes) -> None:
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                tar.addfile(info, io.BytesIO(data))
            add('export-manifest.json', encoded)
            add('SHA256SUMS', ''.join(row['sha256'] + '  ' + row['path'] + '\n' for row in rows).encode())
            for row in rows:
                data = checked(Path(row['path'])).read_bytes()
                if len(data) != row['bytes'] or sha(data) != row['sha256']:
                    raise ValueError('source changed while packaging: ' + row['path'])
                add(row['path'], data)
        print(json.dumps({'archive': str(args.archive), 'bytes': args.archive.stat().st_size, 'sha256': sha(args.archive.read_bytes())}))
    print(json.dumps({'manifest': str(args.manifest), 'files': len(rows), 'payload_bytes': manifest['logical_payload_bytes'], 'source_tree_sha256': manifest['source_tree_sha256']}))


if __name__ == '__main__':
    main()
