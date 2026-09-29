"""Authenticate native CUDA cubins compiled on a separate CPU host."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .errors import BuildError

SCHEMA = 'stwo-cuda-native-cubin-bundle-v1'


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_elf(path: Path) -> None:
    with path.open('rb') as stream:
        header = stream.read(64)
    # EM_CUDA = 190. Reject PTX, host objects and truncated artifacts.
    if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 190:
        raise BuildError('imported AOT is not a 64-bit little-endian CUDA ELF')


class Bundle:
    def __init__(self, root: Path):
        self.root = root.resolve()
        manifest = self.root / 'manifest.json'
        try:
            self.document = json.loads(manifest.read_text())
            self.manifest_sha256 = digest(manifest)
            if self.document['schema'] != SCHEMA or self.document['producer']['provider'] != 'nvidia_nvcc':
                raise BuildError('imported cubin producer must be native NVIDIA CUDA')
            producer = self.document['producer']
            required = ('nvcc_sha256', 'toolkit_manifest_sha256', 'host_cxx_sha256', 'host_cc1plus_sha256')
            if any(re.fullmatch('[0-9a-f]{64}', producer.get(key, '')) is None for key in required):
                raise BuildError('imported cubin producer lacks exact tool identities')
            self.producer_sha256 = hashlib.sha256(json.dumps(producer, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            self.entries = {}
            for entry in self.document['entries']:
                key = (entry['cache_key'], entry['sm'])
                if (type(entry['sm']) is not int or entry['sm'] <= 0 or key in self.entries or
                        re.fullmatch('[0-9a-f]{16}', entry['cache_key']) is None or
                        re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]*', entry['file']) is None):
                    raise BuildError('imported cubin has an invalid or duplicate identity')
                for field in ('source_sha256', 'cubin_sha256'):
                    if re.fullmatch('[0-9a-f]{64}', entry[field]) is None:
                        raise BuildError('imported cubin lacks exact source/artifact digests')
                for field in ('kernel_name', 'abi_schema', 'module_globals'):
                    if not isinstance(entry[field], str) or not entry[field]:
                        raise BuildError('imported cubin lacks kernel ABI or globals')
                if not isinstance(entry['flags'], list) or not all(isinstance(flag, str) for flag in entry['flags']):
                    raise BuildError('imported cubin lacks effective compiler flags')
                path = self.root / entry['file']
                if path.is_symlink() or digest(path) != entry['cubin_sha256']:
                    raise BuildError('imported cubin differs from its digest')
                validate_elf(path)
                self.entries[key] = entry
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise BuildError(f'invalid imported CUDA cubin bundle: {error}') from error

    def validate_selection(self, sources, metadata, sms) -> None:
        expected = {str(entry['cache_key']): (source, entry) for source, entry in zip(sources, metadata, strict=True)}
        for (key, sm), entry in self.entries.items():
            if key not in expected or sm not in sms:
                raise BuildError('imported cubin is outside the selected source/SM catalogue')
            source, actual = expected[key]
            for field in ('kernel_name', 'abi_schema', 'module_globals'):
                if entry[field] != actual[field]:
                    raise BuildError('imported cubin has incompatible kernel ABI or globals')
            if entry['source_sha256'] != digest(source):
                raise BuildError('imported cubin was compiled from different source bytes')

    def find(self, metadata: dict, sm: int, command: list[str], source: Path):
        entry = self.entries.get((str(metadata['cache_key']), sm))
        if entry is None:
            return None
        if entry['flags'] != command[1:command.index(str(source))]:
            raise BuildError('imported cubin has different effective compiler flags')
        path = self.root / entry['file']
        if digest(path) != entry['cubin_sha256']:
            raise BuildError('imported cubin changed during the archive build')
        return path, entry

    def identity(self) -> dict:
        return {'manifest_sha256': self.manifest_sha256, 'producer_sha256': self.producer_sha256,
                'producer': self.document['producer'], 'entry_count': len(self.entries)}
