import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cuda_build_lib import aot_cache, cubin_import
from cuda_build_lib.errors import BuildError


class NativeCubinImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'kernel.cu'
        self.source.write_text('authenticated CUDA source')
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        header[18:20] = (190).to_bytes(2, 'little')
        self.artifact = self.root / 'unit.cubin'
        self.artifact.write_bytes(header + b'device code')
        self.metadata = {'cache_key': '0123456789abcdef', 'kernel_name': 'canonical_kernel',
                         'abi_schema': 'recorded_witness_v1', 'module_globals': 'none'}
        self.command = ['nvcc', '-cubin', '-O3', str(self.source), '-o', 'out.cubin']
        entry = dict(self.metadata, sm=90, file=self.artifact.name,
                     source_sha256=cubin_import.digest(self.source),
                     cubin_sha256=cubin_import.digest(self.artifact), flags=['-cubin', '-O3'])
        self.document = {'schema': cubin_import.SCHEMA, 'producer': {'provider': 'nvidia_nvcc',
                         **{k: 'ab' * 32 for k in ('nvcc_sha256', 'toolkit_manifest_sha256',
                                                  'host_cxx_sha256', 'host_cc1plus_sha256')}},
                         'entries': [entry]}
        self.publish()

    def publish(self):
        (self.root / 'manifest.json').write_text(json.dumps(self.document))

    def bundle(self):
        bundle = cubin_import.Bundle(self.root)
        bundle.validate_selection([self.source], [self.metadata], (90,))
        return bundle

    def test_native_artifact_matches_source_abi_sm_and_flags(self):
        bundle = self.bundle()
        self.assertEqual(bundle.find(self.metadata, 90, self.command, self.source)[0], self.artifact)
        self.assertIsNone(bundle.find(self.metadata, 80, self.command, self.source))
        self.assertEqual(bundle.identity()['entry_count'], 1)
        with self.assertRaises(BuildError):
            bundle.find(self.metadata, 90, ['nvcc', '-cubin', '-O0', str(self.source), '-o', 'out'], self.source)

    def test_source_abi_sm_and_catalogue_mismatch_rejected(self):
        for field, value in [('source_sha256', 'cd'*32), ('kernel_name', 'other'),
                             ('abi_schema', 'other'), ('module_globals', 'other'),
                             ('sm', 80), ('cache_key', 'fedcba9876543210')]:
            with self.subTest(field=field):
                prior = copy.deepcopy(self.document)
                self.document['entries'][0][field] = value
                self.publish()
                with self.assertRaises(BuildError):
                    self.bundle()
                self.document = prior
        self.publish()

    def test_host_elf_ptx_truncation_and_digest_mismatch_rejected(self):
        original = self.artifact.read_bytes()
        host = bytearray(original)
        host[18:20] = (62).to_bytes(2, 'little')
        for content in (bytes(host), b'.version 8.7\n.target sm_90', original[:32]):
            self.artifact.write_bytes(content)
            self.document['entries'][0]['cubin_sha256'] = cubin_import.digest(self.artifact)
            self.publish()
            with self.assertRaises(BuildError):
                self.bundle()
        self.artifact.write_bytes(original)
        with self.assertRaises(BuildError):
            self.bundle()

    def test_invalid_duplicate_missing_and_traversal_entries_rejected(self):
        original = copy.deepcopy(self.document)
        for change in ('duplicate', 'traversal', 'missing', 'bad_sha', 'bool_sm', 'bad_flags'):
            self.document = copy.deepcopy(original)
            entry = self.document['entries'][0]
            if change == 'duplicate': self.document['entries'].append(entry.copy())
            if change == 'traversal': entry['file'] = '../unit.cubin'
            if change == 'missing': del entry['abi_schema']
            if change == 'bad_sha': entry['source_sha256'] = 'invalid'
            if change == 'bool_sm': entry['sm'] = True
            if change == 'bad_flags': entry['flags'] = '-cubin'
            self.publish()
            with self.subTest(change=change), self.assertRaises(BuildError):
                self.bundle()

    def test_symlink_and_post_plan_artifact_change_rejected(self):
        bundle = self.bundle()
        original = self.artifact.read_bytes()
        self.artifact.write_bytes(original + b'changed')
        with self.assertRaises(BuildError):
            bundle.find(self.metadata, 90, self.command, self.source)
        self.artifact.write_bytes(original)
        replacement = self.root / 'replacement.cubin'
        self.artifact.rename(replacement)
        self.artifact.symlink_to(replacement)
        with self.assertRaises(BuildError):
            self.bundle()

    def test_external_compiler_provenance_separates_native_unit_cache(self):
        bundle = self.bundle()
        plan = {'native_runtime_files': [], 'source_closure_sha256': 'cd'*32,
                'tools': {'nvcc': 'local nvcc', 'host_cxx': 'local host compiler'}}
        native = aot_cache.identity(self.source, 90, plan, self.command)
        producer = {'producer_sha256': bundle.producer_sha256, 'producer': bundle.document['producer'],
                    'artifact_sha256': bundle.entries[('0123456789abcdef', 90)]['cubin_sha256']}
        imported = aot_cache.identity(self.source, 90, plan, self.command, producer=producer)
        self.assertNotEqual(imported, native)
        plan['tools']['nvcc'] = 'different rental compiler'
        self.assertEqual(imported, aot_cache.identity(self.source, 90, plan, self.command, producer=producer))


if __name__ == '__main__':
    unittest.main()
