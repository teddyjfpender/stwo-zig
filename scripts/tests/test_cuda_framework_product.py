"""Offline source/ABI rejection checks; these do not claim GPU qualification."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
from cuda_build_lib.framework_identity import parse_catalog, stage_framework_product, SCAN_HELPERS
from cuda_build_lib.errors import BuildError
from cuda_build_lib.product_selection import validate_aot_manifest
from cuda_build_lib.secure_identity import key_for


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class FrameworkProductTests(unittest.TestCase):
    def fixture(self, root):
        export = root / "export"
        export.mkdir()
        identity = sha(b"independent fixture executable identity")
        name = "stwo_cuda_framework_v1_" + identity
        source = ('#include "oods/field.cuh"\nextern "C" __global__ void ' + name +
                  "(" + ",".join(f"uint a{i}" for i in range(11)) + ") {}\n").encode()
        (export / "kernels.cu").write_bytes(source)
        catalog = {"version": 1, "target": "cuda", "scope": "riscv-recursive-parent-composition",
                   "source_file": "kernels.cu", "source_sha256": sha(source),
                   "programs": [{"executable_identity": identity, "kernel": name, "abi_schema": 30,
                                 "argument_count": 11, "cache_key": key_for(identity)}],
                   "dynamic_claims_and_challenges": True, "proof_acceptance_authority": False,
                   "device_compiled": False, "device_executed": False}
        payload = json.dumps(catalog).encode()
        (export / "source_manifest.json").write_bytes(payload)
        field = root / "field.cuh"
        field.write_bytes(b"// Independent field helper fixture; never compiled.\n")
        return export, field, catalog, sha(payload), sha(field.read_bytes())

    def test_private_native_catalog_is_validated_by_existing_builder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export, field, _, pin, field_pin = self.fixture(root)
            path = stage_framework_product(export, pin, field, field_pin, root / "staged")
            manifest = json.loads(path.read_bytes())
            validate_aot_manifest(path.parent, manifest)
            self.assertEqual("framework_polynomial_composition_v1", manifest[0]["abi_schema"])
            self.assertEqual(11, manifest[0]["argument_count"])
            for victim in (path.parent / manifest[0]["file"], path.parent / "oods/field.cuh",
                           path.parent / "framework_source_manifest.json"):
                original = victim.read_bytes()
                victim.write_bytes(original + b"changed")
                with self.subTest(victim=victim.name), self.assertRaises(BuildError):
                    validate_aot_manifest(path.parent, manifest)
                victim.write_bytes(original)
            with self.assertRaises(BuildError):
                stage_framework_product(export, pin, field, field_pin, path.parent)

    def test_unpinned_or_falsely_qualified_catalog_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export, field, catalog, pin, field_pin = self.fixture(root)
            for mutation in ("abi", "arguments", "collision", "identity", "authority", "compiled", "scope", "version"):
                changed = copy.deepcopy(catalog)
                if mutation == "abi": changed["programs"][0]["abi_schema"] = 23
                elif mutation == "arguments": changed["programs"][0]["argument_count"] = 10
                elif mutation == "collision": changed["programs"].append(changed["programs"][0])
                elif mutation == "identity": changed["programs"][0]["cache_key"] += 1
                elif mutation == "authority": changed["proof_acceptance_authority"] = True
                elif mutation == "compiled": changed["device_compiled"] = True
                elif mutation == "scope": changed["scope"] = "full_resident_riscv"
                else: changed["version"] = True
                with self.subTest(mutation=mutation), self.assertRaises(BuildError):
                    parse_catalog(json.dumps(changed).encode())
            for catalog_pin, header_pin in (("f" * 64, field_pin), (pin, "f" * 64)):
                with self.assertRaises(BuildError):
                    stage_framework_product(export, catalog_pin, field, header_pin, root / "rejected")
                self.assertFalse((root / "rejected").exists())
            (export / "kernels.cu").write_bytes(b"changed source")
            with self.assertRaises(BuildError):
                stage_framework_product(export, pin, field, field_pin, root / "rejected")

    def test_duplicate_json_fields_cannot_override_catalog_authority(self):
        with self.assertRaises(BuildError):
            parse_catalog(b'{"version":1,"version":2}')

    def test_interaction_catalog_requires_exact_scan_and_fraction_abis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export, field, catalog, _, field_pin = self.fixture(root)
            catalog.update(version=2, scope="riscv-recursive-parent-composition-and-interaction")
            for prefix, abi, argc in (("stwo_cuda_framework_interaction_v1_", 31, 8),
                                      *((name, 32, 6) for name in SCAN_HELPERS)):
                identity = sha(prefix.encode())
                catalog['programs'].append({'executable_identity': identity, 'kernel': prefix + identity,
                                            'abi_schema': abi, 'argument_count': argc, 'cache_key': key_for(identity)})
            source = ('#include "oods/field.cuh"\n' + ''.join(
                'extern "C" __global__ void ' + p['kernel'] + '(' +
                ','.join(f'uint a{i}' for i in range(p['argument_count'])) + ') {}\n'
                for p in catalog['programs'])).encode()
            catalog['source_sha256'] = sha(source)
            payload = json.dumps(catalog).encode()
            (export / 'source_manifest.json').write_bytes(payload)
            (export / 'kernels.cu').write_bytes(source)
            path = stage_framework_product(export, sha(payload), field, field_pin, root / 'staged')
            validate_aot_manifest(path.parent, json.loads(path.read_bytes()))
            for mutate in ('missing', 'duplicate', 'wrong_abi', 'wrong_arity', 'legacy_version', 'false_scope'):
                bad = copy.deepcopy(catalog)
                if mutate == 'missing': bad['programs'].pop()
                elif mutate == 'duplicate': bad['programs'][-1] = copy.deepcopy(bad['programs'][-2])
                elif mutate == 'wrong_abi': bad['programs'][1]['abi_schema'] = 30
                elif mutate == 'wrong_arity': bad['programs'][-1]['argument_count'] = 5
                elif mutate == 'legacy_version': bad.update(version=1, scope='riscv-recursive-parent-composition')
                else: bad['scope'] = 'riscv-recursive-parent-composition'
                with self.subTest(mutate=mutate), self.assertRaises(BuildError):
                    parse_catalog(json.dumps(bad).encode())


if __name__ == "__main__":
    unittest.main()
