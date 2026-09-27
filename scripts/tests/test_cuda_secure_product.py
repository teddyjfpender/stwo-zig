"""CPU-only staged-source admission tests. No compiler/device/proof is invoked."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from cuda_build_lib.aot_pack import ABI_SCHEMAS, write_aot_carriers, write_aot_pack
from cuda_build_lib.errors import BuildError
from cuda_build_lib.product_selection import validate_aot_manifest
from cuda_build_lib.secure_identity import HELPERS, KINDS, LEGACY_KINDS, key_for, roster_authority
from cuda_build_lib.secure_product import Limits, stage_secure_product


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class CudaSecureProductTests(unittest.TestCase):
    def fixture(self, directory: Path, version: int = 2) -> tuple[Path, Path, str, str]:
        export = directory / "export"
        export.mkdir()
        header = directory / "field.cuh"
        header.write_text("#pragma once\n// Independently pinned fixture-only field source.\n")
        programs, helpers, declarations = [], [], []
        for kind, (abi, roots) in KINDS.items():
            if version == 1 and kind not in LEGACY_KINDS:
                continue
            identity = sha(kind.encode())
            name = "stwo_cuda_secure_v1_" + identity
            programs.append({"kind": kind, "program_identity": sha((kind+"/typed").encode()),
                             "executable_identity": identity, "kernel": name, "inputs": 2,
                             "parameters": 3, "equations_or_buses": roots, "abi_schema": ABI_SCHEMAS[abi],
                             "argument_count": 12, "cache_key": key_for(identity)})
            if version == 2:
                programs[-1]["typed_authority"] = "0a"*32 if kind.startswith("ram_lanes_") else "09"*32
                if kind == "ram_lanes_equations_v1":
                    programs[-1]["inputs"] = 271
            declarations.append(f'extern "C" __global__ void {name}(' + ",".join(f"uint a{i}" for i in range(12)) + ") {}\n")
        for name, (abi, argc) in HELPERS.items():
            identity = sha(name.encode())
            helpers.append({"kernel": name, "executable_identity": identity,
                            "cache_key": key_for(identity), "abi_schema": ABI_SCHEMAS[abi], "argument_count": argc})
            declarations.append(f'extern "C" __global__ void {name}(' + ",".join(f"uint a{i}" for i in range(argc)) + ") {}\n")
        source = ('#include "oods/field.cuh"\n' + "".join(declarations)).encode()
        (export / "kernels.cu").write_bytes(source)
        catalog = {"version": version, "target": "cuda", "word_protocol_version": 4,
                   "word_protocol_abi": "07"*32, "typed_authority": "09"*32,
                   "source_file": "kernels.cu", "source_sha256": sha(source), "programs": programs,
                   "cuda_helpers": helpers, "dynamic_claims_and_challenges": True,
                   "proof_acceptance_authority": False, "device_compiled": False, "device_executed": False}
        if version == 2:
            catalog.update(ram_lanes_protocol_version=1, ram_lanes_protocol_abi="0b"*32,
                           typed_authority=roster_authority(programs))
        payload = json.dumps(catalog).encode()
        (export / "source_manifest.json").write_bytes(payload)
        return export, header, sha(payload), sha(header.read_bytes())

    def test_secure_source_set_uses_existing_manifest_and_lookup_carrier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export, field, expected, field_sha = self.fixture(root)
            staged = root / "staged"
            path = stage_secure_product(export, expected, field, field_sha, staged)
            records = json.loads(path.read_bytes())
            self.assertEqual(13, len(records))
            validate_aot_manifest(staged, records)
            self.assertEqual(set(range(23,30)), {ABI_SCHEMAS[r["abi_schema"]] for r in records})
            # Fake bytes qualify only carrier framing/digests, not CUDA binaries.
            cubin = root / "fixture.cubin"
            cubin.write_bytes(b"not-a-device-binary")
            entries = [{"cache_key": int(r["cache_key"],16), "sm": 90, "kernel_name": r["kernel_name"],
                        "module_globals": 0, "abi_schema": ABI_SCHEMAS[r["abi_schema"]], "cubin": cubin}
                       for r in records]
            entries.sort(key=lambda entry: (entry["cache_key"],entry["sm"]))
            pack = root / "pack.bin"
            write_aot_pack(entries, pack)
            _, lookup = write_aot_carriers(entries, pack, root)
            self.assertEqual(1, lookup.read_text().count('extern "C" bool stwo_aot_lookup('))
            self.assertNotIn("nvrtc", lookup.read_text())

    def test_legacy_word_only_catalog_remains_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export, field, expected, field_sha = self.fixture(root, version=1)
            path = stage_secure_product(export, expected, field, field_sha, root/"staged")
            records = json.loads(path.read_bytes())
            self.assertEqual(11, len(records))
            validate_aot_manifest(path.parent, records)

    def test_lane_catalog_rejects_authority_family_roster_and_bound_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export, field, _, field_sha = self.fixture(root)
            path = export/"source_manifest.json"
            original = json.loads(path.read_bytes())
            for mutation in ("missing", "duplicate", "authority", "family", "inputs", "version", "legacy"):
                changed = copy.deepcopy(original)
                if mutation == "missing":
                    changed["programs"].pop()
                elif mutation == "duplicate":
                    changed["programs"][5] = copy.deepcopy(changed["programs"][4])
                elif mutation in ("authority", "family"):
                    changed["programs"][4]["typed_authority"] = changed["programs"][0]["typed_authority"]
                    if mutation == "family":
                        changed["typed_authority"] = roster_authority(changed["programs"])
                elif mutation == "inputs":
                    changed["programs"][4]["inputs"] = 513
                elif mutation == "version":
                    changed["ram_lanes_protocol_version"] = 2
                else:
                    changed["version"] = 1
                    changed.pop("ram_lanes_protocol_version")
                    changed.pop("ram_lanes_protocol_abi")
                    for entry in changed["programs"]:
                        entry.pop("typed_authority")
                payload = json.dumps(changed).encode()
                path.write_bytes(payload)
                with self.subTest(mutation=mutation), self.assertRaises(BuildError):
                    stage_secure_product(export, sha(payload), field, field_sha, root/mutation)
                self.assertFalse((root/mutation).exists())

    def test_secure_staging_rejects_pins_caps_and_does_not_publish_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export, field, expected, field_sha = self.fixture(root)
            destination = root / "staged"
            for manifest_sha, header_sha, limits in [
                ("01"*32, field_sha, Limits()), (expected, "02"*32, Limits()),
                (expected, field_sha, Limits(max_entries=10)),
                (expected, field_sha, Limits(max_aggregate_bytes=1)),
            ]:
                with self.assertRaises(BuildError):
                    stage_secure_product(export, manifest_sha, field, header_sha, destination, limits)
                self.assertFalse(destination.exists())
            with self.assertRaises(BuildError):
                stage_secure_product(export, expected, field, field_sha, destination, Limits(max_source_bytes=1))

    def test_secure_validator_rejects_source_header_abi_and_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export, field, expected, field_sha = self.fixture(root)
            staged = root / "staged"
            path = stage_secure_product(export, expected, field, field_sha, staged)
            records = json.loads(path.read_bytes())
            for field_name, value in [("program_identity","03"*32), ("argument_count",99),
                                      ("cache_key","0000000000000001"), ("identity_scheme","wrong")]:
                changed = copy.deepcopy(records)
                changed[0][field_name] = value
                with self.assertRaises(BuildError):
                    validate_aot_manifest(staged, changed)
            shader = staged / records[0]["file"]
            original = shader.read_bytes()
            shader.write_bytes(original+b"\n")
            with self.assertRaisesRegex(BuildError,"source SHA"):
                validate_aot_manifest(staged, records)
            shader.write_bytes(original)
            (staged / "oods/field.cuh").write_bytes(b"changed-field")
            with self.assertRaisesRegex(BuildError,"field header SHA"):
                validate_aot_manifest(staged, records)

    def test_secure_source_catalog_rejects_missing_helper_and_wrong_cache_endianness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export, field, expected, field_sha = self.fixture(root)
            catalog_path = export / "source_manifest.json"
            original = json.loads(catalog_path.read_bytes())
            for mutation in ("helper", "endian", "signature"):
                catalog = copy.deepcopy(original)
                if mutation == "helper":
                    catalog["cuda_helpers"].pop()
                elif mutation == "endian":
                    entry = catalog["programs"][0]
                    entry["cache_key"] = int.from_bytes(bytes.fromhex(entry["executable_identity"])[:8], "big")
                else:
                    entry = catalog["cuda_helpers"][0]
                    entry["argument_count"] += 1
                payload = json.dumps(catalog).encode()
                catalog_path.write_bytes(payload)
                with self.assertRaises(BuildError):
                    stage_secure_product(export, sha(payload), field, field_sha, root/mutation)


if __name__ == "__main__":
    unittest.main()
