"""Pinned host source guards; no native client is executed by these tests."""
import hashlib
import json
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('capture_prepare',Path(__file__).parents[1]/'capture_host/prepare.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)


class SourceGuards(unittest.TestCase):
    def test_hash_and_path_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'source.rs').write_bytes(b'original')
            pin={'original_files':{'source.rs':hashlib.sha256(b'original').hexdigest()}}
            P.validate_tree(root,pin)
            (root/'source.rs').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'hash'):P.validate_tree(root,pin)
            with self.assertRaisesRegex(ValueError,'unsafe'):P.validate_tree(root,{'original_files':{'../source.rs':'00'}})
            with self.assertRaisesRegex(ValueError,'unsafe'):P.validate_tree(root,{'original_files':{'/source.rs':'00'}})
            (root/'link.rs').symlink_to(root/'source.rs')
            with self.assertRaisesRegex(ValueError,'hash'):P.validate_tree(root,{'original_files':{'link.rs':hashlib.sha256(b'changed').hexdigest()}})


class ResumeGuards(unittest.TestCase):
    def test_resume_pins_claim_source_and_authenticated_keccak(self):
        spec=importlib.util.spec_from_file_location('capture_run',Path(__file__).parents[1]/'capture_host/run.py')
        R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);previous=root/'old';previous.mkdir();kv=previous/'kv';kv.mkdir()
            pin={'revision':'pinned','patch_sha256':'patch'};candidate={'number':1}
            receipt={'candidate':candidate,'upstream_revision':'pinned','patch_sha256':'patch','host_sha256':'host'}
            (previous/'capture-run.json').write_text(json.dumps(receipt))
            value=b'authenticated';digest=R.C.keccak(value);key=bytes([2])+digest[1:];name=key.hex()
            (kv/name[:4]).mkdir();file=kv/name[:4]/(name[4:]+'.txt');file.write_text(value.hex())
            self.assertEqual(R.resume_kv(previous,root/'copied',candidate,pin,'host',64)['rows'],1)
            with self.assertRaisesRegex(ValueError,'claim'):R.resume_kv(previous,root/'wrong',{'number':2},pin,'host',64)
            self.assertFalse((root/'wrong').exists())
            with self.assertRaisesRegex(ValueError,'bounds'):R.resume_kv(previous,root/'cap',candidate,pin,'host',1)
            file.write_text(b'forged'.hex())
            with self.assertRaisesRegex(ValueError,'Keccak'):R.resume_kv(previous,root/'forged',candidate,pin,'host',64)


if __name__=='__main__':unittest.main()
