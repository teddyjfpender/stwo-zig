"""Shared CUDA archive reuse must preserve the exact closure and both payloads."""
import hashlib,json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cuda_build_lib.builder import reusable_archive,copy_archive,ARCHIVE_NAME,AOT_PACK_NAME,PLAN_NAME,RECEIPT_NAME

class ArchiveReuseTests(unittest.TestCase):
    def seed(self, root):
        receipt={"build_identity_sha256":"a"*64}
        for name,field in ((ARCHIVE_NAME,"archive"),(AOT_PACK_NAME,"aot_pack")):
            data=name.encode();(root/name).write_bytes(data)
            receipt[field]=name;receipt[field+"_sha256"]=hashlib.sha256(data).hexdigest()
        (root/PLAN_NAME).write_text("{}\n")
        (root/RECEIPT_NAME).write_text(json.dumps(receipt))
        return receipt

    def test_copy_reuses_only_matching_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);expected=self.seed(root);destination=root/"copy"
            copy_archive(root,destination)
            self.assertEqual(expected,reusable_archive(destination,"a"*64))
            self.assertIsNone(reusable_archive(destination,"b"*64))

    def test_archive_and_pack_corruption_both_invalidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in (ARCHIVE_NAME,AOT_PACK_NAME):
                self.seed(root);(root/name).write_bytes(b"corrupt")
                self.assertIsNone(reusable_archive(root,"a"*64))

    def test_incomplete_and_malformed_receipts_cannot_authorize(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.seed(root);(root/AOT_PACK_NAME).unlink()
            self.assertIsNone(reusable_archive(root,"a"*64))
            for text in ("[", "null", "[]"):
                (root/RECEIPT_NAME).write_text(text)
                self.assertIsNone(reusable_archive(root,"a"*64))

    def test_receipt_cannot_redirect_payload_outside_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);receipt=self.seed(root);receipt["archive"]="../outside.a"
            (root/RECEIPT_NAME).write_text(json.dumps(receipt))
            self.assertIsNone(reusable_archive(root,"a"*64))

if __name__ == "__main__":unittest.main()
