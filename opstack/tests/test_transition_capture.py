"""Offline material recovery, authenticated headers and parser/resource guards."""
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import zipfile
import zlib

SPEC = importlib.util.spec_from_file_location("transition_capture", Path(__file__).parents[1] / "transition_capture.py")
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class TransitionCaptureTests(unittest.TestCase):
    def setUp(self):
        self.receipt = json.loads(capture.RECEIPT.read_text())
        self.claim = capture.claim_from_receipt(self.receipt)
        self.payload = b"authenticated preimage"
        self.rows = [[capture.keccak(self.payload).hex(), self.payload.hex()]]

    def test_keccak_is_not_nist_sha3(self):
        self.assertEqual(capture.keccak(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_exact_wire_fields_and_material_only_flags(self):
        data = capture.pack(self.claim, self.rows, [], False)
        self.assertEqual(data[:8], b"STWOPD01")
        self.assertEqual(data[8:168], capture.claim_header(self.claim))
        self.assertEqual(struct.unpack_from("<II", data, 168), (24 + 40 + len(self.payload), 0))
        result = capture.inspect_container(data, self.claim)
        self.assertEqual(result["records"], 1)
        for name in ("preimage_hashes_verified", "kzg_verified", "derivation_accepted", "proof_verified"):
            self.assertFalse(result[name])

    def test_duplicate_and_forged_preimages(self):
        with self.assertRaisesRegex(ValueError, "preimage"):
            capture.pack(self.claim, self.rows * 2, [])
        with self.assertRaisesRegex(ValueError, "preimage"):
            capture.pack(self.claim, [[self.rows[0][0], "00"]], [])

    def test_checkpoint_or_reserved_table_mutation_rejects(self):
        data = bytearray(capture.pack(self.claim, self.rows, [], False))
        data[8] ^= 1
        with self.assertRaisesRegex(ValueError, "checkpoint"):
            capture.inspect_container(data, self.claim)
        data[8] ^= 1
        struct.pack_into("<I", data, capture.HEADER + 20, 1)
        with self.assertRaisesRegex(ValueError, "header"):
            capture.inspect_container(data, self.claim)

    def test_compressed_exactness_and_bomb_bound(self):
        data = capture.pack(self.claim, self.rows, [], False)
        compressed = b"STWOPDZ1" + data[8:capture.HEADER] + zlib.compress(data[capture.HEADER:])
        self.assertEqual(capture.inspect_container(compressed, self.claim)["records"], 1)
        for malformed in (compressed + b"suffix", compressed[:-1]):
            with self.assertRaisesRegex(ValueError, "decompression"):
                capture.inspect_container(malformed, self.claim)
        bomb = bytearray(compressed)
        struct.pack_into("<I", bomb, 168, capture.MAX_BODY + 1)
        with self.assertRaisesRegex(ValueError, "cap"):
            capture.inspect_container(bomb, self.claim)

    def test_sidecar_width_and_duplicate_commitment(self):
        sidecar = {"blob": bytes(capture.BLOB_BYTES).hex(), "kzg_commitment": (b"a" * 48).hex(), "kzg_proof": (b"b" * 48).hex()}
        data = capture.pack(self.claim, self.rows, [sidecar], False)
        self.assertEqual(capture.inspect_container(data, self.claim)["sidecars"], 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            capture.pack(self.claim, self.rows, [sidecar, sidecar], False)
        with self.assertRaisesRegex(ValueError, "width"):
            capture.pack(self.claim, self.rows, [{**sidecar, "blob": "00"}], False)

    def test_atomic_publication_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "output")
            capture.write_new(path, b"first")
            with self.assertRaises(FileExistsError):
                capture.write_new(path, b"second")
            self.assertEqual(path.read_bytes(), b"first")
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["output"])

    def test_pinned_recovery_and_zip_path_independence(self):
        data = capture.pack(self.claim, self.rows, [], False)
        with tempfile.TemporaryDirectory() as directory, patch.object(capture, "PINS", {len(data): capture.sha(data)}):
            root = Path(directory)
            with zipfile.ZipFile(root / "archive.zip", "w") as archive:
                archive.writestr("../../outside/input.opd", data)
            output = root / "chosen.opd"
            found = capture.recover([root], output)
            self.assertEqual(len(found["matches"]), 1)
            self.assertEqual(output.read_bytes(), data)
            self.assertFalse((root / "outside").exists())
            self.assertFalse((root.parent / "outside").exists())

    def test_unpinned_magic_and_file_count_cap(self):
        data = capture.pack(self.claim, self.rows, [], False)
        with tempfile.TemporaryDirectory() as directory, patch.object(capture, "PINS", {len(data): "00" * 32}):
            root = Path(directory)
            (root / "candidate.bin").write_bytes(data)
            self.assertEqual(capture.recover([root])["matches"], [])
            with self.assertRaisesRegex(ValueError, "count"):
                capture.recover([root], max_files=0)

    def test_endpoint_labels_never_include_path_query_or_userinfo(self):
        self.assertEqual(capture.endpoint_label("https://example.invalid/private-path?api_key=EXAMPLE"), "https://example.invalid")
        with self.assertRaisesRegex(ValueError, "endpoint"):
            capture.endpoint_label("https://name:EXAMPLE@example.invalid")
        with self.assertRaisesRegex(ValueError, "scope"):
            capture.rpc("https://example.invalid", "debug_traceBlockByNumber", [])

    def test_probe_classifies_historical_window_without_echoing_error(self):
        data = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32614, "message": "eth_getProof is limited to a 10,000 range"}}).encode()
        error = urllib.error.HTTPError("https://example.invalid/private", 413, "failure", {}, io.BytesIO(data))
        with patch.object(capture.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(capture.RpcFailure) as raised:
                capture.rpc("https://example.invalid/private?token=EXAMPLE", "eth_getProof", [])
        self.assertEqual(raised.exception.report, {"status": "historical_proof_window_10000", "http_status": 413, "rpc_code": -32614})
        self.assertNotIn("EXAMPLE", str(raised.exception.report))

    def test_host_preflight_cannot_submit_a_payload(self):
        with self.assertRaisesRegex(ValueError, "scope"):
            capture.rpc("https://example.invalid", "debug_executePayload", ["0x00", {}])
        with patch.object(capture, "rpc", side_effect=capture.RpcFailure("method_unavailable", 403, -32601)) as rpc:
            result = capture.probe_host("https://example.invalid", "l2", self.receipt)
        self.assertEqual(rpc.call_args_list[-1].args[2], [])
        self.assertFalse(result["host_executed"])
        self.assertFalse(result["payload_executed"])
        self.assertTrue(all(row["status"] == "method_unavailable" for row in result["capabilities"]))

    def test_real_pinned_headers_and_root_preimages(self):
        headers = json.loads((Path(__file__).parent / "fixtures/transition-159257842-headers.json").read_text())
        with patch.object(capture, "rpc", side_effect=headers):
            records, result = capture.capture_headers("https://example.invalid", self.receipt, 2)
        self.assertEqual(result["headers"], 2)
        self.assertEqual(len(records), 4)
        self.assertEqual(set(result["output_root_preimages"]), {"previous_root", "next_root"})
        for key, value in records:
            self.assertEqual(capture.keccak(bytes.fromhex(value)).hex(), key)
        headers[0]["stateRoot"] = "0x" + "11" * 32
        with self.assertRaisesRegex(ValueError, "published hash"):
            capture.header_rlp(headers[0])

    def test_resume_reauthenticates_journal_and_fetches_only_missing(self):
        headers = json.loads((Path(__file__).parent / "fixtures/transition-159257842-headers.json").read_text())
        retained = []
        with patch.object(capture, "rpc", return_value=headers[1]) as rpc:
            capture.capture_headers("https://example.invalid", self.receipt, 2, headers[:1], retained.append)
        self.assertEqual(rpc.call_count, 1)
        self.assertEqual(retained[0]["hash"], headers[1]["hash"])
        headers[0]["gasUsed"] = "0x0"
        with patch.object(capture, "rpc") as rpc:
            with self.assertRaisesRegex(ValueError, "published hash"):
                capture.capture_headers("https://example.invalid", self.receipt, 2, headers)
            rpc.assert_not_called()

    def test_strict_rlp_and_authenticated_account_leaf(self):
        for bad in (b"", b"\x81\x01", b"\xb8\x01x", b"\x80\x00", b"\xf8\x00"):
            with self.assertRaises(ValueError):
                capture.decode_rlp(bad)
        key = capture.keccak(bytes(20))
        value = capture.rlp([b"", b"", bytes(32), bytes([7]) * 32])
        leaf = capture.rlp([b"\x20" + key, value])
        root = capture.keccak(leaf)
        self.assertEqual(capture.verify_trie_value(root, key, [leaf.hex()]), value)
        with self.assertRaisesRegex(ValueError, "path"):
            capture.verify_trie_value(root, bytes(32), [leaf.hex()])
        with self.assertRaisesRegex(ValueError, "authenticated"):
            capture.verify_trie_value(bytes(32), key, [leaf.hex()])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            capture.verify_trie_value(root, key, [leaf.hex(), leaf.hex()])
        extension = capture.rlp([b"\x00", root])
        with self.assertRaisesRegex(ValueError, "empty"):
            capture.verify_trie_value(capture.keccak(extension), key, [extension.hex(), leaf.hex()])
        extra = capture.rlp([b"\x20" + bytes(32), b"extra"])
        with self.assertRaisesRegex(ValueError, "extraneous"):
            capture.verify_trie_value(root, key, [leaf.hex(), extra.hex()])

    def test_real_recent_account_proof_and_coherent_mutations(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/recent-account-proof.json").read_text())
        encoded = bytes.fromhex(fixture["header_rlp"])
        self.assertEqual(capture.keccak(encoded).hex(), "3635b3687b9098244a390e6c1f02e9c15eb5e6167e2a5e878ba4777183bfe4b0")
        header = capture.decode_rlp(encoded)
        proof = fixture["proof"]
        key = capture.keccak(capture.unhex(proof["address"], 20))
        raw = capture.verify_trie_value(header[3], key, proof["accountProof"])
        account = capture.decode_rlp(raw)
        self.assertEqual(account[2], capture.unhex(proof["storageHash"], 32))
        self.assertEqual(account[2], header[16])
        self.assertEqual(account[3], capture.unhex(proof["codeHash"], 32))
        changed = list(proof["accountProof"])
        changed[-1] = changed[-1][:-2] + ("00" if changed[-1][-2:] != "00" else "01")
        with self.assertRaises(ValueError):
            capture.verify_trie_value(header[3], key, changed)
        with self.assertRaises(ValueError):
            capture.verify_trie_value(bytes(32), key, proof["accountProof"])

    def test_trie_branch_and_inline_reference(self):
        # Small inline leaf plus a full secure-key extension exercises both
        # canonical reference forms; no trusted expected node comes from RPC.
        key = bytes(32)
        leaf = [b"\x30", b"v"]  # last path nibble 0
        branch = [b""] * 17
        branch[0] = leaf
        extension = [b"\x00" + bytes(31), branch]  # 62 zero nibbles
        encoded = capture.rlp(extension)
        self.assertEqual(capture.verify_trie_value(capture.keccak(encoded), key, [encoded.hex()]), b"v")
        branch[0] = [b"\x40", b"v"]
        encoded = capture.rlp(extension)
        with self.assertRaisesRegex(ValueError, "compact"):
            capture.verify_trie_value(capture.keccak(encoded), key, [encoded.hex()])

    def test_directory_kv_masked_hash_is_recovered_and_authenticated(self):
        digest = capture.keccak(self.payload)
        key = (bytes([2]) + digest[1:]).hex()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / key[:4]).mkdir()
            row = root / key[:4] / (key[4:] + ".txt")
            row.write_text(self.payload.hex())
            records, report = capture.import_kv(root, "directory")
            self.assertEqual(records, [(digest.hex(), self.payload.hex())])
            self.assertTrue(report["preimage_hashes_verified"])
            self.assertFalse(report["complete_witness"])
            row.write_text("00")
            with self.assertRaisesRegex(ValueError, "key mismatch"):
                capture.import_kv(root, "directory")

    def test_read_only_rocksdb_keeps_retained_database(self):
        from rocksdict import Options, Rdict
        digest = capture.keccak(self.payload)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "kv")
            options = Options(raw_mode=True)
            options.create_if_missing(True)
            db = Rdict(str(root), options=options)
            db[bytes([2]) + digest[1:]] = self.payload
            db.close()
            records, _ = capture.import_kv(root, "rocksdb")
            self.assertEqual(records, [(digest.hex(), self.payload.hex())])
            self.assertTrue((root / "CURRENT").exists())


if __name__ == "__main__":
    unittest.main()
