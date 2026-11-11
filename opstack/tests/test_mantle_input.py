"""Mantle admission binds actual input; these tests never accept a mock proof."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zlib
from opstack.mantle import input as M

F = Path(__file__).parents[1] / "mantle/tests/fixtures"


def qualification_inputs():
    """Pinned public regression inputs; successful replay/proofs are separate gates."""
    with (F / "mantle-five-block-inputs.json.zlib").open("rb") as stream:
        packed = stream.read((256 << 10) + 1)
    if (
        hashlib.sha256(packed).hexdigest()
        != "1821b2ddb7f774950e76fcbcddc7f5234d1fe0da971ed90c3b2759e7f4c00fb3"
    ):
        raise ValueError("Mantle qualification fixture identity")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(packed, (1 << 20) + 1)
    if (
        len(raw) > 1 << 20
        or not decoder.eof
        or decoder.unconsumed_tail
        or decoder.unused_data
    ):
        raise ValueError("Mantle qualification decompression bound")
    if (
        hashlib.sha256(raw).hexdigest()
        != "8104c5665d7b232cc31c9b9ace1fc8a2a6bbec122ce45ce0c813f2486971d073"
    ):
        raise ValueError("Mantle qualification decoded identity")
    rows = json.loads(raw)["blocks"]
    if [row["block_number"] for row in rows] != [
        103132217,
        103132921,
        103133433,
        103133561,
        103133753,
    ]:
        raise ValueError("Mantle qualification coverage")
    for row in rows:
        data = row["guest_input_utf8"].encode()
        if (
            len(data) != row["input_bytes"]
            or hashlib.sha256(data).hexdigest() != row["input_sha256"]
        ):
            raise ValueError("Mantle qualification input identity")
        if M.statement(data).hex() != row["expected_output"]:
            raise ValueError("Mantle qualification statement")
    return rows


def fixture():
    return {
        "schema": 1,
        "fixture": json.loads((F / "block-103132217.json").read_text()),
        "expected": {
            "config_sha256": "0xb9583f9b493763c945cc961535b9298070c92d538be1af77523b27053f4a23de",
            "block_hash": "0xbac88cdc801196ab975bb07717bd964f87b14b093ac94997f47f768ed7ff1fcc",
        },
        "preimages": json.loads((F / "block-103132217-preimages.json").read_text()),
    }


class MantleInputTests(unittest.TestCase):
    def test_five_authenticated_qualification_inputs(self):
        self.assertEqual(len(qualification_inputs()), 5)

    def test_normal_transactions_include_authenticated_intrinsic_fee_reads(self):
        C = M.C
        for row in qualification_inputs():
            if row['block_number'] not in (103133433, 103133753):
                continue
            data = json.loads(row['guest_input_utf8'])
            records = {n['hash']: n['data'] for n in data['preimages']}
            root = C.unhex(data['fixture']['parent_header']['stateRoot'])
            proofs = row['intrinsic_fee_account_proofs']
            self.assertEqual([p['address'].lower() for p in proofs], [
                '0x420000000000000000000000000000000000000f',
                '0x4200000000000000000000000000000000000015'])
            for proof, slots in zip(proofs, ([0], [1, 3, 5, 6, 7, 8])):
                account = C.decode_rlp(C.verify_trie_value(
                    root, C.keccak(C.unhex(proof['address'], 20)), proof['accountProof']))
                self.assertEqual(len(account), 4)
                self.assertIn('0x' + account[3].hex(), records)
                self.assertEqual(len(proof['storageProof']), len(slots))
                for entry, slot in zip(proof['storageProof'], slots):
                    self.assertEqual(int(entry['key'], 16), slot)
                    encoded = C.verify_trie_value(account[2], C.keccak(slot.to_bytes(32, 'big')),
                                                  entry['proof'], allow_absence=True)
                    value = 0 if encoded is None else int.from_bytes(C.decode_rlp(encoded), 'big')
                    self.assertEqual(value, int(entry['value'], 16))
                for node in proof['accountProof'] + [n for e in proof['storageProof'] for n in e['proof']]:
                    self.assertEqual(records['0x' + C.keccak(C.unhex(node)).hex()], node)

    def test_wrong_nested_types_reject_before_execution(self):
        for field in ("fixture", "expected", "preimages"):
            value = fixture()
            value[field] = None
            with self.assertRaises(ValueError):
                M.statement(json.dumps(value).encode())
        value = fixture()
        value["fixture"]["rollup_config"]["l1_chain_id"] = True
        with self.assertRaisesRegex(ValueError, "network"):
            M.statement(json.dumps(value).encode())

    def test_exact_input_bound_public_statement_and_mutations(self):
        value = fixture()
        raw = json.dumps(value, separators=(",", ":")).encode()
        digest = hashlib.sha256(
            b"stwo/mantle/execution/v1\0"
            + hashlib.sha256(raw).digest()
            + bytes.fromhex(value["expected"]["block_hash"][2:])
        ).digest()
        public = digest + b"\x01" + (5000).to_bytes(8, "little") + b"ME"
        self.assertEqual(M.statement(raw), public)
        self.assertNotEqual(M.statement(raw + b" "), public)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(raw)
            self.assertEqual(M.read(path), (raw, public))
        for change in (
            "schema",
            "chain",
            "fork",
            "config",
            "parent",
            "adjacency",
            "preimage",
            "block",
        ):
            bad = copy.deepcopy(value)
            if change == "schema":
                bad["schema"] = True
            elif change == "chain":
                bad["fixture"]["rollup_config"]["l2_chain_id"] = 10
            elif change == "fork":
                bad["fixture"]["rollup_config"]["mantle_arsia_time"] += 1
            elif change == "config":
                bad["expected"]["config_sha256"] = "0x" + "11" * 32
            elif change == "parent":
                bad["fixture"]["expected_parent_hash"] = "0x" + "11" * 32
            elif change == "adjacency":
                bad["fixture"]["payload"]["timestamp"] = "0x6af44a7b"
            elif change == "preimage":
                bad["preimages"][0]["data"] = "0x00"
            else:
                bad["expected"]["block_hash"] = "0x" + "11" * 32
            mutated = json.dumps(bad).encode()
            if change == "block":
                self.assertNotEqual(M.statement(mutated), public)
            else:
                with self.assertRaises(ValueError, msg=change):
                    M.statement(mutated)
        for bad in (
            raw.replace(b'"schema":1', b'"schema":1,"schema":1'),
            b"{}",
            b" " * (M.MAX_INPUT + 1),
        ):
            with self.assertRaises(ValueError):
                M.statement(bad)
        self.assertNotEqual(public[:-2] + b"OP", public)
        self.assertNotEqual(public[:33] + (10).to_bytes(8, "little") + b"ME", public)

    def test_benchmark_uses_existing_host_guest_input_mode(self):
        from unittest.mock import patch
        import sys
        from opstack import benchmark

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            block = root / "fixtures/block-103132217"
            block.mkdir(parents=True)
            (block / "guest-input.json").write_text(json.dumps(fixture()))
            argv = [
                "benchmark.py",
                "--network",
                "mantle",
                "--profile",
                "ethereum_services_v3",
                "--fixtures",
                str(root / "fixtures"),
                "--artifacts",
                str(root / "out"),
                "--samples",
                "1",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    benchmark, "run", side_effect=RuntimeError("host boundary")
                ) as native,
            ):
                with self.assertRaisesRegex(RuntimeError, "host boundary"):
                    benchmark.main()
            self.assertEqual(native.call_args.args[0][1], "guest-input")
            self.assertEqual(
                (root / "out/103132217.guest-input.json").read_bytes(),
                (block / "guest-input.json").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
