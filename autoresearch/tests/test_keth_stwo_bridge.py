"""Trust-boundary tests for the experimental Keth PIE orchestration."""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
from autoresearch.experiments.evm_keth import bridge
from autoresearch.experiments.evm_keth.op_stack_journal import OpStackRangeJournal
from autoresearch.experiments.evm_keth.legacy_input import convert, write_compact, OPCODES, BUILTINS


class KethBridgeTests(unittest.TestCase):
    def test_source_lane_and_claim_defaults(self):
        self.assertEqual(bridge.PINS["keth"]["supported_chain_id"], 1)
        self.assertTrue(all(value is False for value in bridge.claims().values()))

    def test_committed_smoke_fixture_matches_source_receipt(self):
        evidence = ROOT / "autoresearch/experiments/evm_keth/evidence"
        receipt = json.loads((evidence / "smoke-provenance.json").read_text())
        self.assertEqual(receipt["source"]["revision"], bridge.PINS["keth"]["revision"])
        self.assertEqual(receipt["pie_sha256"], bridge.digest(evidence / "keth_fibonacci.pie.zip"))
        self.assertEqual(receipt["scope"], "keth-fibonacci-pie-transport-only")
        self.assertEqual(receipt["expected_output"], [144])
        validation = json.loads((evidence / "validation.json").read_text())
        self.assertEqual(validation["proof"]["retained_binary_proof_sha256"],
                         bridge.digest(evidence / "keth_fibonacci.proof.bz2"))
        self.assertTrue(all(value is False for value in validation["claims"].values()))

    def test_wrong_revision_and_dirty_source_rejected(self):
        with patch.object(bridge, "git", return_value="0" * 40):
            with self.assertRaisesRegex(ValueError, "revision mismatch"):
                bridge.authenticate(Path("keth"), bridge.PINS["keth"])
        with patch.object(bridge, "git", side_effect=[bridge.PINS["keth"]["revision"], " M source.cairo"]):
            with self.assertRaisesRegex(ValueError, "dirty"):
                bridge.authenticate(Path("keth"), bridge.PINS["keth"])

    def test_op_stack_cannot_be_smuggled_into_ethereum_data_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            block = bridge.PINS["keth"]["minimum_block"]
            path = base / "1" / str(block) / "zkpi.json"
            path.parent.mkdir(parents=True)
            for chain_id in (5000, 5003, "1", True):
                path.write_text(json.dumps({"chainConfig": {"chainId": chain_id}}))
                with self.assertRaisesRegex(ValueError, "chain ID 1"):
                    bridge.validate_zkpi(base, block)
            path.write_text(json.dumps({"chainConfig": {"chainId": 1}}))
            self.assertEqual(bridge.validate_zkpi(base, block), path)
            with self.assertRaisesRegex(ValueError, "Prague"):
                bridge.validate_zkpi(base, block - 1)

    def test_receipt_cannot_replace_existing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            bridge.write_new(path, {"value": "original"})
            with self.assertRaises(FileExistsError):
                bridge.write_new(path, {"value": "replacement"})
            self.assertEqual(json.loads(path.read_text()), {"value": "original"})

    def test_failed_verification_does_not_publish_bridge_acceptance(self):
        from scripts import benchmark_cairo
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pie = base / "input.zip"
            pie.write_bytes(b"fixture")
            args = argparse.Namespace(pie=pie, product=pie, oracle=pie, trials=1, out=base / "out")
            with patch.object(benchmark_cairo, "run_benchmark", side_effect=RuntimeError("verifier rejected")):
                with self.assertRaisesRegex(RuntimeError, "verifier rejected"):
                    bridge.prove(args)
            self.assertFalse((args.out / "receipt.json").exists())

    def test_cairo_acceptance_never_implies_op_stack_or_ethereum_statement(self):
        from scripts import benchmark_cairo
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pie = base / "input.zip"
            pie.write_bytes(b"fixture")
            args = argparse.Namespace(pie=pie, product=pie, oracle=pie, trials=1, out=base / "out")
            with patch.object(benchmark_cairo, "run_benchmark", return_value={"status": "qualified"}):
                result = bridge.prove(args)
            self.assertTrue(result["cairo_proof_verified"])
            self.assertTrue(all(value is False for value in result["claims"].values()))
            self.assertEqual(result["application_program_provenance"], "not-established-by-this-command")


class LegacyInputTests(unittest.TestCase):
    def test_compact_encoder_matches_existing_official_wire_vector(self):
        fixture = ROOT / 'vectors/cairo/official/all_opcodes.prover_input'
        out = io.BytesIO()
        write_compact(out, json.loads(fixture.with_suffix('.prover_input.json').read_text()))
        self.assertEqual(out.getvalue(), fixture.with_suffix('.prover_input.cpi').read_bytes())

    def fixture(self):
        return {'state_transitions': {'initial_state': {'pc': 1, 'ap': 2, 'fp': 2},
                'final_state': {'pc': 1, 'ap': 2, 'fp': 2},
                'casm_states_by_opcode': {k: [] for k in OPCODES}},
                'memory': {'config': {'small_max': (1 << 72) - 1, 'log_small_value_capacity': 24},
                           'address_to_id': [0x3fffffff, 0], 'small_values': [42], 'f252_values': []},
                'inst_cache': [[1, 42]], 'public_memory_addresses': [1],
                'builtin_segments': {k: None for k in BUILTINS},
                'public_segment_context': {'present': [True] * 11}}

    def test_witness_preserved_and_pinned_schema_names_translated(self):
        old = self.fixture()
        memory = old['memory']
        translated, receipt = convert(old, {'data': ['0x2a']})
        self.assertIs(translated['memory'], memory)
        self.assertEqual(translated['pc_count'], 1)
        self.assertNotIn('inst_cache', translated)
        self.assertIn('jnz_opcode_non_taken', translated['state_transitions']['casm_states_by_opcode'])
        self.assertEqual(receipt['compiled_program_cells_checked'], 1)

    def test_different_program_unknown_schema_and_inconsistent_cache_rejected(self):
        with self.assertRaisesRegex(ValueError, 'compiled program not bound'):
            convert(self.fixture(), {'data': ['0x2b']})
        old = self.fixture()
        old['builtin_segments']['ec_op'] = None
        with self.assertRaisesRegex(ValueError, 'unsupported schema'):
            convert(old, {'data': ['0x2a']})
        old = self.fixture()
        old['inst_cache'][0][1] = 43
        with self.assertRaisesRegex(ValueError, 'cache disagrees'):
            convert(old, {'data': ['0x2a']})
        old = self.fixture()
        old['public_memory_addresses'] = []
        with self.assertRaisesRegex(ValueError, 'compiled program not bound'):
            convert(old, {'data': ['0x2a']})


class OpStackJournalTests(unittest.TestCase):
    def test_solidity_abi_field_order_and_uint64_padding(self):
        journal = OpStackRangeJournal(b"\x11" * 32, b"\x22" * 32, b"\x33" * 32,
                                     94355445, b"\x44" * 32)
        encoded = journal.encode()
        # Independently specified five-word BootInfoStruct ABI, not a generated golden file.
        expected = bytes.fromhex("11" * 32 + "22" * 32 + "33" * 32
                                 + "00000000000000000000000000000000000000000000000000000000059fbff5"
                                 + "44" * 32)
        self.assertEqual(encoded, expected)
        self.assertEqual(OpStackRangeJournal.decode(encoded), journal)

    def test_uint64_noncanonical_padding_and_wrong_journal_rejected(self):
        journal = OpStackRangeJournal(bytes(32), bytes(32), bytes(32), 0, bytes(32))
        mutated = bytearray(journal.encode())
        mutated[96] = 1
        with self.assertRaisesRegex(ValueError, "uint64"):
            OpStackRangeJournal.decode(bytes(mutated))
        for data in (bytes(159), bytes(192), bytes(161)):
            with self.assertRaisesRegex(ValueError, "five ABI words"):
                OpStackRangeJournal.decode(data)
        for value in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                OpStackRangeJournal(bytes(32), bytes(32), bytes(32), value, bytes(32))
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            OpStackRangeJournal(bytes(31), bytes(32), bytes(32), 0, bytes(32))


if __name__ == "__main__":
    unittest.main()
