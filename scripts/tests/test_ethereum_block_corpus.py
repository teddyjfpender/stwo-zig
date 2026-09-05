from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


subject = load_module(
    "ethereum_block_corpus", "autoresearch/benchmarks/ethereum_block_corpus.py",
)
comparison = load_module(
    "ethereum_block_comparison_for_corpus",
    "autoresearch/benchmarks/ethereum_block_comparison.py",
)


def reseal(value: dict) -> None:
    value["corpus_sha256"] = subject.corpus_sha256(value)


class EthereumBlockCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = subject.load()

    def test_corpus_is_small_ordered_unique_and_not_promoted(self) -> None:
        subject.validate(self.corpus)
        self.assertEqual(
            [fixture["category"] for fixture in self.corpus["fixtures"]],
            list(subject.CATEGORIES),
        )
        self.assertEqual(self.corpus["fixtures"][0]["block"]["number"], 24_628_607)
        self.assertEqual(len({fixture["block"]["number"]
                              for fixture in self.corpus["fixtures"]}), 5)
        self.assertFalse(self.corpus["promotion_ready"])

    def test_reference_fixture_cross_binds_existing_transport_custody(self) -> None:
        manifest = comparison.load_manifest()
        subject.validate_reference_manifest(self.corpus, manifest)
        fixture = self.corpus["fixtures"][0]
        block = manifest["block"]
        for field in (
            "chain_id", "number", "hash", "parent_hash", "state_root",
            "transactions_root", "receipts_root", "withdrawals_root", "requests_hash",
            "transaction_count", "gas_used", "timestamp",
        ):
            self.assertEqual(fixture["block"][field], block[field])
        guest = fixture["semantic_io"]["guest_transports"]
        protocol = manifest["benchmark_protocol"]["statement"]
        self.assertEqual(guest["zisk_input"], protocol["inputs"]["zisk_transport"])
        self.assertEqual(guest["stwo_input"], protocol["inputs"]["stwo_transport"])
        self.assertEqual(guest["zisk_output"], protocol["outputs"]["zisk_transport"])
        self.assertEqual(guest["stwo_output"], protocol["outputs"]["stwo_transport"])

    def test_candidate_semantic_io_is_pinned_without_guest_or_proof_inflation(self) -> None:
        for fixture in self.corpus["fixtures"][1:]:
            with self.subTest(fixture=fixture["fixture_id"]):
                self.assertGreater(fixture["semantic_io"]["input"]["bytes"], 0)
                self.assertGreater(fixture["semantic_io"]["output"]["bytes"], 0)
                self.assertTrue(all(value is None for value in
                                    fixture["semantic_io"]["guest_transports"].values()))
                self.assertEqual(fixture["proof_status"]["status"], "not-run")
                self.assertFalse(fixture["proof_status"]["leaf_proofs_freshly_verified"])

    def test_dynamic_categories_remain_candidates_until_instrumented_counts_exist(self) -> None:
        by_category = {fixture["category"]: fixture for fixture in self.corpus["fixtures"]}
        keccak = by_category["keccak-heavy"]
        storage = by_category["contract-or-storage-heavy"]
        self.assertIsNone(keccak["classification"]["metrics"]["dynamic_keccak_calls"])
        self.assertIsNone(storage["classification"]["metrics"]["dynamic_storage_writes"])
        self.assertEqual(keccak["classification"]["status"],
                         "pinned-candidate-dynamic-count-pending")
        self.assertEqual(storage["classification"]["status"],
                         "pinned-candidate-dynamic-count-pending")

    def test_rpc_projection_replay_binds_block_parent_io_and_receipt_counts(self) -> None:
        block = {
            "number": "0x2",
            "hash": "0x" + "11" * 32,
            "parentHash": "0x" + "22" * 32,
            "stateRoot": "0x" + "33" * 32,
            "transactionsRoot": "0x" + "44" * 32,
            "receiptsRoot": "0x" + "55" * 32,
            "withdrawalsRoot": "0x" + "66" * 32,
            "requestsHash": "0x" + "77" * 32,
            "gasUsed": "0x0",
            "gasLimit": "0x100000",
            "timestamp": "0x10",
            "logsBloom": "0x" + "00" * 256,
            "transactions": [],
            "withdrawals": [],
        }
        parent = {"hash": block["parentHash"], "stateRoot": "0x" + "88" * 32}
        input_projection, output_projection = subject.rpc_projections(block, parent)
        fixture = copy.deepcopy(self.corpus["fixtures"][1])
        fixture["block"].update({
            "number": 2,
            "hash": block["hash"],
            "parent_hash": block["parentHash"],
            "parent_state_root": parent["stateRoot"],
            "state_root": block["stateRoot"],
            "transactions_root": block["transactionsRoot"],
            "receipts_root": block["receiptsRoot"],
            "withdrawals_root": block["withdrawalsRoot"],
            "requests_hash": block["requestsHash"],
            "transaction_count": 0,
            "gas_used": 0,
            "gas_limit": int(block["gasLimit"], 16),
            "timestamp": int(block["timestamp"], 16),
        })
        fixture["semantic_io"]["input"] = subject.projection_identity(input_projection)
        fixture["semantic_io"]["output"] = subject.projection_identity(output_projection)
        subject.validate_rpc_fixture(fixture, block, parent, [])
        block["gasUsed"] = "0x1"
        with self.assertRaises(subject.CorpusError):
            subject.validate_rpc_fixture(fixture, block, parent, [])

    def test_mutations_fail_closed_even_when_resealed(self) -> None:
        mutations = (
            lambda value: value["fixtures"][1]["block"].update(
                {"number": value["fixtures"][0]["block"]["number"]},
            ),
            lambda value: value["fixtures"][2]["classification"].update(
                {"status": "selection-evidenced"},
            ),
            lambda value: value["fixtures"][4]["classification"]["metrics"].update(
                {"dynamic_storage_writes": 1},
            ),
            lambda value: value["fixtures"][1]["semantic_io"]["guest_transports"].update(
                {"stwo_input": copy.deepcopy(
                    value["fixtures"][0]["semantic_io"]["guest_transports"]["stwo_input"],
                )},
            ),
            lambda value: value["fixtures"][0]["proof_status"].update(
                {"leaf_proofs_freshly_verified": True},
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.corpus)
                mutate(value)
                reseal(value)
                with self.assertRaises(subject.CorpusError):
                    subject.validate(value)

    def test_corpus_digest_detects_unsealed_custody_changes(self) -> None:
        value = copy.deepcopy(self.corpus)
        value["fixtures"][0]["classification"]["selection_basis"] += " changed"
        with self.assertRaisesRegex(subject.CorpusError, "corpus digest differs"):
            subject.validate(value)


if __name__ == "__main__":
    unittest.main()
