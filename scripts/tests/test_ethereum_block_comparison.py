from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "autoresearch/benchmarks/ethereum_block_comparison.py"
SPEC = importlib.util.spec_from_file_location("ethereum_block_comparison", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)


class EthereumBlockComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = subject.load_manifest()

    def test_manifest_and_stwo_claim_boundary_are_current(self) -> None:
        subject.validate_manifest(self.manifest)
        subject.validate_stwo_source(ROOT, self.manifest)
        self.assertFalse(self.manifest["stwo"]["whole_frontend_verified"])
        self.assertFalse(self.manifest["stwo"]["proof_system_soundness"])
        self.assertFalse(self.manifest["claim_boundary"]["stwo_full_block_comparison_ready"])

    def test_manifest_rejects_claim_inflation(self) -> None:
        for section, field in (
            ("stwo", "whole_frontend_verified"),
            ("stwo", "proof_system_soundness"),
            ("stwo", "full_block_execution_reproduced"),
            ("claim_boundary", "zisk_full_block_proof_reproduced"),
            ("claim_boundary", "stwo_mini_transition_is_full_ethereum_block"),
            ("claim_boundary", "stwo_full_block_comparison_ready"),
        ):
            with self.subTest(section=section, field=field):
                mutated = copy.deepcopy(self.manifest)
                mutated[section][field] = True
                with self.assertRaises(subject.ContractError):
                    subject.validate_manifest(mutated)

    def test_rpc_projection_accepts_exact_block_and_rejects_root_mutation(self) -> None:
        block = self.manifest["block"]
        result = {
            "number": block["rpc_tag"],
            "hash": block["hash"],
            "parentHash": block["parent_hash"],
            "stateRoot": block["state_root"],
            "transactionsRoot": block["transactions_root"],
            "receiptsRoot": block["receipts_root"],
            "withdrawalsRoot": block["withdrawals_root"],
            "requestsHash": block["requests_hash"],
            "gasUsed": hex(block["gas_used"]),
            "gasLimit": hex(block["gas_limit"]),
            "timestamp": hex(block["timestamp"]),
            "transactions": [f"0x{index:064x}" for index in range(block["transaction_count"])],
        }
        subject.validate_rpc_result(result, self.manifest)
        for field in ("hash", "stateRoot", "transactionsRoot", "receiptsRoot"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(result)
                mutated[field] = "0x" + "00" * 32
                with self.assertRaises(subject.ContractError):
                    subject.validate_rpc_result(mutated, self.manifest)

    def test_execution_parser_binds_block_cost_steps_and_output(self) -> None:
        block = self.manifest["block"]
        execution = self.manifest["zisk"]["execution"]
        stdout = f"""
Execution summary:
  - Block Hash: {block['hash']}
  - Transaction Count: {block['transaction_count']}
  - Gas Consumed: {block['gas_used']}
║  STEPS {execution['steps']:,} ║
◆ COST DISTRIBUTION SUMMARY
║  Total {execution['sdk_display_cost']:,} 100.0% ║
"""
        cost = execution["cost"]
        stats = "\n".join((
            f"STEPS,{execution['steps']}",
            "",
            "COST,COST DISTRIBUTION,COST,%",
            f"COST,MAIN,{cost['main']},0%",
            f"COST,OPCODES,{cost['opcodes']},0%",
            f"COST,PRECOMPILES,{cost['precompiles']},0%",
            f"COST,MEMORY,{cost['memory_including_initialization']},0%",
            "COST,VARIABLE,1,0%",
            f"COST,BASE,{cost['base']},0%",
            f"COST,TOTAL,{execution['stats_cost_including_initialization']},0%",
            f"COST,FROPS,{cost['frops']},0%",
        )) + "\n"
        output = bytes([32]) + bytes.fromhex(block["hash"][2:]) + bytes(223)
        self.assertEqual(subject._sha256_bytes(output), execution["output"]["sha256"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout_path = root / "stdout.log"
            stats_path = root / "stats.csv"
            output_path = root / "output.bin"
            stdout_path.write_text(stdout)
            stats_path.write_text(stats)
            output_path.write_bytes(output)
            parsed = subject.parse_execution(stdout_path, stats_path, output_path, self.manifest)
            self.assertEqual(parsed["steps"], execution["steps"])
            output_path.write_bytes(output[:-1] + b"\x01")
            with self.assertRaises(subject.ContractError):
                subject.parse_execution(stdout_path, stats_path, output_path, self.manifest)

    def test_plan_parser_binds_every_air_and_total(self) -> None:
        instances = self.manifest["zisk"]["plan"]["instances"]
        body = " | ".join(f"{name}: {count}" for name, count in instances.items())
        text = (
            f"INFO: Zisk | {body} | Total instances: {sum(instances.values())}\n"
            f"INFO: Execution completed in 999ms, steps: "
            f"{self.manifest['zisk']['execution']['steps']}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.log"
            path.write_text(text)
            self.assertEqual(subject.parse_plan_counts(path, self.manifest), instances)
            path.write_text(text.replace("Main: 15", "Main: 14"))
            with self.assertRaises(subject.ContractError):
                subject.parse_plan_counts(path, self.manifest)

    def test_manifest_json_is_canonical_data(self) -> None:
        raw = subject.DEFAULT_MANIFEST.read_text(encoding="utf-8")
        self.assertTrue(raw.endswith("\n"))
        self.assertEqual(json.loads(raw)["block"]["rpc_tag"], "0x177cd7f")


if __name__ == "__main__":
    unittest.main()
