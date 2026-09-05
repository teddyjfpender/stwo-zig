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
        self.assertTrue(self.manifest["stwo"]["full_block_guest_ported"])
        self.assertTrue(self.manifest["stwo"]["matched_semantic_input_projected"])
        self.assertFalse(self.manifest["stwo"]["full_block_execution_reproduced"])
        self.assertFalse(self.manifest["stwo"]["full_block_segment_proofs_verified"])
        self.assertFalse(self.manifest["stwo"]["full_block_recursive_root_verified"])
        smoke = self.manifest["stwo"]["guest_products"]["abi_smoke"]
        self.assertTrue(smoke["execution_reproduced"])
        self.assertFalse(smoke["execution_receipt"]["proof_generated"])
        self.assertFalse(smoke["execution_receipt"]["independent_proof_verification"])
        diagnostic = self.manifest["stwo"]["execution_diagnostics"]["keccak_only_full_block"]
        self.assertFalse(diagnostic["combined_ethereum_profile"])
        self.assertFalse(diagnostic["segment_proofs_verified"])
        self.assertFalse(diagnostic["timing"]["normative"])
        self.assertEqual(
            self.manifest["stwo"]["provider"]["scope"]["revm_ecrecover"],
            "software-default-crypto",
        )
        self.assertFalse(self.manifest["claim_boundary"]["stwo_full_block_comparison_ready"])

    def test_manifest_rejects_claim_inflation(self) -> None:
        for section, field in (
            ("stwo", "whole_frontend_verified"),
            ("stwo", "proof_system_soundness"),
            ("stwo", "full_block_execution_reproduced"),
            ("claim_boundary", "zisk_full_block_proof_reproduced"),
            ("claim_boundary", "stwo_mini_transition_is_full_ethereum_block"),
            ("claim_boundary", "matched_guest_statement_reproduced"),
            ("claim_boundary", "stwo_full_block_comparison_ready"),
        ):
            with self.subTest(section=section, field=field):
                mutated = copy.deepcopy(self.manifest)
                mutated[section][field] = True
                with self.assertRaises(subject.ContractError):
                    subject.validate_manifest(mutated)

        regressed = copy.deepcopy(self.manifest)
        regressed["stwo"]["matched_semantic_input_projected"] = False
        with self.assertRaises(subject.ContractError):
            subject.validate_manifest(regressed)

        regressed = copy.deepcopy(self.manifest)
        regressed["stwo"]["full_block_guest_ported"] = False
        with self.assertRaises(subject.ContractError):
            subject.validate_manifest(regressed)

    def test_stwo_provider_abi_and_product_boundaries_fail_closed(self) -> None:
        mutations = (
            ("revm precompile", lambda value: value["stwo"]["provider"]["scope"].update(
                {"revm_ecrecover": "native"},
            )),
            ("invalid result", lambda value: value["stwo"]["provider"]["scope"].update(
                {"invalid_result_air_implemented": True},
            )),
            ("ABI offset", lambda value: value["stwo"]["provider"]["abi"]["fields"][4].update(
                {"offset": 104},
            )),
            ("profile digest", lambda value: value["stwo"]["provider"]["profile"].update(
                {"semantic_digest": "00" * 32},
            )),
            ("source overlay", lambda value: value["stwo"]["provider"]["source"]["overlay"]
             ["files"][0].update({"sha256": "00" * 32})),
            ("static site inventory", lambda value: value["stwo"]["guest_products"]
             ["real_guest"].update({"keccak_instruction_sites": 1})),
            ("smoke address", lambda value: value["stwo"]["guest_products"]
             ["abi_smoke"].update({"expected_address": "00" * 20})),
            ("smoke execution regression", lambda value: value["stwo"]["guest_products"]
             ["abi_smoke"].update({"execution_reproduced": False})),
            ("smoke proof inflation", lambda value: value["stwo"]["guest_products"]
             ["abi_smoke"]["execution_receipt"].update({"proof_generated": True})),
            ("smoke row partition", lambda value: value["stwo"]["guest_products"]
             ["abi_smoke"]["execution_receipt"]["execution"].update(
                 {"total_external_trace_rows": 1},
             )),
            ("input cross-binding", lambda value: value["stwo"]["guest_products"]
             ["real_block"].update({"runner_input_sha256": "00" * 32})),
            ("diagnostic profile inflation", lambda value: value["stwo"]
             ["execution_diagnostics"]["keccak_only_full_block"].update(
                 {"combined_ethereum_profile": True},
             )),
            ("diagnostic proof inflation", lambda value: value["stwo"]
             ["execution_diagnostics"]["keccak_only_full_block"].update(
                 {"segment_proofs_verified": True},
             )),
            ("diagnostic timing inflation", lambda value: value["stwo"]
             ["execution_diagnostics"]["keccak_only_full_block"]["timing"].update(
                 {"normative": True},
             )),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                value = copy.deepcopy(self.manifest)
                mutate(value)
                with self.assertRaises(subject.ContractError):
                    subject.validate_manifest(value)

    def test_stwo_product_elf_parser_binds_profile_and_executable_sites(self) -> None:
        products = subject.stwo_products
        blob = bytearray(256)
        blob[:6] = b"\x7fELF\x01\x01"
        blob[18:20] = (243).to_bytes(2, "little")
        blob[28:32] = (52).to_bytes(4, "little")
        blob[42:44] = (32).to_bytes(2, "little")
        blob[44:46] = (1).to_bytes(2, "little")
        blob[52:56] = (1).to_bytes(4, "little")
        blob[56:60] = (128).to_bytes(4, "little")
        blob[68:72] = (32).to_bytes(4, "little")
        blob[76:80] = (1).to_bytes(4, "little")
        blob[128:132] = products.RECOVERY_WORD.to_bytes(4, "little")
        blob[132:136] = products.KECCAK_WORD.to_bytes(4, "little")
        descriptor = (
            b"STWZKVM\x00"
            + (1).to_bytes(2, "little")
            + (3).to_bytes(2, "little")
            + (6).to_bytes(8, "little")
            + (1).to_bytes(2, "little")
            + b"\x00\x00"
            + bytes.fromhex(products.PROFILE_DIGEST)
        )
        blob[192:248] = descriptor
        profile = self.manifest["stwo"]["provider"]["profile"]

        def expected(value: bytes) -> dict[str, object]:
            return {
                "bytes": len(value),
                "sha256": subject._sha256_bytes(value),
                "recovery_instruction_sites": 1,
                "keccak_instruction_sites": 1,
            }

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "guest.elf"
            path.write_bytes(blob)
            products._validate_elf(path, expected(blob), profile, "synthetic Stwo ELF")

            mutated = bytearray(blob)
            mutated[136:140] = products.RECOVERY_WORD.to_bytes(4, "little")
            path.write_bytes(mutated)
            with self.assertRaises(products.ProductContractError):
                products._validate_elf(path, expected(mutated), profile, "synthetic Stwo ELF")

            mutated = bytearray(blob)
            mutated[216] ^= 1
            path.write_bytes(mutated)
            with self.assertRaises(products.ProductContractError):
                products._validate_elf(path, expected(mutated), profile, "synthetic Stwo ELF")

    def test_stwo_projection_binds_canonical_transport_and_success_output(self) -> None:
        canonical = b"\x14\x01canonical-ssz"
        runner_input = len(canonical).to_bytes(4, "little") + canonical
        root = bytes(range(32))
        host_output = root + b"\x01" + (1).to_bytes(8, "little") + (0x1401).to_bytes(2, "little")
        manifest = copy.deepcopy(self.manifest)
        projection = manifest["stwo"]["semantic_projection"]
        projection["canonical_input"]["bytes"] = len(canonical)
        projection["canonical_input"]["sha256"] = subject._sha256_bytes(canonical)
        projection["stwo_runner_input"]["bytes"] = len(runner_input)
        projection["stwo_runner_input"]["sha256"] = subject._sha256_bytes(runner_input)
        projection["host_validation"]["output_sha256"] = subject._sha256_bytes(host_output)
        projection["host_validation"]["new_payload_request_root"] = root.hex()
        with tempfile.TemporaryDirectory() as directory:
            root_path = Path(directory)
            canonical_path = root_path / "canonical.bin"
            runner_path = root_path / "runner.bin"
            output_path = root_path / "output.bin"
            canonical_path.write_bytes(canonical)
            runner_path.write_bytes(runner_input)
            output_path.write_bytes(host_output)
            result = subject.validate_stwo_projection(
                canonical_path, runner_path, output_path, manifest,
            )
            self.assertEqual(result["status"], "host-semantic-projection-valid")

            runner_path.write_bytes((len(canonical) + 1).to_bytes(4, "little") + canonical)
            with self.assertRaises(subject.ContractError):
                subject.validate_stwo_projection(canonical_path, runner_path, output_path, manifest)
            runner_path.write_bytes(runner_input)
            output_path.write_bytes(root + b"\x00" + host_output[33:])
            with self.assertRaises(subject.ContractError):
                subject.validate_stwo_projection(canonical_path, runner_path, output_path, manifest)

    def test_zisk_stdin_frame_authority_rejects_payload_padding_and_length_mutations(self) -> None:
        payloads = [b"public-frame", b"witness-frame-longer"]
        raw = bytearray()
        frames = []
        semantic_types = [
            "guest_reth::RethInputPublic",
            "guest_reth::RethInputWitness",
        ]
        for index, payload in enumerate(payloads):
            header_offset = len(raw)
            raw.extend(len(payload).to_bytes(8, "little"))
            payload_offset = len(raw)
            raw.extend(payload)
            padding_bytes = (-len(raw)) % 8
            raw.extend(bytes(padding_bytes))
            frames.append({
                "index": index,
                "header_offset": header_offset,
                "payload_offset": payload_offset,
                "payload_bytes": len(payload),
                "padding_bytes": padding_bytes,
                "sha256": subject._sha256_bytes(payload),
                "codec": "bincode-v2-serde-standard",
                "semantic_type": semantic_types[index],
            })
        expected = {
            "schema": "zisk-stdin-frame-authority.v1",
            "framing": "u64le-length-prefixed-eight-byte-aligned",
            "frames": frames,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.bin"
            path.write_bytes(raw)
            self.assertEqual(subject.validate_zisk_stdin(path, expected), frames)

            payload_mutation = bytearray(raw)
            payload_mutation[frames[0]["payload_offset"]] ^= 1
            path.write_bytes(payload_mutation)
            with self.assertRaises(subject.ContractError):
                subject.validate_zisk_stdin(path, expected)

            padding_mutation = bytearray(raw)
            padding_offset = (frames[0]["payload_offset"] + frames[0]["payload_bytes"])
            padding_mutation[padding_offset] = 1
            path.write_bytes(padding_mutation)
            with self.assertRaises(subject.ContractError):
                subject.validate_zisk_stdin(path, expected)

            length_mutation = bytearray(raw)
            length_mutation[:8] = (len(payloads[0]) + 1).to_bytes(8, "little")
            path.write_bytes(length_mutation)
            with self.assertRaises(subject.ContractError):
                subject.validate_zisk_stdin(path, expected)

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
