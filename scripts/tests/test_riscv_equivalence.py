from __future__ import annotations

import struct
import unittest

from scripts import riscv_equivalence as equivalence


def retirement(
    *,
    pc: int = 0x1000,
    instruction: int = 0x00100093,
    rd: int = 1,
    rd_value: int = 1,
    next_pc: int = 0x1004,
) -> dict:
    return {
        "order": 0,
        "pc": pc,
        "instruction": instruction,
        "rd": rd,
        "rd_value": rd_value,
        "next_pc": next_pc,
        "memory": {
            "address": 0,
            "read_mask": 0,
            "read_value": 0,
            "write_mask": 0,
            "write_value": 0,
        },
    }


def trace(row: dict) -> dict:
    return {
        "schema": equivalence.TRACE_SCHEMA,
        "profile": equivalence.PROFILE,
        "initial_pc": row["pc"],
        "retirements": [row],
        "final_pc": row["next_pc"],
        "total_steps": 1,
    }


class RiscvEquivalenceTests(unittest.TestCase):
    def test_canonical_retirements_compare_every_memory_field(self) -> None:
        expected = trace(retirement())
        actual = trace(retirement())
        self.assertEqual([], equivalence.compare_traces(expected, actual))
        actual["retirements"][0]["memory"]["write_value"] = 7
        errors = equivalence.compare_traces(expected, actual)
        self.assertEqual(1, len(errors))
        self.assertIn("retirement 0.memory.write_value", errors[0])

    def test_trace_validation_rejects_noncanonical_order_and_masks(self) -> None:
        malformed = trace(retirement())
        malformed["retirements"][0]["order"] = 3
        with self.assertRaisesRegex(equivalence.EquivalenceError, "order"):
            equivalence.validate_trace(malformed)
        malformed = trace(retirement())
        malformed["retirements"][0]["memory"]["read_mask"] = 0x10
        with self.assertRaisesRegex(equivalence.EquivalenceError, "exceeds RV32"):
            equivalence.validate_trace(malformed)

    def test_rvfi_v1_packet_decoder_uses_official_byte_layout(self) -> None:
        words = [
            9,
            equivalence.RVFI_DII_ENTRY,
            equivalence.RVFI_DII_ENTRY + 4,
            0x00100093,
            11,
            22,
            33,
            0x2000,
            0xAABBCCDD,
            0x11223344,
            0,
        ]
        packet = bytearray(struct.pack("<11Q", *words))
        packet[80] = 0x3
        packet[81] = 0xF
        packet[82] = 2
        packet[83] = 3
        packet[84] = 1
        decoded = equivalence.decode_rvfi_dii_v1(bytes(packet))
        self.assertEqual(equivalence.RVFI_DII_ENTRY, decoded["pc"])
        self.assertEqual(0x00100093, decoded["instruction"])
        self.assertEqual(1, decoded["rd"])
        self.assertEqual(33, decoded["rd_value"])
        self.assertEqual(0x3, decoded["memory"]["read_mask"])
        self.assertEqual(0xF, decoded["memory"]["write_mask"])

    def test_formal_transport_patch_is_hash_pinned(self) -> None:
        self.assertEqual(
            equivalence.PINNED_RVFI_TRANSPORT_PATCH_SHA256,
            equivalence._sha256_file(equivalence.RVFI_TRANSPORT_PATCH),
        )
        patch = equivalence.RVFI_TRANSPORT_PATCH.read_text(encoding="utf-8")
        self.assertIn("-  return 0x80000000;", patch)
        self.assertIn("+  return 0x00010000;", patch)

    def test_spike_commit_log_decoder_and_comparator_cover_exposed_effects(self) -> None:
        expected = trace(retirement())
        log = (
            "warning: tohost and fromhost symbols not in ELF\n"
            "core   0: 3 0x00001000 (0x00100093) x1  0x00000001\n"
        )
        rows = equivalence.decode_spike_commit_log(log)
        self.assertEqual(1, len(rows))
        self.assertEqual(1, rows[0]["rd"])
        self.assertEqual([], equivalence.compare_spike_commit_trace(rows, expected))

        rows[0]["rd_value"] = 2
        errors = equivalence.compare_spike_commit_trace(rows, expected)
        self.assertEqual(1, len(errors))
        self.assertIn("retirement 0.rd_value", errors[0])

    def test_spike_commit_decoder_rejects_unknown_effect_shapes(self) -> None:
        with self.assertRaisesRegex(equivalence.EquivalenceError, "unknown effects"):
            equivalence.decode_spike_commit_log(
                "core   0: 3 0x00001000 (0x00100093) csr 0x300 0x1"
            )


if __name__ == "__main__":
    unittest.main()
