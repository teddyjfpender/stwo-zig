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


class SeedPreambleTests(unittest.TestCase):
    """The memory-seeding preamble, decoded rather than trusted.

    A wrong encoder would seed the wrong word or land at the wrong pc and turn
    every seeded comparison into noise, so the words are re-executed here by an
    independent decoder before the pinned Sail ever sees them.
    """

    @staticmethod
    def _execute(words: list[int]) -> tuple[int, dict[int, int], dict[int, int]]:
        """Interpret the RV32I subset a preamble may use; returns pc/regs/mem."""
        pc = equivalence.RVFI_DII_ENTRY
        regs: dict[int, int] = {}
        memory: dict[int, int] = {}

        def signed12(imm: int) -> int:
            return imm - 0x1000 if imm >= 0x800 else imm

        for word in words:
            opcode = word & 0x7F
            if opcode == 0x37:  # LUI
                regs[(word >> 7) & 0x1F] = (word >> 12 << 12) & 0xFFFF_FFFF
                pc += 4
            elif opcode == 0x13:  # ADDI
                rd = (word >> 7) & 0x1F
                rs1 = (word >> 15) & 0x1F
                base = regs.get(rs1, 0) if rs1 else 0
                regs[rd] = (base + signed12(word >> 20)) & 0xFFFF_FFFF
                pc += 4
            elif opcode == 0x23:  # SW
                imm = ((word >> 25) << 5) | ((word >> 7) & 0x1F)
                address = regs[(word >> 15) & 0x1F] + signed12(imm)
                memory[address & 0xFFFF_FFFF] = regs[(word >> 20) & 0x1F]
                pc += 4
            elif opcode == 0x6F:  # JAL x0
                imm = (
                    ((word >> 31) & 1) << 20
                    | ((word >> 12) & 0xFF) << 12
                    | ((word >> 20) & 1) << 11
                    | ((word >> 21) & 0x3FF) << 1
                )
                pc += imm - (1 << 21) if imm & (1 << 20) else imm
            else:
                raise AssertionError(f"preamble emitted 0x{word:08x}")
        return pc, regs, memory

    def test_jal_encoding_matches_known_word(self) -> None:
        # `j -4` is the canonical assembler fixture for the scattered immediate.
        self.assertEqual(0xFFDFF06F, equivalence._encode_jal_x0(-4))

    def test_preamble_seeds_image_restores_registers_and_lands_on_entry(self) -> None:
        image = [(0x0018_0000, 0x0403_0201), (0x0010_0000, 0xFFFF_F800)]
        pc, regs, memory = self._execute(equivalence.seed_preamble(image))
        self.assertEqual(equivalence.RVFI_DII_ENTRY, pc)
        self.assertEqual(0, regs[equivalence._SEED_ADDRESS_REGISTER])
        self.assertEqual(0, regs[equivalence._SEED_VALUE_REGISTER])
        self.assertEqual(dict(image), memory)

    def test_preamble_longer_than_one_jal_hop_still_lands_on_entry(self) -> None:
        image = [(0x0010_0000 + 4 * index, index) for index in range(70_000)]
        words = equivalence.seed_preamble(image)
        self.assertGreater(4 * len(words), equivalence._JAL_MAX_BACKWARD)
        pc, _, memory = self._execute(words)
        self.assertEqual(equivalence.RVFI_DII_ENTRY, pc)
        self.assertEqual(70_000, len(memory))

    def test_preamble_rejects_misaligned_and_duplicate_words(self) -> None:
        with self.assertRaisesRegex(equivalence.EquivalenceError, "word-aligned"):
            equivalence.seed_preamble([(0x0018_0002, 1)])
        with self.assertRaisesRegex(equivalence.EquivalenceError, "seeded twice"):
            equivalence.seed_preamble([(0x0018_0000, 1), (0x0018_0000, 2)])


if __name__ == "__main__":
    unittest.main()
