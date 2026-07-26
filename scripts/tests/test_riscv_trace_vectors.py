"""Encoder and fixture-identity tests for the riscv trace-vector gate."""

import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import riscv_trace_vectors as rtv
from riscv_trace_vectors_lib import admission as admission_policy
from riscv_trace_vectors_lib import corpus as corpus_contract

ROOT = Path(__file__).resolve().parents[2]


def elf_symbols(elf: bytes) -> dict[str, int]:
    """Read the minimal ELF32 symbol table emitted by the fixture builder."""
    section_offset = struct.unpack_from("<I", elf, 32)[0]
    section_size = struct.unpack_from("<H", elf, 46)[0]
    section_count = struct.unpack_from("<H", elf, 48)[0]
    sections = [
        elf[section_offset + index * section_size:section_offset + (index + 1) * section_size]
        for index in range(section_count)
    ]
    symbol_section = next(section for section in sections if struct.unpack_from("<I", section, 4)[0] == 2)
    symbols_offset, symbols_size = struct.unpack_from("<II", symbol_section, 16)
    strings_index = struct.unpack_from("<I", symbol_section, 24)[0]
    symbol_size = struct.unpack_from("<I", symbol_section, 36)[0]
    strings_offset, strings_size = struct.unpack_from("<II", sections[strings_index], 16)
    strings = elf[strings_offset:strings_offset + strings_size]

    result = {}
    for offset in range(symbols_offset + symbol_size, symbols_offset + symbols_size, symbol_size):
        name_offset, value = struct.unpack_from("<II", elf, offset)
        name_end = strings.index(0, name_offset)
        result[strings[name_offset:name_end].decode()] = value
    return result


class EncoderTest(unittest.TestCase):
    """Known-good encodings cross-checked against the Zig decoder's tests."""

    def test_addi(self):
        self.assertEqual(rtv.ADDI(1, 0, 10), 0x00A00093)
        self.assertEqual(rtv.ADDI(2, 0, 20), 0x01400113)

    def test_r_type(self):
        self.assertEqual(rtv.ADD(3, 1, 2), 0x002081B3)
        self.assertEqual(rtv.SUB(4, 2, 1), 0x40110233)
        self.assertEqual(rtv.XOR(8, 1, 2), 0x0020C433)

    def test_m_extension(self):
        self.assertEqual(rtv.DIV(1, 2, 3), 0x023140B3)
        self.assertEqual(rtv.MUL(5, 1, 2), 0x022082B3)

    def test_negative_immediate_wraps_to_twelve_bits(self):
        self.assertEqual((rtv.ADDI(1, 0, -1) >> 20) & 0xFFF, 0xFFF)

    def test_branch_immediate_scrambling_round_trips(self):
        # BLT x3, x4, -16: decode the scrambled fields back into the offset.
        word = rtv.BLT(3, 4, -16)
        imm = (
            ((word >> 31) & 1) << 12
            | ((word >> 7) & 1) << 11
            | ((word >> 25) & 0x3F) << 5
            | ((word >> 8) & 0xF) << 1
        )
        if imm & (1 << 12):
            imm -= 1 << 13
        self.assertEqual(imm, -16)

    def test_jal_immediate_scrambling_round_trips(self):
        word = rtv.JAL(5, 12)
        imm = (
            ((word >> 31) & 1) << 20
            | ((word >> 12) & 0xFF) << 12
            | ((word >> 20) & 1) << 11
            | ((word >> 21) & 0x3FF) << 1
        )
        self.assertEqual(imm, 12)

    def test_ecall(self):
        self.assertEqual(rtv.ECALL(), 0x00000073)

    def test_fence_reserved_fields_are_encoded_without_register_effects(self):
        self.assertEqual(rtv.FENCE(), 0x0FF0000F)
        self.assertEqual(
            rtv.FENCE(pred=0b0101, succ=0b1010, fm=0b0111, rs1=1, rd=2),
            0x75A0810F,
        )


class FixtureIdentityTest(unittest.TestCase):
    def test_historical_ecall_fixture_layout_still_reproduces(self):
        # The pre-restoration no-symbol ELF layout remains reproducible only so
        # its missing declared-program contract can be tested diagnostically.
        historical = [
            rtv.ADDI(1, 0, 10), rtv.ADDI(2, 0, 20), rtv.ADD(3, 1, 2),
            rtv.SUB(4, 2, 1), rtv.ECALL(),
        ]
        elf = rtv.build_elf(historical)
        self.assertEqual(len(elf), 104)
        self.assertEqual(elf[0x18:0x1C], (0x00010000).to_bytes(4, "little"))
        self.assertEqual(elf[0x3C:0x40], (0x00010000).to_bytes(4, "little"))

    def test_every_release_program_sets_the_nonzero_halt_flag(self):
        for name, program in rtv.PROGRAMS.items():
            self.assertEqual(program[-len(rtv.EPILOGUE()):], rtv.EPILOGUE(), name)
            self.assertNotEqual(program[-1], rtv.SENTINEL(), name)

    def test_every_release_elf_declares_text_and_io_contract(self):
        required = {
            "__text_start", "__text_len", "__data_start", "__data_len",
            "__global_pointer$", "__stack_bottom", "__stack_top",
            "__input_start", "__input_end", "__halt_flag", "__output_len",
            "__output_data", "__output_end",
        }
        for name, program in rtv.PROGRAMS.items():
            symbols = elf_symbols(rtv.build_release_elf(program))
            self.assertEqual(set(symbols), required, name)
            self.assertEqual(symbols, rtv.release_symbols(program), name)
            self.assertEqual(symbols["__text_len"], len(program) * 4, name)

    def test_multi_shard_addi_is_a_compact_declared_loop(self):
        program = rtv.prog_multi_shard_addi()
        self.assertEqual(len(program), 8)
        self.assertEqual(program.count(rtv.ADDI(1, 1, 1)), 1)
        self.assertIn(rtv.BLT(1, 2, -4), program)
        self.assertGreater(rtv.MULTI_SHARD_ADDI_ROWS, 65_536)
        self.assertEqual(
            elf_symbols(rtv.build_release_elf(program))["__text_len"],
            len(program) * 4,
        )

    def test_branch_fib_contains_signed_unsigned_taken_and_fallthrough_edges(self):
        program = rtv.prog_branch_fib()
        expected = {
            rtv.BNE(7, 8, 8),
            rtv.BNE(8, 8, 8),
            rtv.BGE(7, 8, 8),
            rtv.BGE(8, 7, 8),
            rtv.BLTU(7, 8, 8),
            rtv.BLTU(8, 7, 8),
            rtv.BGEU(7, 8, 8),
            rtv.BGEU(8, 7, 8),
        }
        self.assertEqual({word for word in program if word in expected}, expected)

    def test_mulhu_only_is_independently_proof_admitted(self):
        program = rtv.prog_mulhu_only()
        self.assertEqual(program.count(rtv.MULHU(3, 1, 2)), 1)
        self.assertNotIn(rtv.MULH(3, 1, 2), program)
        self.assertNotIn(rtv.MULHSU(3, 1, 2), program)
        self.assertEqual(
            rtv.PROOF_ADMISSION["mulhu_only"],
            {"status": admission_policy.SUPPORTED},
        )

    def test_every_rv32im_corpus_program_is_proof_admitted(self):
        self.assertEqual(set(rtv.PROOF_ADMISSION), set(rtv.PROGRAMS))
        vectors = [
            {"name": name, "proof_admission": dict(rtv.PROOF_ADMISSION[name])}
            for name in sorted(rtv.PROGRAMS)
        ]
        self.assertEqual(admission_policy.errors(vectors, rtv.PROOF_ADMISSION), [])
        supported = {
            name
            for name, policy in rtv.PROOF_ADMISSION.items()
            if policy["status"] == admission_policy.SUPPORTED
        }
        self.assertEqual(supported, set(rtv.PROGRAMS))

        unknown = [{**vector, "proof_admission": dict(vector["proof_admission"])} for vector in vectors]
        unknown[0]["proof_admission"]["status"] = "unknown"
        self.assertTrue(any(
            "unknown proof-admission status 'unknown'" in error
            for error in admission_policy.errors(unknown, rtv.PROOF_ADMISSION)
        ))
    def test_legacy_shapes_are_explicit_negative_diagnostics(self):
        undeclared, undeclared_reason = rtv.NEGATIVE_FIXTURES["undeclared_program"]
        self.assertEqual(struct.unpack_from("<I", undeclared, 32)[0], 0)
        self.assertEqual(undeclared_reason, "missing_declared_program_symbols")

        self_loop, self_loop_reason = rtv.NEGATIVE_FIXTURES["self_loop_sentinel"]
        text_len = elf_symbols(self_loop)["__text_len"]
        last_word_offset = 84 + text_len - 4
        self.assertEqual(struct.unpack_from("<I", self_loop, last_word_offset)[0], rtv.SENTINEL())
        self.assertEqual(
            self_loop_reason,
            "self_loop_terminates_without_setting_halt_flag",
        )

    def test_vector_file_covers_every_program(self):
        payload = json.loads(
            (ROOT / "vectors" / "riscv_elfs" / "trace_vectors.json").read_text()
        )
        self.assertEqual(
            {v["name"] for v in payload["vectors"]},
            set(rtv.PROGRAMS),
        )
        self.assertEqual(
            {v["name"] for v in payload["negative_vectors"]},
            set(rtv.NEGATIVE_FIXTURES),
        )
        self.assertEqual(
            {vector["name"]: vector["proof_admission"] for vector in payload["vectors"]},
            rtv.PROOF_ADMISSION,
        )
        self.assertTrue(all(
            vector["expected"] == "zig_reject_before_retirement"
            for vector in payload["negative_vectors"]
        ))
        for field, expected in rtv.manifest_identity().items():
            self.assertEqual(payload[field], expected)
        self.assertEqual(
            {
                opcode_id
                for vector in payload["vectors"]
                for opcode_id in vector["executed_opcode_ids"]
            },
            corpus_contract.EXPECTED_PROOF_OPCODE_IDS,
        )

    def test_decode_and_trap_negative_set_is_closed_and_declared(self):
        self.assertEqual(
            set(rtv.FORMAL_WORD_DISPOSITIONS),
            {
                "illegal_opcode",
                "reserved_op_funct7",
                "fence_i_outside_profile",
                "misaligned_jump_target",
                "misaligned_word_load",
                "system_ecall",
            },
        )
        self.assertEqual(
            rtv.FORMAL_WORD_DISPOSITIONS["fence_i_outside_profile"],
            (0x0000100F, False),
        )


if __name__ == "__main__":
    unittest.main()
