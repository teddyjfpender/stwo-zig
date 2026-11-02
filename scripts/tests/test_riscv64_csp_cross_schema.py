"""Complete-public-statement adapter mutation tests, not proof verification."""
import copy
import struct
import unittest
from scripts import riscv64_csp_cross_schema as adapter
from scripts.tests import test_riscv64_csp_full_proofs as fixture


class CrossSchemaTests(unittest.TestCase):
    statement = fixture.FullProofDriverTests.statement

    # Reuse only fixture construction, not legacy orchestration tests.
    def setUp(self):
        fixture.FullProofDriverTests.setUp(self)
        self.old = self.statement()
        self.histogram = [0] * 65
        self.histogram[adapter.OPCODES.index('ADDI')] = 100
        self.old['opcodes'] = [bool(x) for x in self.histogram]
        guest = {'elf': str(self.elf), 'input': str(self.input), 'expected_digest': '0' * 64,
                 'symbols': {k.removeprefix('__'): v for k, v in self.symbols.items()}, 'max_steps': 100}
        self.old_config = {'guest': guest, 'expected_steps': 100, 'profile_only': False, 'control_policy': 'limbs24_v2'}
        self.new_config = {'guest': copy.deepcopy(guest), 'expected_steps': 100, 'workers': 8,
                           'elf_sha256': adapter.legacy.digest(self.elf), 'input_sha256': adapter.legacy.digest(self.input)}
        self.bundle = {'schema': 4, 'geometry': {}, 'cpu': {k: copy.deepcopy(self.old[k]) for k in adapter.CPU_FIELDS},
                       'epoch': 1, 'division_requests': 0, 'multiplication_requests': 0, 'ls_count': 0,
                       'memory_words': len(self.old['cells']), 'claims': {}}
        common = {'pcs_config': copy.deepcopy(adapter.PCS), 'workers': 8, 'build_mode': 'ReleaseFast',
                  'pow_bits': 26, 'fri_queries': 70, 'opcode_names': list(adapter.OPCODES), 'opcode_histogram': self.histogram}
        self.old_report = {**copy.deepcopy(common), 'verified': True, 'whole_guest_proof': True, 'instructions': 100, 'control_policy': 'limbs24_v2'}
        self.old_fresh = copy.deepcopy(self.old_report)
        self.new_report = {**copy.deepcopy(common), 'physical_proof_verified': True, 'expected_output_bound_to_terminal_ram': True, 'steps': 100, 'geometry': {}}
        self.new_fresh = copy.deepcopy(self.new_report)
        self.sidecar = self.root / 'cells.bin'
        before, after = [], []
        for cell, clock in zip(self.old['cells'], self.old['memory_clocks']):
            before.append(struct.pack('<QQHIB', cell['address'], cell['initial'], 0, 0, 3))
            after.append(struct.pack('<QQHIB', cell['address'], cell['final'], 1, clock, 3))
        self.raw = b'RV64RAM1' + struct.pack('<II', len(before), len(after)) + b''.join(before + after)
        self.sidecar.write_bytes(self.raw)

    def check(self):
        return adapter.checked_pair(self.old, self.bundle, self.sidecar, self.old_config, self.new_config,
                                    self.old_report, self.new_report, self.old_fresh, self.new_fresh)

    def test_complete_full64_statement_accepts(self):
        result = self.check()
        self.assertTrue(result['clock_rights_complete_coverage_checked'])
        self.assertEqual(result['semantic_statement_sha256'], adapter.legacy.semantic_statement_digest(self.old))

    def test_each_cpu_boundary_and_clock_mutation_rejects(self):
        for field in adapter.CPU_FIELDS:
            saved = copy.deepcopy(self.bundle)
            value = self.bundle['cpu'][field]
            if isinstance(value, list):
                value[5] += 1
            else:
                self.bundle['cpu'][field] += 4 if 'pc' in field else 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check()
            self.bundle = saved

    def test_epoch_count_schema_and_provider_mutations_reject(self):
        for field in ('epoch', 'memory_words', 'division_requests', 'multiplication_requests', 'ls_count', 'schema'):
            saved = copy.deepcopy(self.bundle)
            self.bundle[field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check()
            self.bundle = saved
        self.bundle['unreviewed_field'] = 0
        with self.assertRaises(ValueError): self.check()

    def test_ram_full64_rights_clocks_epochs_coverage_reject(self):
        for offset, fmt, value in ((16, '<Q', 0x100003000), (16+22, '<B', 1),
                                   (16+23*5+16, '<H', 2), (16+23*5+18, '<I', 401),
                                   (16+23*5+22, '<B', 1)):
            raw = bytearray(self.raw)
            struct.pack_into(fmt, raw, offset, value)
            self.sidecar.write_bytes(raw)
            with self.subTest(offset=offset), self.assertRaises(ValueError): self.check()
        for raw in (self.raw[:-1], self.raw+b'x'):
            self.sidecar.write_bytes(raw)
            with self.assertRaises(ValueError): self.check()

    def test_fresh_security_worker_build_and_complete_coverage_reject(self):
        for target, field, value in ((self.old_fresh,'workers',4), (self.new_fresh,'build_mode','ReleaseSafe'),
                                      (self.new_fresh,'pcs_config',{}), (self.new_report,'physical_proof_verified',False),
                                      (self.new_report,'expected_output_bound_to_terminal_ram',False),
                                      (self.old_fresh,'whole_guest_proof',False), (self.new_report,'opcode_names',[]), (self.new_report,'geometry',{'cpu_log': 22})):
            saved = copy.deepcopy(target[field]); target[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.check()
            target[field] = saved
        self.new_report['opcode_histogram'] = [100]+[0]*64
        with self.assertRaises(ValueError): self.check()

    def test_trusted_pins_program_and_terminal_output_reject(self):
        for field in ('elf_sha256','input_sha256'):
            saved = self.new_config[field]; self.new_config[field] = 'f'*64
            with self.subTest(field=field), self.assertRaises(ValueError): self.check()
            self.new_config[field] = saved
        self.old['program']['base'] &= 0xffffffff
        with self.assertRaises(ValueError): self.check()


if __name__ == '__main__': unittest.main()
