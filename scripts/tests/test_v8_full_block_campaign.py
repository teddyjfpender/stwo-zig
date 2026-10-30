"""Coverage and checkpoint-integrity controls for the block assembly planner."""
import json
import copy
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import v8_full_block_campaign as campaign


class BlockCampaignTests(unittest.TestCase):
    def census(self, root):
        rows = []
        for index in range(5):
            counts = dict(cycles=16, core_rows=16, keccak_calls=0, recovery_calls=0, sha_calls=0)
            rows.append(dict(index=index, first_cycle=1 + 16 * index, entry_pc=4 + index * 4, exit_pc=8 + index * 4, terminal='halt_flag' if index == 4 else None, counts=counts))
        summary = dict(elf_sha256=campaign.PINS['guest.elf'][0], input_sha256=campaign.PINS['input.bin'][0], output_sha256=campaign.PINS['expected-output.bin'][0], segments=5, expected_cycles=80, counts=dict(cycles=80, core_rows=80, keccak_calls=0, recovery_calls=0, sha_calls=0))
        (root / 'summary.json').write_text(json.dumps(summary))
        (root / 'segments.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return rows

    def test_odd_tree_has_exact_coverage_without_duplicate_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.census(root)
            plan = campaign.make_plan(root, 16, 16, 4)
            campaign.validate_plan(plan)
            self.assertEqual(len(plan['windows']), 5)
            self.assertEqual(len(plan['folds']), 4)
            self.assertTrue(plan['windows'][0]['initial'])
            self.assertTrue(plan['windows'][-1]['terminal'])
            children = {node['id']: node['children'] for node in plan['folds']}
            def leaves(node):
                return sum((leaves(child) for child in children[node]), []) if node in children else [node]
            self.assertEqual(leaves(plan['root_id']), [window['id'] for window in plan['windows']])
            for tamper in ('path', 'root', 'repeat'):
                changed = copy.deepcopy(plan)
                if tamper == 'path':
                    changed['windows'][0]['id'] = '../../escape'
                elif tamper == 'root':
                    changed['root_id'] = changed['windows'][0]['id']
                else:
                    changed['folds'][0]['children'][1] = changed['folds'][0]['children'][0]
                with self.subTest(tamper=tamper), self.assertRaises(ValueError):
                    campaign.validate_plan(changed)

    def test_gap_wrong_program_and_premature_terminal_rejected(self):
        for alteration in ('gap', 'program', 'terminal'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                rows = self.census(root)
                if alteration == 'program':
                    summary = json.loads((root / 'summary.json').read_text())
                    summary['elf_sha256'] = '00' * 32
                    (root / 'summary.json').write_text(json.dumps(summary))
                else:
                    rows[1]['first_cycle' if alteration == 'gap' else 'terminal'] = 18 if alteration == 'gap' else 'halt_flag'
                    (root / 'segments.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
                with self.assertRaises(ValueError):
                    campaign.make_plan(root, 32, 16, 4)

    def test_snapshot_identity_is_canonical_and_rejects_bad_address_order(self):
        # This canonical identity uses u64 operands, unlike transport u32 words.
        raw = bytearray(b'B7WIN001' + struct.pack('<33I', 4, *([0] * 32)) + struct.pack('<Q', 2) + struct.pack('<IIII', 16, 7, 20, 8))
        expected = campaign.hashlib.sha256(b'stwo-v7-real-window-state-v1' + struct.pack('<38Q', 4, *([0] * 32), 2, 16, 7, 20, 8)).hexdigest()
        self.assertEqual(campaign.snapshot_identity(raw), expected)
        struct.pack_into('<I', raw, 156, 16)
        with self.assertRaises(ValueError):
            campaign.snapshot_identity(raw)


if __name__ == '__main__':
    unittest.main()
