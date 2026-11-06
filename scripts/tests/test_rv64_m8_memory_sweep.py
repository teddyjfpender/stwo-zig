import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_m8_memory_sweep as sweep

ROOT = Path(__file__).resolve().parents[2]
ARENA_HEADER = ROOT / 'src/backends/cuda/native/runtime/device_arena_runtime.cuh'
HEADER = sweep.SCHEMA_TRACE + '\top\tt_us\tdevice\toffset\trounded\trequested\tlong\tsmall\tfenced\tcontext\tordinal\tdomain\tepoch\tstage\n'
G = 1 << 30

# The GPU layout the sweep and the 22 GiB preset assume (ZisK pins its RTX 5090
# buffer layout in goldilocks/tests/test_unified_buffer_layout_cpu.cpp). A change
# to any arena default must re-run the sweep and update this table.
PINNED_LAYOUT = {'chunk': 32 << 20, 'small_chunks': 16, 'reserve': 2 << 30, 'stack': 12544}


def row(op, offset, rounded, ordinal=-1, stage='main_witness', small=0, long=0, device=0, epoch=1, t=0):
    return '\t'.join(map(str, [op, t, device, offset, rounded, rounded, long, small, 0, 7, ordinal, 1 if ordinal >= 0 else 0, epoch, stage])) + '\n'


class SweepTests(unittest.TestCase):
    def write(self, tmp, rows):
        path = Path(tmp) / 'arena-trace-1.tsv'
        path.write_text(HEADER + ''.join(rows))
        return path

    def test_keep_next_input_and_shared_offload(self):
        rows = [row('A', 0, 2 * G, long=1),              # shared cache, untagged
                row('A', 1 * 1 << 34, 3 * G, 0),             # node 0 input
                row('S', 0, 0, 0),                           # main_witness closes, input live
                row('A', 2 << 34, 5 * G, 0, 'composition'),
                row('F', 2 << 34, 5 * G, 0, 'composition'),
                row('F', 1 << 34, 3 * G, 0, 'composition'),
                row('A', 3 << 34, 4 * G, 1),                 # node 1 input
                row('S', 0, 0, 1),
                row('F', 3 << 34, 4 * G, 1)]
        with tempfile.TemporaryDirectory() as tmp:
            policy = sweep.sweep([self.write(tmp, rows)], 22 * G, 32 << 20, 16, {0: 'leaf', 1: 'fold'})
        gen = policy['generated']
        self.assertEqual(gen['leaf']['own_peak'], 8 * G)
        self.assertEqual(gen['leaf']['keep_envelope_peak'], 10 * G)
        self.assertEqual(gen['leaf']['input_bytes'], 3 * G)
        # node 1's 4 GiB input is reserved while node 0 runs.
        self.assertEqual(gen['leaf']['next_input_envelope_peak'], 14 * G)
        self.assertEqual(gen['leaf']['shared_offload_envelope_peak'], 12 * G)
        self.assertEqual(gen['leaf']['policy'], 'next_input')
        self.assertEqual(gen['fold']['keep_envelope_peak'], 6 * G)

    def test_does_not_fit_is_reported_and_check_rejects(self):
        rows = [row('A', 1 << 34, 30 * G, 0), row('S', 0, 0, 0), row('F', 1 << 34, 30 * G, 0)]
        with tempfile.TemporaryDirectory() as tmp:
            policy = sweep.sweep([self.write(tmp, rows)], 22 * G, 32 << 20, 16, {})
            self.assertEqual(policy['generated']['node0']['policy'], 'DOES_NOT_FIT')
            path = Path(tmp) / 'policy.json'
            path.write_text(json.dumps(policy))
            with self.assertRaisesRegex(ValueError, 'no fitting policy'):
                sweep.check(path, 22 * G, 32 << 20, 16)
            with self.assertRaisesRegex(ValueError, 'swept layout'):
                sweep.check(path, 23 * G, 32 << 20, 16)

    def test_static_model_reports_fragmentation(self):
        # Two 8 GiB holes separated by a live 1 GiB block cannot host 12 GiB.
        rows = [row('A', 1 << 34, 8 * G, 0), row('A', 2 << 34, 1 * G, 0), row('A', 3 << 34, 8 * G, 0),
                row('F', 1 << 34, 8 * G, 0), row('F', 3 << 34, 8 * G, 0), row('A', 4 << 34, 12 * G, 0)]
        with tempfile.TemporaryDirectory() as tmp:
            stats, model = sweep.replay(sweep.read_trace(self.write(tmp, rows)), 'keep', 18 * G, 512 << 20, 32 << 20, {})
        self.assertFalse(model['static_fit'])
        self.assertTrue(stats[(1, 0, 1)]['fits_vmm'])

    def test_pinned_gpu_layout_matches_arena_defaults(self):
        text = ARENA_HEADER.read_text()
        config = text[text.index('struct Config {'):text.index('inline bool parse_bytes')]
        def value(name):
            m = re.search(r'\b' + name + r' = (?:uint64_t\((\d+)\) << (\d+)|(\d+));', config)
            return int(m.group(1)) << int(m.group(2)) if m.group(1) else int(m.group(3))
        self.assertEqual({k: value(k) for k in PINNED_LAYOUT}, PINNED_LAYOUT)


if __name__ == '__main__':
    unittest.main()
