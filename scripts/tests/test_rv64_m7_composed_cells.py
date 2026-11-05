"""Exercise receipt scope/schema refusals against the preserved real proof corpus."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package'
SCRIPT = ROOT / 'scripts/rv64_m7_composed_cells.py'


class ComposedCells(unittest.TestCase):
    def run_gate(self, package, output):
        return subprocess.run(['python3', str(SCRIPT), str(package), '--out', str(output)],
                              capture_output=True, text=True)

    def test_real_cold_warm_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'cells.json'
            result = self.run_gate(PACKAGE, out)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = json.loads(out.read_text())['runs']
            self.assertEqual(len(rows), 5)
            m6 = next(row for row in rows if row['configuration'] == '24628607-combined-m6-v3')
            self.assertEqual(m6['cells']['total'], 35790524160)

    def test_mutated_scope_and_schema_refused(self):
        source = PACKAGE / '24628607-combined-d2-coalesce-v1'
        original = (source / 'producer.stderr').read_text()
        marker = re.search(r'^GPU_RESIDENT_BLOCK .*$', original, re.M)
        mutants = {
            'duplicate_node': original.replace('RECURSION_NODE_SHAPE node=1 ', 'RECURSION_NODE_SHAPE node=0 ', 1),
            'foreign_scope': original.replace('GPU_RESIDENT_BLOCK block=24628607 trial=0', 'GPU_RESIDENT_BLOCK block=26235156 trial=0', 1),
            'duplicate_boundary': original[:marker.start()] + marker[0] + '\n' + original[marker.start():],
            # Change both cold/warm fixed-table logs so the schema check,
            # rather than the cold/warm multiset check, must refuse it.
            'component_roster': re.sub(r'(logs=\{[^}]*?,[^}]*?,[^}]*?,[^}]*?,[^}]*?,)\s*16,', r'\g<1> 17,', original),
        }
        for name, text in mutants.items():
            with self.subTest(mutation=name), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp) / source.name
                directory.mkdir()
                for item in source.iterdir():
                    if item.name != 'producer.stderr':
                        (directory / item.name).symlink_to(item, target_is_directory=item.is_dir())
                (directory / 'producer.stderr').write_text(text)
                result = self.run_gate(Path(tmp), Path(tmp) / 'out.json')
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn('RuntimeError:', result.stderr)


if __name__ == '__main__':
    unittest.main()
