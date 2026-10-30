import importlib.util
from pathlib import Path
import struct
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'native_geometry_cost_model.py'
spec = importlib.util.spec_from_file_location('native_geometry_cost_model', MODULE)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)

class GeometryCostModelTests(unittest.TestCase):
    def shape(self, width=50, cycles=1, public_cycles=1):
        return (struct.pack('<I', 1) + struct.pack('<BIII', 12, 1, 1, width) +
                struct.pack('<IIII', 0, 4, cycles, 1) + struct.pack('<IIII', 2, 1, 1, 10) +
                struct.pack('<III', 0, 4, public_cycles)).hex()
    def test_family_enum_and_infrastructure_use_different_canonical_widths(self):
        result = model.geometry(self.shape())
        self.assertEqual(result['shards'][0]['family'], 'load_store')
        self.assertEqual(result['infrastructure'][0]['kind'], 'clock_update')
        self.assertFalse(result['authenticates_statement'])
    def test_rejects_truncated_geometry(self):
        with self.assertRaises(ValueError):
            model.geometry(self.shape()[:-2])
    def test_rejects_unreviewed_family_width(self):
        with self.assertRaisesRegex(ValueError, 'unreviewed native width'):
            model.geometry(self.shape(width=49))
    def test_rejects_different_statement_and_public_counts(self):
        with self.assertRaises(ValueError):
            model.geometry(self.shape(public_cycles=2))
    def test_rejects_different_family_row_census(self):
        with self.assertRaises(ValueError):
            model.geometry(self.shape(cycles=2, public_cycles=2))

if __name__ == '__main__':
    unittest.main()
