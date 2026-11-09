import importlib.util
from pathlib import Path
import tempfile
import unittest

_spec = importlib.util.spec_from_file_location('miller_fixture', Path(__file__).parents[1] / 'tools/miller_capacity_fixture.py')
fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fixture)

class MillerFixtureTest(unittest.TestCase):
    def test_tower_basis_relations_and_identity(self):
        def unit(i):
            out = [0] * 12
            out[i] = 1
            return out
        self.assertEqual(fixture.mul(unit(1), unit(1)), [fixture.Q - 1] + [0] * 11)
        self.assertEqual(fixture.mul(unit(6), unit(6)), unit(2))
        self.assertEqual(fixture.mul(fixture.mul(unit(2), unit(2)), unit(2)), [9, 1] + [0] * 10)
        sample = list(range(1, 13))
        self.assertEqual(fixture.mul(sample, unit(0)), sample)
        self.assertEqual(fixture.mul(unit(0), sample), sample)
        self.assertEqual(fixture.mul([fixture.Q] + [0] * 11, unit(0)), [0] * 12)
        self.assertEqual(fixture.mul([fixture.Q + 1] + [0] * 11, unit(0)), unit(0))

    def test_embedded_symbols_and_loop_program(self):
        initial, _, _ = fixture.reference(2)
        code, terminal = fixture.program(2)
        image = fixture.elf(code, initial)
        self.assertEqual(fixture.symbols_from_elf(image), fixture.ABI)
        self.assertEqual(int.from_bytes(code[16:20], 'little'), 0x73)
        self.assertEqual(int.from_bytes(code[24:28], 'little'), 0xFE029CE3)
        self.assertEqual(terminal, fixture.PC + len(code) - 4)
        with tempfile.TemporaryDirectory() as d:
            path = fixture.generate(Path(d) / 'fixture', 2)
            self.assertTrue(path.is_file())

if __name__ == '__main__':
    unittest.main()
