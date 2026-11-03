from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_cuda_partition_instruction_slices as S


class InstructionModules(unittest.TestCase):
    def test_definition_coverage_unique_symbols_and_original_call_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "kernel.cu"
            prefix = 'using namespace stwo::cuda::rv64;\n'
            helpers = ''.join(f'__device__ __noinline__ OM31 rv64_truth_bounded_step_{i}(int a){{return use(powers+{100+i}u);}}\n' for i in range(3))
            tail = '__device__ __noinline__ void original_part(){rv64_truth_bounded_step_0(0);rv64_truth_bounded_step_1(0);rv64_truth_bounded_step_2(0);}\nextern "C" __global__ void original_kernel(){original_part();}\n'
            original = prefix + helpers + tail
            source.write_text(original)
            plan = S.partition(source, root / "parts", 2)
            self.assertEqual(plan['instruction_slices'], 3)
            self.assertEqual(len(plan['sources']), 3)
            chunks = [p.read_text() for p in plan['sources']]
            self.assertIn('powers+100u', chunks[0])
            self.assertIn('powers+101u', chunks[0])
            self.assertNotIn('powers+102u', chunks[0])
            self.assertIn('powers+102u', chunks[1])
            self.assertNotIn('original_kernel', chunks[0])
            self.assertIn('original_kernel', chunks[2])
            calls = chunks[2].split('void original_part(){')[1]
            self.assertLess(calls.index('_step_0('), calls.index('_step_1('))
            self.assertLess(calls.index('_step_1('), calls.index('_step_2('))
            self.assertNotIn('rv64_truth_bounded_step_', ''.join(chunks))
            self.assertEqual(source.read_text(), original)

    def test_invalid_bound_and_unbounded_input_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'kernel.cu'
            source.write_text('not an instruction module')
            with self.assertRaisesRegex(ValueError, 'positive'):
                S.partition(source, root, 0)
            with self.assertRaisesRegex(ValueError, 'functions'):
                S.partition(source, root)


if __name__ == '__main__':
    unittest.main()
