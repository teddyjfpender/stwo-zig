from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_cuda_partition_grouped as G
import rv64_cuda_partition_instruction_slices as I


class PrivateNames(unittest.TestCase):
    def test_helper_names_are_kernel_local_and_separable_lowering_accepts_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('role_a', 'role_b'):
                source = root / (name + '.cu')
                source.write_text('using namespace stwo::cuda::rv64;\n' +
                    f'__device__ __noinline__ void {name}_part_0(){{\n' +
                    ' OM31 folded=zero();\n const uint32_t v0=42;\n const OM31 v1=base(v0);\n folded=add(folded,v1);\n const OM31 result=mul(folded,one());\n}\n' +
                    f'extern "C" __global__ void {name}(){{}}\n')
                G.bound_ssa_module(source)
                text = source.read_text()
                self.assertIn(name + '_bounded_step_0(', text)
                self.assertNotIn('rv64_truth_bounded_step_', text)
                plan = I.partition(source, root / name)
                self.assertEqual(plan['instruction_slices'], 1)
                self.assertNotIn(name + '_bounded_step_', ''.join(p.read_text() for p in plan['sources']))


if __name__ == '__main__':
    unittest.main()
