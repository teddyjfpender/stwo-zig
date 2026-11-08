from pathlib import Path
import ctypes
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_cuda_private_host_symbols as S


@unittest.skipUnless(sys.platform.startswith('linux') and all(shutil.which(p) for p in ('g++', 'objcopy', 'nm', 'c++filt')), 'requires Linux ELF/binutils')
class PrivateCudaHostHelpers(unittest.TestCase):
    def object(self, root, name, result=7, wrong_signature=False):
        source = root / (name + '.cpp')
        helper = 'int rv64_truth_bounded_step_0(int){return 0;}' if wrong_signature else '''
namespace stwo {namespace cuda {namespace rv64 {struct OM31 {unsigned v[8];};}}}
stwo::cuda::rv64::OM31 rv64_truth_bounded_step_0(volatile unsigned*,volatile stwo::cuda::rv64::OM31*,const unsigned*,const unsigned*,const unsigned*,const unsigned long*,const unsigned*,const unsigned*,unsigned,unsigned,unsigned){return {};}
'''
        source.write_text(helper + f'\nextern "C" int stwo_catalog_{name}(){{return {result};}}\n' + '__attribute__((used,section(".nv_fatbin"))) const unsigned char cuda_bytes[]={91,82,73,64,55,46,37,28};\n')
        output = root / (name + '.o')
        subprocess.run(['g++', '-fPIC', '-O2', '-c', str(source), '-o', str(output)], check=True)
        return output

    def test_collision_repair_preserves_code_cuda_bytes_and_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = [self.object(root, 'a', 7), self.object(root, 'b', 9)]
            failed = subprocess.run(['g++', '-shared', *map(str, original), '-o', str(root / 'bad.so')], capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            selected = []
            for path in original:
                old_sha = S.sha(path)
                output, receipt = S.localize(path, root / 'localized')
                self.assertEqual(S.sha(path), old_sha)
                self.assertEqual(S.protected_sections(path), S.protected_sections(output))
                self.assertEqual(len(receipt['whitelist']), 1)
                selected.append(output)
            library = root / 'good.so'
            subprocess.run(['g++', '-shared', *map(str, selected), '-o', str(library)], check=True)
            image = ctypes.CDLL(str(library))
            self.assertEqual(image.stwo_catalog_a(), 7)
            self.assertEqual(image.stwo_catalog_b(), 9)

    def test_unknown_helper_signature_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.object(root, 'wrong', wrong_signature=True)
            with self.assertRaisesRegex(ValueError, 'signature'):
                S.localize(path, root / 'output')

    def test_changed_cuda_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.object(root, 'guard')
            run = S.subprocess.run
            def corrupt(command, **options):
                result = run(command, **options)
                if command[0] != 'objcopy':
                    return result
                output = Path(command[-1])
                data = output.read_bytes()
                marker = bytes([91,82,73,64,55,46,37,28])
                self.assertIn(marker, data)
                output.write_bytes(data.replace(marker, bytes([90,82,73,64,55,46,37,28]), 1))
                return result
            with mock.patch.object(S.subprocess, 'run', side_effect=corrupt):
                with self.assertRaisesRegex(ValueError, 'code/CUDA'):
                    S.localize(path, root / 'output')


if __name__ == '__main__':
    unittest.main()
