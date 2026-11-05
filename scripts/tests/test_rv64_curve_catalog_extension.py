import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("partition", Path(__file__).parents[1] / "rv64_cuda_partition_grouped.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def catalogue(n, offset=0):
    lines = ["#pragma once", "// immutable base declarations"]
    for i in range(n):
        lines += [f'extern "C" void rv64_truth_domain_{i}_shard_0();',
                  f'static const Part truth_parts_{i}[]={{kernel_{i}}};']
    lines += ["static const StwoTruthKernelSpan truth_catalog[]={" +
              ",".join(f"{{truth_parts_{i},{i+1+offset}u}}" for i in range(n)) + "};"]
    return "\n".join(lines) + "\n"

class Extension(unittest.TestCase):
    def test_existing_geometry_and_new_definitions_are_independent(self):
        base, fresh = catalogue(10), catalogue(15, 99)
        out = m.extend_catalog(base, fresh)
        for i in range(10):
            self.assertIn(f"{{truth_parts_{i},{i+1}u}}", out)
            self.assertNotIn(f"{{truth_parts_{i},{i+100}u}}", out)
            self.assertEqual(out.count(f"void rv64_truth_domain_{i}_shard_0();"), 1)
        for i in range(10,15):
            self.assertIn(f"{{truth_parts_{i},{i+100}u}}", out)
            self.assertEqual(out.count(f"void rv64_truth_domain_{i}_shard_0();"), 1)
    def test_truncated_or_unadmitted_catalogue_is_rejected(self):
        for base, fresh in [(catalogue(7), catalogue(15)), (catalogue(10), catalogue(12)), (catalogue(10)+"int x;", catalogue(15))]:
            with self.assertRaises(ValueError): m.extend_catalog(base, fresh)

if __name__ == "__main__": unittest.main()
