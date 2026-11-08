import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "perf"))
from stwo_prof import scaffold, zigtools


class ScaffoldTest(unittest.TestCase):
    def test_isolate_zig_creates_contract_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os
            os.environ["STWO_PROF_SCRATCH"] = tmp
            try:
                dest = scaffold.isolate_zig("t1", None)
                for name in ("workload.zig", "main.zig", "build.zig"):
                    self.assertTrue((dest / name).exists(), name)
                # the fold-trap defence is part of the contract
                self.assertIn("run(seed: u64)", (dest / "workload.zig").read_text())
                self.assertIn("proc_pid_rusage", (dest / "main.zig").read_text())
            finally:
                del os.environ["STWO_PROF_SCRATCH"]

    def test_isolate_preserves_existing_workload(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os
            os.environ["STWO_PROF_SCRATCH"] = tmp
            try:
                dest = scaffold.isolate_zig("t2", None)
                (dest / "workload.zig").write_text("// custom\n")
                scaffold.isolate_zig("t2", None)
                self.assertEqual((dest / "workload.zig").read_text(), "// custom\n")
            finally:
                del os.environ["STWO_PROF_SCRATCH"]

    def test_isolate_wires_module_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os
            os.environ["STWO_PROF_SCRATCH"] = tmp
            try:
                module = Path(tmp) / "stwo.zig"
                module.write_text("pub const x = 1;\n")
                dest = scaffold.isolate_zig("t3", None, imports={"stwo": str(module)})
                build = (dest / "build.zig").read_text()
                self.assertIn('module.addImport("stwo", stwo_mod)', build)
                self.assertIn(str(module.resolve()), build)
                self.assertEqual(scaffold.workload_imports(dest),
                                 {"stwo": str(module.resolve())})
                # re-isolating without imports must not drop the wiring
                scaffold.isolate_zig("t3", None)
                self.assertIn("stwo_mod", (dest / "build.zig").read_text())
            finally:
                del os.environ["STWO_PROF_SCRATCH"]


ASM_FIXTURE = """\t.section __TEXT,__text
_hot_kernel:
\tld1 { v0.4s }, [x0]
\tmul v1.4s, v0.4s, v0.4s
\tst1 { v1.4s }, [x1]
\tadd x2, x2, #1
\tcmp x2, x3
\tb.lo _hot_kernel
\tret
"_scalar.helper":
\tadd x0, x0, x1
\tret
lTmp0:
\t.long 0
"""


class AsmSummaryTest(unittest.TestCase):
    def test_summary_counts_neon_branches_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            bench = Path(tmp)
            (bench / "bench.s").write_text(ASM_FIXTURE)
            # bypass the build step: parse the fixture directly
            original = zigtools._run
            zigtools._run = lambda *a, **k: None
            try:
                summary = zigtools.asm_summary(bench)
            finally:
                zigtools._run = original
            hot = summary["symbols"]["_hot_kernel"]
            self.assertEqual(hot["instructions"], 7)
            self.assertEqual(hot["neon"], 3)
            self.assertEqual(hot["branches"], 2)  # b.lo + ret
            self.assertEqual(hot["memory"], 2)  # ld1 + st1
            self.assertIn("_scalar.helper", summary["symbols"])
            self.assertNotIn("lTmp0", summary["symbols"])
            self.assertFalse(hot["std"])

    def test_std_symbol_classification(self):
        for name in ("_Io.Writer.printValue__anon_3357", "_fs.File.Writer.drain",
                     "___udivti3", "_memcpy", "_fmt.float.round__anon_5137"):
            self.assertTrue(zigtools.is_std_symbol(name), name)
        for name in ("_workload.run", "_main", "_fields.batchInverseInPlace",
                     "_m31.M31.inv"):
            self.assertFalse(zigtools.is_std_symbol(name), name)


SAMPLE_FIXTURE = """Call graph:
    2732 Thread_123
    + 2732 start  (in dyld) + 6  [0x1a2b3c]
    +   2732 main  (in bench) + 40  [0x104abc]
    +     2698 workload.run  (in bench) + 24  [0x104def]
    +     ! 2100 fields.batchInverseInPlace__anon_1234  (in bench) + 96  [0x104fed]
    +     34 counters  (in bench) + 12  [0x104aaa]
"""


class SampleFramesTest(unittest.TestCase):
    def test_hot_frames_are_inclusive_and_ranked(self):
        frames = zigtools.sample_hot_frames(SAMPLE_FIXTURE, top=3)
        self.assertEqual(frames[0]["symbol"], "main")
        self.assertEqual(frames[0]["pct_of_run"], 100.0)
        self.assertEqual(frames[1]["symbol"], "workload.run")
        self.assertEqual(frames[2]["samples"], 2100)
        self.assertNotIn("start", [f["symbol"] for f in frames])


class ResolveTest(unittest.TestCase):
    def test_resolve_prefers_paths_then_scratch(self):
        self.assertEqual(scaffold.resolve("./x/y"), Path("./x/y"))
        resolved = scaffold.resolve("justaname")
        self.assertTrue(str(resolved).endswith("justaname"))


if __name__ == "__main__":
    unittest.main()
