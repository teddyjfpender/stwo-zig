"""Unit tests + repository gate for scripts/rv64_sync_lint.py (stream enqueue, M6).

  python3 -m unittest tests/scripts/rv64_sync_lint_test.py
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("rv64_sync_lint", ROOT / "scripts/rv64_sync_lint.py")
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)


def sites(path, text):
    return [(f, p) for f, p, _, _ in lint.scan_text(path, text)]


class Detection(unittest.TestCase):
    def test_zig_joins_syncs_and_readbacks(self):
        text = """
pub fn generate(owner: *Owner) !void {
    try ctx.join();
    // try ctx.join(); comments are ignored
    try ctx.download(try ctx.borrow(status), &flag);
    if (self.sync(native_context) != 0) return error.X;
}
test "tests are not on the prove path" {
    try ctx.join();
}
"""
        self.assertEqual(sites("a.zig", text), [("generate", "session_join"), ("generate", "staged_readback"), ("generate", "host_sync")])

    def test_nested_helper_fn_keeps_enclosing_method(self):
        text = """
    fn run(self: *Job) !void {
        const Sort = struct {
            fn less(a: u32, b: u32) bool { return a < b; }
        };
        try ctx.join();
    }
"""
        self.assertEqual(sites("a.zig", text), [("run", "session_join")])

    def test_cuda_blocking_calls(self):
        text = """
extern "C" int stwo_x_on(void *ctx) {
  CHECK(cudaStreamSynchronize(stream));
  // cudaDeviceSynchronize(); comment
  if (cudaEventSynchronize(end)) return 1;
  CHECK(stwo_exec_context_sync(o.ctx));
  owner->sync();
  cudaMemcpy(dst, src, n, cudaMemcpyDeviceToHost);
  cudaMemcpyAsync(dst, src, n, cudaMemcpyDeviceToHost, s);
  return 0;
}
"""
        got = sites("a.cu", text)
        self.assertEqual([p for _, p in got], ["cudaStreamSynchronize", "cudaEventSynchronize", "context_host_join", "owner_sync", "cudaMemcpy(blocking)"])
        self.assertTrue(all(f == "stwo_x_on" for f, _ in got))


class RepositoryGate(unittest.TestCase):
    def test_outer_prove_path_has_no_new_blocking_sites(self):
        sites_now, detail, missing = lint.scan()
        allowed = __import__("json").loads(lint.ALLOWLIST.read_text())["sites"]
        grown = {k: (allowed.get(k, 0), v) for k, v in sites_now.items() if v > allowed.get(k, 0)}
        self.assertEqual(grown, {}, "new host-blocking call(s) on the outer-node prove path; see scripts/rv64_sync_lint.py")


if __name__ == "__main__":
    unittest.main()
