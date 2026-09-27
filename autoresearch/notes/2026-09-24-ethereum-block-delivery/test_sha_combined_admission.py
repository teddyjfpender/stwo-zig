"""Run combined admission checks through the shared focused Zig harness."""
from pathlib import Path
import runpy
import sys

filters = sys.argv[1:] or ["BLAKE3 execution commitment Ethereum external witness census"]
script = Path(__file__).with_name("test_sha_memory_proof.py")
sys.argv = [str(script), "--root", "src/frontends/riscv/blake3_execution_commitment_test_root.zig", *filters]
runpy.run_path(str(script), run_name="__main__")
