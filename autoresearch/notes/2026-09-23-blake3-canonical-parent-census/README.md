# Canonical BLAKE3 parent census

This focused gate proves and authenticates a canonical guest-Poseidon leaf,
prepares its parent circuit, reports pre-lowering fusion candidates, and counts
the actual final padded columns for each parent AIR. It does not prove a parent.
The leaf uses 70 queries / 26 PoW bits and one guest precompile invocation.

The analyzer reports padded trace words across main, preprocessed and interaction
columns. These are geometry counts, not measured execution time or peak memory.
They exclude shared lookup tables, LDE expansion, Merkle trees and scratch.
Candidate counts describe existing fusion opportunities before lowering; they
must not be presented as new savings on top of the already-fused parent rows.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe '-Driscv-test-filter=canonical parent row census' --summary all
python3 autoresearch/notes/2026-09-23-blake3-canonical-parent-census/analyze.py
```

The gate passed. The actual G component has 3,174,808 live rows, padded to
4,194,304; it accounts for 86.3% of the counted trace words. Byte routing adds
5.2%, XOR adds 2.7%. Arithmetic/opening components (multiply-add, inverse, linear,
dot4 and native opening4) together contribute about 1.4%.

The parent retains 2,707,426,052 bytes of prepared rows, including 2,290,957,312
main-column bytes. ReleaseSafe preparation took 35.90 seconds and final row
assembly 0.34 seconds in this single qualification run; neither is a clean
performance baseline. The census proves no parent and establishes no speedup.

Next target: characterize transcript versus Merkle-opening hash work, then eliminate
repeated authenticated hash work where safe. Source inspection shows current
recursive path sizing sums a full group per opening and emission allocates a fresh
namespace per opening. Ancestor sharing is therefore a candidate, but its benefit
must be separated from leaf-payload hashing before choosing the implementation.
This is distinct from the shared execution-memory paths already optimized.

The 361,492 DEEP and 80,073 FRI removable arithmetic rows reported by the graph
census are candidates for the *existing* lowerer, not additional savings. The
actual roster already includes 23,870 native opening4 rows. Adding another DEEP
fusion first would address a small fraction of this fixture's padded geometry.

