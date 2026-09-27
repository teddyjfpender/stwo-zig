# Full-STARK transcript and arithmetic in one parent fixture

Previous turn: progress; composition, DEEP and FRI of an actual verified STARK
capture shared one arithmetic proof, but the transcript used another proof.

The full transcript preparation now returns live and independently reconstructed
fixed rows instead of launching a standalone proof. Its operation/query storage
is released after preparation. Composition-root substitution uses a copied root
array, preserving caller capture data. Native transcript counter parity and
transactional rejection checks remain.

The arithmetic fixture includes the transcript's G, XOR, boundary, challenge,
byte-routing and query-mask rows with the multiply/inverse/linear rows. It merges
live and trusted boundaries separately and reconstructs all preprocessing before
native verification. Transcript schedules start at namespace 1,000,000; the three
arithmetic circuits occupy 1500, 1502 and 1504 (binary-mode alternates 1501/3/5).
The single-graph regression uses the same roster with padded transcript rows.

The observer now invokes the requested fixture directly. The composition fixture
owns full-STARK arithmetic/transcript assembly; the old implicit arithmetic call
plus separate transcript proof has been removed. The combined gate therefore
contains two complete proofs: the original standalone joined PCS proof, and the
parent fixture proving its transcript plus composition/DEEP/FRI arithmetic.

Inputs remain public fixture statements from one native verified capture. This
stage does not introduce private shared-input wires. The parent's full captured
trace/FRI authentication paths are still missing; the first proof's own standalone
PCS paths do not authenticate that first proof's native STARK commitments in the
parent. Production fixed-key/profile admission, CPU/Metal and parent-of-parent
qualification remain. Production still uses Poseidon; no speedup is claimed.

Validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri test-blake3-fri-arithmetic-proof -Doptimize=ReleaseSafe --summary all
```

Eight steps succeeded; both guarded tests passed. Combined gate: 12 seconds,
1 GiB peak RSS, compilation 35 seconds / 2 GiB. Single-graph FRI regression:
5 seconds, 368 MiB, compilation 26 seconds / 1 GiB. These are qualification test
timings, not production benchmark results. Formatting and diff checks passed;
no broad suite was run.
