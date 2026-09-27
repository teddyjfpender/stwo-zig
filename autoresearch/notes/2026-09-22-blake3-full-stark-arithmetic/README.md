# Real full-STARK composition, DEEP and FRI arithmetic

Previous stage: composition/OODS proof for a real verified STARK capture. The
opening arithmetic still used the much smaller standalone two-column fixture.

This stage builds DEEP and FRI geometry from the admitted native components and
proof-gate parameters. All four trees are included: preprocessed, main,
interaction and composition. Component-generated column degrees receive the
configured blowup, and exact ordered masks are classified using the shared
sample_point_layout authority. The FRI schedule comes from the same configured
fold width, terminal degree and lifting size. Captured geometry is checked
against these independently generated profiles.

pcs_arithmetic_capture.Owned is a hash-independent checked conversion to canonical
DEEP inputs. It checks tree/column logs, ordered sample points, sample/query/answer
counts, field encodings and raw query bounds before owning copied witness data.
Its contract requires caller-admitted profile and capture provenance; it does
not authenticate Merkle roots. The existing FRI capture adapter remains in use.

The arithmetic proof harness now accepts several graph lanes. Composition,
DEEP and FRI are lowered into the SAME complete BLAKE3 arithmetic proof, using
existing multiplication, inverse and linear AIRs. All graph inputs are public
fixture statement values from the same native capture. This is not yet private
cross-graph source wiring or transcript/hash integration. Independent operation
preprocessing and false-key rejection remain. The original single-graph API and
FRI proof gate use the same harness.

The combined test still contains three complete proofs: original standalone
joined PCS; full-STARK composition/DEEP/FRI arithmetic of that proof; its complete
transcript. These three do not constitute a single full recursive parent.
Production profile/key admission, joining full captured authentication paths and
transcript, CPU/Metal and parent-of-parent qualification remain. Production still
uses Poseidon. No production performance improvement is claimed.

Validation (M5 Max, serialized ReleaseSafe):

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri test-blake3-fri-arithmetic-proof -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-pcs-arithmetic-capture -Doptimize=ReleaseSafe --summary all
```

Both proof gates passed: combined test 14 seconds / 2 GiB max RSS, compilation
36 seconds / 2 GiB; independent FRI proof 3 seconds / 367 MiB, compilation
23 seconds / 1 GiB. These remain qualification timings, not production latency.
The adapter unit gate passed in 491 ms / 1 MiB, compilation 3 seconds / 460 MiB.
It covers allocation failures, copied samples/values/answers/duplicate queries,
sample-order substitution at identical counts, valid previous-first order,
out-of-range queries, noncanonical base/extension fields and column-log swaps.
The initial unit run hit the field constructor's assertion while constructing
an intentionally invalid field. The test now injects invalid storage directly;
admission rejects it as intended. Both unit logs are retained. Formatting and
whitespace checks passed. No full suite rerun.
