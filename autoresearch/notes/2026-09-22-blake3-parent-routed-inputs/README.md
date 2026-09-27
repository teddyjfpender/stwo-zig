# Shared parent arithmetic and transcript inputs

Previous turn: progress; routed absorption qualified independently, but the parent
still absorbed claims and samples as public byte constants.

The full parent now uses routed_felts for both claimed sums and sampled values.
The PCS operation builder exposes optional sampled-value routing through new
appendOpeningFrom/appendStarkVerifierFrom entrypoints; the original wrappers
retain public behavior. Native transcript checks and transactional publication
are unchanged. Prefix construction no longer locates samples by pointer identity
or guesses their operation offset: the builder assigns their protocol role.

The composition recorder supplies its exact leading sample-input and claim-input
node ranges. Prefix preparation builds canonical field-byte encoder rows reading
those QM31 wires, plus owned input-read metadata. The arithmetic producer's
multiplicity includes its graph consumers and exactly one encoder read. Duplicate,
non-input/out-of-range and mismatching-value bindings are rejected during assembly.
The canonical encoder feeds the transcript's external byte source using its exact
per-coordinate use receipt. No new AIR or semantic digest was introduced.

Claim producers now use private boundary rows: their direct expected-value fields
are zero/disabled, while the same value is constrained by composition and transcript.
Sample producers keep public arithmetic anchors because DEEP's coordinate inputs
are not yet privately joined. This avoids introducing independent private copies.
The eleven-AIR parent retains all composition/DEEP/FRI, transcript and path checks.
Encoder preprocessing is independently generated from schedules.

This closes the parent integration gap for routed absorption and makes its claim
sources private. It does NOT make the entire parent key reusable: public sampled
values, challenge/root/query values, dynamic path routing and rejection scheduling
remain. Other per-proof public outputs can depend on the claims even though the
direct claim anchors are removed. The source capture still comes from successful
native verification. Production profile/key/private-input admission, CPU/Metal,
parent-of-parent qualification and performance evidence remain. Production uses
Poseidon; no migration completion or speedup is claimed.

Validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-combined-fri test-blake3-fri-arithmetic-proof -Doptimize=ReleaseSafe --summary all
```

Eight steps succeeded; both guarded tests passed. Combined original/parent gate:
28 seconds / 6 GiB peak RSS, compilation 35 seconds / 2 GiB. Single-graph FRI
regression: 5 seconds / 368 MiB, compilation 28 seconds / 1 GiB. Timings are
qualification costs, not production recursion latency. Formatting and diff checks
passed. No full repository suite was run.
