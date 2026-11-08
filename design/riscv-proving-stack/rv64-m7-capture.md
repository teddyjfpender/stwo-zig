# M7 capture program views

The resident capture path reuses immutable decoded program metadata without
allocating a dense ROM matrix that capture never reads. Native key construction
still owns its materialized fixed columns. The authority cache indexes a freshly
rehash-checked ELF pin plus authority/ROM/control profiles, avoiding repeated
executable-word extraction. Each request still reloads and pins ELF and input,
validates its terminal and immutable policy, and derives its request identity.
Neither cache retains request memory or input-derived state.

`STWO_RV64_IMAGE_PROGRAM_CACHE=0` and
`STWO_RV64_CAPTURE_PROGRAM_VIEW=0` select the old paths for same-binary A/B.
Both default to enabled. The capture-bench constructor uses the same view.

## Qualification

Both development blocks ran three times in each selector configuration. All
12 complete native/bundle/recursive artifact sets are byte-identical to the
admitted M6 default c1 receipts. Fresh, cache-disabled CPU receivers from the
new build accepted both blocks in each configuration. Production uses the
unchanged M6 CUDA library; its hash and receiver/driver hashes are in the
receipts. Two named filtered ReleaseSafe tests passed on the pod: per-request
ELF/input pin and terminal rechecks, and full padded ROM-tuple/map equality
between a capture view and the materialized constructor. This is not a claim
that the entire test suite ran.

Single loaded-session observations [M]:

| measure | old | view |
|---|---:|---:|
| warm small Program construction, ms (median of 2) | 78.996 | 0.544 |
| warm headline Program construction, ms (median of 2) | 87.144 | 0.510 |
| first Program construction, ms | 123.905 | 22.308 |
| producer peak RSS, GiB | 34.159 | 33.327 |
| warm small request, s (median of 2) | 13.577 | 13.574 |
| warm headline request, s (median of 2) | 18.489 | 18.577 |

The decoded view removes about 78–87 ms per warm request's Program construction
and observed peak RSS is 0.832 GiB lower. Whole-request latency improvement is
not established: the control load was 14.62 to 15.48 [M], and view load was
33.88 to 22.27 [M]. Image setup includes fresh request loading/pinning and varied
with load. Capture execution itself remains roughly 1.7–2.1 s [M]. This does not
meet the M7 request or RSS target, and this roster is not a never-seen-block
installation claim.

The build's base commit and SHA-256 of every changed source are bound by
`source-and-tests-v2.json`; build/daemon/parity receipts live beside it under
`vectors/reports/rv64-m7-20261105/capture/`. No performance claim is based on an
unbuilt source revision.
