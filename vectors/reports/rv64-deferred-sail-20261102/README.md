# Deferred binding on the pinned continuous Sail corpus

Source `137ebb50e` adds one producer-only qualification option:
`defer_local_binding: true`. It does not change the image identity, statement,
VM profile, instructions, PCS parameters or receiver authority. The default is
false. No production library implementation changes are included in this slice.

The existing pinned corpus contains 1,032,240 retirements, 12,903 generated cases
and all 63 supported ordinary RV64IM opcodes. The adapter checks every retirement
against the independent RVFI stream before building advice. It retains the strict
Sail revision, ELF and oracle pins from the previous qualification.

| Profile | Proving time | Physical proof bytes | Fresh receiver |
|---|---:|---:|---|
| OM control, beta1/q70/P26/fold4 | 2.829 s | 569,304 | accepted |
| OM candidate, beta2/q256/P0/fold4 | 3.654 s | 1,903,064 | accepted |

Both runs use source-dense80 (`STWO_ZIG_GKR_STREAM_BOTTOM=1`), with checkpoint and
other GKR producer selection overrides removed. The fresh receiver runs with all
GKR producer flags removed. Wrong expected endpoints are rejected, and exchanging
the two PCS profiles is rejected with `GlobalGkrManifestExecution`.

For each profile, `bundle.json`, `cells.bin`, `cpu-0.bin` and `stage-one.bin` hash
identically to the previously accepted source80 Sail artifacts under
`/tmp/stwo-rv64-om-sail-stream-dense80-{control,candidate}-v1`. Thus the numerical
child proof and its previously independently replayed numerical contexts do not
change. This receipt does not claim an additional Rust PCS/execution verifier.

The retained projection allocation is 93,792,496 bytes; the completed binding is
187,584,752 bytes. Plane payloads halve; descriptor headers remain. The admitted
construction overlap is 281,377,248 bytes, and both runs report successful local
binding completion. Local metadata is retired on the existing timeline.

These are single functional runs, not an isolated performance A/B. Process RSS is
5,577,752,576 bytes (control) and 5,990,187,008 bytes (candidate), including the
existing bounded recycler and other runtime owners. The shared allocator cap is
48 GiB and the adapter uses eight workers. No whole-protocol 128-bit certificate,
GPU qualification, new CSP adapter or throughput promotion is claimed.

`reproduce.py`, the exact qualification config, raw build/producer/receiver logs,
proof hashes and detailed counters are included. Run the script under
`lockf -k /private/tmp/stwo-rv64-perf-heavy.lock` after building
`rv64-om-sail-qualification` in ReleaseFast. Corpus files are referenced by their
existing pinned paths; they are not regenerated or duplicated in this report.
