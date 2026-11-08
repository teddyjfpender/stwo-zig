# Compact eager state: less trace scratch, two-lane run still fails

Raw evidence links below now resolve through `../raw-artifacts-summary.json`; verified raw copies are retained outside Git under the receipt policy.

**P1 remains open.** Compact storage removes unused pending Blake2s planes
without changing arithmetic, column order, streaming calls or proof format.
The intended composed two-lane small-block cold request reaches the 120 s
watchdog without a root [M]. Headline timing is skipped. A separate single-lane
correctness diagnostic completes both requests with byte/capture identity and
fresh CPU acceptance [M]; it does not qualify the failed two-lane configuration.

| 26235156, two RTX 5090s | Default baseline | Intended composed candidate |
|---|---|---|
| Cold request wall [M, correctness only] | 28.468 s | watchdog at 120 s; no root |
| Warm request wall [M, correctness only] | 15.429 s | not reached |
| Warm capture / setup / native prove / recursion [M] | 1.701 / 4.736 / 3.345 / 5.490 s | unavailable |
| Largest logged INTER scratch [M, requested allocation] | 3,825,206,528 bytes | 2,952,791,296 bytes |
| Whole-request GPU-seconds / busy | unavailable | unavailable |
| Exact per-node peak | unmeasured | unmeasured |
| Root proof bytes [M] | 749,464 | absent |
| Fresh CPU accepts [M] | both baseline requests | no completed candidate proof |

These walls include capture hashing and diagnostic admission observations;
they are not matched quiet headline timings. Scratch sizes are logged at the
same 304-column, 18-call, 2^24-row geometry [M]. The saving is 872,415,232 bytes
[D, difference of logged allocations], not an exact whole-node peak reduction.

The failed service waits at MAIN trace commit: node 4 requires
24,561,844,224 bytes against 23,085,449,216 capacity [D, admission model]. Node
13 waits behind the wide stage [M, logged wait]. Stable live and future fields
are model inputs, not exact node peaks. The failure has 27 matching partial
payload files and is missing five required files, including the root [M].
Partial payloads do not count as an accepted proof. No same-configuration
headline retry or performance profile was run.

The separate single-lane diagnostic retains the 22 GiB arena, global
admission, sessions, sparse composition, all four P1 flags, and the physical
ceiling guard. Only lane count and its pending-authority floor change. Both
requests preserve the accepted baseline's payload and captured-input hashes;
both fresh CPU receivers accept [M]. Logs record 78 compact trace invocations
and 208 compact late-PCS invocations across those requests [M]. Its walls are
30.350 s cold and 14.747 s warm [M, correctness only, overlapping CPU corpus
work]; no speed comparison is valid. Process/session arena high-water lines
remain raw observations, not per-node attribution.

The independent preservation gate **PASSES**: build, five Zig test targets,
Python tests, both default small-block proofs matching all 32 frozen payloads,
two fresh CPU accepts, and all 19 corpus cases [M]. V04 rejects by file-size
cap, not semantic verification. The standalone numerical fixture also passes
64 cases across both GPUs, rejects 384 invalid calls, and passes Compute
Sanitizer with zero errors [M, numerical ABI scope]. All six distinct completed
proof sets in this checkpoint have fresh CPU acceptance [M].

Default remains D2 + truth coalescing, automatic arena, one lane. The new
`STWO_RV64_COMPACT_EAGER_STATE=1` selection is off by default, as are the three
earlier P1 flags. A requested compact plan requires the native capability and
compact entry; it cannot silently call the legacy full-state validator.
Conjectured-128 security and the hash-based proof format are unchanged.

Next: audit real simultaneous PCS allocations and retire composition/INTER
buffers at their actual last use. The existing PCS calculator deliberately
sums disjoint phases. Its bound must not be discounted without validating the
native lifetime and zero-idle-cache contracts. The read-only
`pcs-phase-lifetime-audit.json` records the relevant source boundaries; it
changes no budget or admission behavior. Removing only INTER numerator
storage may leave the summed PCS future dominant.

Evidence is under `p1-compact-state-integrated-evidence-20261106-01/`:

- `p1-compact-state-gate-20261106-01/gate.json`: preservation gate.
- `p1-compact-state-small-20261106-04/experiment.json`: failed intended run.
- `p1-compact-state-postabort-20261106-01/postabort.json`: baseline acceptance,
  frozen/reference parity and partial-file audit.
- `p1-compact-state-singlelane-correctness-20261106-01/experiment.json`:
  explicitly separate correctness diagnostic.
- `p1-compact-state-preflight-20261106-04/preflight.json` and `link-inputs.json`:
  source image, compiler dependency checks and exact link inputs.

The 300-file integrated archive is hash-verified locally, and all 8,483 source
hashes match the checkout [M]. The first alignment assertion, malformed C++
fixture, workspace ENOSPC link, object-list assertion and queued-controller
race are preserved in the earlier failure archives and raw controller logs.
No GPU experiment ran from those failed preflights. The successful image links
the exact 950 compiled objects directly in `/tmp` with the canonical SONAME;
all required exports and the existing stack-frame limit pass [M]. Legacy
builder commit labels in raw receipts are retained; the explicit source map
and current-base-plus-overlay label identify this checkpoint.

The accepted-duplicate and superseded-host-binary prune frees 889 MB [M]. It
retains the current and prior accepted reference, failed partials, current
runtime/driver/receiver, frozen native reference images and all receipts.
See `p1-compact-state-prune-20261106-01/prune.json`. The M8 ledger validates;
the unrelated historical missing commit in `device-fs.jsonl:1` remains.
