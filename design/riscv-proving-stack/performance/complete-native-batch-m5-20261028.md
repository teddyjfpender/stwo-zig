# Direct native aggregation with complete global verification

The new complete receiver passes both diagnostic and canonical security on a
real register/RAM loop with SHA and Keccak calls. A single direct-native batch
can replace the native wrapper forest **at the verification boundary**, while
all original global base proofs remain mandatory. The replacement publication
driver and standalone recursive global closure are not implemented by this change.

Implementation: `ac05f9660` on `codex/ethereum-block-fast-lab`.

## Measured batch stages

| Stage | Diagnostic q8/PoW0, 20,494 cycles | Canonical q70/PoW26, 307,214 cycles |
|---|---:|---:|
| Original native proof capture loop | 0.054 s | 0.091 s |
| Recursive preparation | 1.274 s | 9.446 s |
| Key and setup | 0.345 s | 2.127 s |
| Recursive STARK proving | 1.521 s | 8.750 s |
| Encoding and independent native-batch verification | 0.164 s | 0.192 s |
| Sum of recursive stages | **3.304 s** | **20.515 s** |
| Batch helper wall, including its controls/cleanup | 3.382 s | 20.629 s |
| Fresh complete global + batch verification | **1.811 s** | **2.065 s** |
| Recursive committed AIR cells | 113,234,668 | 766,619,648 |
| BLAKE3 G rows | 324,576 | 3,293,472 |
| Batch proof bytes | 135,625 | 937,929 |
| Batch subjob charged allocator peak | 1.480 GB | 6.591 GB |

Single samples, ReleaseFast, eight M5 CPU workers. Each job has two adjacent
executions. Inputs are identical to the [custody comparison](register-custody-m5-20261028.md).
The capture timer starts after loader and array initialization. The batch
subjob's allocator includes retained captures and hostile receive checks but
excludes original driver metadata retained by the enclosing test; it is not
whole-process RSS or a replacement driver's peak.

The original canonical mode1 driver in this run took 86.833 s, including
52.478 s after base publication for the forest. Its two native recursive
callbacks took 11.031 and 10.756 s. Their sum plus forest is 74.265 s, about
3.62× the new batch's recursive-stage sum. These are timed stages from the same
base proofs, not a measured 3.62× end-to-end speedup. In particular, the test
still runs the old driver first to obtain base files; it does not skip or
replace the old work during that driver invocation.

The earlier 17× direct-batch recursion result concerned a tiny ALU fixture.
This richer workload's 3.62× comparison is the relevant integration evidence.
The original bundle wall times remain around 86.7–86.8 s across the two
canonical runs, but there is only one direct-batch sample at each security
profile. No confidence interval is claimed.

## What changed and what is checked

`Global.ForBackend.verifyCompleteNativeBatch` performs the existing fresh
global receive loop first. It reconstructs every native recursive admission
from the original roster and uses only native receipts produced inside that
loop. The normalized batch must match the complete execution span and native
residual. It then decodes and verifies the actual batch STARK under independent
key/schedule pins. There is no caller-supplied native receipt shortcut.

The result is a distinct `VerifiedNativeBatchBundle`. It does not set the V5
exact-forest flag. It accepts 1–8 executions and rejects unsupported capacity
and readonly-global stacks. Global RAM, caller, ROM, lookup, register and
endpoint proof files remain necessary; the batch file alone is open.

Both selected runs exit zero with all 12 tests passed. Controls reject a
missing child, wrong key identity, changed security configuration, and two
altered physical recursive claims whose sum is unchanged (`OodsNotMatching`).
Existing direct-batch controls also exercise PC/clock adjacency, public
residual substitution and changed native captures. The custody comparison
rejects changed register windows and cancelling fused claims.

An initial diagnostic invocation passed the assertions but exited one because
the intentionally corrupted Merkle proof emitted an error log. It is excluded
from the results. The retained negative probe instead changes two serialized
recursive claims and pins the exact OODS rejection; production logging was
not suppressed or changed. The results parser now rejects logged-error and
leak failures even when the log contains an all-tests-passed line.

## What this says about the next 10×

Canonical preparation is 46% of the new recursive-stage sum; setup is 10%,
STARK proving 43%. Preparation includes input-dependent witness construction:
it cannot all be treated as cacheable compilation. Split static verifier-plan
construction from dynamic witness filling before proposing a reusable plan.
Query positions, transcript challenges and physical claim bindings cannot be
reused from a previous child proof merely because its geometry matches.

Even deleting preparation and setup would leave 8.94 s of recursive work,
already exceeding a roughly 8.7 s target for the entire previous bundle. Thus
cache tuning alone cannot supply the next 10× at unchanged remaining costs.
The design must reduce the STARK work itself: larger independently sized
native partitions, joint native/companion PCS groups, and ultimately recursive
closure over fewer global proof groups. The
[integration plan](complete-batch-problem-match-20261028.md) specifies the
versioned driver/manifest work required before claiming end-to-end gains.

## Reproduce and data

```sh
STWO_COMPLETE_NATIVE_BATCH=1 STWO_REGISTER_COMPARE_ITERATIONS=61440 \
  python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_register_custody_test_root.zig \
  -OReleaseFast --test-filter 'register custody complete comparison canonical' \
  > complete-native-batch.log 2>&1
python3 design/riscv-proving-stack/performance/register-custody-results.py \
  complete-native-batch.log
```

[JSON](block-v6-complete-native-batch-m5-20261028.json) includes both original
driver arms, new batch stages, negative controls, source commit and log hashes.
[CSV](block-v6-complete-native-batch-m5-20261028.csv) provides the two new batch
samples. The parser checks profile/segment matching, timer partition, scope,
proof size and cell-count agreement between generation and complete reception.
