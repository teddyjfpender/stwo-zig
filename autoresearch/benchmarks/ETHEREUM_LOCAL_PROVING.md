# Local Ethereum proof development

Run commands from the repository root. The [comparison contract](ETHEREUM_BLOCK.md)
defines the whole-block endpoint; the commands here exercise individual development
gates. The [current evidence](../notes/2026-09-05-pr198-local-ethereum-plan/evidence/2026-09-07-real-campaign-v1/README.md)
retains source/artifact hashes, successful checks, genuine failures and measurements.

Before queuing a large build after a source edit, run `zig ast-check path/to/changed.zig`
on each changed Zig file. This caught a real parameter-shadowing failure immediately
instead of after a whole-leaf queue wait. It does not replace compilation, AIR checks
or complete-proof verification.

## Focused ownership and real-geometry loop

Run the small boundary and complete-proof checks before the real-input replay:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-validation-ownership test-ethereum-small-composition-proof \
  test-ethereum-prepared-wrapper-boundary test-ethereum-symbolic-public-boundary \
  -Doptimize=ReleaseSafe -Dethereum-proof-strip=true --summary all
```

The ownership gate checks immutable row access, canonical interaction columns,
independent domain sums, allocation-failure cleanup, and the replay publication
codec for ordinary and initial profiles. Run it before the real replay: a retained
failure showed that Zig omits `void` fields during JSON serialization, which the
decoder must handle without admitting injected fields. The small complete proof
also serializes, destroys producer state and freshly verifies. Neither substitutes
for the real geometry gate below.

For changes to preparation arithmetic or tuple closure, these smaller commands
exercise the scalar-reference and record-ledger comparisons before rebuilding the
complete proof target:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/ethereum_public_sums_v4_test_root.zig \
  --test-filter 'incremental public V4' -OReleaseSafe -fstrip
python3 scripts/zig_protocol_test.py \
  src/integrations/riscv_cpu/ethereum_compact_tuple_ledger_v1_test_root.zig \
  --test-filter 'Ethereum compact tuple ledger' -OReleaseSafe -fstrip
```

The compact Ethereum ledger accumulates range tuples in their canonical fixed
table and other domains under the existing canonical tuple hashes. It preserves
original event counts and checks malformed requests before cancellation. The
ordinary diagnostic ledger remains available; CSP's default path is unchanged.
Phase output distinguishes event count, live balances, map capacity and estimated
retained bytes. Capacity can exceed live entries after cancellation.

The same frontend root has the filter
`Ethereum surviving public sums sparse work benchmark`. It compares the retained
scalar calculation with direct surviving fractions over an expanded authenticated
fixture (4,096 sparse words by default). It excludes admission/setup and is an
arithmetic microbenchmark, not a real-block or complete-request speedup.

Use the existing retained native-pair inputs and independently pinned campaign
materialization for `test-ethereum-statement-root-cohort-replay` (the same
`STWO_ETHEREUM_NATIVE_REPLAY_DIR`, `STWO_ETHEREUM_REAL_MATERIALIZATION`, and
`STWO_ETHEREUM_REAL_MATERIALIZATION_SHA256` inputs as complete-proof replay).
Select `STWO_ETHEREUM_COMPLETION_OPENING_V1=1` for the admitted fixed-program
route. Set `STWO_ETHEREUM_PROOF_PROGRESS` to a fresh log path for live phase output.
This target bypasses the secure-session constructor and Tree0 commitment. It
builds real geometry, closes exact tuples, generates Tree2, serializes the full
generated result, destroys its producer, then independently reconstructs Tree2
and closure. It reports preparation, generation, destruction and cold-check
costs separately, and always reruns against the external inputs. It produces no
STARK and cannot establish wrapper or block acceptance.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-statement-root-cohort-replay \
  -Doptimize=ReleaseSafe -Dethereum-proof-strip=true --summary all
```

Preparation owners admit their private rows and plans at construction. Metadata
reads do not reaccept input hierarchies. Explicit input/proof checks remain full
checks, and generated audit data from a caller is never accepted solely because
its self-hash matches. Keep those boundaries when extending either profile.

## Produce and independently verify the retained whole block

After the selected-leaf and bundle-verifier correctness gates pass, run the
existing controller with explicit profile selection. The optimized profile needs
the verifier's `verify-leaf-fixed-program-v5` and `verify-bundle-fixed-program-v5`
commands. Use pinned product binaries; the controller rejects changed binaries or
campaign policy on resume. The legacy default remains `field_authority_v4`.

```sh
ethereum_campaign=.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907
python3 -m scripts.ethereum_full_leaf_bundle_producer \
  --prover .git/local-ethereum/real-leaf-field5-cpu-product-v1/bin/ethereum-prepared-leaf-cpu-v1 \
  --verifier .git/local-ethereum/fixed-program-native-verifier-v2/bin/ethereum-full-leaf-bundle-verify-v1 \
  --materialization "$ethereum_campaign/authority/materialization-v2.json" \
  --publication-root "$ethereum_campaign/capture/publication-parent/ethereum-incremental-capture-v4" \
  --selected-leaf-admission-root "$ethereum_campaign/cpu-field5-block-selected-admissions-v1" \
  --output "$ethereum_campaign/cpu-field5-block-v1" \
  --claim-admission fixed_program_narrow_v5 --workers 1 \
  --host-byte-budget 17179869184 --pcs-retained-byte-budget 25769803776 \
  --host-byte-limit 34359738368 --timeout-seconds 14400
```

There is one leaf in flight. Each new or resumed proof is freshly verified before
the next producer starts. After all 121 leaves, a separate bundle-verifier process
checks the complete proof inventory, coverage and continuation. A partial leaf
inventory is not a verified block. Retry the same command to resume; failures and
their logs remain in create-only attempt directories.
Successful producer attempts awaiting fresh verification are recovered on resume,
including interruption before proof publication. They are candidates until the
fresh verifier accepts them; a verifier failure does not trigger re-proving.

By default each child holds the shared heavy-job lock, releasing it between
processes so focused development gates can run. Do not wrap the whole controller in that lock.
Per-attempt `execution.json` records process wall time excluding lock waits;
`invocation_ns` includes waits and only covers that invocation. Report retries,
resumed work and scheduling interference when calculating complete-block time.
The explicit memory values above are admission/allocation budgets, not an OS RSS
cap. Controller custody checks run with
`python3 -m unittest scripts.tests.test_ethereum_full_leaf_bundle_producer`;
these mocked process tests do not establish cryptographic proof acceptance.

Selected native verification can opt into a separate bounded lane with
`--verification-policy POLICY_JSON --verification-policy-sha256 INDEPENDENT_PIN`.
The policy pins the verifier, materialization and genuine measurement receipts;
it admits only the fixed-program v5 selected-leaf endpoint with one worker.
The runner checks host headroom, monitors child footprint and execution time,
and drains its own child on failure. Proof production, builds and final-bundle
verification retain the shared heavy lock. A scheduling pass is not a proof
acceptance: the controller still checks the fresh verifier receipt and rechecks
proof and metadata custody. This option leaves CSP's default policy unchanged.

## Verify the retained field wrapper

The retained small Ethereum fixture has a verified field wrapper. It is not a
mainnet block proof. This check launches independent verifier processes and tests
key, claim, nonce and proof mutations. It needs no native child proof inputs.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  build-ethereum-wrapper-root-verifier \
  -Doptimize=ReleaseSafe -Dethereum-proof-strip=true --summary all

python3 scripts/ethereum_wrapper_root_check.py \
  src/integrations/riscv_cpu/zig-out/bin/ethereum-wrapper-root-verify-v1 \
  .git/local-ethereum/root-candidates/d029f4f5819e443e4c9d2f2b6b370ad65a92e5cf9730e5118344989b10773dee \
  --expected-key-sha256 d2503c44689dd487e96f12b782fee7a0d063a70a6175804124fce17ad19fac00 \
  --output .git/local-ethereum/root-check-new
```

The output directory must be new. The key pin is an independent input: do not
replace it with the hash of an untrusted candidate key. Local artifacts under
`.git/local-ethereum` are not included in a clone; copy the pinned bundle when
moving this development loop to another laptop.

For authenticated transcript, public-input and symbolic composition changes:

```sh
STWO_ETHEREUM_ROOT_REPLAY_DIR="$PWD/.git/local-ethereum/root-candidates/d029f4f5819e443e4c9d2f2b6b370ad65a92e5cf9730e5118344989b10773dee" \
STWO_ETHEREUM_ROOT_KEY_SHA256=d2503c44689dd487e96f12b782fee7a0d063a70a6175804124fce17ad19fac00 \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-detached-field-transcript \
  -Doptimize=ReleaseSafe -Dethereum-proof-strip=true --summary all
```

This uses the actual proof and the same fixed graph for hostile public, claim,
wire and sample inputs. The pinned artifact wraps the fixed-program/narrow-v5
native fixture using the field9 outer transcript. Its
[detached replay passed](../notes/2026-09-05-pr198-local-ethereum-plan/evidence/2026-09-07-real-campaign-v1/fixed-program-wrapper-detached-replay-v1.json);
it does not establish a parent fold proof.

The existing common-fold verifier also accepts the explicit Ethereum parent key
namespace. After producing a parent with `writeEthereumBundle`, run:

```sh
recursive-common-fold-verify-v2 --ethereum-v1 \
  KEY_JSON EXPECTED_KEY_SHA256 INPUTS_JSON PROOF_BIN
```

Build it with `build-recursive-common-fold-verifier-v2`. The key pin must come from
independent circuit admission. The command consumes no child proofs or witnesses;
its transport and retained legacy-proof rejection checks pass, but a successful
real Ethereum parent proof is still required. Omitting `--ethereum-v1` preserves
the existing legacy verifier invocation.

## Produce and independently verify a new small wrapper

```sh
STWO_ETHEREUM_PROOF_CORPUS="$PWD/.git/local-ethereum" \
STWO_ETHEREUM_NATIVE_REPLAY_DIR="$PWD/.git/local-ethereum/field-bound-v4" \
STWO_ROLE0_GENUINE_WORKER_COUNT=1 \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-complete-proof \
  -Doptimize=ReleaseSafe -Dethereum-proof-strip=true --summary all
```

This generates a wrapper, serializes it, destroys producer state, verifies from
key/public inputs/proof alone, then runs native-assisted cold replay and retained
regressions. Its measured field9 baseline took 38 minutes and peaked at 52.65 GB
process lifetime footprint; it is not the routine two-second replay above. Use
the shared build wrapper so large builds and proofs do not compete for memory.

## Real-leaf resource controls

Build the narrow producer with `build-ethereum-prepared-leaf-cpu-v1` in
`src/integrations/riscv_cpu`. The prepared replay command accepts three distinct
execution limits:

| Option | Scope | Current single-worker development request |
| --- | --- | ---: |
| `--host-byte-budget` | CPU composition allocations | 17,179,869,184 B (16 GiB) |
| `--pcs-retained-byte-budget` | Retained commitment columns; uses actual coefficient-retention policy | 25,769,803,776 B (24 GiB) |
| `--host-byte-limit` | Host admission envelope | 34,359,738,368 B (32 GiB) |

These are request choices, not protocol constants. The host admission option
does not impose an operating-system memory cap, and the whole-block controller
does not stop a process at that footprint. Early diagnostic Metal runners had a
separate 32 GiB watchdog; their retained scripts describe that historical policy.
Production retries observe footprint without that automatic cutoff. A fitting
commitment estimate excludes Merkle nodes, FRI, composition, twiddles, witness
owners and allocator/driver overhead.

The field4 baseline for real segment9 has 20,550,093,056 B of retained commitment
columns; fixed-program/narrow-v5 reduces this to 5,874,223,360 B. Geometry varies
by segment: optimized segment0 requires 24,512,287,728 B of retained columns and
reported 34,836,719,344 B peak footprint during its accepted CPU request.
The old rejection at 16 GiB was a misapplied composition budget, not allocation
failure. A second Tree1 check also needed the actual `.never` retention policy;
both failures and their regression cases are retained. Exact real-leaf command,
input pins and process samples are in each campaign attempt's `plan.json` and
`run.py`.

The corrected CPU attempt (`cpu-field4-segment9-selected-v5`) passed: core and
all provider shards, serialization, producer destruction and fresh verification.
Its complete request took 1,190.960 s, with 26,345,901,712 B (24.54 GiB) lifetime
peak footprint and a 62,552,044 B proof. This is one real block segment, not a
whole-block proof. A separate verifier process also passed: 70.718 s complete
request and 1,029,882,912 B peak footprint, including cold input admission.
The retained proof mutation and boundary-clock mutation both rejected. Exact
pins and the matched Metal request are tracked in the
[real campaign evidence](../notes/2026-09-05-pr198-local-ethereum-plan/evidence/2026-09-07-real-campaign-v1/README.md).

The measured 1,089.657 s proving phase breaks down as follows. These are
same-depth host spans, so nested profiler events are not added again.

| Phase | Seconds | Share of proving |
| --- | ---: | ---: |
| Three trace Merkle commitments | 557.564 | 51.17% |
| FRI quotient construction and commitment | 244.896 | 22.47% |
| Composition evaluation | 148.237 | 13.60% |
| Sampled-value evaluation | 51.016 | 4.68% |

Merkle acceleration is therefore the first measured target. Even eliminating
that phase entirely would save about half of this proving time, not 99%.
Further gains require FRI/composition improvements and less authenticated AIR
work, measured with the same complete-request and worker policy.

## Poseidon changes and CSP preservation

Poseidon AIR calls and the prover's native Merkle hashes are different costs.
The opt-in CPU Merkle cache preserves every layer and measured 1.606x on a small
same-tail-ratio comparison. Field9 wrapper construction selects it; the real
field4 leaf above retains the original CPU Merkle path for its baseline.
The opt-in grouped physical column layout preserves
logical order and lets preparation adopt source coefficients instead of copying
them. The full-size wrapper Tree0 comparison now passes with the same pinned
root: CPU commitment 268.805 s versus authenticated Metal 7.768 s (34.60x).
Metal used one device Poseidon commitment and no host Merkle fallback. It
adopted the 4,559,583,744 B source arena with zero additional coefficient
backing; the earlier layout copied another 4,379,791,360 B. See
[the exact phase evidence](../notes/2026-09-05-pr198-local-ethereum-plan/evidence/2026-09-07-field-wrapper-v1/tree0-cpu-metal-v2.json).

This probe releases its cohort before Metal preparation and does not produce
a wrapper proof. The real-leaf route now also packs independently owned source
columns into aligned groups that Metal adopts as coefficient storage. Its first
attempt stopped at 37.97 GB; the successful matched attempt
(`metal-field4-segment9-selected-v3`) peaked at 29,375,469,072 B and published
proof and metadata bytes identical to the CPU reference. Producer state was
destroyed before fresh native verification, which took 52.259 s.
A separate pinned verifier process then reopened the actual Metal publication
and passed in 69.184 s with 1,029,866,504 B peak footprint. That process also
destroyed retained materialization admission before cold-opening the proof.
Its 69.109 s inner timer includes cold proof admission and native verification,
not only the STARK/PCS check. The [open verifier-latency TODO](../notes/2026-09-05-pr198-local-ethereum-plan/progress.md#open-todo-investigate-native-stark-verification-latency)
requires phase attribution and comparison with the earlier CSP verification
slowdown before attributing this cost to a particular proof operation.

The successful Metal request took 247.37 s versus the CPU request's 1,191.75 s
(4.82x in this paired observation); its proving phase took 147.069 s versus
1,089.657 s. Both use the same real segment, field4 profile and one worker.
This is not a repeated latency distribution or CSP performance promotion. The
retained intermediate failure passed cryptographic verification but withheld
publication because a tiny-fixture placement expectation required three CPU
transforms. Benchmark admission now explicitly pins that count: zero for this
real request, with the legacy default of three preserved and all other host
fallbacks still rejected.

Existing CSP defaults, identities and worker policy remain the compatibility
boundary. These focused gates do not replace the existing 16-case CPU/Metal
latency/memory suite. A noisy host run is not a performance-promotion waiver.

## Reduce repeated AIR work

Two Ethereum-only components now pass isolated complete-proof checks, including
serialization, producer destruction and verification from independently rebuilt
fixed columns:

* Narrow Poseidon: 287 main columns instead of 445, retaining degree three and
  the existing narrow lookup relation. Every row, including padding, satisfies
  the permutation. The existing wide/IO and CSP layouts remain unchanged.
* Fixed program: six ELF-derived preprocessed columns authenticate the decoded
  instruction table. Dynamic instruction-fetch counts remain in the AIR; the
  repeated program Merkle checks are removed. Admission requires an independent
  full ELF hash, not merely the legacy field-sized program root.

Run these focused component checks with the canonical runner. It now shares the
machine-wide lock with `zig_serial_build.py`, so builds and checks queue rather
than competing for memory:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/ethereum_narrow_poseidon_proof_test_root.zig \
  -O ReleaseSafe -fstrip --test-filter 'Ethereum narrow degree3 Poseidon'

python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/ethereum_fixed_program_proof_test_root.zig \
  -O ReleaseSafe -fstrip --test-filter 'Ethereum fixed program table'
```

For real segment 9, the retained geometry contains 3,396,146 Poseidon calls;
2,917,696 belong to the fixed program. Removing those calls crosses a power-of-two
padding boundary, reducing the Poseidon and Merkle trace domains from log 22 to
log 19. Including the six new fixed columns, the combined geometry model reduces
retained commitment-column storage from 20,550,093,056 B to 5,874,223,360 B.
This is a storage model, not a measured process peak or proof-time speedup.
The combined profile now passes a two-leaf native fixture gate, including
producer destruction, fresh verification and rejection of a different full
ELF with the same decoded table/root. Retain that complete input set with:

```sh
STWO_ETHEREUM_PROOF_CORPUS="$PWD/.git/local-ethereum" \
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu \
  test-ethereum-fixed-program-native \
  -Doptimize=ReleaseSafe -Dethereum-proof-strip=true --summary all
```

The separate `fixed-program-narrow-v5` corpus contains both content-addressed
native proofs, the independently admitted ELF, global metadata and their hash
manifest. It is saved before cold verification so a failing proof remains
replayable; the manifest records custody, not successful verification. Existing
files cannot be replaced with different bytes. See the
[retained passing gate](../notes/2026-09-05-pr198-local-ethereum-plan/evidence/2026-09-07-real-campaign-v1/fixed-program-native-retained-v1.json).
Recursive exact closure, a new independently verified wrapper and a complete
real-leaf measurement are still required for this profile.
