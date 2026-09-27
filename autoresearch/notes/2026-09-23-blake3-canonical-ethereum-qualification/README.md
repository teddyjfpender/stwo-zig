# Canonical Ethereum recursion and full-width Metal qualification

Status: canonical CPU recursion gate failed after parent preparation. The compiled
test is being rerun directly with its cached leaf to recover the error omitted
by Zig server-mode output. Metal gates are implemented but not compiled/run.
No new qualification result is claimed.

The CPU test explicitly selects q70/PoW26 for both full-width Ethereum leaf and
recursive parent and verifies the parent's query count. The canonical parent
worker has a 36 GiB allocation cap, distinct from the diagnostic 24 GiB cap;
its retained source rows are measured separately. This is capacity qualification,
not a memory reduction claim or an isolated performance benchmark.

An optional STWO_B3EH_LEAF_ARTIFACT local cache avoids regenerating a canonical
leaf proof while iterating on parent-only changes. Admission is independently
reconstructed from the fixture every time; cached bytes still pass bounded decode,
full verification and capture validation. Cache reuse does not trust received
keys, disable cryptographic checks or silently accept a stale artifact.

```sh
STWO_B3EH_LEAF_ARTIFACT=/tmp/stwo-b3eh-canonical-leaf.artifact python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment Ethereum canonical recursive parent independently verifies' -Doptimize=ReleaseSafe --summary all
```

The new Metal leaf gate reconstructs CPU and GPU preprocessing separately and
requires their full roots and keys to match. It proves the complete full-width
signer-recovery + Keccak leaf at q70/PoW26, serializes it, releases the original
proof/witness, and performs bounded decode plus independent CPU capture
verification. Telemetry is taken around proving and requires actual Metal
dispatch. Source-JIT and authenticated-AOT entry points share runtime admission
with the existing BLAKE3 CSP gate.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-ethereum-full-aot -Dmetal-core-aot-bundle=/tmp/stwo-blake3-core-aot-20260922 -Doptimize=ReleaseSafe --summary all
```

Canonical Ethereum aggregation, recursive Metal proving and production routing,
key admission/default activation remain separate requirements. Existing CSP
results still measure the previous memory contract, not the full replacement.

## Follow-on gates prepared during CPU qualification

The two-real-segment Ethereum fixture now shares one implementation across
its existing diagnostic profile and a new canonical q70/PoW26 profile. The
canonical target selects only that test and checks the received aggregate query
count. Its worker allocation cap is 48 GiB (versus 24 GiB diagnostic); retained
source rows and other process allocations are additional. This is an untested
capacity allowance, not evidence of a memory or latency improvement.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-ethereum-canonical-aggregation -Doptimize=ReleaseSafe --summary all
```

The Metal qualification fixture also has a canonical leaf-to-parent variant.
It derives parent admission on CPU, proves with the persistent Metal worker,
requires actual Metal dispatch during parent construction/proving, releases
worker and prepared rows, then decodes and independently verifies on CPU. This
variant is implemented but has not compiled or run yet.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-ethereum-parent-aot -Dmetal-core-aot-bundle=/tmp/stwo-blake3-core-aot-20260922 -Doptimize=ReleaseSafe --summary all
```

## Live observation: serial admission-key preparation

A one-second macOS stack sample of the live canonical CPU run found the main
thread inside `deriveKeyWithProfile` → CPU Merkle commitment → BLAKE3 leaf
hashing, after the fixture released its pool binding. This only identifies the
sampled phase; it does not establish its share of total runtime. The sample is
preserved in `canonical-key-live-sample.txt`.

Added `deriveKeyWithProfileAndPool`, which scopes the caller's persistent pool
around existing key derivation without changing key semantics. The upcoming
canonical aggregation and Metal parent gates use it. The already-running CPU
gate uses the preceding entry point; no speedup is claimed from that run.

## First canonical CPU result

The canonical CPU build/test exited 1 (7/8 tests passed; the selected recursive
test failed). The log shows a freshly encoded 5,587,689-byte canonical leaf,
19,110 query-fusion groups, 1,419,557 arithmetic rows, and a parent preparation
retaining 10,150,562,296 bytes with 1,172,700 inputs. There is no verified parent
artifact. The server-mode test runner omitted the error name; this does not
justify attributing the failure to memory without further evidence.

A direct execution of the same compiled binary, with the cached leaf and no
`--listen` server mode, is running to expose the error. No limits were changed.

## Paired admission hardening (pending validation)

Ethereum `validateForProving` now owns the non-consuming phase, witness hash-plan
and independently prepared key checks, shared by one-shot proving and paired
segment admission. Previously pairing checked the second key but deferred its
interaction phase and hash-plan check until after proving the first child.
The shared two-segment fixture now exercises invalid second-child phase and
hash-plan rejection and asserts that the first child remains unconsumed.

Direct rerun completed with `ParentWorkerHostBudgetExceeded`, confirming the
36 GiB worker cap was exceeded. Bounded interaction scratch is being implemented
and tested in the neighboring `2026-09-23-blake3-tiled-interactions` experiment;
the next canonical retry retains the same cap and uses the cached admitted leaf.
