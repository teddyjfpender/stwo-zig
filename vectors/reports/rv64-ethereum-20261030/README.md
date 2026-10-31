# RV64 Ethereum execution milestone — 2026-10-30

The separate software-only RV64IM/LP64 guest executed mainnet block **24,628,607**
(**66 transactions**) and matched the independently validated 43-byte result.
Unicorn 2.1.4 independently verifies exactly **835,695,366 instructions**, all
32 final registers, final PC, and output. **No Ethereum STARK proof is claimed.**

| Measurement | Result |
| --- | ---: |
| Native execution, no retained trace | 6.577 seconds |
| Retired RV64IM instructions | 835,695,366 |
| Guest loads / stores | 142,773,568 / 103,941,153 |
| Allocated backing pages | 4,398 (17.18 MiB) |
| Canonical input | 2,700,688 bytes |
| Expected output | 43 bytes |
| Keccak permutation leaf | 511,996,155 instructions (61.27%) |
| k256/secp256k1-associated symbols | 181,374,875 instructions (21.70%) |
| Compiler memcpy leaf | 42,251,372 instructions (5.06%) |

Execution time excludes compilation, witness construction and proving. Backing
pages are not process peak RSS. Symbol attribution is exact by PC range, not a
source-level call graph: all retirements are accounted for, with six instructions
outside named functions. The broader crypto-token grouping is an explicitly
labelled heuristic; the Keccak leaf count above names a specific function.

## Evidence and reproduction

- [Native execution](execution.json), [profile summary](profile-execution-summary.json),
  [exact function attribution](function-profile.json), [validation scope](validation.json).
- [Independent oracle and boundary normalization](ORACLE.md), [raw oracle](unicorn-full.json).
- [Reproducible build and fixture identities](build-report.json).
- [Next accelerator contract and full footprint model](accelerator-plan.json).

The guest is built from the pinned stateless validator with software crypto,
reviewed single-thread atomic libcalls, and an explicit LP64 runtime. Existing
RV32 guest source is unchanged. No custom instruction, syscall service, host
crypto hook, or witness-result hint executes. The canonical witness is recovered
from the manifest-pinned upstream blob with byte count, SHA-256 and Git-blob
checks; fresh projection and native host validation agree with the guest.

The result is **payload-request-root[32] || success[1] || chain-id-LE[8] ||
schema-id-LE[2]**, not a standalone block hash. Expected block/header identity
comes from the pinned mainnet fixture. The runtime initializes a read-only
length-prefixed input region, sparse writable heap/stack and explicit halt/output
region. Artifact hashes are checked before execution. The new adapter does not
relax the CSP contract.

Build and run instructions live beside the [guest](../../../autoresearch/benchmarks/guest_runtime/ethereum/rv64/README.md).
The execution command is:

```
zig build --build-file src/frontends/riscv/rv64/build.zig ethereum-run -Doptimize=ReleaseFast -- CONFIG.json
```

Dense PC histograms, binaries and witnesses remain in the ignored local archive
`vectors/reports/interop_artifacts/rv64-ethereum-20261030/`; curated receipts retain
hashes. The profile command checks the raw histogram against ELF SHA-256 and exact
retirement accounting. Safe execution/ABI tests pass, including allocation-failure
cleanup, input permissions and overlapping-region rejection. Four profile tests
and three pinned-oracle tests pass. Without the pinned Unicorn environment, the
two engine-dependent tests explicitly skip; this is not a substitute for the
recorded successful oracle run.

## Blocking work for a proof

This execution cannot be proved by increasing one row limit. It exceeds the
current `<2^22` step admission and 24-bit clock design. A one-row-per-step domain
would round to 2^30 rows; the current four-way CPU quotient extension would then
require 2^32 rows, outside the core domain limit. Even one base-field column
would occupy 4 GiB. These are representation and protocol limits.

The first acceleration target is the measured Keccak permutation leaf. Keep
absorb/padding/squeeze software and admit a versioned ECALL contract whose
register arguments, 64-bit pointers, clocks, RAM input/output and call coverage
are constrained. A host result is never authority. Reuse arithmetic only after
its RV64 caller envelope and receiver/adversarial gates pass.

The existing compact provider is wide: all 32,835 observed leaf entries together
would need 2^19 rows and about 12.5 GiB of raw source columns before PCS/FFT.
That height also exceeds its current admitted log18. Component sizes, aggregate
cells, opening masks, provider/table costs and batch geometry must be compared
before choosing the layout. Unqualified narrower source is not a measured win.

After acceleration, measure the remaining execution and design bounded proving
with authenticated CPU/RAM continuation and limb-safe global clocks. Construct
wide witnesses once, retain narrow global obligations, cache immutable setup by
program/ABI/geometry, share independently sized providers, and aggregate compatible
proof families before specialized recursion. Do not introduce tiny fixed windows
or one wrapped proof per crypto call.

OP/Kona remains a separate guest/runtime and public-output contract. This L1
execution receipt does not establish OP derivation, blobs, preimage authentication
or BootInfo proof compatibility.
