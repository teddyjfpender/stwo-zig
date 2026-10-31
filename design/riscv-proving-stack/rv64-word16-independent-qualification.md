# Independent qualification of the full Word16 execution AIR

This qualification runs the joined Word16 CPU, ROM, register boundary,
arithmetic, binary, shift, load/store, INIT, TEARDOWN and lookup providers. It
does not substitute the older RV64 proof or a set of short proof windows.
The accompanying receipt pins the exact source revision, tools and artifacts;
that receipt is the authority for completed runs and geometry-specific counts.

## Software CSP requests

`src/integrations/riscv_cpu/word16_qualification/csp_image.zig` loads the
existing `rv64.csp_contract` directly. The expected result is **32 bytes**,
with a four-byte halt flag and four-byte output length. It is independent of
the Ethereum ABI. The only helpers reused from `rv64_ethereum_request.zig`
are generic executable-ROM extraction and SHA pin checking.

The caller supplies independently expected ELF/input SHA-256 digests, ABI
symbols, output digest and retirement count. The qualification driver obtains
these from the retained Unicorn 2.1.4 execution report, suite manifest and
ELF symbol table. It checks the actual ELF and input against that evidence
before invoking either proof process. These pins are expected inputs, not
values copied from the prover's response.

`csp_capture.zig` executes once into the existing compact Tape. It retains no
retirement array or logical AIR-row array. A separately loaded pristine image
supplies initial words and permissions. `Prepared.capture` then restores the
compact advice once and owns its narrow metadata and family facts. The Tape
is released before wide CPU/provider construction. Grouped facts determine
independent provider heights; setup takes ownership of the immutable program
without decoding or constructing the main witness again.

The optional operational `ls_ladder` setting chooses two LS prefix domains
only when their total padded rows are smaller. It does not change the expected
execution identity. Actual geometry and both physical roles remain bound by
the canonical setup and transcript. Counts and absent-tail claims are checked
before receiver sidecar/key allocation. In ECDSA, 549,261 LS operations split
as 524,287 plus 24,974 active rows in log19/log15 domains, rather than one
log20 domain. The receipt reports actual source cells and proof costs; this
row reduction alone is not a speed claim.

`csp_execution.zig` uses the existing closed `Execution.provePreparedWithOptions`
and `Execution.verify` authorities. The fresh receiver reconstructs its own
expected image and ROM, checks CPU genesis, INIT and permissions, and checks
the output bytes, length=32 and halt=1 against the **authenticated terminal
RAM words**. Reading native output during capture is only a diagnostic and
does not establish this terminal assertion. The independently expected step
count prevents accepting an arbitrary shorter prefix. Final CPU values remain
public proof claims; the CSP oracle does not independently pin every final
register value.

The retained suite covers complete SHA-256, Keccak, Poseidon2-M31 and ECDSA
software guests, including an invalid-signature ECDSA request. Each request
has one complete proof and a separate fresh receiver. The positive ECDSA
request retires 1,625,938 instructions, fits CPU log21 and uses ordinary RV64IM
code with no service acceleration.

## One continuous Sail workload

`scripts/riscv64_word16_sail_workload.py` checks the clean Sail revision
`8c7f2da58de0ba5e4457e4de07e0046f0439f35f`, its Sail 0.20.2 build information
and exact `rv64im` configuration. It uses one RVFI-DII connection and one
architectural execution. There is no reset between target cases. Operand and
RAM setup is performed by ordinary guest instructions and is included in the
same proof.

The workload includes all 63 ordinary retiring RV64IM opcodes, edge Cartesian
products, division-by-zero and signed-overflow operands, W operations, all
immediate shift amounts, both outcomes of all branch kinds, x0 and register
aliases, and naturally aligned loads/stores. Additional cases cover
nonzero-immediate JALR (-2048, -1, 7, 2047) and every legal offset within an
eight-byte word for each load/store width. The RAM address `0x100004000`
exercises addresses above 32 bits. The PC starts at Sail's DII entry
`0x80000000`; this workload is not evidence for every possible 64-bit PC or
wrapping-address combination.

The strengthened workload has 12,903 target cases and 1,032,240 total retired
instructions, including 1,019,337 setup instructions. Setup dominates its
instruction mix, so its wall time is an ISA-qualification workload measurement,
not a representative application-throughput benchmark.

The producer retains the exact raw RVFI bytes and an immutable ELF containing
the instructions at the PCs observed from Sail. The expected oracle metadata,
ELF and RVFI files are SHA-pinned separately from proof advice.
`sail_capture.zig` streams the RVFI file and executes the native session once
into compact Tape. It checks instruction order, PC/next-PC, retired instruction,
register writes, memory addresses, masks and values for every retirement.
The SHA pin covers the exact bytes consumed during that pass, including unused
RVFI fields, rather than hashing and subsequently rereading a mutable file.

This pinned Sail model leaves its RVFI input-register extension zero. The
adapter therefore reconstructs the independent register pre-state from **all
prior Sail register-write outputs**, then compares the native operands to that
state. It does not pretend those absent RVFI fields were independently
reported. This bookkeeping contains no second implementation of instruction
arithmetic. Final PC, all 32 register values and both terminal RAM words are
also independently pinned by the Sail oracle. The fresh proof receiver checks
these endpoints without executing the guest or invoking Sail again.

ECALL and EBREAK are nonretiring in this software RV64IM contract and are
excluded. These runs do not qualify service semantics, trap-state rollback,
misaligned accesses, arbitrary memory mappings, cross-epoch global RAM, a full
Ethereum block, or recursion.

## Actual receiver attacks

`scripts/riscv64_word16_receiver_attacks.py` first accepts the unchanged proof
in a fresh process. It then independently copies and mutates actual artifacts.
The cases include false final PC/registers, shortened execution, balanced
CPU/ROM physical-claim changes, foreign INIT values/permissions, altered
terminal output, invalid epoch, truncated public cells and a corrupted proof.
CSP adds false halt and output-length mutations. In particular, a balanced
claim mutation preserves the scalar aggregate sum but must still fail because
the actual physical claims enter the transcript and AIR proof.
Schema3 additionally rejects an invalid LS-tail capacity and a balanced
nonzero claim for an absent LS role before allocating the receiver's key.

The dedicated `test-riscv64-word16-csp` target also covers expected-image pins,
completion/output bytes including the last output byte, high-PC compact
capture, allocation-failure cleanup, RVFI mutations, absent-input-extension
handling, load-to-x0 RAM reads and independently expected CPU/RAM endpoints.
Source-level tests supplement actual complete proofs; they are not counted as
proof verification.

## Reproduction

Build `rv64-word16-csp`, `rv64-word16-sail` and the focused authority tests in
ReleaseSafe and ReleaseFast. The CSP driver takes the retained independent
execution report and matching guest build:

```sh
python3 scripts/riscv64_word16_csp_qualify.py \
  --execution-report vectors/reports/rv64-qualification-20261030/csp-execution-final.json \
  --guest-build /path/to/csp-build \
  --tool /path/to/rv64-word16-csp --output /new/qualification-directory
```

Generate the continuous Sail fixture once, then prove and verify it in separate
processes using the same independently expected config:

```sh
python3 scripts/riscv64_word16_sail_workload.py \
  --source /path/to/pinned/sail-riscv --output /new/sail-workload
rv64-word16-sail --prove /new/sail-workload/config.json /new/sail-proof
rv64-word16-sail --verify /new/sail-workload/config.json /new/sail-proof
```

Timing receipts describe complete processes and their source/geometry. No
speedup is inferred from committed-cell reductions or from comparisons with
old AIR timings.
The tools' internal `total_ns` starts after expected-image/pool initialization
and ends before final teardown. The qualification receipt's process durations
include those costs; the two scopes must not be confused.

## Remaining independent Rust verifier gap

`scripts/riscv64_rust_qualify.py` and
`tools/stwo-interop-rs/src/rv64_qualification/` implement the older dense-v2
qualification AIR and small instruction fixture. They do **not** independently
verify the new Word16 joined proof. Running that historical Rust control cannot
be reported as qualification of this route. Compiling the CSP guest from Rust
also does not turn the guest into an independent Rust verifier.

A same-authority solution would need a strict Rust PCS/proof adapter and an
independently admitted representation of the **same** new AIR constraints and
receiver obligations, such as a qualified authority IR. Hand-porting another
set of chip semantics or accepting host-supplied OODS residuals would not close
this gap. No such accepting adapter is introduced by this slice. These are
empirical differential and cryptographic proof qualifications, not a formal
proof of the ISA implementation.

## Schema4 requalification

The additive `independent-qualification-schema4-v1.json` receipt records a new
run at commit `026567e00`, using core schema4, 21 structural role tags and 45
canonical ledger fields. The original schema3 receipt remains historical
qualification evidence. No AIR equations, proof configuration or guest binaries
were changed for this rerun.

All 17 complete CSP requests (5,522,860 total instructions per build) passed both
ReleaseSafe and ReleaseFast producers and separate fresh receivers. Every
corresponding Safe/Fast encoded proof is byte-identical. The strengthened
continuous Sail workload also passed both builds: 12,903 target cases and
1,032,240 retired instructions, with every retirement compared against the
pinned RVFI stream. Its fresh receiver succeeds with a deliberately nonexistent
RVFI path. Safe/Fast Sail proofs are byte-identical. Schema3 and schema4 hashes
are intentionally different because the transcript and claim ledger changed.

The positive software ECDSA request also passed in one-shot single-LS and
LS-ladder geometries. Both constrain the same 1,625,938-instruction CPU statement
and produce byte-identical authenticated RAM sidecars. Safe/Fast proofs match
within each geometry. The ladder removes 87,490,560 logical committed source
cells, while adding 187 sampled QM31 values and 76,096 proof bytes. These are
physical geometry and wire measurements, not a performance claim. Functional
process timings were collected during concurrent engineering; controlled
benchmarking is recorded separately.

Pure ALU/BINARY/SHIFT tails remain absent in these CSP/Sail configurations.
Actual fresh-receiver mutation runs add a nonzero claim to each absent tail
and an equal opposite CPU claim, preserving the aggregate sum. Each must reject
with its specific canonical omission-guard error. The complete suites reject 17
mutations for ECDSA single-LS, 16 for ECDSA LS-ladder and 15 for Sail. They also
retain endpoint, initial/terminal memory, epoch, proof corruption and LS-tail
attacks. This qualifies absence enforcement; accepting present pure-function
tails is separately covered by `pure-function-ladders-v1.json`.

All previous scope exclusions and the same-AIR Rust verifier gap remain.
These proofs are complete CSP requests and one ordinary-ISA Sail execution;
they are not Ethereum block, service, cross-shard or recursion acceptance.
