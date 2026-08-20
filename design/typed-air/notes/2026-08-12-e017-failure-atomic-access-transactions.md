# 2026-08-12 — E-017 failure-atomic access transactions

## Question

Can generated typed rows consume one allocation-free authority for register and
RW-memory access facts without publishing a partial state chain, while retaining
the exact Stark-V-compatible load ordering?

## Context and exact revisions

E-017 follows the completed typed family migration and A-013 row-window model.
The legacy runner currently derives access clocks before execution, appends the
trace row after execution, and only then performs fallible state-chain appends.
An allocation failure can therefore expose a row whose access transitions were
not published.

The shadow implementation is:

- `src/frontends/riscv/air/lang/access_transaction.zig`
- `src/frontends/riscv/air/lang/access_transaction_test.zig`

No production dispatch or runner path is activated by this revision.

## Boundary and invariants

The boundary has four explicit phases:

1. `compile` resolves a completed candidate retirement into a pointer-free,
   fixed-size `Transaction`. It allocates nothing and mutates nothing.
2. `applyToRow` validates every stable row identity/value before writing any
   derived clock or memory fact. A rejected projection leaves the row unchanged.
3. `prepareCommit` validates the tracker snapshot and reserves every collection.
   Capacity may grow, but no logical state-chain entry becomes visible.
4. `PreparedCommit.commit` revalidates freshness, then commits through the
   existing assume-capacity state-chain API. No allocation or fallible operation
   remains after the first logical write.

The compiler resolves and checks:

- x0 reads and writes are exactly zero;
- rs1/rs2/rd aliases advance through distinct physical subclocks and carry the
  preceding access's value and clock;
- every predecessor is strictly earlier than its current access;
- synthetic gap counts and effective predecessors exactly match
  `StateChainTracker`;
- access clocks remain within the 26-bit protocol predecessor domain;
- load/store base addresses are canonical M31 values and aligned word addresses
  fit the typed AIR's uint20 word-index domain;
- natural byte/half/word alignment;
- unshifted addressed masks and shifted aligned-word lane masks;
- exact selected load values, signed extension, x0 result discard, and partial
  store word merges;
- missing or unexpected memory state and stale tracker snapshots.

Loads preserve both compatibility orderings rather than conflating them:

| Effect | Logical ordinal | Physical phase |
| --- | ---: | ---: |
| rs1 read | 1 | 1 |
| memory read | 2 | 3 |
| rd write | 3 | 2 |

Events are stored by physical phase, so state-chain commit is monotonically
clock ordered. Stores remain rs1/rs2/memory at phases 1/2/3.

## Performance properties

- The compile and projection APIs accept no allocator.
- A transaction contains at most three numeric events and is compile-time
  bounded to 256 bytes.
- There are no runtime strings, owned slices, function pointers, or indirect
  dispatch tables in the hot boundary.
- Clock-gap work is bounded by the 26-bit protocol clock domain.
- Memory hash-map capacity is reserved only for a previously unknown address;
  repeated accesses do not request needless map growth.
- The final commit uses only `appendAssumeCapacity`,
  `getOrPutAssumeCapacity`, and `putAssumeCapacity` paths already exercised by
  the precompile machinery.

## Commands and observations

```sh
zig build test-air-semantics --build-file src/frontends/riscv/build.zig \
  -Doptimize=Debug
zig build test-air-semantics --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseSafe
```

Both complete focused suites pass.

The E-017-only ReleaseFast root passes all transaction tests. Coverage includes
all decoded opcodes, all 32^3 rs1/rs2/rd alias combinations, every legal
load/store width and lane, malformed values and transitions, strict clock/gap
boundaries, exact legacy state-chain differential commit, stale snapshots, and
allocation-failure sweeps.

The complete ReleaseFast semantic root continues to have a pre-existing noisy
hot-row floor failure in an unrelated typed family; the E-017 filtered
ReleaseFast tests are green.

## What this does not establish

This does not activate the boundary in `runner/mod.zig`. A production caller
must stage architectural results, compile the transaction, reserve both its
trace sink and the state-chain transaction, and only then publish the row and
architectural mutation. E-018 can do this narrowly for LUI through `compileLui`,
which derives the LUI result and x0 behavior before a row exists. Later family
migrations must retain the same pre-publication discipline.

## Decisions/tasks affected

- E-017 has executable shadow evidence and is ready to close.
- E-018 has a narrow LUI integration seam without expanding production
  authority prematurely.
- Production activation remains gated on exact row/relation/proof/performance
  parity in E-018.
