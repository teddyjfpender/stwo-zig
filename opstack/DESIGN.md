# Mainnet CPU continuation

Use genuine historical OP Mainnet inputs and actual chain 10 configuration.
The host must reproduce the complete expected block hash before RV64 execution,
and RV64/Unicorn must match all registers, output bytes, terminal PC and service
counts at exactly N instructions (N-1 then one). These are execution checks.
A CPU proof succeeds only after a fresh durable receiver accepts the complete
statement. Corruption is tested both with the original transport digest and
with a recomputed digest, so the proof verifier is also exercised.

The statement proves supplied OP execution, not authenticated L1 derivation,
KZG, chain-head anchoring, recursion or settlement. The selected conjectured-128
native profile keeps `security_qualified=false`; no protocol parameters are
weakened to make CPU runs fit. No SNARK wrapper is introduced.

## Optimizations and measurement

SHA and modular arithmetic reuse admitted v3 services. Bulk memory uses the
existing aligned wrappers and fallback rules. Source-derived FIXED, MAIN and
INTERACTION cell counts include padding; MAIN+INTERACTION bits are payload
accounting, not proof size. Whole-proof measurements always include reception.

BN254 is experimental and separate from the default guest. Ark Montgomery
residues use radix 2^256; the existing 384-bit Montgomery service accepts the
first operand shifted 128 bits, yielding the same residue. The CPU evaluator
recognizes only this canonical shape and uses four-limb REDC. Arbitrary odd
moduli and noncanonical operands retain the original mathematical operation.
Fixed-field inverses are computed at compile time. No AIR or transcript changes
are needed. Avoid zero-then-fill service packets: that creates a bulk memset
service for every field multiplication. Direct packet construction removes
that unnecessary work. Added service RAM and truth costs must be counted before
claiming a proof-speed improvement from the instruction reduction.

## CPU orchestration

Use bounded lanes, workers, capture geometry, disk and memory admissions. A
failed admission or killed process is a failure, never a successful prefix.
The source-bound arithmetic accountant reserves an inactive row; the candidate
producer now pads an exactly full arithmetic table rather than relaxing that
receiver bound. Capture and early-shard admission use the same CPU planner.

A process-local producer setup cache enables the existing identity-only/source
sharing path without restoring files. Its owner dies at process exit. A fresh
receiver has no cache selection in its environment and rebuilds all authority.
Disk-backed retained trees are operational storage, not verifier authority.

## Ownership and remaining decomposition

CPU geometry moved from `ethereum/plan.zig` into `ethereum/cpu_plan.zig`, taking
the planning owner from 973 lines to 811. Source-bound candidate cost/accounting
is owned by `ethereum/capture_plan.zig`, shared with production rather than a
second estimator. The BN254 REDC kernel and its wide-integer differential tests
are isolated in `ethereum_services/montgomery_bn254.zig`. Guest dependency
patches and native-only witness diagnostics have their own directories.

`ethereum/gkr_main.zig` remains oversized. The small extra native-only entry
keeps existing GPU entry points and recursion-policy checks stable while giving
CPU builds an explicit dependency boundary. Next split its operational resource
schemas, timeline/report types and linked entry points from the producer/receiver
orchestrator, preserving allocator ownership and error teardown in separate
move-only changes. A large mechanical rewrite during the proving changes would
obscure the authority and lifetime review; this file's residual size is explicit.
