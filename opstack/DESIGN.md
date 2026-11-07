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

`ethereum/gkr_main.zig` now owns orchestration in 843 lines. Operational schemas
and their rejection tests live in `resources.zig` / `resources_test.zig`;
`input_timeline.zig`, `profile_selection.zig`, and `cpu_prestage.zig` own timeline,
CLI naming, and optional linked-device callbacks. The native-only product retains
its explicit dependency boundary and all linked recursion-policy checks.

The explicit CPU resident entry lives in `native_batch.zig`. Its closed manifest
bounds the number of requests, repeats, names and immutable-key admission. It
reuses the existing `ResidentSession`, never witness or statement data. The
production index explicitly says independent reception is still required.
`cpu_batch.py` supplies its own expected request and proof path to a fresh
receiver for every result, then runs transport and rehashed-proof negatives.
Neither index contents nor a producer's cached setup can choose receiver authority.

Cold benchmarks preserve the request's batch geometry unless the operator gives
an explicit override. Changing 1,048,575 steps into 262,143 steps silently creates
many extra CPU proofs and repeats setup work; tests pin this boundary. Comparisons
record geometry, proof/service worker counts, wall time, user/system CPU time and
peak RSS. A single timing sample, especially during compilation, is not a speedup.

## Guest field and allocation costs

`canonical-glv` combines canonical BN254 Fq/Fp2 services, validated prepared-G2
reuse and a four-bit joint GLV multiplication. Its lattice constants and reciprocal
bounds are reproduced by `tools/derive_bn254_glv.py`; exact residual correction
and checked 128-bit conversion replace division without adding a trusted hint.
Revm retains gas and fork activation, and the native host uses registry Arkworks.
The plain Fp2 representation avoids the larger Mont384 packets used by the earlier
experiment. Instruction reductions still carry service RAM and truth costs.

Borrowed postcard views stream transactions during canonicality comparison and
payload hashing. A legacy owned byte oracle covers boundaries and all six mainnet
OPX inputs remain byte-identical. Trie mutation transfers subtree ownership;
failed extension splits preserve the original node. Allocator free-list metadata
uses volatile stores because physical minimum-size slots can exceed a caller's
logical Rust allocation size under LTO. These are separate ownership contracts,
covered by targeted tests and complete execution replay.

## Anchored L1 provider

`stwo-kona-execution`'s opt-in `derivation` feature implements Kona's
`ChainProvider` over the canonical preimage table. Initialize it with the L1
number and hash from the checkpoint statement. Number lookups walk a contiguous
parent chain from that head. Hash lookups must match the corresponding ancestor,
even when a competing header is present in the witness. The provider opens the
canonical transaction and receipt tries from the authenticated header and decodes
all EIP-2718 entries in order. Missing or malformed data is a critical error.

Run `cargo test --locked --manifest-path opstack/kona/Cargo.toml --features
host,derivation` for the provider and existing execution tests. The provider tests
cover fork substitution, a corrupt trie node and mismatched anchor height.
The execution benchmark entry point retains its execution statement and fixtures.

`AnchoredL2` opens the previous checkpoint's V0 output preimage, checks its
number and state commitment against the authenticated header, and exposes
only that safe history to Kona's batch validation and system-config lookup.
The integration test reconstructs the transaction trie for OP Mainnet block
121057303 and checks the header, transaction root, L1 origin and gas limit
against the pinned Kona replay corpus. The test checkpoint uses a synthetic
withdrawal root to isolate safe-head authentication.

The anchor test also uses Ethereum Mainnet headers 20,035,799 and 20,035,800
from PublicNode. The earlier hash matches the origin in the OP block's L1-info
deposit. The test recomputes both hashes from header RLP and opens the earlier
header through the successor's parent link.

`AnchoredL2::execute_prepared` consumes Kona's exact prepared attributes,
checks their parent and next height, executes using the anchored parent state,
and checks the OP V0 output root computed by Kona. The pipeline must supply the
prepared attributes, and the transition relation must still bind the returned
L1 origin to the public anchor and statement. The existing OP replay witnesses
cover block execution but lack account-trie nodes needed to open
`L2ToL1MessagePasser` for the output root. The block 121057303 probe reaches the
missing node `55b88d8d3ce0ca3c4073bc95277af8960db21669a01ebe48ca3a1fc5615776b1`.
Supply authenticated archive account proofs when collecting a transition fixture.

`transition::verify_calldata_transition` connects these providers to the pinned
Kona pipeline. The caller supplies the trusted anchor, pinned chain configs and
transition claim separately from the witness. The pipeline resets from the
checkpoint, authenticates L1 origins during its L2 history walk, and executes
only the attributes it derives. It checks the executed output root and L1
origin against the claim. It bounds pipeline steps and rejects blob-backed DA,
Alt-DA and interop until those inputs can be authenticated.

The mainnet provider test exercises this entry point against OP 121057303 and
Ethereum anchor 20035800. It rejects a substituted origin and reaches the
missing safe history during Kona's reset with the correct origin. A positive
mainnet transition needs that history, the L1 DA and the execution/output-root
witnesses in one fixture. Guest statement encoding and recursive admission of
the transition remain separate work.
