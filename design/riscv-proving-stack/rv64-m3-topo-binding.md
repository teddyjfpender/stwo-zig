# Fold v2: proof-independent fold topology, and why child keys cannot be swapped

Stream `topo` (RV64 M3), branch `codex/rv64-m3-topo`. Code: `src/integrations/riscv_cpu/rv64_recursion/om31_outer.zig`
(`version = 2`, `classKey`, `buildFoldMode`, `messageWords`), receiver class cache in `om31_native/execution_wrap.zig`
(`FoldClasses`, `combine`), restore path `om31_native/outer_wrap.zig` (`restoreWithAuthority`).

## What changed

A fold circuit verifies two child OM31 circuit proofs. In fold message v1 each child's verifying key entered the circuit as
**constants**: the authority identity (32 B, absorbed by the child's in-circuit transcript in `Statement.mixPublic`) and the
FIXED/preprocessed Merkle root (`constantHash` + `eq` against the child's guessed `commitments[0]`). Constants are interned and
later decomposed into value-dependent gates and preprocessed columns, so every fold had its own PP, FIXED root and authority
identity even when its gate graph was identical to another fold's (measured: 16 folds, 8 gate graphs, 16 authorities).

In v2:

1. The child identity is 8 **guessed, range-checked u32 words** (`B.wrappers.guessU32`). The same wires are absorbed by the
   child's in-circuit Fiat–Shamir transcript (`mixPublic`) and appended to the fold message.
2. The constant FIXED-root equality is removed. The child's guessed `commitments[0]` wires (already range-checked by
   `guessHash`, already absorbed by `channel.mixRoot` and already the root that every tree-0 Merkle decommitment is checked
   against) are appended to the fold message.
3. Message: `domain ‖ 2 ‖ for each child: identity[8] ‖ fixed_root[8] ‖ n_outputs ‖ outputs[4·n]`; output = Blake2s of the
   message (8 raw-u32 public outputs). `expectedDigest` computes the same words from the receiver's authorities.

Everything else in the fold circuit is a function of the child **geometry class**: bound AIR (template + component row logs +
layout derived from them), FIXED column logs, output count, PCS config and protocol domain. `classKey` hashes exactly that set.

## Binding argument

Let a receiver hold, for each child `x ∈ {L, R}`, an authority `A_x = (I_x, R_x, S_x)` that it built itself from the child's
circuit (identity, FIXED root, structure). The producer supplies a fold proof `π` with outputs `o`. The receiver accepts `π`
only if (i) `π` verifies under the fold authority it built itself for class `(S_L, S_R)` (fresh `Outer.verify`), and
(ii) `o = expectedDigest(A_L, A_R, child outputs)` (`requireDigest`). In the receiver these are `outer_wrap.zig` /
`restoreWithAuthority` and `execution_wrap.zig` `combine`; the root is additionally checked by `Root.check`.

By soundness of the outer OM31 STARK (unchanged profile `stwo/circuit/native-om31/q108-p20-fold4/lens-v1`), (i) implies there
exist wire values satisfying the fold circuit, i.e. words `I'_x, R'_x`, child outputs `o'_x`, claims and a child proof such that
the child proof verifies in-circuit against structure `S_x` (circuit constants of this class), with transcript seeded by
`I'_x` and preprocessed commitment `R'_x`, and `o = Blake2s(domain ‖ 2 ‖ I'_L ‖ R'_L ‖ … ‖ I'_R ‖ R'_R ‖ …)`.

By (ii), `Blake2s(m') = Blake2s(m)` where `m` is the receiver's message over `(I_x, R_x, o_x)`. Both messages have the same
length (the length is fixed by the class: `n_outputs` is a constant) and the same framing, so unless the producer found a
Blake2s-256 collision, `m' = m`, hence `I'_x = I_x`, `R'_x = R_x` and `o'_x = o_x`. Therefore the child proof was verified
in-circuit against exactly the receiver-trusted FIXED commitment, the receiver-trusted identity in its transcript, and the
receiver-trusted structure — which is precisely the v1 statement. The v1 constants were therefore redundant with the digest:
the reduction costs one Blake2s collision bound (≈2^-128 for 256-bit output; the security target of the system is 128-bit
under the documented assumptions, unchanged).

Why `S_x` cannot be swapped: it is not a witness. It is the topology of the fold circuit, which the receiver builds from its own
child authority (`classKey` covers logs, FIXED logs, output count and the derived bound-AIR sizes; layout is
`ColumnLayout.fromComponentSizes(logs)`), and it is committed by the fold's own FIXED root that the receiver computes.

Why `R_x` cannot be swapped without `I_x`: both are separately digest-bound; neither is derived from the other in-circuit, so
the in-circuit SHA-256 identity recomputation suggested in the review is unnecessary.

Range checks: identity words use `guessU32` (two u16 limbs); root words use `guessHash`. A non-canonical encoding of a word
cannot alias a different u32 because the Blake2s gadget consumes the canonical limb form and its output must equal the
canonical `requireDigest` words (`outer_wrap.zig: requireDigest` rejects non-canonical outputs).

Adjacency/coverage: unchanged; the receiver still checks leaf adjacency in `combine`, node coverage at the root, and the
tree/root bytes.

## Receiver class cache (soundness)

`FoldClasses` is in-process, receiver-built, never persisted and never fed by producer bytes. The first fold of each class is
built from an honest trace-only graph exactly as in v1; its retired PP and verifier `Authority` are adopted. A later fold with
equal `classKey` is restored from its bytes and freshly verified under that authority plus the digest check above. Correctness
of reuse rests on the determinism claim "fold topology = f(classKey)", which is (a) tested
(`rv64_om31_outer_test_root.zig`: two children with distinct FIXED roots/identities of one class yield `expectEqualDeep`
circuits and identical constant tables, while digests differ), (b) checked on real blocks with
`STWO_RV64_FOLD_CLASS_CACHE=check` (rebuild every hit and require equal authority identity), and (c) observable with
`STWO_RV64_TOPOLOGY_CENSUS=1`. If the claim were false, a cached authority would differ from the producer's authority and the
proof would be **rejected** (completeness failure), not accepted: the cache can only restrict acceptance to proofs valid
under an authority the receiver itself derived from an honest graph of that class. `STWO_RV64_FOLD_CLASS_CACHE=0` disables it.

## Versioning

Fold message word 1 = `2`. v1 and v2 fold/root proofs are mutually unverifiable (different digests and authorities); leaf
proofs are unchanged and byte-identical. Accepted v1 controls stay verifiable only by a v1 binary.

## Not covered

Leaves remain proof-dependent: CPU leaf pre-finalize variable counts differ per segment (19.3M–33.3M vars on 24628607) because
each segment has its own native setup (component roster/sizes), not because of key constants. Making leaves class-only needs
canonical native segment geometry (a native-side change) — see the stream report.

## Producer class caches (completeness only)

The producer reuses, per `classKey`, the fold assignment plan (`outer_assignment.zig` `ClassCache`: tasks, indices,
level ends, seed-variable layout; seed values are re-read from each graph and their layout is checked) and the immutable
PP (`outer_wrap.zig` `PPCache`; authority and device FIXED precommit stay per proof). Neither enters a proof or the
receiver. A wrong reuse could only produce a proof that the independent receiver rejects. On 24628607/26235156 the
`=check` modes rebuilt every reused plan/PP and found them byte-equal (15/15 each), and proofs are byte-identical with the
caches on and off (`vectors/reports/rv64-m3-20261104/topo/warm-two-block.json`).
