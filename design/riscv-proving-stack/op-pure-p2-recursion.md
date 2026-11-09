# OP pure-P2 recursion workstream

The heavy OP 121065789 matched D2 qualification costs 1,586.092 seconds native
and 1,742.353 seconds recursive production. The acceptance target is at most
332.845 seconds for both stages together on the same CPU, security assumptions
and complete execution. This workstream replaces work in recursive verification;
it does not meet that target merely by proving a smaller fixture.

The retained M6 tree has 115 native members and 173 outer nodes. Its measured
outer INTER commitment is 409 seconds, composition 334, interaction generation
256 (185 in BLAKE gate rows), MAIN commitment 190 and FRI quotient 174. More CPU
proof lanes failed the complete heavy comparison. Fused BLAKE's existing model
is about 1.43x, not the required structural multiplier.

## New suite and current gates

The candidate uses the existing source-owned Poseidon2-M31 width24 permutation,
rate12/capacity12 sponge and nine-coordinate output. The pure five-roster AIR
has 497 MAIN and 248 classic INTER columns; the permutation constraints have
degree at most three. There is no implicit selection from existing BLAKE proof
bytes or producer geometry. Existing Ethereum/OP production profiles remain
unchanged. `production_admission_open=false` and `security_qualified=false`.

The first gate now generates an actual numerical local GKR proof from source
fractions, checks it natively, and constrains the same proof in the dedicated
P2 circuit. All OOD coordinates, terminal marginals, eta and nine receipt limbs
agree. The result is **pending**: execution still needs physical source/mask
binding, global RAM/KIO/Wire closure and independent endpoint authority.

One typed visitor defines the new local receipt for both native and circuit:

- External 256-bit statement IDs remain eight exact raw u32 words, encoded as
  two checked 16-bit halves per word, including P, 2^31 and 2^32-1.
- Roots are nine canonical M31s; secure fields are eight canonical M31s. They
  are not expanded into four byte columns per coordinate.
- Metadata integers are exact u64s, encoded through two raw u32s. Variable
  vectors all carry lengths; tags, schema, field degree and root width are fixed.
- Native decoding rejects noncanonical coordinates. Dedicated P2 ports bind
  complete source QM31 values to base M31 cells through the Var lookup bus.

The actual same-input local-verifier census falls from 3,216,384 cells under
byte receipt framing to 1,630,144 under typed framing. Permutations fall
694 to 426; arithmetic rows 23,615 to 11,239; M31-to-u32 rows 8,626 to 58.
This is a small component measurement, not a full CPU leaf or block speedup.

## Physical prover foundations

The first b4 physical gate exposed an existing experimental component bug:
it indexed the committed 4n LDE as if it were the disjoint 2n quotient domain.
The correction re-evaluates that component's columns from authenticated
coefficients onto the exact quotient domain; it does not relax the log guard.

The old reference path also rebuilt FIXED after deriving the key and used flat
Merkle leaf hashing at the largest range-table height. The new path retains
immutable FIXED once and uses the existing bounded-prefix streaming committer,
so native-height prefixes are absorbed once. A frozen-code monolithic control
has identical roots, transcript and complete proof bytes in six balanced cold-process
runs of the same executable. Median producer time is 2.158s versus 22.474s
(10.42x); independently derived fresh receiver is 0.223s versus 2.485s
(11.13x). All six proofs are exactly 511,876 bytes with the same SHA-256.
The receipt is `vectors/reports/rv64-opstack-cpu-20261109/pure-p2-local-physical-v1.json`.
This measures only the 1.63M-cell local-child verifier. It does not close the
heavy native+root target. Dense native
CPU columns do not share this mixed-height saving: a separate microbenchmark
finds scalar P2 leaf hashing 5.9–7.5x slower than BLAKE on 16/53/128/497 fields.
Packed independent-state hashing and real full-leaf measurements are required.

## Security target and bounded review

The label remains **128-bit security target under documented assumptions**.
This document is a bounded engineering review, not a composed certificate or
independent cryptographic audit. The first physical proof authenticates only
local-child verification, not execution. No production admission follows from it.

Two receiver-owned experimental profiles cost the query/grinding tradeoff:
`op_target_b4_q72_p0_fold4_v1` and `op_control_b2_q144_p0_fold4_v1`. Under the
same conjectured FRI query accounting, each has 144 nominal bits without costly
P2 grinding. At most 4,096 native/recursive proofs would debit 12 bits of this
term by a union bound, leaving 132 before other terms. That proof-count premise
is a review scenario, not permission to increase a native roster cap.

The concrete construction review must bound all of the following together:

1. FRI query soundness and the total accepted native/recursive proof inventory.
   Query positions drawn from canonical M31s have maximum per-query likelihood
   ratio 2^31/(2^31-1) relative to uniform power-of-two indices. The small bias
   is accounted multiplicatively, not dismissed as exact uniform u32 draws.
2. Tuple-compression collisions, rational identities and poles in OM31. The
   concrete field has size (2^31-1)^8. Current source-owned circuit admission
   requires each Var/range mass and variable count below the characteristic.
   Source arities, signed/absolute occurrence counts, global relation masses
   and all proof-family unions must enter the whole-execution bound. A local
   proof alone does not establish cross-shard conservation.
3. Fiat–Shamir/GKR rounds, layer/instance counts and total oracle/permutation
   calls. The v2 draw counter is checked u32 and cannot wrap. Scope roots,
   statements, relation families, exact dimensions and every terminal marginal
   enter the explicitly versioned transcript or canonical receipt.
4. Hash collisions and sponge/permutation assumptions with **aggregate** query
   counts. Capacity is 12*31=372 bits; output is 9*31≈279 bits. Ideal birthday
   work factors are about 186 and 139.5 bits respectively, but those figures
   alone are not a composed protocol argument. For an illustrative total
   oracle-call bound Q<=2^64, ideal output and capacity birthday terms are at
   most roughly 2^-151 and 2^-244; cryptanalytic claims still depend on the
   pinned permutation and sponge assumptions. The actual accepted execution's
   hash-call census and adversary-work convention must be stated explicitly.
5. Packing/admission: injective raw u32/u64 and external-ID encodings; canonical
   nine-coordinate roots; field coordinate checks; complete vector lengths;
   exact source geometry and separately established verifier authority. No
   producer-provided hash, degree, row count or terminal claim is authority.

## Remaining integration gates

1. Pure native stage-one/local receipt and nine-limb manifest framing, shared
   challenge parity and stage-two source-bound terminal projections.
2. Complete actual CPU leaf: every original AIR, OODS residual, global lifted
   mask and terminal binding; native/circuit value parity; source-owned geometry.
3. Every service truth family and physical boundary closure; no unsupported
   family can silently fall back to raw BLAKE or skip its obligation.
4. New five-roster proof verifier inside the same algebraic parent; fold
   adjacency/coverage and manifest/global-claim conservation; fresh root receiver.
5. Native+root profiling on real heavy requests, then the larger OP basket.
   Compare native cost, active/padded cells, lifted exposure, system time and
   peak RSS as well as elapsed time. Only the matched full pipeline can close 10x.

Focused development:

```sh
zig build check-riscv64-op-pure-p2 -Doptimize=ReleaseSafe -j1
zig build test-riscv64-op-pure-p2 -Doptimize=ReleaseFast -j1
```

`STWO_OP_P2_MONOLITHIC_CONTROL=1` selects only the explicit reference scheduling
control of this unadmitted prototype. It cannot select a different cryptographic
profile or weaken receiver checks; malformed values refuse.
