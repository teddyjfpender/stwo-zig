# M5 canon-vk: named recursion options, VK tables and the uniform outer shape

Stream `canon-vk` (RV64 M5), branch `codex/rv64-m5-canon-vk`, 2026-11-04. Companion to the binding note
(`rv64-m5-binding.md`, owned by profiles) and the recsize note (`rv64-m3-recursion-profile.md`). This note gives the written
argument for every proof-format option this stream adds, so profiles can fold it into the binding/profile notes.
Labels: **[M]** measured (receipt exists), **[D]** derived from measured numbers, **[E]** estimate.

Interface contract: `/workspace/m3/M5-INTERFACES.md`, section `canon-vk` (CV1 options, CV2 VK tables, CV3 node summary).

## 1. What is selectable, and what stays the default

| option | env (producer AND receiver) | default | proof bytes |
|---|---|---|---|
| outer profile | `STWO_RV64_OUTER_PROFILE` = `r1_b2_q108_p20_fold4` / `m3_b4_q51_p26_fold4` / `m3_b8_q34_p26_fold4` | r1 | r1: M4 bytes |
| fold arity | `STWO_RV64_FOLD_ARITY` = 2..4 | 2 (r1), 4 (m3) | 2: M4 bytes |
| outer shape | implied by the profile: the registry-named canonical profiles `m5_outer_canonical_r1_b2_q108_p20_fold4_v1` / `m5_outer_canonical_m3_b4_q51_p26_fold4_v1` (profiles' domain strings) use `uniform-v1`, every other profile uses `exact`. `STWO_RV64_OUTER_SHAPE` may only restate it, or force `uniform-v1` on a non-canonical profile for diagnostics (E4) | exact | exact: M4 bytes |

Every unknown or unreadable value fails closed. Since `b833f4e3e`, the driver and receiver entry (`gkr_main.runArguments` →
`execution_wrap.checkPolicyEnv`) validate profile, shape and arity first, and exit with a clean error instead of a panic (corpus
`P03`). A canonical profile with `STWO_RV64_OUTER_SHAPE=exact` is refused (`CanonicalOuterProfileRequiresUniformShape`). The harness passes producer
environment only through `--env`, while the receiver inherits the caller's environment, so both must be set (a mismatch is
rejected; see section 5).

**Default-path evidence [M]:** with the recsize port and the k-ary pipelined executor merged, both dev blocks are byte-identical
to the M3/M4 baseline (26235156 37/37, 24628607 55/55 proof hashes) and the fresh receiver accepts
(`vectors/reports/rv64-m5-20261104/canon-vk/*-e1-r1-port.json`).

## 2. k-ary folds (arity 3, 4) under any outer profile

The fold message is `domain || ((k<<8)|2) || for i: I_i[8] || R_i[8] || n_i || o_i[4 n_i]`. For a fixed class, k and every
`n_i` are constants, so the message is fixed-length and its framing is injective. This is the binding note §4.3 lemma for k
children. Equal Blake2s digests therefore imply equal (identity, FIXED root, outputs) for every child, except with a collision.

Arity is bound three ways:
1. `k` is in the version word, so binary messages (word 2) never collide with k-ary ones (0x302, 0x402);
2. `k` is in `classKey`, so a k-ary fold circuit is a different circuit with a different authority;
3. the receiver derives the plan itself (`Plan.initArity`), so a proof of arity k' at a k-position fails both the authority and
   the digest check.

The pipelined executor change is scheduling only. Each node runs the same graph, the same proving call and the same
publication as the lane path, in topological order. Kids are retired only after the parent is durably published. Under arity 2
it is byte-identical [M] (section 1).

Soundness accounting is unchanged per proof: each fold is a 128-bit conjectured outer proof under its profile. A 4-ary tree over
κ leaves has fewer outer proofs (⌈(κ−1)/3⌉ folds instead of κ−1), so the union bound only shrinks.

## 3. The m3 outer profiles

These are the recsize note's profiles, merged unchanged:
- `m3_b4_q51_p26`: 2·51 + 26 = 128 conjectured bits;
- `m3_b8_q34_p26`: 3·34 + 26 = 128.

The profile domain string enters three places: every outer authority identity, the wire header and every outer transcript
(`mixProfile`). `validateConfig` requires a proof's PCS config to equal the receiver's exactly. A proof under one profile is
therefore rejected by a receiver of another (`P02`). The recsize CPU qualification exercises this: the r1 receiver rejects the
m3 root.

## 4. VK tables (`rv64-m5-vk-table`): `T_nat` (canon-native v1) and `T_rec` (canon-vk v1)

The hash rule is canon-native's frozen `H(tag, words) = Blake2s(Blake2s(tag) || LE32(words))`. Leaves, empty slots and
internal nodes carry distinct tags. `T_nat` and `T_rec` leaves carry distinct tags too.

Each leaf commits to its own index. The depth is `D = max(1, ⌈log2 n⌉)`, a constant per table.

In-circuit membership (`vk_table.verifyMembership`) works as follows:
- the index word is `Σ b_d 2^d`, computed from exactly D path bits;
- each bit is constrained by `b·b = b`, and QM31 is a field, so b ∈ {0, 1};
- the index is therefore range-checked to `[0, 2^D)` by construction (binding checklist item 5);
- an index in `[n, 2^D)` reaches an empty leaf, whose tag differs from the leaf tag, so a non-member is admitted only with a
  Blake2s collision.

At a canonical leaf, `T_nat` membership uses a constant index. That is binding §3.2(2): the class constant cannot be relabelled
(`G01`).

Tests [M] (`test-riscv64-m5-vk-table`, 7/7 on the pod):
- `T_nat` reproduces canon-native's golden vectors byte for byte (leaves, root, path, header);
- members are accepted in-circuit;
- these are rejected: a forged VK (`G03`), an arity relabel (`G05`), a member at another index, a different root (`G02`), a
  rung-0 VK at the rung-1 constant index (`G01`), and a non-Boolean index bit;
- a node preimage hashed under the leaf tag differs from the node (`Z08`).

The tables are not yet wired into a fold or leaf circuit. That is fold v3, section 7.

## 5. Uniform outer shape `uniform-v1` (`S_out`)

**Why.** A v2 fold's topology is a function of its children's geometry (`classKey`: component row logs, FIXED column logs,
preprocessed layout, output count, constraint count, max eval log). Today there are 8 distinct outer shapes on 24628607 (4 leaf,
6 fold) [M, diet census]. So there are many fold classes, and their VKs depend on the block.

If every recursion node is padded to one shape `S_out`, every fold of arity k has the same children's geometry. Its circuit, and
so its VK, then depends only on k. This is the binding note §1 `S_out` requirement, and it is what lets `T_rec` hold a constant
fold VK per arity.

**What.** `S_OUT_V1` = log2 rows (eq 18, qm31_ops 23, triple_xor 20, m31_to_u32 21, blake_g_gate 23). This is the elementwise
maximum of the 33 node shapes of 24628607. Every leaf and fold is padded to it (`outer_wrap.paddingTargets`). A node above the
target fails closed (`ComponentExceedsTarget`).

**Argument.**
- Padding appends only the builder's own padding gates (`padToTargets`). These are satisfied by construction and touch no
  verifier wire, so the set of accepted statements of each node circuit is unchanged.
- The padded sizes enter the preprocessed circuit, and so the FIXED root and the authority identity.
- The receiver rebuilds every authority from its own trace-only graph under its own shape selection. A proof made under the other
  shape is therefore an authority mismatch (fail closed).
- The outer profile (blowup, queries, PoW) is unchanged, so the conjectured bits per proof are unchanged.
- A larger trace changes only the degree bound that FRI tests, which the ethSTARK conjecture already covers at any size.
- The tree has the same number of outer proofs, so the union bound is unchanged.

**Cost [D].** +19.5% recursion cells on 24628607: 32.4 → 38.8 G, from the census row logs × fitted component widths, exact fit.

**Measured [M]:**
- One binary fold VK, shared by 26235156 and 24628607 (E4: `bf610ea9…`). Under exact there are 11 distinct fold VKs across
  the two blocks.
- An exact receiver rejects uniform-v1 proofs (`Om31CircuitWireAuthority`).
- The negative corpus passes 36/36 on uniform-v1 proofs.
- Interleaved same-binary A/B on 24628607 (E5, load 20–37), recursion stage: exact 21.9 / 23.3 s against uniform-v1
  23.6 / 25.9 s. That is about +2.2 s (+10%).
  - The cost is leaf padding: leaf device-stage time sums to 18.1 / 19.6 s exact and 21.9 / 25.0 s uniform. Six leaf shapes
    are padded up to one.
  - Folds gain: with the class-PP reuse (section 5a) the fold prep median falls 1.05 / 1.24 → 0.47 / 0.66 s.

**Benefit.** One fold class per arity:
- the producer's class-keyed PP/FIXED cache hits for every fold after the first;
- `derive-vk-tables` can compute the fold VKs from source with no block;
- it is the prerequisite for fold v3.

The measured effect is in the receipts listed in section 6.

## 5a. Class-PP reuse in the pipelined prep (scheduling only)

The lane path already borrowed a fold class's preprocessed circuit from `PPCache`; the pipelined prep rebuilt it per fold.
`prepareHost` now borrows the class PP for fold v2 classes. Ownership:
- the class key is read on the prep thread, because `class_hint` is threadlocal;
- a borrowed flag travels `HostPrep` → `Proved` → `Wrapped`, so a borrowed PP is never freed or retired;
- the first fold of a class is cloned into the cache.

Argument: the fold classKey is collision-free by construction. It hashes every input of the topology: row logs, FIXED logs, the
full preprocessed layout, output count, constraint count and max eval log. The PP is a pure function of the padded topology, so a
cached PP equals a fresh one. `STWO_RV64_OUTER_PP_CLASS_CACHE=check` asserts this per fold.

Evidence [M]: under exact, 8 of 16 folds hit, and both E5 exact runs are 55/55 byte-identical to M3/M4.

## 5b. P02 and P03 on this receiver [M]

- **P02.** A receiver selecting `m3_b4_q51_p26` for r1 proofs rejects them.
  - At the default m3 arity 4 it rejects with `MissingRecursiveNodeProof` (plan mismatch).
  - With `STWO_RV64_FOLD_ARITY=2` it rejects with `Om31CircuitWireProfile` (the profile domain in the wire header).
- **P03.** An unknown profile name is a clean error exit; see `p03` in the receipts README.

## 6. Measurements

See `vectors/reports/rv64-m5-20261104/canon-vk/README.md` (E1 parity; E2 r1 4-ary; E3 m3 4-ary; E4 uniform-v1).

## 7. Not done in this iteration (honest scope)

- **Fold v3.** In-circuit `T_rec` membership replaces the receiver's `expectedDigest`. The node summary `NS` (binding §2) is
  replaced by the interval chain, `κ`, `bus[R]`, `mass`, `ctr`, `steps` and `depth`. Every §9.2 receiver check moves
  in-circuit, plus the root statement §4.4. Building blocks landed: `vk_table.zig` and `S_out`.
- **Canonical leaves `R_leaf[f, r]`.** These need canon-native's rung padding and the χ-chain native version.
- **`derive-vk-tables` CLI and the root-only receiver path.** The table formats are frozen in CV2, and the fold VKs become
  derivable once `uniform-v1` holds.
- **The 0.1 s per-node host preprocess+plan+graph gate.** Under `uniform-v1` plus class-PP reuse the fold prep is 0.47–0.66 s
  [M]: graph 0.27–0.35 s plus padding. The class plan cache hits: fold `host_plan` falls 0.756 → 0.012 s. Leaves are still
  2.0–3.0 s, because each leaf is its own circuit. Meeting 0.1 s needs three things:
  - canonical leaves, so the leaf PP and plan become class store hits;
  - a cached padded topology, so padding and graph are not rebuilt;
  - the M6 hint tape for the witness.
