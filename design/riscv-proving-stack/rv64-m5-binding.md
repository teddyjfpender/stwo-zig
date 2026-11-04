# M5 binding note: canonical leaves, constant recursion VK, root-only receiver

Stream `profiles` (RV64 M4–M7), branch `codex/rv64-m4-profiles`, 2026-11-04. This note gates M5 (plan §4.2–4.4, §5 "M5 entry"). No M5 code may merge until this note has been reviewed and the M5 cases of the negative corpus (§7) pass.

**Status:** design. Adversarial review 1 (2026-11-04, §9) found 3 blocking gaps (F1–F3) and 9 smaller ones. §2, §3.2, §4.1, §5 and §6 are amended in place and marked **[R1]**. The note stays **not approved** until a second reviewer signs off on §9. Labels: **[M]** measured (receipt exists), **[D]** arithmetic on measured numbers, **[E]** estimate.

Related material:
- the fold v2 note (`rv64-m3-topo-binding.md`, code in `om31_outer.zig`);
- the recsize note (`rv64-m3-recursion-profile.md` @ `5d68d0f01`, 4-ary folds and the `m3_b4_q51_p26` outer profile);
- the M7 profile note (`rv64-m7-profiles.md`).

Corpus harness: `scripts/rv64_m5_negative_corpus.py`. Today's results are in `vectors/reports/rv64-m4-20261104/profiles/`.

---

## 0. What M5 changes, and the one claim this note proves

Today (fold v2), the receiver:
1. rebuilds every child authority;
2. recomputes every fold digest (`expectedDigest`);
3. checks leaf adjacency and coverage itself (`execution_wrap.zig combine`).

This costs 77 s per block [M], and the receiver must re-derive the native setup of every segment.

M5 moves those checks **into the circuits**. The receiver then checks one proof and a constant-size public statement.

**Claim (M5 binding).** Suppose:
- a final proof is accepted under a recursion VK that the receiver derived itself;
- its public node summary (§2) passes the receiver checks of §5.

Then there exists a sequence of native segment proofs `π_0 … π_{κ-1}`, each accepted by the native verifier under the native VK the receiver derived for its (family, rung). Those proofs share one χ, and χ is bound to all their MAIN roots. Their boundary statements chain from the block's initial state to its final state. Their bus claims sum to the value the statement requires.

The failure probability is at most the sum of:
- the per-node outer soundness errors;
- the native soundness errors;
- one Blake2s-256 collision bound per hash use;
- the Merkle-membership collision bound.

The accounting is in §6.

---

## 1. Objects

| symbol | what | who fixes it |
|---|---|---|
| `img` | guest image id (ELF hash plus ROM authority) | statement |
| `stmt` | block statement digest: input commitment, expected output, `img` | receiver policy (request) |
| `(f, r)` | segment family (cpu, keccak, …, truth families, global) and rung (one of ≤ 3 canonical heights) | producer chooses per segment; must be a table entry |
| `S^nat_{f,r}` | native structure of (f, r): component roster, every component log size, the trees, the column counts and log sizes per tree, mask offsets, composition split, FRI layer count, query-index widths, profile | **circuit constant** of `R_leaf[f,r]` |
| `V^nat_{f,r}` | native VK of (f, r): native FIXED root, preprocessed roots, authority identity, profile id | derived from source per image; guessed in-circuit, then checked by membership |
| `T_nat` | Merkle root over `leafhash_nat(f, r, V^nat_{f,r})` in canonical (f, r) order | `derive-vk-tables(img, profile)` |
| `S_out` | the **uniform outer shape**: component row logs, FIXED column logs, preprocessed layout, `n_outputs`, constraint count, max eval log, profile | constant per (image-independent) build |
| `V_x` | outer VK of a recursion circuit `x ∈ {R_leaf[f,r], F_2, F_3, F_4}`: (authority identity `I_x`, FIXED root `R_x`) | derived from source |
| `T_rec` | Merkle root over `leafhash_rec(kind, f, r, k, V_x)` for every leaf class and every fold arity | `derive-vk-tables` |
| `χ` | the native global challenge | Fiat–Shamir, §3.3 |

**Why `S_out` is needed.** This is a new requirement, and it is the main correction to plan §4.3.

A fold verifies its children in-circuit. Its topology is a function of each child's geometry class, which is exactly v2's `classKey`.

Suppose leaves of different (f, r), and folds, had different outer shapes. Then the fold classes would be the ordered tuples of child classes: about `Σ_k C^k` circuits for `C` child classes. That gives over 20,000 classes for C = 12 and k ≤ 4, and no constant VK.

So M5 must pad every recursion circuit to one shape `S_out`, which every leaf class and every fold class shares. A fold's topology then depends **only on its arity k**. That gives 3 fold VKs, independent of the children.

The padding cost is small for leaves vs folds: the census puts leaves at about 1.17 G cells and folds at about 1.13 G [M]. It has to be measured per (f, r) at M5 entry.

**Fallback** if the padding tax on small leaves exceeds 25%: use two shapes, `S_leaf` and `S_fold`. Fold classes are then keyed by the shape vector of their children, giving at most 2² + 2³ + 2⁴ = 28 fold VKs. That is still a constant per build and still fits in `T_rec`.

---

## 2. The node summary (public outputs of every leaf and fold)

Every recursion circuit exposes the same fixed-length public output `NS` (raw u32 words, as today's 8-word digests). This uniformity is what lets the fold circuit be child-independent.

```
NS = ( T_nat[8], T_rec[8], img[8], stmt[8], chi[8 as OM31 words],
       seg_lo, seg_hi, kappa,
       m_in[8], m_out[8],          // ordered segment chain, interval form (§3.2)
       s_in[W], s_out[W],          // boundary machine state at seg_lo start / seg_hi end
       bus[R][8 as OM31 words],    // [R1] one sum per global relation R in {ram, kio, wire}, never one combined sum
       mass[M],                    // [R1] integer LogUp masses per characteristic bound (ram, kio, wire, range16, range8, and, io)
       ctr_in[F], ctr_out[F],      // [R1] per-family cumulative call / truth-id counters (today: firstIds, truth spans, sponge ids)
       steps_in, steps_out,        // [R1] cumulative CPU step counter (today: first_step mixed per segment)
       E[..],                      // [R1] global expected words every CPU transcript mixes (total_steps, max_total_steps, final pc/regs)
       depth )                     // [R1] fold height; leaf 0, fold 1 + max child depth; checked <= D_MAX
```

**[R1] Typing rule.** Every field is one of three types and the circuit enforces the type on every node:
- *digest* words: u32 via `guessU32` limbs;
- *OM31* coordinates (`chi`, `bus`): canonical, each coordinate `< p`. A u32 limb pair can encode `w` and `w + p` for one M31 value, so the `< p` check is required for hash inputs and for comparisons;
- *counters* (`seg_*`, `kappa`, `mass`, `ctr`, `steps`, `depth`): integers with an explicit bit bound. Folds add them as integers and range-check the sum against its bound; they never add them in M31 and compare afterwards. Two children with mass `p − 1` each would wrap to `p − 2`.

Choices made here:
- `T_rec` is a **public input**, not a constant. No circuit hashes its own VK, and the PCD self-reference disappears.
- `vk_fold` (plan §4.3) is a special case. With per-arity fold classes, the three fold VKs sit inside `T_rec`, so no separate `vk_fold` word is needed. If the review prefers the plan's literal form, `vk_fold` is the `T_rec` leaf for `F_4`, and the argument is unchanged.

Encoding rule:
- Every hash input below is a fixed-length, domain-tagged sequence of canonical u32 words: a `guessU32` 2×u16 limb check per word, as v2 does.
- For a fixed class, the message length is a circuit constant.
- So message framing is injective, and equal digests imply equal messages except with a Blake2s collision. This is the same lemma as v2.

---

## 3. Leaf `R_leaf[f, r]` (plan §4.2)

### 3.1 What is constant and what is guessed

**Constants of the circuit:**
- everything in `S^nat_{f,r}`;
- `(f, r)` itself;
- the `T_nat` leaf index of (f, r);
- the native profile.

These are **never guessed**. Guessing a log size would need in-circuit muxing over domain sizes, FRI layer counts and query-index widths, and that is the classic source of under-constrained verifiers.

Canonical rungs make this possible. Every AIR of family f is padded to height `2^r`, and every component of the roster is present, possibly all padding. The roster and sizes are therefore constant per (f, r). This is canon-native's job (`keys.zig`, rung padding).

**Guessed, range-checked:**
- `V^nat` words: FIXED root, preprocessed roots, identity;
- the segment index `k`;
- the boundary statement `(s_in, s_out)` and the per-segment request `stmt_k`. **[R1]** `stmt_k` is today's per-segment `Request`: steps, `ls_count`, `calls[F]`, sponge counts and `first_id`, `ls_dword` and bridge presence. It is *not* free: constraint 7 below checks every field;
- `χ`;
- the MAIN root(s) `ρ_k`;
- the global-relation claim `c_k`;
- the proof body.

### 3.2 Constraints of the leaf

1. **Transcript seeding (frozen-heart rule).** The in-circuit native verifier begins its Fiat–Shamir transcript exactly as the native verifier does. It mixes the profile, the guessed `V^nat` words, `img`, `stmt`, `k`, `stmt_k`, `s_in`, `s_out`, `ctr_in`, `steps_in`, `E`, `χ`, and each committed root, in native order, **before** any challenge is drawn. **[R1]** Mixing a word only binds the challenges to it. Step 3 must also *use* `s_in`/`s_out` as the public boundary values of the native AIR, through its boundary constraints or its public LogUp terms. A boundary that is mixed but not constrained proves nothing about the trace (`Z12`).

   The words mixed are the same wires that are hashed in steps 2 and 4. A producer therefore cannot choose a VK or a statement after seeing a challenge: changing any of them changes every challenge.
2. **Native VK membership.** `MerkleVerify(T_nat, index(f,r), leafhash_nat(f, r, V^nat), path)`.
   - The path is guessed and the root is the `T_nat` output wire.
   - The index is a constant, and `leafhash_nat` is tagged and covers (f, r). So a VK of another class, or one that is not in the table, fails unless there is a Blake2s collision.
3. **Native verification.** Every check that today's leaf performs, against structure `S^nat_{f,r}` and the guessed roots.
4. **Chain step.** Set `m_out = H("rv64-m5-seg" ‖ m_in ‖ k ‖ f ‖ r ‖ vkhash(V^nat) ‖ stmt_k ‖ s_in ‖ s_out ‖ ρ_k)`, with `m_in` guessed. The claim `c_k` is deliberately **not** in the chain (§3.3).
5. **Interval and other outputs.** `seg_lo = seg_hi = k`, with `k < MAX_PROOFS` range-checked in the leaf (`Z05`). `κ = 1`, `depth = 0`, `bus[R] = c_k[R]` per relation, `mass = mass(f, r, stmt_k)`, `ctr_out = ctr_in + calls(stmt_k)` and `steps_out = steps_in + steps(stmt_k)`.
   - **[R1]** If relation R is absent for (f, r), a circuit constant, then `c_k[R] = 0` is asserted (today `NonzeroAbsentGlobalGkrClaim`, case `Z11`).
   - **[R1] State rule per family.** Only CPU-family leaves may change machine state. Every other family (truth/service shards, the memory-boundary family) asserts `s_out = s_in`. Without this, a keccak-shard leaf placed between two CPU segments can jump the machine to an arbitrary halted state with the wanted output. The interval chain only enforces *continuity* (`NS_{i+1}.s_in = NS_i.s_out`), so this rule is load-bearing (`Z01`).
6. **Pass-through.** `T_nat`, `T_rec`, `img`, `stmt`, `χ`, `E` go to the outputs. `T_rec` is unused by a leaf but carried, so that `NS` is uniform.
7. **[R1] Per-segment admission.** The leaf re-checks in-circuit the per-segment part of today's receiver admission (`global_execution/protocol.zig validateInventory` and `services/protocol.zig admit*`), against `stmt_k` and the constant `S^nat_{f,r}`:
   - steps ≤ `max_prefix_steps`;
   - `ls_count` ≤ steps, and service calls ≤ steps;
   - geometry capacity per bridge;
   - bridge presence ⇔ `calls[F] ≠ 0`;
   - sponge permutation bounds;
   - per-proof AND, range16 and range8 mass < p;
   - epoch = CPU ordinal + 1. Today `epoch = index + 1` counts CPU requests only, so the epoch is a CPU-segment counter in `ctr` and not the global index `k`;
   - initial memory only at the first CPU segment and teardown only at the last, both expressed through the memory-boundary family (§5.1).
   
   A truth leaf checks `first_id = ctr_in[f]` and `ctr_out[f] = ctr_in[f] + count`. That is the truth span of today's `InvalidCombinedTruthSpan` in interval form (`Z03`).

The leaf **does not** prove `m_in` is anything in particular. The interval form leaves it free, and the folds and root pin it down. That is what makes the accumulator independent of the tree shape.

### 3.3 χ binding

χ is defined as `χ = H("rv64-m5-chi" ‖ stmt ‖ m_final)`, where `m_final` is the sequential chain of step 4 from `m_0 = IV` over all segments in index order.

`m_final` is an injective, ordered digest of every (k, f, r, vk, stmt_k, boundary, MAIN root) entry. So this is the plan's χ = H(statement ‖ roots sorted by segment index) under a different but equivalent encoding. Everything the chain covers is known at the stage-1 barrier: capture gives the boundaries and stage 1 gives the roots.

The global-relation claim `c_k` is computed **after** χ, because LogUp sums need χ, so it cannot be in the chain that defines χ.

`c_k` is bound in two other ways:
- it is mixed into segment k's native transcript, which the leaf replays;
- it is summed into `bus`, which the root checks against `expected_bus(stmt)`.

The negative case `B01` covers a shifted claim.

This is a **native-side format change**: today χ is drawn from the global stage. It needs a new native protocol version (canon-native) and a byte-level test that the native prover and the in-circuit rule compute the same χ.

---

## 4. Fold `F_k`, k ∈ {2, 3, 4} (k-ary generalisation of fold v2)

### 4.1 Constraints

For children `c_1 … c_k`, in order, each with guessed outer VK `V_i = (I_i, R_i)`, proof and public outputs `NS_i`:

1. **Child transcript seeding.** As in v2: the in-circuit outer verifier for child i mixes the profile domain, `I_i`, the child's `n_outputs` and `NS_i` words. Its tree-0 commitment is `R_i`, through `mixRoot`. All of this happens before child challenges are drawn.
2. **Child VK membership (PCD self-VK).** `MerkleVerify(T_rec, j_i, leafhash_rec(kind_i, f_i, r_i, k_i, V_i), path_i)`, with the index `j_i` guessed.
   - Any child that is a genuine leaf class or a genuine fold class is admitted.
   - The kind fields are inside the hashed leaf, so they cannot be relabelled.
   - The fold's own VK is in `T_rec`, as are its siblings'. No circuit contains its own VK: the circularity is broken by `T_rec` being an input.
3. **Child verification** against structure `S_out`, which is constant. This is v2's in-circuit verifier, unchanged.
4. **Agreement.** `NS_i.{T_nat, T_rec, img, stmt, χ, E}` equal the fold's own corresponding outputs for every i.
5. **Adjacency and interval.**
   - `NS_{i+1}.seg_lo = NS_i.seg_hi + 1`;
   - `NS_{i+1}.m_in = NS_i.m_out`;
   - `NS_{i+1}.s_in = NS_i.s_out` (state continuity).
   - **[R1]** `NS_{i+1}.ctr_in = NS_i.ctr_out` and `NS_{i+1}.steps_in = NS_i.steps_out`. Outputs take the first child's `_in` and the last child's `_out`.
   - Outputs: `seg_lo = NS_1.seg_lo`, `seg_hi = NS_k.seg_hi`, `m_in = NS_1.m_in`, `m_out = NS_k.m_out`, `s_in = NS_1.s_in`, `s_out = NS_k.s_out`.
   - Range: `seg_lo ≤ seg_hi < MAX_PROOFS`. **[R1]** A 16-bit range check on the values bounds them by 2^16, not by `MAX_PROOFS`. The circuit range-checks `seg_hi − seg_lo` and `MAX_PROOFS − 1 − seg_hi` in [0, 2^16) **for every child, not only for the outputs**, so that `seg_hi + 1` can never wrap in M31.
6. **Count and bus.** `κ = Σ κ_i` as integers, and `bus[R] = Σ bus_i[R]` in OM31 for each R separately.
   - **[R1]** `mass[M] = Σ mass_i[M]` as integers, and each sum is `< p`. This is today's `GlobalRamCharacteristicBound` and `CombinedLookupMassExceeded`, enforced at every node. LogUp over a field of characteristic p is sound only while the total multiplicity of any key is below p, and per-leaf bounds × `MAX_PROOFS` exceed p: 256 × 2^24 × 2 > 2^31 (`Z04`).
   - **[R1]** `depth = 1 + max_i depth_i ≤ D_MAX`, with D_MAX = 8 suggested (`Z06`).

Arity is a **class constant**. The three fold circuits are distinct and so have distinct VKs. A fold of arity k cannot be presented as arity k', because its VK sits at a different `T_rec` leaf with `k` in the hashed leaf, and its structure differs.

This replaces both v2's `version` word `(arity << 8) | 2`, used for receiver digests, and the plan's "null slots".

### 4.2 Null slots (only if the review chooses a single `F_4` class)

The alternative to per-arity classes is one `F_4` class with tagged null slots, as in ZisK. It requires these rules:
- a guessed Boolean `n_i`;
- nulls are trailing: `n_i ≤ n_{i+1}`;
- at least two real children;
- a null child contributes the identity to every aggregate: `κ` 0, `bus` 0, `m` and `s` passed through, no interval;
- every assertion of the null child's verifier gadget is multiplied by `(1 − n_i)`.

The last rule is the "wide muxing" the plan warns about. It touches every equality of a full outer verifier. A single missed gate admits a forged child under `n_i = 1` while that child's NS is still consumed.

**Recommendation:** per-arity classes, with no nulls. This costs 2 extra VKs and removes a whole bug class.

The corpus keeps `N01`–`N03` for the null-slot variant and `G05` (arity relabel) for the per-arity variant (§7).

### 4.3 The v2 lemma for k children (also covers recsize's 4-ary v2 folds in M7)

Fold v2's binding argument (`rv64-m3-topo-binding.md`) generalises to k children.

**Lemma.** For a fixed class (k and every child's `n_outputs` are constants), the map from `(I_i, R_i, o_i)_{i ≤ k}` to the message
`domain ‖ ((k<<8)|2) ‖ for i: I_i[8] ‖ R_i[8] ‖ n_i ‖ o_i[4 n_i]`
is injective, because every field has a constant length.

So `Blake2s(m') = Blake2s(m)` implies `m' = m`, except with a collision (about 2^-128). Each child's identity, FIXED root and outputs then equal the receiver-trusted values, exactly as for k = 2.

**Arity binding.**
- `k` is in the version word.
- `k` is also in `classKey`, because the circuit differs.
- The receiver derives the tree plan itself (`Plan.initArity`).

A proof of arity k' at a k-position therefore fails both the authority check and the digest check. This is what the recsize stream relied on. M5 subsumes it: in-circuit membership replaces receiver-side digests.

---

## 5. Root statement and receiver checks (plan §4.4)

The final proof is the top fold, or, from M7, C2 wrapping it with `NS` passed through unchanged (see `rv64-m7-profiles.md` §5). The receiver:

1. Runs `derive-vk-tables(img, profile)` from the **pinned source commit**, once, and caches the result locally.
   - The derivation must be byte-reproducible.
   - It never reads a producer ArtifactStore.
   - Unknown profile ids are refused.
   - It yields `T_nat`, `T_rec` and the set of top-level VKs.
2. Verifies the final proof under a VK from that set. This is a fresh `Outer.verify` with the receiver's own authority.
3. Checks the public `NS`:
   - `T_nat = T_nat*` and `T_rec = T_rec*` (the derived values);
   - `img` and `stmt` match the request;
   - `seg_lo = 0`, `seg_hi = κ − 1` and `1 ≤ κ ≤ MAX_PROOFS`;
   - `m_in = IV` and `χ = H("rv64-m5-chi" ‖ stmt ‖ m_out)`;
   - `s_in = initial(stmt)` and `s_out = final(stmt)`, where the final state has the halt flag set and the output commitment equals `expected_output`;
   - **[R1]** `ctr_in = 1` for every family and `steps_in = 0`. `steps_out = E.total_steps ≤ E.max_total_steps`, and `E` is consistent with `s_out` (final pc and registers). For every family, the CPU call total equals the truth coverage, and Keccak sponge ids start after the Keccak-f total. This is today's `admit` tail, now on `ctr_out`;
   - **[R1]** `mass[M] < p` (already enforced at each node; re-checked here);
   - **[R1]** `bus[R] = 0` for each R separately, with no cross-relation cancellation (`Z09`). The INIT and TEARDOWN terms are **not** public receiver terms. They come from the memory-boundary leaves of §5.1, and `χ` used there is `NS.χ`, after the `χ` check above.
4. Instantiates the native error ledger (`Facts`) at the caps: `MAX_PROOFS` segments, all at the largest admitted rung. **[R1]** The (f, r) histogram is not in `NS`, and `κ` is producer-chosen, so neither may be used.

### 5.1 [R1] The RAM boundary needs its own leaf family

Today the receiver reads `cells.bin`, the touched set with its initial and terminal cells. With those it:
- checks sortedness, alignment, equal address sets and rights;
- checks initial values against the image (`UntrustedGlobalMemoryInitialization`);
- bounds terminal epochs by the segment count;
- adds the INIT and TEARDOWN fractions to the RAM closure.

The terminal memory is a **result of execution**, not a function of `stmt`. A root-only receiver therefore cannot compute "expected_bus(stmt)" as v0 of this note said. If an implementation took the teardown terms from the producer, the producer could pick terminal cells that balance any forged RAM trace and any claimed output (`Z10`).

M5 needs a **memory-boundary family** `mb`, whose leaves are canonical like every other (f, r):
- A leaf takes a chunk of touched cells. It proves sortedness against the previous chunk's last address, carried as a `ctr`-style counter.
- It proves each initial value against the image commitment in `img`/`stmt`, by Merkle opening or by a sorted merge with the image table.
- It contributes the INIT and TEARDOWN fractions to `bus[ram]` and their count to `mass[ram]`.
- It derives the output commitment from the output-region cells.
- It asserts `s_out = s_in`.

The receiver checks only the root. The case `X06` (coherent terminal-value flip) already exercises the M3 equivalent of this obligation.

The receiver does **not** need κ in advance. Segmentation is the producer's choice. Soundness only needs every segment to be counted once, which the interval chain guarantees.

The receiver also does not re-execute the block. That is the 77 s → ≤ 1.5 s step.

`--audit` keeps today's full-tree path for differential checks.

---

## 6. Soundness accounting (conditional, same model as r1/m3)

The assumptions are the same as the accepted profiles:
- the ethSTARK conjecture for every FRI layer;
- the ideal-hash Fiat–Shamir and Blake2s collision bounds;
- per-attempt 2^-128 per proof attempt;
- no whole-protocol certificate (`security_qualified` stays false).

The argument is by induction on node height. Let `Φ(NS)` be the statement in §0, restricted to `[seg_lo, seg_hi]` and to the chain from `m_in` to `m_out`.

- **Leaf.**
  - The outer STARK is sound, so the circuit is satisfied except with ε_out.
  - The in-circuit native verifier is complete and sound, so π_k is accepted by the native verifier under the guessed `V^nat`, except with ε_nat.
  - Membership plus the tagged leaf hash gives `V^nat = V^nat_{f,r}` of the table, except with a collision.
  - The transcript-seeding rule makes the native challenges a function of `V^nat`, the statement and χ, so the native soundness bound applies to the receiver's VK and statement.
  - Hence Φ holds.
- **Fold.**
  - Outer soundness gives a satisfying assignment.
  - Each child proof is accepted in-circuit under a `V_i ∈ T_rec` with outputs `NS_i`.
  - Every `V_i` in `T_rec` is an honest circuit derived from source.
  - By the induction hypothesis, Φ(NS_i) holds.
  - Adjacency and `m`/`s` linking concatenate the intervals.
  - Hence Φ(NS).
- **Root.** The receiver checks pin the interval to `[0, κ−1]`, the chain start to `IV`, and the states to the statement. χ is fixed by `m_out`, which contains every MAIN root, so χ was determined after all of them. The native soundness of the global relation then gives bus balance.

**[R1] Correction (depth).** v0 said the depth is constant. It is not: the tree shape is the producer's choice, and a comb-shaped tree of arity-2 folds has depth κ − 1 = 255. The `depth` field (§2) with `D_MAX` restores the constant-depth premise. Without that field the extraction caveat below does not hold.

**Union.** Over a tree with `κ ≤ 256` leaves and at most `κ − 1` folds, plus C1 and C2, the union runs over:
- at most 2κ + 1 outer attempts, each 2^-128 under its own profile;
- κ native attempts;
- the hash collisions, which are 2^-256-scaled terms with H ≤ 3·(2κ+2) + 1 scopes, as in the recsize note.

There is one **caveat**, and it is the standard one for PCD. A knowledge-soundness extractor for depth d recursion blows up with d. With the [R1] `depth ≤ D_MAX` check, the depth is constant: at most D_MAX fold levels (4 for a balanced 4-ary tree), plus C1, C2 and the leaf. The extraction loss is therefore a constant factor that the per-attempt accounting does not hide. This is the same caveat today's r1/m3 recursion carries implicitly. The note states it, and it does not change any profile.

**What breaks the claim (review checklist):**
1. any `S^nat` or `S_out` field guessed instead of constant;
2. a VK word mixed into the transcript after a challenge;
3. a variable-length hash input;
4. a node summary field not compared in step 4 of §4.1;
5. the membership index not range-checked to the table size;
6. `T_rec` derivation that is not reproducible;
7. `bus` or `χ` checked against producer-supplied expected values;
8. **[R1]** a non-CPU leaf that does not assert `s_out = s_in`;
9. **[R1]** any field of `stmt_k` left unconstrained, or any receiver check of today's `validateInventory` / `admit` / `checkClaimsClosure` without an in-circuit home (the table in §9);
10. **[R1]** a counter or mass added in M31 instead of as a range-checked integer, or a range check applied only to a node's outputs and not to its children;
11. **[R1]** OM31 coordinates not checked canonical (`< p`) before hashing or comparing;
12. **[R1]** Merkle leaf and internal-node hashes without distinct domain tags, or a variable path depth;
13. **[R1]** global relations summed into one `bus` (cross-relation cancellation).

---

## 7. Negative corpus specification

Ids are stable, and `scripts/rv64_m5_negative_corpus.py spec` prints the machine-readable list.

- "today" says whether the case runs against the M3 receiver: `m3` means runnable now, `m5` or `m7` means pending its format.
- **M5 rejecting check** names the constraint of this note that must reject it.
- Every case must be rejected by a fresh, cache-disabled, GPU-disabled receiver process. The only exceptions are the advisory-metadata cases (`K01`–`K03`). Those may be accepted only if the receiver's statement equals the control's.

| id | family | mutation | today | M5 rejecting check |
|---|---|---|---|---|
| C00 | control | unmodified | m3 (accept) | — |
| S01–S07 | segment chain | drop, duplicate or permute native segment files or leaf proofs (byte level) | m3 | bundle file hashes; outer authority; §4.1(5) |
| S08–S11 | segment chain | **coherent**: permute, drop or duplicate native segments **and** rewrite `bundle.json` (declarations, claims, file hashes) consistently | m3 | §3.2(4) chain, §4.1(5), §5(3) `seg_lo`/`seg_hi`/`χ` |
| K01–K03 | κ | producer metadata (`tree.json` leaf_count, `report.json` cpu_proofs, a tree node removed) | m3 (reject or same statement) | the receiver re-derives κ; it never reads it |
| K04 | κ | root `κ` ≠ `seg_hi + 1` | m5 | §5(3) |
| V01–V05 | child VK | cross-class fold; cross-block fold, leaf, root or native segment | m3 | §4.1(2) membership, §3.2(2), §5(3) `stmt` |
| G01 | rung | leaf of rung r' at a segment of rung r | m5 | §3.2(2) constant index, §3.2(1) |
| G02 | vk_fold / T_rec | root `T_rec` ≠ derived | m5 | §5(3) |
| G03 | child VK | fold child VK not in `T_rec` | m5 | §4.1(2) |
| G04 | native VK | non-member native VK with a valid-looking path | m5 | §3.2(2) |
| G05 | arity | `F_3` proof at an `F_4` position, or arity field relabelled | m5 | §4.1 class constant, `T_rec` leaf covers k |
| R01–R09 | native root / bytes | bit flips in native proofs (byte level and **coherent**, with rehashed bundle), root, leaf, truncation | m3 | native verify in-circuit; outer verify |
| X01–X04 | χ | stage-one / cells flips (byte level and coherent) | m3 | §3.3 |
| X05 | χ | root χ ≠ H(stmt ‖ m_out) | m5 | §5(3) |
| T01 | statement | receiver's expected output changed | m3 | §5(3) `s_out` |
| B01 | bus | one segment's claim shifted, chain re-hashed | m5 | §5(3) `bus` |
| N01–N03 | null slot | real slot re-tagged null; null with payload; non-trailing null | m5 (null variant only) | §4.2 |
| P01 | profile | receiver selects another native profile | m3 | profile identity in transcript |
| P02 | profile | receiver selects another outer profile | m5 (needs recsize) | outer domain in identity, wire and transcript |
| X06 | χ / RAM teardown | **coherent** terminal-cell value flip in `cells.bin`, with rehashed bundle | m3 | §5.1 memory-boundary leaf; today the RAM closure |
| Z01–Z12 | review 1 (§9) | truth leaf state jump; free `stmt_k`; family counter gap; mass wrap; segment index wrap; depth; non-canonical word; Merkle node as leaf; cross-relation cancellation; forged teardown; absent-relation claim; boundary not in AIR | m5 | §9 F1–F12 |
| M01–M04 | outer GKR / compress | GKR round or claim tamper; C2 under C1 profile; compress over another root | m7 | `rv64-m7-profiles.md` §4–5 |

### Today's receiver (M3 integrate build `7b823d49…`, source `d6f7b2b5e`) [M]

Receipts: `vectors/reports/rv64-m4-20261104/profiles/{26235156,24628607}-negative-corpus.json`.

**On both dev blocks, 35 of 35 runnable cases pass.** The control is accepted with the original statement, and nothing is accepted that should be rejected.

`K02` (`report.json` cpu_proofs) is **accepted with an identical statement**. The receiver re-derives the count and does not read that field, which is the correct behaviour.

What today's receiver relies on, and what M5 must replace:
- **Byte-level native mutations** stop at the `bundle.json` file-hash check (`WideBundleFileChanged`). The coherent variants reach the semantic checks:
  - permuted, dropped or duplicated segments hit `InvalidServicesWireRequest` or `InvalidServicesWireBoundary`;
  - truth shards hit `InvalidCombinedTruthSpan`;
  - native bit flips hit `RootMismatch` or `GlobalGkrPhysicalRootMismatch`;
  - stage-one and cells flips hit `CircuitCheckFailure` or `UntrustedGlobalMemoryInitialization`.

  These checks run in the receiver, on the native proofs and the bundle. M5's root-only receiver no longer reads either, so §3 and §4 move every one of them into leaves and folds: the chain, the boundary states and membership.
- **Outer-proof mutations** are caught by authority, digest and root checks after the receiver has re-derived the tree: `Om31CircuitWireAuthority`, `CurrentOm31OutputDigest`, `RootMismatch`, `RecursiveReceiverArtifactMismatch`. Root-proof tampering (`R04`, `R05`, `V04`) is only detected at the end, after about 48 s on 26235156, or by a size cap (`FileTooBig` on 24628607). In M5 the root check comes **first**.

**Exit gate of M5** (plan §5): every `m3` and `m5` case passes against the M5 root-only receiver, and `--audit` agrees with root-only on both dev blocks.

---

## 8. Owners and hand-offs

| item | owner |
|---|---|
| `S_out` padding, leaf and fold circuits, `NS`, membership gadget, `derive-vk-tables` | canon-vk |
| rungs, constant roster, the native χ chain (§3.3, a native format change) | canon-native |
| corpus `m5` cases: implement the mutations once the format exists | profiles (spec), canon-vk (hooks) |
| review of this note | integrate, before any M5 merge |

---

## 9. Adversarial review 1 (2026-11-04)

The reviewer worked from today's receiver code, not from the plan. For each check the M3 receiver performs, the question was where that check lives once the receiver reads only the root. Where v0 had no home for a check, that is a finding. The fixes are made inline above and marked [R1].

### 9.1 Findings

| id | severity | finding | where fixed |
|---|---|---|---|
| F1 | **blocking** | `NS` had no field for any **cross-segment admission** check of today's receiver. Missing: the per-family call counters and truth-id spans (`firstIds`, `InvalidCombinedTruthSpan`, sponge ids after Keccak-f), the cumulative step counter (`first_step`, `GlobalExecutionCoverageMismatch`), and the LogUp **characteristic bounds** (`GlobalRamCharacteristicBound`, `CombinedLookupMassExceeded`, `CombinedRangeMassExceeded`). `stmt_k` was guessed and unconstrained. A producer could skip or repeat truth ids, or push a relation's multiplicity mass past p so that LogUp multiplicities wrap. Per-leaf caps do not save this: 256 × 2^24 × 2 > p. | §2 `mass`/`ctr`/`steps`/`E`, §3.2(5,7), §4.1(5,6), §5(3) |
| F2 | **blocking** | `expected_bus(stmt)` cannot include RAM TEARDOWN. The terminal memory is an execution result, and today the receiver reads it from `cells.bin`. A root-only receiver either lacks it or takes it from the producer, and the latter lets the producer balance a forged RAM trace and choose the output. The same applies to the touched-set checks (`UntrustedGlobalMemoryInitialization`, `GlobalTouchedSetMismatch`, `InvalidGlobalMemoryTerminal`). | §5.1 memory-boundary family; `X06` (runnable today), `Z10` |
| F3 | **blocking** | Non-CPU leaves had no state rule. The chain enforces only continuity, so a truth-shard leaf with `s_out ≠ s_in` can move the machine to any halted state. | §3.2(5) state rule; `Z01` |
| F4 | high | One combined `bus`. Today the ram, kio and wire relations close separately, and claims of absent relations must be zero (`checkClaimsClosure`). | §2 `bus[R]`, §3.2(5), §5(3); `Z09`, `Z11` |
| F5 | high | The tree depth is not bounded. Shape is free, so a comb gives depth κ − 1, and the PCD caveat's "constant depth 4" was false. | §2 `depth`, §4.1(6), §6 correction; `Z06` |
| F6 | medium | Range checks. "A 16-bit range check on both" does not prove `< MAX_PROOFS`. It applied only to fold outputs, so interior children and leaves could carry `k = p − 1` and wrap `seg_hi + 1` to 0. Counters and masses were summed in M31. | §2 typing rule, §3.2(5), §4.1(5); `Z04`, `Z05` |
| F7 | medium | The boundary was mixed but not constrained. Mixing `s_in`/`s_out` into the transcript does not bind them to the trace; the native AIR must use them as public boundary values. v0's step 1 did not even list them. | §3.2(1); `Z12` |
| F8 | medium | Non-canonical OM31 words. `χ` and `bus` are carried as u32 limbs, and `w` and `w + p` alias the same M31 value. Today `NoncanonicalGlobalGkrCoordinate` rejects this. | §2 typing rule; `Z07` |
| F9 | medium | The global `Expected` words (`total_steps`, `max_total_steps`, final pc/registers) are mixed into **every** CPU transcript by `beginMaterials`. In M5 they are producer values: they need an agreement field and a root consistency check. | §2 `E`, §4.1(4), §5(3) |
| F10 | low | Merkle membership did not state leaf/node domain separation or a fixed depth (`T_nat`, `T_rec`). | checklist 12; `Z08` |
| F11 | low | Receiver step 4 used an (f, r) histogram that is not in `NS`. | §5(4) |
| F12 | low | `χ` used in `bus` closure must be `NS.χ` taken after the `χ = H(stmt ‖ m_out)` check. The order is now stated. | §5(3) |

No issue was found with these parts:
- the canonical-leaf constants;
- `T_rec` as a public input (the PCD self-VK break);
- per-arity fold classes over null slots;
- the interval chain itself;
- χ excluding `c_k`;
- the k-ary v2 lemma.

The `S_out` argument (fold-class explosion without one uniform shape) checks out: Σ_{k=2..4} 12^k = 22,896.

### 9.2 Today's receiver checks and their M5 home

| today (file: error) | M5 home |
|---|---|
| `global_execution/protocol.zig`: `InvalidGlobalExecutionEpoch` | §3.2(7): epoch = CPU ordinal + 1, from `ctr` |
| `UntrustedGlobalGenesis`, `GlobalCpuBoundaryMismatch` | §5(3) `s_in`; §4.1(5) continuity; F3 rule |
| `ExecutionPrefixBudgetExceeded`, `InvalidExecutionMemoryCount`, `GlobalMemoryCapacity`, `GlobalArithmeticCapacity` | §3.2(7) |
| `GlobalExecutionCoverageMismatch`, `GlobalExecutionBudgetExceeded` | `steps` chain, §5(3) |
| `RepeatedGlobalInitialization`, `PrematureGlobalTeardown`, `GlobalTouchedSetMismatch`, `UntrustedGlobalMemoryInitialization`, `InvalidGlobalMemoryTerminal` | §5.1 `mb` family |
| `GlobalRamCharacteristicBound` | `mass[ram]`, §4.1(6) |
| `services/protocol.zig`: `InvalidCombinedTruthSpan`, `firstIds` | `ctr` chain, §3.2(7), §5(3) |
| `CombinedLookupMassExceeded`, `CombinedRangeMassExceeded` | per-proof part: §3.2(7); cross-proof part: `mass` |
| `InvalidCombinedBridgePresence`, `InvalidCombinedServiceCount`, `InvalidServicesWireRequest` | §3.2(7) |
| `MixedWord16PcsSuites` | the suite is a field of `S^nat` (constant), and `T_nat` holds one suite |
| `gkr_local/manifest.zig`: `UnclosedGlobalGkr{Ram,Kio,Wire}`, `NonzeroAbsentGlobalGkrClaim`, `NoncanonicalGlobalGkrCoordinate` | `bus[R]`, §3.2(5), typing rule |
| `GlobalGkrPhysicalRootMismatch` | §3.2(4): `ρ_k` is the leaf's own verified root, in the chain |

**Exit criterion added to M5:** canon-vk keeps this table complete. Any new receiver-side check added before M5 merges gets a row here first.

### 9.3 Must hold before M5 code merges

1. A second reviewer signs §9 and the [R1] amendments.
2. Every row of §9.2 is implemented in-circuit, with a test naming the row.
3. Each `Z` case and each `m5` case has a hook and is rejected by the M5 root-only receiver. `X06` and every `m3` case stay rejected.
4. canon-native's χ-chain version also defines the `mb` family and `stmt_k` encoding, with a byte-level test that the native prover and the in-circuit chain agree.
5. The `mass` bounds are re-derived from the code's mass formulas (`admit*`), not copied from this note.
