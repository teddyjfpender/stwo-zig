# B8 RISC-V circuit wrapper and homogeneous fold

Status: design from saved proofs/reports and local source, 2026-10-30. The live
139,214,856-instruction run is untouched. No prover, test, build, GPU, or guest
execution was run for this analysis. The proposed wrapper is not qualified yet.

Source implementation is staged under `src/integrations/circuit_cpu/riscv_recursion/`
and the new `riscv_circuit_recursion_v1.zig` entry point. It has **not been
compiled or tested**. The additive circuit exports select no default route.

### Deferred hostile-proof gate that isolates typed AIR enforcement

Post-expansion claim/root corruptions are useful transport controls, but their
failure alone does not establish AIR enforcement: they can break the transcript
or PCS even when typed composition is omitted. The staged
`invalid_air_fixture_v1.zig` supplies the stronger control:

1. Reconstruct the canonical B8 fixed tree from independently admitted metadata.
   An explicit qualification-only lease retains this tree; ordinary authority
   construction retains no polynomial tree and the lease is not an admission
   receipt or an alternative expected-key selector.
2. Commit constant-2 MAIN columns, then independently re-admit metadata with
   that actual nominated MAIN root. Replay the exact native parent prefix,
   both first roots, and all 47 challenge pairs.
3. Include all 25 physical claims. Set their sum to minus the exact public
   supply under those challenges and require the canonical admission's header
   closure check to pass. Commit constant-3 interaction columns and a zero
   quotient, preserving the exact claim/root/alpha/OODS ordering.
4. Invoke the ordinary PCS `proveValues` constructor directly. It makes honest
   sampled evaluations, DEEP answers, Merkle openings, PoW26 and q70 FRI from
   those low-degree polynomials; it does not request a native AIR verdict.
5. Encode and decode real native-parent bytes, then require successful complete
   PCS-only expansion through the wrapper's actual `Material.fromBytes` path.
   Require the canonical equation DAG's AIR/OODS residual to be nonzero and its
   separate physical-claim/public-supply residual to be zero.
6. Feed that freshly expanded material to the **actual complete `leaf_wrap.build`**
   with eager circuit equalities enabled. Require the error specifically at
   `Lower.constrain`, labelled `RiscCircuitTypedCompositionRejected`. No mode
   that skips typed AIR is added to the wrapper.

The separate opt-in test is named
`RISC valid PCS and public supply invalid typed AIR rejected by actual complete leaf q70`
in `qualification_v1.zig`. A wrapper with its typed-composition seam stubbed out
would accept this fixture's PCS and fail that expected-error assertion. The host
DAG residual is only a diagnosis of fixture invalidity; rejection must come
from the real circuit-builder constraints. One aggregate-invalid fixture does
not independently test omission of each individual AIR; all-23 inclusion still
comes from the shared canonical compiler and its authenticated roster.

**Implemented as source only:** constructor, exact header compensation, raw
PCS proof path, positive PCS control, residual diagnosis and deployed-builder
rejection assertion. **Not yet observed:** compilation, a generated hostile
artifact, successful PCS verification or actual circuit rejection. No code
generation, tests or proving were run during the full-block CPU hold.

## Source-only cost sanity: builtin G, arithmetic fusion, providers

The existing circuit helper does not bit-decompose a G into generic arithmetic.
`builder/blake3_reuse_v1.compress` calls the actual
`builder/blake.blakeGGate` once for each of eight G calls in seven rounds. That
method appends one `BlakeGGate` AIR row with four consecutive output variables.
The same compression appends sixteen `TripleXor` rows for its two output halves.
There is no ten-round Blake2s compression substitution: the seven-round message
permutation comes from the canonical BLAKE3 compression module.

| Work item | NativeParent fused AIR | Existing circuit route | Raw base cells before padding/providers |
|---|---|---|---:|
| One G | 82 MAIN + 80 I + 16 fixed | 52 MAIN + 52 I + 11 fixed | 178 → 115 |
| Full BLAKE3 compression in circuit | 56 G plus native output handling | 56 G + 16 TripleXor; each XOR has 20 MAIN + 24 I + 5 fixed | Circuit 7,224 |
| One unrestricted QM31 FMA | one 17 MAIN + 8 I + 10 fixed row | one QM31 multiplication + one addition; each 12 MAIN + 8 I + 8 fixed | 35 → 56 |
| Four products plus accumulator | one 41 MAIN + 20 I + 13 fixed row | four QM31 multiplications + four additions | 74 → 224 |

These circuit arithmetic operations are **QM31 gates**, not four-limb scalar
M31 emulation. Nevertheless, the first straightforward DAG lowering loses
existing dot4/FMA contraction. Generic compilation preserves semantic authority;
it does not automatically preserve a good proving layout. The counts above
exclude variable/constant finalization, equality gates, use accounting and any
common-expression sharing, and do not compare complete compression workloads.

The G builtin also makes real lookup demands. Per G the circuit component has
six Gate-relation input uses and sixteen bitwise-provider uses (2 each of XOR12,
XOR4, XOR7, XOR8_B and XOR9, plus 6 XOR8). A TripleXor adds three Gate uses and
eight XOR8 uses. Thus one full compression has 384 Gate-input uses and 1,024
bitwise-provider uses before output consumers and finalization. The circuit's
fixed XOR12 provider has domain log 20, 16 MAIN and 32 I columns; its fixed
tuple columns add further area. Its cost cannot be dismissed because the
request's G component is narrower. All eleven AIRs and their tables remain in
the wrapper proof.

Further structural overheads require the first full source/witness census:

- Each guessed M31/QM31 value gains a finalization arithmetic row; each guessed
  U16 gains an M31ToU32 row. A guessed U32 has two U16 guesses plus packing work.
- Merkle conditional swaps use the existing four-operation `condFlip` on every
  digest word. The first PCS kernel expands raw paths and does not preserve the
  NativeParent's existing two-level path sharing.
- Challenge rejection, canonical QM31-to-U32 conversion, PoW bits and public
  byte decomposition add gates beyond hash compression.
- One G component avoids four separately padded NativeParent G shards, but its
  next-power-of-two domain can be larger. Fixed tables, maximum lifting height,
  composition/LDE blowup and all provider rows determine actual area and peak.

Therefore 1,657 → 319 physical child columns is an opening-width inventory,
**not an acceleration prediction**. A complete wrapped proof and homogeneous
fold must measure total rows × columns, lookup providers, LDE, memory and fresh
receiving before any speed claim. The existing
`keccak-tiled-problem-match-20261029.md` already demonstrates why width-only
models fail: its one-lane/five-lane caller prototypes reduce OODS samples while
raising raw core area by 1.83×/1.97×.

## Qualification update after baseline observation stopped

The focused standalone ReleaseSafe build now succeeds. The installed binary
`/tmp/stwo-riscv-circuit-qual-v1/bin/riscv-circuit-recursion-v1-tests` ran with
all genuine-proof flags unset: **17 passed, 3 skipped, 0 failed**. The passing
controls include actual circuit DAG inverse/zero anchors, boundary gap/overlap,
CPU/snapshot continuity, interior policies, role/security operands, metadata
cycles and thin-catalog structure. Log:
`/tmp/riscv-circuit-recursion-v1-structural.log`.

The valid-PCS/invalid-AIR q70 control now passes on the same frozen binary:
18 passed, 2 skipped, 0 failed. It generated honest PCS/PoW26/q70 under the
canonical fixed key and exact transcript, closed all 25 physical claims against
public supply, observed a nonzero canonical AIR residual, and required rejection
by the actual leaf builder at its typed-composition seam. Functional gate cost:
22.88 s wall, 9,269,968,896 B maximum RSS, zero swaps. Evidence:
`campaign/qualification/riscv-circuit-valid-pcs-invalid-air-q70-v1/`. Generated
hostile proof bytes were temporary and are not retained. Positive full leaf
and depth-two fold proof gates remain unrun. Earlier source-only descriptions below
record the pre-hold implementation stage; the current implementation is compiled
and structurally checked, but complete positive leaf and depth-two fold proof acceptance remain unqualified. No build/test/proof ran
while the baseline CPU hold was active.

## Evidence and the work it identifies

| Saved closed window root | Actual 890-Keccak / 131,072 instructions | Native 16M / two 8M cohorts |
|---|---:|---:|
| Original bodies consumed once | Mixed14 + Bridge + Compact7 | 2 Local11 + Bridge + Compact7 |
| Whole saved-original-to-root request | 77.106056 s | 90.612453 s |
| Parent proving | 40.881663 s | 44.571564 s |
| Fixed compilation / commitment | 4.595298 / 4.983500 s | 5.367838 / 5.076568 s |
| Witness / plan | 12.934948 / 3.667221 s | 12.245086 / 4.671879 s |
| Fresh receiving | 8.410251 s | 12.377554 s |
| Retained verifier rows/columns | 5,900,858,304 B | 7,358,735,608 B |
| Charged peak | 15,856,936,832 B | 18,287,402,246 B |
| Root bytes | 1,028,985 | 1,030,765 |

These are separate workloads, not a throughput comparison. The 890 run was a
functional, potentially contended diagnostic. Its historical
`source_preparation.whole_ns` includes recursive production; the accompanying
`timing-boundary-notes.json` corrects that interpretation without rewriting the
report. The native 16M report is the earlier nonterminal skip-one window.
Neither timing is a prediction for the full retained block.

Source reports:

- `vectors/reports/riscv-cpu-architecture-20261029/keccak-131072-mixed-wide-closed-root-v1/`
- `vectors/reports/riscv-cpu-architecture-20261029/native-16777216-direct-clock-v3-wide-2x8388608-sparse-compact-profile4-single-dag-root/`

The saved fusion logs report 1,112,606 arithmetic rows for the 890 window,
including 491,947 opening/dot4 groups and 192,894 FMA groups. The Mixed verifier
alone accounts for 886,911 of these rows. The 16M verifier machines total
873,072 arithmetic rows, 110,725 dot4 groups and 307,000 FMA groups. These are
existing emitted arithmetic counters, not a complete per-component memory or
G-row census; neither report records the latter. A new census must wait until
the live run finishes.

A bounded read-only parser inspected the already qualified postcard bytes
(using `src/interop/postcard.zig` field order; it did not verify proofs or execute
any witness). Its inventories are:

| Proof | Physical columns | OODS QM31 samples | Queried M31 cells |
|---|---:|---:|---:|
| Actual 890 Mixed original | 8,139 | 21,439 | 569,730 |
| 16M first Local original | 1,396 | 2,018 | 97,720 |
| 16M second Local original | 1,274 | 1,853 | 89,180 |
| Either resulting NativeParent root | 1,657 | 1,757 | 115,990 |

The Mixed original's ordered tree widths are
`[94,515,23,1,0,101,2317,492,44,8,4,24,4176,324,16]`.
Caller MAIN 2,317 and caller arithmetic/RAM interaction 4,176 alone contribute
6,493 columns, **79.8%** of its total. Tree 13 separately contains 324 caller
basic/program interaction columns. This does not establish which arithmetic
columns can be removed: the per-component caller descriptors and actual
multiplicities must be audited before pruning any inactive recipe.

Both NativeParent root proofs have exactly
`[316 fixed,669 main,664 interaction,8 composition]` columns and 22 FRI layers.
Their queried-value sections occupy 550,376 and 548,643 serialized bytes;
trace sibling sections 144,265 and 145,161 B; FRI sections 298,771 and 301,466 B.
For the 890 root, 8,625 additional sibling hashes occur in FRI, beyond 4,508
trace siblings. Serialized sibling counts are compressed proof witnesses, not
counts of all hashes executed after path expansion.

For 70 raw queries, hashing these four NativeParent leaf payloads alone costs
7,840 BLAKE3 compressions / 439,040 G calls before paths, FRI, or transcript.
This follows from the actual widths and native 28-byte leaf prefix. A leaf with
W words costs `ceil(W/16) + ceil(W/256)-1` compressions when multi-chunk, with
one compression minimum. Every compression performs 56 G calls. The Mixed
original's trace leaves alone require 2,156,000 G calls; its caller MAIN and
large interaction trees account for 1,697,360 (78.7%). This is a structural
raw-query count, not an additional execution measurement.

## The concrete short route

Wrap each **existing closed NativeParent window root** once, then reduce the
resulting circuit proofs. This preserves today's qualified original/window
path and immediately gives a real RISC-V entry into homogeneous circuit folds.
It does not remove the existing 77–91 s window-root stage; the extra leaf wrap
must earn its cost through cheaper higher folds. The later direct-original
route below removes that normalization stage.

The wrapper input is a bounded `B3NPART4` byte proof and independently admitted
window metadata. The following theorem is indivisible:

1. Exact B8 Join or B8 window-fold transcript, all 47 relation pairs, all **25
   private physical claims**, and the protocol-specific public-supply closure.
2. All **23 NativeParent AIR components** (including four physical G shards)
   and two lookup-table evaluators, through the existing authenticated equation
   compiler, not hand-transcribed equations.
3. Composition challenge, composition commitment, OODS draw/point, exact
   ordered samples, quotient denominators and split-composition equality.
4. All four native unlifted BLAKE3 trees, DEEP responses, PoW26, raw query order,
   every physical opening and complete fold-one/constant-terminal FRI.
5. Output binding to the independently admitted key, public-input identity,
   closed-window statement, ELF/security and boundary/scope obligations.

The resulting **outer proof uses the existing 11-component circuit AIR**.
The 23 native components are verifier arithmetic inside that circuit; they do
not become 11 components by relabeling.

The exact existing authorities are
`air/block_v5_open_parent_composition_v2.zig`,
`block_v8_window_root_{admission,profile,protocol,statement}_v1.zig`, and the
NativeParent roster/component definitions. Translate the authenticated
composition graph into circuit QM31 operations, preserving constants, shared
nodes, inverse constraints and zero outputs. Dynamic `.packed_public_input`
ports must remain genuine inputs. A CPU capture may supply optional debug
comparison values, but must not be an input to acceptance or key selection.

The qualified circuit PCS seam is
`builder/blake3_pcs_reuse_v1.verifyAfterOods`. `verifyStandalone` has the wrong
prelude for B8 roots and must not be used as if it verified them. The wrapper
must absorb its exact prefix, roots 0/1, draw 47 pairs, absorb 25 claims, root 2,
draw composition alpha, absorb root 3 and draw OODS **in native order**, then
call the seam using the same root/sample/query wires. Native config absorption
inside the B8 admission is preserved, not added a second time.

### Public port identity, not matching witness values

A new `ResolvedPublicPorts` inventory must retain the original B8 public-wire
schedule and resolve each term to a canonical field identity in the prefix:

- raw word -> one range-constrained U32 wire and constrained four byte limbs;
- felt word -> one canonical M31 coordinate of a QM31 field, then its bytes;
- public QM31 input -> the same four canonical coordinate wires;
- first root -> the same digest-word wires used by transcript and PCS.

The circuit prefix replay and public-supply denominators reuse these exact
variables. Searching the concrete prefix for an equal numeric value is unsafe
(especially zero) and is forbidden. Independently guessing a supply tuple and
merely checking a host-computed equality is also forbidden. Today's pinned
admission intentionally erases these references; the new authority compiler
must retain structural references while it independently reconstructs the
original Join/fold admission.

### Proposed new namespace and interfaces

No existing production entry point, Cairo registry, or proof identity changes.

- `circuit/statements/riscv_native_parent_v1.zig`: complete theorem builder.
- `circuit/builder/riscv_composition_lowering_v1.zig`: authenticated DAG ->
  circuit gates; input references are resolved by kind, never by value.
- `integrations/circuit_cpu/riscv_recursion/authority_v1.zig`: independently
  reconstructs child key/statement from current typed metadata and checkpoints;
  returns geometry, exact frame schema and resolved public-port references.
- `proof_material_v1.zig`: bounded raw-byte parsing and path expansion into
  **untrusted witness material**; no `Verified`/capture verdict is required.
- `leaf_wrap_v1.zig`: topology build/cache, value replay, circuit satisfaction,
  CPU circuit proving and fresh verification, then `CircuitSerialize` output.
- `registry_v1.zig`: explicit opt-in RISC wrapper profile and authorized
  preprocessed root/circuit hash. Existing Cairo hashes authorize nothing here.
- `fold_statement_v1.zig`: CLOSED_FOLD encoding and shared circuit boundary
  constraints over the exact hashed child statement words.
- `circuit_fold_v1.zig`: actual two-child circuit STARK verification, NoValue
  parent key derivation, backend proving and fresh serialized/full receiving.
- `fold_wire_v1.zig`: bounded structural catalog, ordered source references and
  pointer-indirected fold metadata; no transported key or successful receipt.

Conceptual inputs are `Authority{native_key_id,public_input_id,fixed_root,
geometry,frame_schema,term_refs,window_span,scope}` and
`Material{roots,claims,samples,queried_cells,paths,nonce,fri}`. Request-dependent
keys, roots and prefix values are public wires/output bindings. Geometry,
semantic equation programs, frame sizes, port schedules and admitted retry
profile define topology. Instance-specific authority and large receiving data
remain explicit: this work does **not** prove source-key derivation or make the
current checkpoint-dependent verifier universal.

The production topology/value split must check exact variable/gate counts,
preprocessed root and circuit hash. A cache key is an optimization, never an
admission authority. A first finite profile can fail closed on unsupported
sampler retries; claiming all native-proof coverage requires a qualified retry
and draw-counter grammar. The current standalone PCS tests accept one sampler
attempt and reject unsupported cases; bounded retries are not already solved.

## The actual homogeneous RISC fold

The existing circuit `multiverifier` verifies children and hashes ordered
`[circuit_hash, output_digest]` pairs. That alone is not a RISC window merge.
The new fold circuit must open each child output's typed preimage, recompute
its digest using the same encoding as the leaf, constrain equality with the
**verified proof output**, and check:

- authorized RISC leaf/fold circuit key (not any satisfiable circuit);
- same ELF, security, VM/precompile semantics and authority-catalog identity;
- exact integer first-cycle/count adjacency and summed coverage;
- initial/final CPU continuity and current snapshot-ID continuity;
- no initial or terminal boundary policy in an interior position;
- scope closure: `CLOSED` children yield `CLOSED`; `VM_OPEN`, `BRIDGE`,
  `RAM_SHARD`, `INIT`, `TERM` obligations cannot be hidden by hashing.

It emits the canonical merged statement digest. Preserve two-child odd carry
without duplication; qualify a fold proof as the child of another fold.
The staged implementation uses the established internal Blake2sM31 circuit
proof protocol, explicitly q70/PoW26/fold1, for leaves and all fold levels.
Its final artifact is CircuitSerialize and is independently received by the
RISC full receiver; a separate production packed/plain-hash root profile is
not implemented and `.root` backend output fails closed. This is a
change of proof backend **after a genuine BLAKE3 verifier circuit**, not a
reinterpretation of original BLAKE3 proof bytes as Cairo/Blake2s proofs.

The staged keys are instance-specific. Each expected child entry is rebuilt
from current RISC metadata, canonical circuit equations and checkpoint pins;
ordered child roles, key identities, preprocessed roots, circuit hashes and
statement digests enter the parent's fixed statement and NoValue key. The
actual child verifier consumes those root wires and the digest of the same
statement words used by adjacency gates. There is no free supplied-VK hash or
Cairo registry entry. This is direct independent admission, not a proved
snapshot-to-key derivation or universal authenticated-registry membership.
A future finite reusable registry requires request-dependent values to become
public wires and key-derivation/initial/global/terminal obligations to have a
proved source. Generic Cairo packed-output hashing is not that proof.

### Structural fold source now staged, still unqualified

`circuit_fold_v1.Metadata` is `.leaf(Upper.Tree)` or
`.pair(*const [2]Metadata)`. Depth/total-visit checks happen before recursive
rendering and include nested native Upper.Tree metadata; cycles fail through
that finite budget. A child may itself be a circuit fold. Only detached fixed
layout entries with static IDs, exact config, registry/key identifiers and
typed certificate values survive child key compilation. Producer keys and
captures are never inputs to high-level receiving.

Each parent build calls the existing `CircuitStatement.init`, `proof.guess`
and complete `stark_verifier.verify` for both children. It recomputes each
typed certificate's BLAKE3 digest and uses that same wire array as the child
proof's output claim. The parent descriptor's root/hash/digest words are tied
to the actual verifier operands. Shared boundary gates enforce ELF/security,
positive bounded cycles, integer adjacency/summed coverage, both 33-word CPU
boundaries, snapshot IDs and only exterior initial/terminal policy ports.
All start/count/end values are below 2^30; the possible pre-bound pair sum is
below M31, excluding modular aliases. CPU words remain two-U16 U32 values.

`certificate.leaves` counts **circuit-wrapper leaves**, not execution windows:
one window-role leaf can wrap an already aggregated native Upper.Tree. Depth
and wrapper-leaf counts are bound into parent statements. Odd carry returns
the identical borrowed proof/metadata without padding or a new proof.

The new thin `R8CFMD01` catalog contains only source ordinals and ordered pair
edges. It rejects reused/dropped sources, reused child nodes, forward/cyclic
edges, noncanonical root/count framing and depth above 16. A fresh receiver
decodes it with separately supplied source statements/checkpoints, recompiles
all expected RISC entries and checks the serialized outer proof. Full receiving
also independently checks source boundary-policy selections and the loader/
input-derived first state plus the terminal output policy.

Dormant tests are staged in `fold_qualification_v1.zig`: three actual saved
native roots → three circuit wrappers → first pair → odd carry → second pair,
so a fold proof is itself a child at depth two. Producer keys/material/child
proof owners are destroyed before a new backend authority and FullPolicy load,
thin-catalog decode and fresh full receiver. Separate negative gates exercise
the actual shared boundary constraints for gaps, overlaps, CPU/snapshot errors,
interior policies, unclosed roles and weakened security; a genuine proof with
changed independently reconstructed key must reject. Resource/cycle and thin
catalog controls are separate from proof tests.

**Implemented source boundary:** actual child-verifier calls, typed circuit
merge, NoValue parent key, CPU/backend-neutral proof serialization, fresh
byte/catalog/full receivers, bounded odd carry and dormant depth-two/hostile
gates. **Not observed:** compilation, successful native→circuit wrapping,
depth-one/depth-two circuit fold proofs, fresh receiver acceptance or any test
result. Memory fit, circuit-verifier variable-use finalization and proof shape
compatibility remain qualification questions. No speed or universal-VK claim
is made. The live native-parent full-block driver remains unchanged.

### Focused deferred qualification order

Do not execute while the full-block CPU hold is active. From the lab checkout,
one focused build installs a single binary without running it:

```sh
python3 scripts/zig_serial_build.py --lock /tmp/stwo-zig-build.lock \
  --build-file build_riscv_circuit_recursion_v1.zig compile \
  -Doptimize=ReleaseSafe -j1 --prefix /tmp/stwo-riscv-circuit-qual-v1
```

The dedicated build imports the actual circuit/Cairo/core/backend/wire packages,
shares injected Cairo interop module instances with the recursion wire package,
and reuses the pinned existing circuit CPU composition AOT generator. The older
protocol-test command's selected-package list does not include these circuit
packages. The new build itself is not yet compiled, so package/build-root/AOT
wiring is the first integration check, not a claimed working invocation.

Run the installed binary from the repository root in this order; unset the
other genuine-gate flags at each stage:

```sh
/tmp/stwo-riscv-circuit-qual-v1/bin/riscv-circuit-recursion-v1-tests
STWO_RISCV_CIRCUIT_AIR_INVALID_Q70=1 /tmp/stwo-riscv-circuit-qual-v1/bin/riscv-circuit-recursion-v1-tests
STWO_RISCV_NATIVE_PARENT_CIRCUIT_Q70=1 /tmp/stwo-riscv-circuit-qual-v1/bin/riscv-circuit-recursion-v1-tests
STWO_RISCV_CIRCUIT_FOLD_Q70=1 /tmp/stwo-riscv-circuit-qual-v1/bin/riscv-circuit-recursion-v1-tests
```

The first stage covers actual DAG lowering and boundary/role/security/catalog
constraints without a proof. The next generates valid PCS with false AIR and
requires real leaf-builder rejection. Only then prove the complete leaf and
freshly receive its bytes. The last stage uses three already saved native roots,
wraps them, proves a fold-parent as a child of another fold, preserves odd carry,
and invokes `FoldWire.verifyFullBytes` after destroying producer owners. That
entry point independently loads SHA-pinned canonical evaluators and derives a
new FullPolicy; no serialized backend or VK selects its authority.

All heavy gates use a 48 GiB charged budget and four CPU workers. They are
functional qualification, not matched performance comparisons. No invocation
above has run. Compilation, finalization compatibility, byte-proof compatibility,
memory fit and actual accepted/rejected results remain outstanding.

## Structural work elimination and limits

The existing circuit AIR has `[45 fixed,114 main,152 interaction,8 composition]`
columns: 319 total, versus NativeParent's 1,657. This is **5.19x less physical
leaf width** for a proof subsequently folded, not a measured speedup or a claim
that its rows are free. Its G gate has 52 main/52 interaction/11 fixed columns;
the current native G call has 82/80/16. Per-row cell reduction is 35.4%, before
lookup-table and padding costs. Four native G shards themselves repeat 712
physical columns. Combining/sharding differently would change memory/domain
costs and needs a new explicit profile; current shards solved real padding/OOM.

Do not regress existing work reductions. Native query hashing already shares
a two-level Merkle frontier. The new circuit kernel currently verifies raw
openings independently; a direct port could hash **more** paths. Any additional
sharing must constrain common `(tree,level,index)` identities and all query
coverage, not trust a host dedup list. Ordinary compressed sibling byte counts
are not the executed hash count.

The native route also fuses FMA and opening/dot4 rows. A naive translation into
separate circuit add/mul/div gates can expand this work substantially. The
qualified circuit PCS helper currently derives DEEP by individual responses;
reuse common denominators/beta powers and preserve algebraic sharing before
claiming a faster wrapper. New specialized gates would require a changed
circuit AIR/table/registry and fresh recursive verification qualification.

A direct `RiscWindowCircuit` is the second step: consume Local11/Mixed14,
Bridge and Compact7 originals directly, reuse each existing typed composition
and ledger compiler, and enforce the same window join. It removes the native
window-parent proof rather than adding a wrap after it. It must preserve the
53-pair continued epoch / 67-pair mixed grammar, all physical claims and all
per-tree masks. The current complete PCS primitive supports the heterogeneous
physical trees, including empty and higher unsampled trees; it does not yet
supply those typed AIR/transcript/closure adapters.

Larger fan-in eliminates intermediate proofs, not per-child verification.
For 107 leaves, binary reduction has 106 internal nodes / 212 child-proof
verifications. A valid fan-in <=4 tree can use 36 internal nodes / 142 child
verifications, without padding fake leaves. That is at most a 1.49x reduction
in child-verifier count; each larger node needs larger gate domains. Choose
component sizes separately for hash, arithmetic, conversion and XOR; do not
blindly pad a RISC wrapper to the existing Cairo production target. Authenticate
any new target and prove heterogeneous-leaf/homogeneous-fold compatibility.

The 8,139-column Mixed original is a separate large target. Pruning genuinely
inactive recipe components, changing caller representation, or a new physical
packing profile can reduce both hashing and DEEP. Those are explicit new
original proof profiles with independent keys and hostile omission controls;
file consolidation or a smaller component row count alone does not remove
queried column width.

## Backend and GPU readiness: source map only

Reuse `integrations/circuit_cpu/recursion/proof_source.zig`'s input of values,
authenticated preprocessing, AIR bundle, PCS config and expected preprocessed
root. Output is an actual circuit proof plus its preprocessed root, circuit
hash and statement digest. CPU fresh verification remains mandatory. The
`leaf_wrap` topology cache and `canonical` internal/root separation provide the
lifecycle; their Cairo-specific statement/registry checks need new RISC peers.

The BLAKE3 gadget emits existing Blake-G and TripleXor circuit gates, so it does
not require a new device hash algorithm merely to prove those gates. The maps
`integrations/circuit_cuda/{recursion_source,resident_prover,resident_verifier,
resident_composition,resident_interaction,resident_quotient,resident_fri,
resident_decommit}.zig` are potential backend hooks. Their accepted AIR/profile,
geometry, registry and committed root checks must authorize the **new** RISC
circuit; no existing Cairo device receipt grants that authority. No GPU was run
and no GPU speed or capacity estimate is made here.

## Required acceptance gates

1. Saved actual 890 window root and saved 16M root: original producers, decoder
   and all successful capture owners destroyed before circuit construction.
   Exact roots, claims, native transcript digest/draw count and samples agree.
2. ALL typed AIR + public-supply + composition + PCS in one circuit. Reject
   root/nonce/sample/physical-claim changes and compensating claim deltas.
3. Prefix and supply reference-identity audit; zero/high-bit alias controls,
   empty/higher-domain trees, negative masks, periodic response ordering and
   retry counters. No host-supplied DEEP/composition answer or skipped tree.
4. Actual CPU circuit proof at q70/26, fresh wire-only receiver with independently
   selected topology/key/statement, hostile key/preprocessed-root controls.
5. Two adjacent RISC windows and actual depth two, odd carry, wrong CPU/snapshot,
   overlap/gap/ELF/security/boundary/scope rejection. Explicit authorized-key
   membership; arbitrary valid circuit proofs must not yield a RISC certificate.
6. Only then compare matched original/leaf-wrap/fold/final-receive phases,
   component gate/padded-row counts, compression origins and peak memory.
   The full retained-block run remains the baseline; no Cairo/H100 timing is
   transplanted into a RISC prediction.
