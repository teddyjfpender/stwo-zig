# RISC-V originals through the existing circuit wrap/fold stack

Status: implementation comparison, with a new constrained BLAKE3 gadget; no
RISC-V original has yet been wrapped by this circuit stack. Existing qualified
RISC-V and Cairo proof identities remain unchanged. All observations below come
from local source and retained reports; no network or GPU execution was used.

## What the measurements actually compare

The qualified RISC-V 4M window root consumes **already proved** eight sparse-ROM
Local11 originals, one late endpoint bridge and one Compact7 global RAM original.
It replays ten original verifier machines in one native recursive AIR DAG. The
saved V3 report records 186.963823 s parent proving, 27.577010 s witness building,
9.359947 s fixed compilation, 24.400754 s fixed commitment, 10.834327 s admission,
17,608,030,068 B retained rows, 49,250,680,832 B OS maximum RSS, and a 1,115,560 B
root. Including fresh receiver reconstruction, total is 290.826288 s. This is a
nonterminal declared window, not a full Ethereum block. Source execution and
source reproof counts are both zero. See
`vectors/reports/riscv-cpu-architecture-20261029/native-4194304-local-sparse-compact-parallel2-8x524288-single-dag-root-v3/report.json`.

The Cairo production-registry two-PIE run on M5 Max records 70.38 s for the two
Cairo originals, 25.80 s for their circuit wraps, 8.58 s for a two-child circuit
fold, and 106.13 s from PIE adaptation through root; 28.49 GB CPU peak RSS and
1,508,773 root bytes. The leaves have 1,224,007 and 785,807 Cairo steps. These
numbers do **not** show that replacing the RISC-V root would cost 8.58 s: its
missing leaf wraps are the essential work. The Cairo leaves and circuit are
specialized to a different verifier, input size, transcript and statement.
`tools/starknet-block-collector/README.md:96` gives boundaries and qualifications.

The H100 resident receipt is a separate observation, not a CPU prediction:
32.308 s serial wall, 9.494 s Cairo proving, 12.579 s wrap and 9.021 s fold,
5,043,953,664 B host RSS. Individual leaf circuit arena peaks are 28,123,850,272 B
on device; whole-device peak is explicitly null. It excludes PIE execution,
adaptation, queue and build. No CPU/GPU or identical-work speed ratio is inferred.
See `vectors/reports/recursive-product-20260918/cuda-resident-pipeline-h100-20261001/receipt.json`.

## Existing architecture worth reusing

1. **A specialized leaf verifier followed by homogeneous folds.**
   `src/frontends/circuit/statements/cairo_verifier.zig:1` uses the enabled slots
   of the 83-slot Cairo evaluator table and a program/preprocessed-root-specific
   topology. This is not a generic VM interpreter. `leaf_wrap.zig` obtains the
   exact registry entry from the original lifting height, checks column counts,
   enabled components, aux length, satisfaction, committed root and circuit hash.
   Every accepted leaf then runs in the same **11-component circuit AIR**.
   `src/frontends/circuit/statements/multiverifier.zig:1` verifies two such
   circuit proofs and hashes ordered `[circuit_hash, output_digest]` pairs.
   It does not reinterpret their original VM AIRs at every higher tree level.
   Production target logs are Eq20, QM31-ops23, M31-to-U32 21, TripleXor20
   and Blake-G23, with circuit FRI70/26, blowup1 and fold-step4; Cairo uses
   fold-step1. These are substantial fixed circuit domains. The circuit
   preprocessed layout has 45 columns.

2. **Setup once, values per request.**
   `src/integrations/circuit_cpu/recursion/topology_key.zig` keys the leaf by
   exact config, target sizes, Cairo variant, enabled components, FRI/lifting,
   program and preprocessed root. `leaf_wrap.LeafTopology` retains preprocessed
   circuit columns, authenticated root/hash, commitment and twiddles. Cache hits
   still check circuit hash and exact variable count. `canonical.CanonicalCircuit`
   builds one two-child topology, checks the registry, and checks homogeneous
   padding parity. Requests rebuild values, not a new authorized key.
   Values-only reconstruction exists, but it may omit local gate checking only
   when proving against a separately authenticated topology and independently
   verifying the resulting proof.

3. **Bounded tree residency and explicit terminal profile.**
   `fold.reducePair` consumes its children; `reduceRootSingle` duplicates the
   verifier input but preserves one packed leaf. Unpaired tails carry unchanged.
   `fold-stage` checkpoints represent nonterminal subtrees; terminal roots cannot
   be folded as internal children. `src/products/circuit_recursion_cpu/stage_session.zig` reuses AIR/canonical state
   across jobs. Internal proofs use Blake2sM31 channel; terminal proofs use the
   distinct Blake2s channel/felt-stream contract. A compact terminal topology is
   separately authenticated, not quietly treated as a homogeneous child.

4. **Backend-neutral proof handoff.**
   `src/integrations/circuit_cpu/recursion/proof_source.zig` accepts values,
   authenticated preprocessed columns/root, AIR and PCS profile; a backend returns
   its proof, root, circuit hash and output digest. The CPU prover exposes cached
   preprocessed commitment/twiddle and early `release_values` options.
   `verifier_proof.fromVerifiedCapture` converts native verified opening captures
   without requiring retained prover auxiliary trees. CUDA
   `resident_verifier.zig:1` independently replays the exact profile and checks
   committed preprocessed root, geometry and AIR before producing that capture.
   This API is useful on CPU too; CUDA is not required by the architecture.

## Why the current originals do not plug into leaf_wrap

| Contract | Qualified Cairo/circuit path | Current RISC-V path | Required bridge |
|---|---|---|---|
| Hash/Fiat–Shamir | Plain Blake2s Merkle; reduced Blake2sM31 internal transcript | Full-digest domain-separated experimental-v1 BLAKE3 | Exact BLAKE3 framing, reduction/rejection, draws, PoW and Merkle checks inside leaf circuit |
| Physical PCS | Four trees: fixed, main, interaction, composition; equal lifting | Local11, Mixed14, Group `4N+3M+7`, bridge and Compact7 physical trees; per-tree masks/domains | Generalized opening/FRI/transcript circuit or a separately proved four-tree normalizing layer; not a byte conversion |
| Statement verifier | Cairo-specific public memory/program/Opcodes relation and 83-slot evaluator table | Typed native AIR, halt guard, endpoint planes, ROM/lookups/ranges, optional caller and late-global closure | RISC-V statement implementation and exact original component equations under circuit arithmetic |
| Statement binding | Program/root interned, registry-authorized leaf key; output in two 128-bit cells | Fresh ELF reconstruction, root roster, frames/ordinals, CPU boundaries, same 23-column endpoint roots, physical claims | An authenticated output commitment carrying these exact public obligations, including open/closed scope |
| Folding | Child circuit key and digest committed in ordered packed output | Current flat DAG executes all original verifier bodies together | First prove leaf verifier circuits, then reuse the bounded fold unchanged under a newly authorized registry |

The four-tree assumption is concrete in `stark_verifier/proof.zig:N_TRACES`,
`verify.zig:ORIGINAL_TRACE_IDX/INTERACTION_TRACE_IDX`, `ProofConfig.init` equal
lifting checks, and `verifier_proof.fromProofMaterial` exact four-tree inventory.
`stark_verifier/channel.zig` explicitly replays Blake2sM31, with its own draw byte
lengths and reduced digest state. Substituting a new statement object alone
cannot fix those differences. Neither renaming a BLAKE3 proof nor forwarding a
host verification result into `fromVerifiedCapture` proves the missing circuit
checks. A capture supplies witness data, never recursive authority.

The PIE/simple bootloader is useful because it standardizes a **Cairo execution
and its task output contract** before the Cairo proof. It does not grant the
Cairo AIR the ability to verify an RV32 ELF proof. Running a new BLAKE3/RISC-V
verifier program under Cairo is another valid design, but requires implementing
and proving that program and measuring its steps; no existing bootloader timing
applies automatically.

## Concrete reuse implemented now

`src/frontends/circuit/builder/blake3_reuse_v1.zig` emits BLAKE3 using the existing
`builder.blake.blakeGGate` and `tripleXor`. The G function is identical in both
hashes (additions mod2^32, rotations16/12/8/7); BLAKE3 differs in initialization,
seven-round permutation schedule, output XOR, counters and flags. The gadget
imports the canonical `core.crypto.blake3_compression` schedule, not a parallel
magic table. Each compression emits exactly 56 existing G gates and 16 XOR gates,
including the full 16-word XOF output. No new circuit AIR or backend kernel is
required for this primitive.

The API provides full compression with 64-bit counters, chunk chaining/root,
ordered internal-parent/root, and constrained prefix-plus-U32 serialization up
to 1024 bytes. `protocolNode` uses the exact canonical experimental-v1 protocol
ID/node tag, including its 28-byte prefix. It is **not** BLAKE3's
internal PARENT operation. Aligned native prefixes reuse input word wires
directly; arbitrary unaligned prefixes use constrained byte decomposition. Final zero padding and bytes are
constrained in existing arithmetic gates. Input U32 wrappers must carry their
normal builder range contracts. Parameters supplied as host constants affect
topology; moving request-dependent counters/flags to witnesses will require
explicit authenticated wiring, never an unchecked substitution.

Qualification checks full 16-word output/counters/flags, independent std BLAKE3
hashes at block/chunk boundaries, an ordered two-chunk tree, corrupted internal
values, exact native domain framing and arbitrary prefix alignments,
topology/value parity and gate-free replay. All 14 focused ReleaseSafe tests
pass (`/tmp/v8-circuit-blake3-reuse-qualification.log`).
This is a kernel/circuit-satisfaction gate, **not** a new recursive STARK route or
registry qualification. Multi-chunk arbitrary leaf frames, transcript replay and
PoW/draw verification remain open.

## Proposed implementation boundary

Build a new RISC-V leaf-wrap family, while keeping original BLAKE3 proofs and
legacy protocols exact. First implement the exact original transcript/PCS
verifier over the circuit builder, with a finite independent shape and a bound
on every tree/mask/claim/frame. Reuse existing typed AIR equation authorship via
an explicit circuit-field adapter; do not replace AIR checks with public sums.
Public output should commit to the ELF/profile, security, ordered coverage,
CPU boundary, original roots/claims, endpoint roster and declared OPEN buses.
Admit the leaf key from the independent structural compiler, not its envelope.

The original can stay BLAKE3 while the wrapping circuit proof uses the existing
Blake2sM31 profile. That is an ordinary nested-proof boundary, not a claim that
the hash functions are interchangeable. No original source reproof or guest
replacement is required by this design.

Then produce an actual circuit proof using existing circuit CPU prove APIs,
`PreprocessedCircuit`, cached commitments/twiddles and native verified captures.
Pad leaves and the two-child multiverifier to a **new** compatible fixed target;
prove and independently check each new registry root/hash. Once that leaf proof
is sound, existing `fold.reducePair`, checkpoint/session machinery and final
circuit verifier are reusable without importing the original AIRs into every
upper node. Fold output hashing authenticates order and keys; it does not itself
prove CPU adjacency or shared late-RAM closure. Preserve these in leaf/merge
statements or in one final application circuit over authenticated child outputs.

A first qualification should use two real tiny RISC-V originals with altered
halt equation, compensated physical claim, wrong ELF/key, reordered endpoint
root, broken CPU adjacency, transcript/PoW and Merkle-path negatives. Only after
that gate should a retained 4M source be compared with the existing root,
separating cold setup, warm value replay, per-leaf wraps, folds and fresh receiver.
The expected structural advantage is bounded peak residency and reusable setup;
no latency or total-work advantage has yet been measured.
