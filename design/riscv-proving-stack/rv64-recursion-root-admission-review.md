# RV64 recursion root admission hardening

Review of user commit `154a60c58` found receiver topology, statement and layout binding gaps, and a missing native fixed-root circuit constraint. These are
integration policy issues; this change does not replace the in-circuit native
verifier or add in-circuit batch adjacency.

First, the old `verify-root` command admitted each leaf's circuit hash directly
from the untrusted leaf JSON. The production registry independently defines the
canonical generic multiverifier, not the RV64 native-verifier leaf topology for
each layout. A self-declared leaf hash cannot establish that topology's meaning.
The command now requires an independently trusted topology manifest, just as it
requires an independently trusted Ethereum/ELF configuration:

```
rv64-recursion verify-root ROOT_DIR EXPECTED_CONFIG TRUSTED_TOPOLOGIES
```

The trusted file has this exact JSON shape, in batch order:

```json
{"schema":"rv64-recursion-leaf-topologies-v1","leaves":[{"circuit_hash":[0,0,0,0,0,0,0,0],"layout_digest":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}]}
```

The zero digests above are syntax only, not admitted circuits/layouts. Real entries must
come from an independently validated RV64 leaf construction/layout or a separately
qualified pinned allowlist. Copying hashes out of producer leaf files is not an
admission workflow. The caller owns the authenticity of this expected input;
the receiver does not automatically derive or certify RV64 topology semantics.
Runtime production-registry assets remain trusted receiver assets as before.

The statement digest contains FREE words. Layout words, such as opcode masks,
state/control policies, rosters and table geometry, are constants in the pinned
circuit and are deliberately absent from that digest. Therefore each trusted
entry also pins a layout digest. The receiver computes this fingerprint before
constructing setup from the untrusted leaf public metadata, preventing metadata
from advertising a different policy/layout with the same free words. The
fingerprint uses the SAME `walkPublicWithProgramIdentity` authority as the full
walk; no transcript sequence is copied. It hashes domain-separated framed
constant words, free-field roles/call boundaries and PCS configuration. Free
values and program identity are excluded here; the full statement check binds
them using the independently expected executable. Fresh wrap emits an optional
`layout_digest` field for constructing a separately trusted admission artifact
from independently verified native proofs; that producer hint is not authority
and old files without the hint remain readable.

Second, the old receiver recomputed packed-tree digests but separately validated
leaf JSON's public values and statement words. It did not require that JSON's
statement digest equal the corresponding leaf digest inside the authenticated
packed tree. The root proof and packed tree could remain unchanged while a
self-consistent JSON public/words/digest record was substituted. `verifyRoot`
now receives both the trusted topology and expected statement digest per position.
Packed traversal compares both. The later transcript walk binds those exact
words to the independently expected program and the supplied public values;
host chain checks bind genesis, coverage and adjacent batch state.

Third, every internal packed composite must have the independently derived
canonical multiverifier circuit hash, including the packed root. Without that
check an arbitrary child circuit could output a fabricated parent digest while
metadata presented trusted leaf hashes beneath it. Checking only the outer root
and terminal leaf hashes does not authenticate the intervening recursive logic.
Leaf topology pins and internal canonical topology have distinct authorities.

The leaf constructor had additionally verified native commitment zero only in
host-side `native_capture.verify`. All native proof commitments are guessed
wires, and the generic in-circuit native verifier accepts a statement/shape but
does not independently know RV64's fixed root. Host validation of the honest
constructor does not constrain a malicious circuit witness. The RV64 wrapper
now emits eight full-u32 equality gates binding commitment zero to the receiver
key's independently derived root BEFORE invoking the native verifier. This binds
ROM, fixed selectors and immutable policy columns inside the circuit. It changes
the leaf topology/hash; old leaf pins and roots are not promoted as fixed by a
new metadata policy. Fresh independently verified wrap/fold/pins are required.
The builder test mutates each of the eight high-bit words and demonstrates that
the actual recorded circuit becomes invalid, while the exact expected root is
valid. There is no reduction of hash words into one M31 scalar.

The root receiver also invokes the complete native `A.Public` admission after
restoring the expected program, not only `Prepared.initForLayout`. Layout
validation omits root canonicality and the requirement that before/after RAM
roots agree when the RAM roster is absent. These roots are free statement words,
so native receiver admission remains necessary even with a trusted circuit pin.
This preserves existing native checks rather than adding a parallel policy.

The v1 admission cap is 1..64 leaves, checked before allocating root/leaf advice.
Layout hashing rejects zero/oversized steps before the shared walk computes a
logarithm or a receiver setup is allocated.
The trusted JSON file is bounded to 64 KiB, packed JSON to 64 MiB, each leaf JSON
to 4 MiB, and each revealed statement to 65536 words. Traversal permits at most
127 composite nodes and depth below 64; the shared packed-node parser separately
rejects depth 64, including plain children. The normal pair/carry tree with at
most 64 leaves fits, as does the existing single-leaf wrapper. This cap does not
claim bounded prover memory or a streaming recursion schedule.

Targeted tests in
`src/integrations/riscv_cpu/rv64_recursion/root_admission_test.zig` check trusted
right cases, topology mismatches, detached self-consistent statement replacement,
ordered leaf binding, layout-policy mismatches, malicious root/internal topology, single-leaf wrapping,
preallocation count rejection, node budget and exhaustive allocation cleanup for
the binding parser. These tests are binding/admission checks, not fake physical
root proofs. Existing physical proof suites and independent fresh root receiver
runs must still qualify the complete path with a trusted manifest.

No root-proof byte format, multiverifier arithmetic, generic native-verifier equations,
recursion core, or RV64 batch-proof authority is changed. In-circuit adjacency,
automatic independent leaf-topology derivation, and a semantic full-block terminal
certificate remain separate work. A host root-prefix chain check is not a claim
that these additional properties are already inside the recursive circuit.
