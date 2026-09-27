# Shared public-program preprocessing (work in progress)

This implements the first architectural reduction in the repository-wide BLAKE3
G-row regression. It is not a completed recovery or an end-to-end speedup claim.
The old baseline suite continues using unchanged installed binaries.

The complete decoded program image is public. Previously, each execution proof
recomputed a sparse BLAKE3 tree over its four M31 values per instruction. The v3
commitment plan carries those canonical decoded values, checks their addresses
against the complete program schedule, reconstructs the existing BLAKE3 root,
and requires equality with the admitted public program root. The root semantics,
BLAKE3 rounds and digest width are unchanged.

A new typed AIR supplies program-access tuples from six fixed columns: four
values, address, and negative lookup multiplicity. It has no witness main columns
and no recursion-wire output. It is part of the shared base/extension commitment
roster, replacing the program boundary/packing/field-encoding chain. Program hash
emission is removed; private initial/final memory authentication remains intact.
Both prepared-key owners copy and reauthenticate the public table. The plan
identity includes values and the new AIR geometry/identity. The plan codec uses
version 3 and 28-byte program records, rejecting earlier schedule-only versions.

This does not authorize an arbitrary program table. The verifier reconstructs
its fixed commitment from the root-authenticated plan; source admission still
binds ELF/input to public roots. Recursive leaf admission must retain the expected
preprocessed key and plan identity. Merely committing witness-chosen fixed data
would not provide that binding.

## Qualification still required

- PASS: new typed AIR identity and root-authenticated program/codec checks.
  Semantic digest: ce40e3b88fb0410ceef6580541d83e8b97e5d0379a3d26f5dd8431ef95146cac.
  `qualification.log` retains initial digest discovery and the successful rerun.
  Replacing the zero placeholder with the reviewed definition's computed identity
  was intentional; root/value/tuple/codec negative tests pass with the pinned AIR.
- PASS: joined native/hash lookup, final-layout, padding and buffer reuse with
  zero-main program components (`integration.log`). Canonical Ethereum extension
  proof and independently authenticated replay also pass (`ethereum-proof.log`).
- PASS: Ethereum extension leaf at canonical 70/26, including Keccak and signer
  precompiles, fresh verification, artifact round-trip and capture mutation
  rejection. Complete CPU/Metal CSP timing is still required.
- PASS: base execution proof, independent verification, capture, parent and
  parent-of-parent (`proof-retry.log`). A 70/26 parent over an 8-query/0-PoW
  diagnostic child also passed with successful authenticated plan reuse.
  PASS: canonical guest-Poseidon extension leaf and parent both use 70 queries
  and 26 PoW bits (`canonical-parent.log`). Fresh outer artifact verification,
  source/pin mutation rejection and capture mutation rejection pass. This is
  guest instruction support; core commitments remain BLAKE3.
- Measure complete CPU/Metal CSP results and memory against the retained baseline.

The shared geometry census distinguishes hypothetical shared-tree compressions
from actual proved compressions; public-program proved compressions are zero.
On the retained SHA-256/128 plan this would remove 3,227,056 of 4,997,216 G rows,
leaving 1,770,160 (padded 2^21 instead of 2^23). ECDSA would remove 274,064 of
489,328, leaving 215,264 (padded 2^18 instead of 2^19). These are structural
predictions pending production qualification, not measured speedups.

Remaining repository-wide work includes private-memory tree geometry/framing
and recursive authenticated hash graphs. Public-program preprocessing alone is
not the complete requested fix. No benchmark identity or case-specific branch
selects the new path.

## Next structural candidate: memory word leaves

`geometry.py` inspects retained, independently verified v2 CPU artifacts. Its
`geometry.json` compares actual v2 geometry, public-ROM preprocessing geometry,
and a hypothetical 28-level tree over aligned u32 memory words. The hypothesis
keeps two-compression internal-node framing; it does not assume a novel BLAKE3
construction or fewer rounds. It predicts 62,552 remaining ECDSA G rows and
451,192 SHA-256/128 G rows (padded 2^16 and 2^19 respectively). This suggests
word granularity is a stronger next target than host micro-optimizations.

Word leaves are NOT implemented. A valid migration must version the memory-root
contract, bind all four byte limbs to the native word-access tuple, preserve
unaligned instruction semantics, and consistently update host roots, source
admission, initial/final boundaries, public I/O custody, continuation spans,
codecs and recursive verification. Merely changing the tree depth or dropping
three byte openings is invalid. Program-field roots and memory-word roots must
remain explicitly separated. This follow-up must use shared code across all
profiles, not branch on benchmark names.

The first base integration proof run (`proof.log`) failed an old expected-error
assertion: a corrupt serialized program root now fails earlier with
`ProgramRootMismatch`, before the previous `UntrustedCommitmentPlan` check.
The assertion was updated for that specific mutation; the proof and negative
checks then passed. No verifier condition was relaxed.

Canonical parent qualification used four workers and the testing allocator:
94.275047 s total, 15,356,969,954 tracked worker peak bytes, 865,743 artifact bytes.
This is a correctness/compatibility gate, not a matched performance comparison
against the prior 16-worker SMP benchmarks. The unchanged CSP baseline launcher
resumed successfully after qualification. Next: preserve that baseline, build
new CPU/Metal products after it finishes, and measure canonical complete CSP
transactions before claiming performance recovery.
