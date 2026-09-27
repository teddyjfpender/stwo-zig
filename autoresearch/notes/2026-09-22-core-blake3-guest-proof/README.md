# Core BLAKE3 suite proves a real guest precompile and verifies v5 transport

Core proof_suites.zig now centralizes canonical BLAKE2s/BLAKE3 hasher, channel,
Merkle-channel and proof types. The recursion BLAKE3 suite and current ordinary
BLAKE2s frontend aliases use these bundles. No default selection changed.

Guest artifact encoding/decoding has one shared implementation specialized only
for the two admitted core suites. Existing facade exports remain immutable v1
BLAKE2s; its Blake3 namespace selects new guest version 5 and hasher ID 3. Header
versions 1--3 remain BLAKE2s, version 4 remains Poseidon2-M31. Preflight, resource
bounds, metadata ownership and canonical fields remain shared. Legacy bytes are
not reinterpreted through default alias changes.

Guest orchestration, finalization, trace-root checking and independent verification
now carry ProofForEngine/HasherForEngine rather than hardcoded BLAKE2s types.
Owned outputs are keyed by hasher so engines using the same suite share the same
output type. The default output alias and existing BLAKE2s callers remain intact.
There is no parallel BLAKE3 prover or verifier implementation.

Qualification (ReleaseSafe):
- Focused guest artifact gate: 12/12 tests, 8 s /4 MiB reported MaxRSS, compile
  9 s /966 MiB. Includes legacy header bytes, bounded canonical v5 roundtrip,
  wrong suite/version rejection before allocation, malformed legacy artifacts,
  and all allocations failing in BLAKE3 encode/decode ownership paths.
- Real CPU guest proof gate: 2/2 tests, 9 s /1 GiB, compile 58 s /4 GiB. Existing
  guest Poseidon execution is proved using BLAKE3 commitments/transcript; its v5
  artifact is decoded and independently verified, as is the original proof.
  Legacy BLAKE2s proof still verifies. Forging a genuine legacy proof's header
  to v5/hasher3 passes structural decoding but independent BLAKE3 verification
  rejects InvalidPreprocessedCommitment. No leaks reported.
- Core BLAKE3 protocol/PCS gate: 5/5 tests, 553 ms /3 MiB, compile 9 s /824 MiB.

The real guest proof uses diagnostic q3/PoW0. It is not a canonical CSP70/26
benchmark, fresh OS-process product routing qualification, or an end-to-end
speed comparison. Guest Poseidon semantics remain unchanged; the proving hashes
are BLAKE3. Production CLI defaults and Metal remain unmigrated.

Next: extend explicit suite/version admission through ordinary and Ethereum/CSP
product artifacts and routing; make transcript receipts handle BLAKE3 u64 draw
counts and identify the suite; qualify real CPU/Metal products and switch defaults
together with codecs; run and document canonical CSP70/26 outputs. Production
recursion keys, distinct-child/parent-of-parent and full-profile timing remain.
