# Guest prover carries the selected suite through output and verification

Mechanical type propagation through existing generic Engine APIs: guest output,
finalization and verifier currently hardcode the base BLAKE2s proof/hasher despite
accepting an Engine parameter. Replace these with ProofForEngine/HasherForEngine
and a generic owned profile output. Keep the default output alias for current
callers. Preserve the single orchestration, component assembly and verifier.

Qualify a real CPU BLAKE3 guest-precompile proof, encode/decode under v5 and
independently verify the decoded proof plus original. Retain legacy guest proof
checks. This proves guest Poseidon execution semantics with BLAKE3 prover hashing,
not a full CSP benchmark or production default migration. Test parameters remain
diagnostic and are never reported as canonical CSP70/26 results.
