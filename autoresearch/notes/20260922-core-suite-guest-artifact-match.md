# Canonical core suites and explicit BLAKE3 guest artifact admission

Mechanical protocol refactoring: centralize canonical BLAKE2s/BLAKE3 proof type
bundles in core; reuse the core BLAKE3 bundle from recursion. Generalize the
existing guest artifact implementation over these two explicitly admitted suites,
with immutable v1/BLAKE2s and new v5/BLAKE3 framing. Re-export the existing v1
surface through a thin facade; publish v5 from the same implementation. No cloned
codec, permissive arbitrary suite parameter, or interpretation of legacy bytes
under new keys. Version 4 remains the existing Poseidon2 Ethereum product.

Inputs and wire geometry are unchanged guest statement/extension/claim sections;
the typed proof hasher and fixed version-to-hasher mapping select the suite.
Preserve all preflight bounds, canonical fields, config checks, cleanup and
claim validation. Test legacy vectors, BLAKE3 canonical roundtrip, wrong suite/
version before allocations, malformed payloads and allocation failures. Synthetic
codec fixtures do not establish full guest proof verification or CSP speedups;
real product engine/default switching and CPU/Metal gates remain next.
