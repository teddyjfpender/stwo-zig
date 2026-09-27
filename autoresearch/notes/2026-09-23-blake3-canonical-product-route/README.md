# Canonical BLAKE3 product proving

Removed the legacy base prove/benchmark transaction, the separate guest-profile
prove/benchmark transaction, the historical CSP ECDSA proving loop, and the
Metal-only guest Poseidon proving transaction. Base, Ethereum and guest Poseidon
ELFs now route through the same typed full-width BLAKE3 product implementation.
The guest Poseidon instruction still executes its original permutation.

Requests to generate historical-suite proofs return
`LegacyProofGenerationRemoved`. Historical base, guest-profile and CSP artifact
verifiers remain. The Metal-only guest command retains verification but rejects
proving; use ordinary `prove` or `bench` with the profile-labelled ELF instead.
The benchmark runner can still select BLAKE2s for an older executable; a current
executable refuses that generation request rather than silently switching suites.

The initial product compile caught an error-set narrowing in the generic CLI's
admission diagnostic. The diagnostic now matches through `anyerror`, preserving
its behavior for both the retired and canonical engine branches. A second product
build is pending, followed by default-route and legacy-refusal runtime checks.

This removes product orchestration, not every historical library or diagnostic
API. Remaining Poseidon recursion/channel providers and their exported integration
entry points still need a reachability audit before removing unused implementations.
Expanded Ethereum block support remains out of scope. The original planning,
fusion, direct-layout and parameter research objective is still active.


The rebuilt Metal product rejects explicit BLAKE2s ordinary bench, explicit
BLAKE2s CSP bench and the retired guest-Poseidon prove command with
`LegacyProofGenerationRemoved`. It also independently verifies the retained
canonical full-width artifact. Receipts are retained here. CPU build and a
follow-up Metal help/registry refresh are still running; no completion claim is
made for those gates. Historical verifier code is retained but has not yet been
requalified against a retained historical artifact in this cleanup iteration.


The combined CPU/Metal product build completed successfully (4/4 steps). CPU
legacy-generation refusals also pass. A fresh canonical q70/PoW26 guest proof
from the cleaned CPU product independently verifies and is byte-identical to the
retained full-width artifact. Only the subsequent Metal help/registry refresh
is still running. These checks do not constitute new performance measurements.

The Metal help/registry rebuild also completed (2/2 steps). Installed help directs
the retired command to ordinary proving, and the registry now advertises prove|bench.
