# Bitcoin proof implementations

- [`consensus/`](consensus/) implements target, retarget, and checked work arithmetic.
- [`fold/`](fold/) defines checkpointed chain state and constrained update relations.
- [`verification/`](verification/) contains native chain verifiers and pinned keys.
- [`cli/`](cli/) exposes standalone chain verification.
- [`tests/`](tests/) exercises proof and verifier behavior.

The [Bitcoin design notes](../../../../design/s31/bitcoin/) track the light-client work; the [SHA256d walkthrough](../docs/bitcoin-sha256d.md) explains the byte-exact header relation.
