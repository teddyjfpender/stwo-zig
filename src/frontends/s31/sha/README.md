# SHA proof implementations

- [`air/`](air/) defines trace constraints, equation helpers, and word buses.
- [`config/`](config/) pins proof shapes, public ABI, and profile digests.
- [`proving/`](proving/) constructs traces and proofs.
- [`verification/`](verification/) checks the corresponding native proof profiles.
- [`package/`](package/) handles proof packages and runtime transport.
- [`recursion/`](recursion/) contains SHA-specific recursive transcript logic.
- [`tests/`](tests/) holds focused proof and adversarial tests.

The [SHA design notes](../../../../design/s31/sha/) describe the intended chip boundaries and tradeoffs; the [language documentation](../docs/bitcoin-sha256d.md) walks through a Bitcoin SHA256d program.
