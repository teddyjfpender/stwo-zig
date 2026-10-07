# SHA proof implementations

- [`air/`](air/) defines trace constraints, equation helpers, and word buses.
- [`config/`](config/) pins proof shapes, public ABI, and profile digests.
- [`proving/`](proving/) constructs traces and proofs.
- [`verification/`](verification/) checks the corresponding native proof profiles.
- [`package/`](package/) handles proof packages and runtime transport.
- [`recursion/`](recursion/) contains SHA-specific recursive transcript logic.
- [`tests/`](tests/) holds focused proof and adversarial tests.

The [SHA design notes](../../../../design/s31/sha/) describe the intended chip boundaries and tradeoffs; the [language documentation](../docs/bitcoin-sha256d.md) walks through a Bitcoin SHA256d program.

The fused three-call word bus pairs simultaneous state `a` and `e` boundary
events in one rational LogUp fraction, leaving the schedule event in the
other slot. This uses eight interaction columns instead of twelve and keeps
the same signed word claim. The [matched production measurement](../../../../design/s31/measurements/sha/bitcoin-sha-rational-pair-matched-production-2026-10-07.json)
records the before/after proof costs and native verification checks. On its
fixed header, fused non-PoW proving took 39.27 ms versus 153.65 ms for the
generic circuit, while its 376,675-byte proof was about 11% larger than the
generic 338,282-byte proof. FRI PoW nonce search dominates wall time for this
header and varies with the transcript.
