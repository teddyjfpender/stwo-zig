# Independent base ELF/input admission for full-width BLAKE3

Implemented; pending the queued real-base proof and statement-wire compatibility
checks. This validator accepts complete base executions, not interior segments or
expanded Ethereum/block profiles.

It validates the release ABI and byte-exact public input, loads the declared ELF
without running the guest, checks initial PC/registers and I/O symbol addresses,
and checks completion against the declared program/halt symbol. It independently
reconstructs the BLAKE3 program root and ordinary initial-memory root from the
loaded image. No legacy Poseidon commitment is built. Only after those checks does
it return source digest labels for the caller-pinned manifest.

The existing guest-profile verifier and new validator now use one input-byte
binding implementation on IoEntries. Existing mismatch/padding error names remain.
A focused regression checks changed input bytes, length, partial-word padding,
exact words and empty input. The statement-wire target includes it (floor six).

The real-base fixture now calls source validation and rejects mutations in the
last byte of the program and initial-memory roots and the initial register state.
This prepares the product integration seam; CLI artifact routing and default
activation are not yet implemented.

Queued logs:
- /tmp/blake3-owned-base-run-proof-v2.log
- /tmp/blake3-statement-wire-legacy-compatibility.log
