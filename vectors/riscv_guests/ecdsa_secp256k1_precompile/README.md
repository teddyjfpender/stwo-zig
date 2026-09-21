# CSP ECDSA guest with typed recovery

This guest consumes the unchanged canonical 161-byte CSP input:
`digest[32] || uncompressed_SEC1_key[65] || r[32] || s[32]`.
It enforces the uncompressed key prefix and k256's low-S policy, invokes the
existing typed Ethereum signer-recovery instruction, compares the recovered
64-byte key against the supplied key, and publishes the digest only on success.
The proof includes RISC-V execution, instruction fetches, the recovery AIR,
caller/memory relations, public input/output and successful completion.

Two authenticated ELFs fix the recovery parity to zero or one. Host recovery
selects a candidate ELF; it is not an accepted signature verdict. Independent
verification binds the proof to the selected authenticated ELF, initialized
memory/registers, canonical input, output and secure PCS parameters.

The accelerated route proves successful verification. Inputs without a matching
supported recovery take the existing k256 software guest and receive a complete
proof there, including rejection. This covers malformed keys/signatures, high-S
signatures and the rare unsupported recovery branch with x = r + n. A failed
fast guest never publishes output or a halt flag. The suite's negative fixture
must produce and independently verify a software rejection proof.

Rebuild and check source/ELF identity:

```sh
python3 scripts/build_csp_ecdsa_precompile.py
```

After intentional source changes, `--write` updates both ELFs and
`vectors/riscv_csp/ecdsa-precompile-v1.json`. The original software manifest and
canonical input remain unchanged.
