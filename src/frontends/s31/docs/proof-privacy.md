# Public inputs, private witnesses and proof blinding

`private` controls the public ABI. It does not by itself hide the witness in a
STARK proof: trace openings, out-of-domain evaluations and lookup interaction
sums can depend on private values. Ordinary S31 `circuit` proofs use the legacy
transparent mode. Do not infer zero knowledge from a parameter's visibility.

To request the **experimental random-row blinding mode**, declare the whole
circuit as `blinded`:

```s31
use std@1;

blinded circuit preimage(private secret: [m31; 8]) -> public Digest<Poseidon2> {
    std::hash::poseidon2_leaf(secret)
}
```

Pure functions specialize into that circuit and share its proof mode. There
is no separate proof for a helper function. `public` inputs and results are
still disclosed in the public statement. Returning a private input publishes
it; returning an invertible function of it can reveal it as well. The compiler
does not certify that a chosen public output preserves secrecy. Note salts and
hash preimages still need sufficient entropy.

The normalized relation has `"proof_mode": "blinded"`. Omitting the field,
or explicitly selecting `"transparent"`, preserves the legacy mode and
canonical arithmetic hash. Unknown or non-string modes are rejected.

## What this mode implements

After circuit finalization and before power-of-two padding, the prover appends
80 rounds of the existing pinned upstream random-row construction. Each round
adds 14 QM31 arithmetic rows, and one equality, triple-XOR, M31 conversion and
Blake-G row. All five witness gate kinds receive blinding, even when the source
uses only arithmetic or Poseidon2. The fixed budget follows 70 FRI queries plus
the upstream allowance of 10 non-query openings.

Every proving invocation draws a fresh, private 32-byte seed from the OS-seeded CSPRNG
and expands it with ChaCha20. The seed is absent from proofs, statements,
packages and logs; the CLI has no seed override. Topology reconstruction uses
a dummy seed because row addresses and counts do not depend on random values.
Value and topology gate lists must agree after blinding and after padding.

The request changes the canonical IR identity. The package uses the
`circuit-blinded-v1` profile and `s31-verification-key-blinded-v1` schema, with
the exact `proof_privacy` policy in the sealed key, manifest and cost report.
The native verifier recompiles the source with the declared blinding rows and
checks its fixed commitment and geometry. Stripping the policy, reducing the
budget or substituting transparent geometry fails verification. A verifier
cannot establish whether a dishonest prover used fresh randomness; privacy
depends on the prover's entropy and its implementation.

`cost-report.json` retains the source's raw gate counts; padded counts include
the blinding and padding rows. Use `proof_privacy` to interpret the difference.
Blinding can cross a power-of-two boundary and the full profile retains its
fixed lookup tables, so existing sparse-profile costs do not apply.

## Supported boundary

Only `--lowering gate --fri-fold-step 1` is supported. Other lowerings and
fold step 4 reject a blinded source in both the package builder and native
binaries. The query budget has not been established for those profiles.
Blinded packages contain no recursive or fold keys. Recursive/fold commands
reject the source because an unblinded outer proof can disclose its child
proof. No command silently switches a blinded request to transparent mode.

The [hash-payment example](../examples/payments/README.md) requests this mode.
To exercise native verification and policy tampering:

```sh
python3 -m unittest discover -s src/frontends/s31/tests/python -p 'test_proof_privacy.py' -v
python3 src/frontends/s31/tests/acceptance/acceptance_proof_privacy.py
python3 src/frontends/s31/tests/acceptance/acceptance_tongo_transfer.py
zig build --build-file src/frontends/circuit/build.zig circuit-parity-r5 -Doptimize=ReleaseSafe
```

The privacy acceptance driver verifies repeated proofs of one witness and a
different private witness for the same public statement. It checks distinct
trace commitments with identical fixed commitments, and rejects changed
statements, corrupted proofs, policy changes embedded into rebuilt verifiers,
transparent proof substitution and unsupported profiles. These are regression
checks for the implemented mechanism, **not tests that prove zero knowledge**.

## Remaining security work

This mode does **not** claim a general zero-knowledge guarantee or production
payment confidentiality. A reviewed argument must cover the complete
transcript, including lookup multiplicity traces, interaction claimed sums,
OODS, FRI queries, repeated proofs and cryptographic hash assumptions. The
existing R5 fixture authenticates random-row construction against pinned Rust;
complete new-package proof interoperability through pinned Rust remains a
release gate. Successful Zig verification alone does not satisfy that gate.

The exact scope, pin and invariants are in the
[proof privacy contract](../../../../design/s31/language/PROOF_PRIVACY.md).
