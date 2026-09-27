# BLAKE3 migration foundation — 2026-09-21

Priority redirected by the user from fused PCS integration to BLAKE3 across the
prover. Production recursive proofs remain on Poseidon until the new recursive
AIR, key/wire identities and device implementation qualify together.

Implemented: explicit experimental full-digest BLAKE3 channel and lifted Merkle
hasher; focused guarded CPU PCS/FRI integration and mutation tests; native hash
comparison. No production route changed and no new recursive key produced.

See [migration specification and remaining work](../../../design/riscv-proving-stack/blake3-migration.md).

Validation: `tests.log`, five guarded tests passing. The PCS test proves and
verifies a nonconstant polynomial with real FRI and low test-only PoW; it also
rejects a modified sampled value. Other tests cover all 35 upstream unkeyed hash
vectors, split updates, independent protocol vectors, field rejection/domain
boundaries, 32 root-byte mutations and wrong hash-family rejection.
`official-vectors.json` retains the first 32 digest bytes of the official vectors
(input bytes cycle modulo 251). Source:
https://github.com/BLAKE3-team/BLAKE3/blob/6aab490a26124663329dfd3961b8469f8fdb158b/test_vectors/test_vectors.json

`oracle.py` independently encodes the protocol using Python blake3==1.0.9;
`oracle.json` is its output. That dependency exists only in the temporary oracle
environment `/tmp/stwo-blake3-oracle-20260921`, not in production.

`native-hash-samples.jsonl` contains six alternating pairs for each operation;
`native-hash-summary.json` contains median paired ratios. Single-message native
leaf hashing improved 8.76–10.99x for the three tested sizes; internal nodes
improved 3.70x. These are not recursive proof speedups or Metal measurements.
Host: Apple M5 Max, 68719476736 bytes RAM, Zig 0.15.2, ReleaseSafe.

Reproduce:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-protocol -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu benchmark-blake3-hash -Doptimize=ReleaseSafe --summary all
```

Run the benchmark without other build/proof work. It is a diagnostic, not a
substitute for a same-profile complete proof comparison. The new suite has no
production security qualification.

Source conformance still reports 103 pre-existing findings; normalized finding
identities are unchanged. This check is not green. Formatting and `git diff --check` pass.
