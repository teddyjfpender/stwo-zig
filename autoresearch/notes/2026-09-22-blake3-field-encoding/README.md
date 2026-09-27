# Canonical arithmetic-to-byte encoding — 2026-09-22

The previous turn qualified native lifted leaf geometry. This turn adds the
canonical serialization bridge needed between arithmetic wires and hash payloads.

`blake3_field_bytes.zig` consumes one authenticated QM31 wire and emits the four
little-endian packed words of its M31 coordinates. Each coordinate has bounded
bytes, a high-byte AND-127 check, field reconstruction, and a nonzero certificate
for 892 minus the byte sum. Under these byte bounds, only the encoding of p has
zero certificate, so the inverse constraint excludes the modular alias of zero.
High-bit aliases fail the bitwise predicate even when field equalities hold.

The component has 24 main columns, nine fixed columns, eight quadratic roots,
17 relation events and 36 interaction columns. It reuses existing byte-pair and
bitwise tables. Semantic identity:
`751f8d3a07d29de0f9e882b13c7b68e11f25cfffcd781620059123ed92a72542`.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-field-bytes test-blake3-field-bytes-proof -Doptimize=ReleaseSafe --summary all
```

Unit cases cover native canonical boundaries, each coordinate's field/byte/inverse
mutations, padding, the encoding of p, high-bit aliases, real table membership,
semantic authentication and framework export. The complete proof binds a QM31
source tuple to its canonical 16 bytes and hashes those bytes through the existing
private input bridge. The final digest matches standard BLAKE3. Trusted hash
preprocessing receives the length and final digest, not encoded message bytes.

The source tuple is public in this fixture; bytes are derived through constraints.
This is not yet private child-payload admission. Production arithmetic producers
must supply the source wire, and framed leaf/transcript payload routing still
needs integration. Complete PCS DEEP/FRI composition, source admission, production
identities, Metal and parent-of-parent qualification remain. Development proofs
use eight queries, blowup 1 and zero PoW. No production speed/security claim is
made; Poseidon remains the default and the full goal stays active.

Both guarded tests pass, including the complete core-verifier proof and changed
digest/preprocessing admission checks. Unit runtime was 501 ms; proof runtime
approximately 3 seconds, max RSS 349 MiB on M5 Max. Formatting and diff checks
pass. New manual sources remain below the source-size ceiling. Earlier evidence
snapshots are unchanged.
