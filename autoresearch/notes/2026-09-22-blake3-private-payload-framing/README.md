# Private arithmetic payloads in canonical frames — 2026-09-22

The previous turn qualified canonical QM31 bytes. This turn routes those bytes
through native leaf/transcript framing without exposing payload bytes in fixed
preprocessing.

The shared Frame writer now offers an optional indexed protocolWord callback for
leaf M31 words, QM31 coordinates and raw word payloads. Ordinary hashing sinks
still receive the same little-endian bytes. No protocol domain or encoding changes.
The existing symbolic router supports one checked payload range alongside digest
roles; it counts actual consumers across unaligned frame-word boundaries.
Missing/mismatched role or length, producer namespace aliasing and invalid wire
ranges are rejected. No second byte-routing AIR or private serializer was added.

The routed-frame witness now supports payload producers and exposes their exact
word-use counts. The earlier plain 16-byte hash proof fixture was upgraded to a
canonical leaf proof: authenticated QM31 tuple -> canonical coordinate words ->
routed leaf frame -> native BLAKE3 Merkle leaf digest. Trusted preprocessing uses
placeholder payload values and never receives encoded message bytes.

Focused commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-protocol test-blake3-field-bytes-proof test-blake3-byte-route -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-frame-witness -Doptimize=ReleaseSafe --summary all
```

Ten guarded tests pass. Native official/independent protocol vectors and CPU
PCS/FRI tests remain unchanged. The complete framed-leaf proof passes the core
verifier and changed-digest/preprocessing admission checks. Existing Merkle and
digest-frame routing tests pass. Payload tests cover leaf, secure-field and raw
word roles, exact fixed columns with zero placeholders, word multiplicities,
mismatched roles/lengths and allocation failures. A final range-admission guard
was tightened before the focused witness rerun; no valid framing or AIR changed.

Native protocol tests ran in 533 ms; byte routing in 702 ms; payload witness tests
in 651 ms. The complete leaf proof took approximately 3 seconds, max RSS 347 MiB
on M5 Max. These are development fixtures (eight proof queries, blowup 1, zero
PoW), not production performance/security results. Formatting and diff checks
pass; changed manual sources remain below the source-size ceiling.

The fixture source tuple remains public. Production arithmetic/child-proof
producers must supply authenticated field wires; complete private payload/source
admission and PCS DEEP/FRI composition remain. Production identities, Metal and
parent-of-parent qualification also remain. Poseidon is still the default and
the full recursion optimization goal stays active.
