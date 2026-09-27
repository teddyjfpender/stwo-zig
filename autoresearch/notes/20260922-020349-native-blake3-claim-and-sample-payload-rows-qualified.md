---
title: Native BLAKE3 claim and sample payload rows qualified
author: Teddy Pender
created_utc: 2026-09-22T02:03:49Z
---

# Native BLAKE3 composition payload connections

The native composition adapter now prepares canonical transcript payload joins
for 28 component aggregate claims and 705 sampled values in the real nonfinal
BLAKE3 capture. These 733 secure values produce 2,932 scalar-source rows, 733
QM31 pack rows and 733 canonical field-byte encoding rows. It uses existing
scalar_wire_source, qm31_pack_wire and blake3_field_bytes AIRs; no new cryptographic
primitive or AIR identity was introduced.

Authenticated VM bindings determine exactly four input nodes per value. Scalar
producers emit graph use counts plus one pack consumption; each pack emits one
secure value to its encoder; each encoder emits the exact transcript byte-word
read counts. Trusted and live receipts must agree in operation, endpoint and
multiplicity. Every selected payload occurs exactly once. Operation values must
match all four composition evaluation coordinates. Missing nodes/receipts,
duplicate payloads and wrong shapes or values reject.

The native recorder and transcript adapter now expose their canonical claim and
sample source constants, so downstream code does not duplicate those assignments.
All returned row buffers belong to one arena with rollback on preparation errors.
Fixed rows retain only graph/endpoint coordinates and multiplicities; witness
cells are zero. The integration gate checks this for all three row kinds and
checks missing-receipt and changed-claim rejection.

Detailed physical claims remain private VM inputs. The existing composition
recorder's bindTranscriptAggregates constrains their reduction to the 28 canonical
claims; this adapter connects those aggregate inputs to the transcript rather
than conflating the two claim arrays. No claim authority was weakened.

Qualification command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-recorder test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0: 8/8 steps, 4/4 tests passed. Native tests: 20 s / 1 GiB,
compile 57 s / 4 GiB. Recorder ownership/allocation-failure test: 498 ms / 1 MiB,
compile 3 s / 417 MiB. Formatting and git diff --check passed. No broad suite
ran and no build remains live.
The initial native segment gate passed 3/3 tests, with 57 s / 4 GiB compilation
and 20 s / 1 GiB test execution. Tiny q1/PoW0 diagnostics are not canonical CSP
measurements or speedup evidence.

Scope: row construction and native capture parity. These rows are not yet all
included in a complete native recursive parent proof. Remaining joins include
shared sampled-value consumption by PCS/DEEP, public-boundary/native-sum authority,
challenge fanout and the complete parent roster. Statement-independent keys,
production artifact admission, Metal and parent-of-parent qualification remain.
