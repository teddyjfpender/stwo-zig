---
title: Native BLAKE3 transcript DEEP and FRI query joins qualified
author: Teddy Pender
created_utc: 2026-09-22T02:28:09Z
---

# Native BLAKE3 query joins

Native query row preparation reuses canonical blake3_query_links to map transcript
outputs to DEEP query positions, the 31 DEEP/FRI query bits, and FRI derived
positions/offsets. Transcript-plan and live output schedules must match exactly;
operation domain and ordered query values must match the validated DEEP graph.
Both graph evaluations are validated before any rows are admitted.

Each DEEP position scalar emits for its graph consumers plus canonical encoding.
The field-byte AIR uses negative emission for the transcript's emitted byte word,
as in the qualified joined PCS fixture. Each DEEP bit emits for its arithmetic
consumers plus one FRI consumer. All shared bits agree and are Boolean. FRI
derived position/offset producers use graph-derived multiplicities and remain
constrained by the canonical FRI arithmetic. Fixed rows contain no witness values.

The native gate compares row/fixed schedules and encoded native query values,
rejects missing query outputs, and rejects a changed query operation position.
The prior composition, payload, DEEP, FRI, challenge and terminal checks remain.

Serial command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Final terminal exit 0: 4/4 build steps, 3/3 tests passed. One query produces
104 scalar rows (position, 31 paired bits and 41 derived FRI inputs), plus one
canonical byte-encoding row. Compile 59 s / 4 GiB; tests 20 s / 1 GiB. Formatting
and git diff --check pass. No broad suite ran and no live build remains.
This tiny q1/PoW0 qualification
is not a canonical CSP measurement or a production speed/security claim.

Remaining: path direction and lifted-projection consumers need explicit extra
bit-read multiplicities before final parent materialization. The returned query
mapping exposes the canonical bit nodes, but mutating its path counters does not
retroactively update prepared rows. Native authenticated trace/FRI paths and
public-boundary authority must be joined before the complete parent proof.
Production keys, statement-independent preprocessing, Metal and parent-of-parent
qualification remain outstanding.
