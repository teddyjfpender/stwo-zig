# `ethereum_services_v3`: extension points for further admitted services

`ethereum_services_v3` is the v2 service roster (Keccak-f, LE-word secp
ADD/DOUBLE) plus SHA-256 compression (`0x0003_0010`). It is deliberately built
so that a sibling family (for example bulk memory `0x0003_0001`/`0x0003_0002`)
can join the same profile by merging, with additions kept in one place each.
Every v3 addition is appended after the v2 roster, so a bundle that uses no
v3 family is byte-identical to a v2 bundle.

| Layer | File | What a new v3 family adds |
|---|---|---|
| Tag and profile | `src/frontends/riscv/rv64/execution_profile.zig` | A tag constant; extend `admitsV3` (ISA decode/effects never change). |
| Native execution | `src/frontends/riscv/rv64/ethereum_services/session.zig` | A call record type, an `Event` arm, and a dispatch arm in `Session.step` before secp. |
| Compact tape | `src/frontends/riscv/rv64/compact_tape.zig` | A list, an `append*` (v3-only), `appendEvent`/`serviceCount`/`clear`. |
| Tape wire | `src/frontends/riscv/rv64/compact_tape_wire.zig` | A section after the SHA-256 records. The old reserved header word now holds the SHA-256 count; a further count needs a v3-only extension field, never a pre-v3 byte. |
| Boundary capture, census | `boundary_capture.zig`, `access_census.zig`, `ethereum_execution.zig` | One `Event` arm each. |
| Native jobs | `src/integrations/riscv_cpu/rv64_ethereum_batch.zig`, `rv64_work_packet_admission.zig`, `word16_execution/packet.zig` | Count the tag next to `sha256` (v3 tapes run under the v2-decoded ROM via `tapeMatches`). |
| CPU capture | `word16_execution/prepared.zig` | Add the tag to `.combined_words_v3`. |
| Services roster | `word16_global_execution/services/types.zig` | Append a `Family`, a `Logs` field (omitted from JSON when null), `words`/`bridgeWires`. |
| Collector | `services/collector.zig` | Per-shard advice list and a ledger arm (predecessors, rights, after-state). |
| Protocol | `services/protocol.zig` | `admit` masses, a conditional `beginCpu` block (only when the bridge is present), `beginTruth`/`drawTruth` arms. |
| Claims/wire | `services/statement.zig`, `services/wire.zig` | Five CPU claims appended only when present (`CpuClaims.count`); optional JSON fields. |
| Bridges/truths | `services/air_components.zig`, `services/roster.zig`, `services/worker.zig` | Bridge component, `Truth`/`TruthSource` arms, claim generation. |
| Ethereum driver | `word16_global_execution/ethereum/{plan,keys,main,role_cost,telemetry}.zig` | Planning, keys, the profile gate `admitProfile`, cost rows. |

Things a merge must preserve:

- `T.Family` order and `T.V2_FAMILIES = 3`: v2 ordinals, offsets and transcript
  words never move. Families with ID 4 and above must be appended.
- `CpuClaims.count`: today it is v2 or v2+SHA. A second v3 bridge needs a
  per-family presence vector rather than the single `sha256` flag.
- `admitProfile` in `ethereum/main.zig` is the receiver policy that gates v3
  families on the request's `execution_profile`.
- Wire35 program kind 3 is SHA-256. Another Wire35 family needs a fresh kind.
