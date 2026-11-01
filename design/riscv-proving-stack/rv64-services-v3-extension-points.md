# `ethereum_services_v3`: extension points for further admitted services

`ethereum_services_v3` is the v2 service roster (Keccak-f, LE-word secp
ADD/DOUBLE) plus three admitted services, integrated on
`codex/rv64-guest-prover-v3-integration` (see
[rv64-services-v3-integration.md](rv64-services-v3-integration.md)):

| Service | Tag | Services lane | Wire35 kind | Tape |
|---|---|---|---|---|
| SHA-256 compression | `0x0003_0010` | `T.Family` 3 + truth | 3 | records after secp; count in header word 28..32 (low 31 bits) |
| arith256_mod | `0x0003_0021` | `T.Family` 4 + truth | 4 | v3 extension after the SHA-256 records, flagged by bit 31 of word 28..32 |
| memcpy / memset (aligned) | `0x0003_0001` / `0x0003_0002` | bulk block after the families (desc/copy/set components inside the CPU proof, no truth) | none | none (the ECALL step carries pointer and tag) |

Every v3 addition is appended after the v2 roster, so a bundle that uses no
v3 family is byte-identical to a v2 bundle, and a SHA-only v3 bundle is
byte-identical to the pre-integration SHA-only bundle (both checked).

| Layer | File | What a new v3 family adds |
|---|---|---|
| Tag and profile | `src/frontends/riscv/rv64/execution_profile.zig` | A tag constant; extend `admitsV3` (ISA decode/effects never change). |
| Native execution | `src/frontends/riscv/rv64/ethereum_services/session.zig` | A call record type, an `Event` arm, and a dispatch arm in `Session.step` before secp. |
| Compact tape | `src/frontends/riscv/rv64/compact_tape.zig` | A list, an `append*` (v3-only), `appendEvent`/`serviceCount`/`clear`. |
| Tape wire | `src/frontends/riscv/rv64/compact_tape_wire.zig` | Canonical order: steps, memory, Keccak, secp, SHA-256, then the v3 extension (u32 arith256_mod count, u32 reserved, records), present only when bit 31 of the SHA-256 count word is set. A further family claims the extension's reserved word (and keeps the extension absent when unused). `rv64_work_packet_budget.zig` and `rv64_work_packet_admission.zig` mirror this layout. |
| Boundary capture, census | `boundary_capture.zig`, `access_census.zig`, `ethereum_execution.zig` | One `Event` arm each. |
| Native jobs | `src/integrations/riscv_cpu/rv64_ethereum_batch.zig`, `rv64_work_packet_admission.zig`, `word16_execution/packet.zig` | Add the tag to `execution_profile.admitsV3` and count it next to `sha256`/arith/bulk (v3 tapes run under the v2-decoded ROM via `tapeMatches`). Payload-free families (bulk) add their worst-case touched words to the admission cell bound. |
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
- `CpuClaims.mix`: the v2 vector and the five claims of every present v3
  family (`T.V3` order) are mixed in ONE `mixFelts` call; the channel mix is
  not concatenation-invariant, so splitting it per family changes every
  SHA-only transcript (this regression was found and fixed during the
  integration). Bulk claims are a separate trailing call, only when present.
- `admitProfile` in `ethereum/main.zig` is the receiver policy that gates v3
  families on the request's `execution_profile`.
- Wire35 program kinds 3 (SHA-256) and 4 (arith256_mod) are taken; another
  Wire35 family needs kind 5 or above. `T.Family` 5 is the next family ordinal.
- Bulk-style components that live inside the CPU proof without a truth go in
  the block after the families (roster sources, fixed columns, components,
  claims, wire JSON), never between families.
