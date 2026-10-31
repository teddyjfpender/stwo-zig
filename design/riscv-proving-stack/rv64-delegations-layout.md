# Delegations: layout and contract

Status: layout decision for the `codex/rv64-arith-memory` program (Workstream
D); executed after the CPU v3, LS v2 and coordinator workstreams land, so
that no file moves under a running build.

## 1. What a delegation is

A delegation is an independently sized component family that proves one
class of operations the CPU row only requests: it consumes typed bus
tuples the CPU emits (FUNCTION, MEMORY or SERVICE bus), proves the
semantics in its own rows at its own fixed log size, and closes its lookup
claims against the shared tables (U16, U8, AND). Zisk calls these
secondary state machines and precompiles; Airbender calls them delegation
circuits. Today the repository has four (Keccak-f, secp256k1 ADD/DOUBLE,
division, multiplication) under two unrelated trees (`air/crypto`,
`air/arithmetic`) with per-family naming, and their integrations are 24
flat `rv64_*` files. The layout below gives every delegation one directory
with the same file roles, so each can be improved in place and a new one is
added by copying the template.

## 2. Standard file roles (per delegation directory)

| File | Role | Required |
| --- | --- | --- |
| `README.md` | what it proves, bus tuple, provider shape, fixed log, mass formula, measured cost, open items | yes |
| `layout.zig` | column indices, widths, fixed log, `ROWS_PER_REQUEST` | yes |
| `equations.zig` | the constraint authority, `emitFor(comptime F)` over any lane | yes |
| `component.zig` | native component (vtable), degree bound, `evaluateQuotientsAtPointFor` | yes |
| `trace.zig` | witness fill from request facts (the fact ABI lives in `operations.zig` of the CPU lane) | yes |
| `interaction.zig` | LogUp columns: one accumulator, pair batching | yes |
| `cpu_bus.zig` | the bus tuple it consumes, its challenge tag, `denominatorFor` | yes |
| `packed_rows.zig`, `parallel.zig` | SIMD domain evaluation and the worker split | when the family has a packed lane |
| `tables.zig` | any private lookup table it owns | when needed |
| `bridge/` | the RAM bridge: lanes read/written as RAM tuples with the service tick | services only |
| `experimental/` | alternatives under measurement (the Keccak quartet) | optional, never imported by production |

Integrations mirror the frontend: `src/integrations/riscv_cpu/delegations/<name>/`
holds `sources.zig` (native source construction), `native.zig` (native
reference), `fixture_main.zig`, `verify_main.zig`, `test_root.zig`; shared
service plumbing (`journal.zig`, `proving_sources.zig`, `borrowed.zig`)
lives in `src/integrations/riscv_cpu/delegations/common/`.

## 3. Registry

`air/delegations/registry.zig` is the single list of delegations with:
actual operation IDs on the FUNCTION bus (ALU 0..9, composite JALR10, BINARY16..18, SHIFT32..37, MUL49..52/57, DIV53..56/58..61), SERVICE ids (Keccak 0x10001, secp ADD
0x20011, DOUBLE 0x20012, SHA-256 and others reserved), the bus kind each
consumes, provider shape (fixed/main/interaction, rows per request, fixed
log per protocol version), and the lookup-mass contribution formula. The
chip planner and the receiver read this registry instead of per-family
constants scattered through `rv64_keccak_cpu.zig`.

## 4. Mapping, old to new

| Old | New |
| --- | --- |
| `air/crypto/keccak/{layout,equations,component,trace,interaction,interaction_parallel,packed_row,packed_rows,parallel,gather,tables,cpu_bus,batch_policy}.zig` | `air/delegations/keccak/` same roles (`packed_row` folds into `packed_rows`, `interaction_parallel` into `parallel`) |
| `air/crypto/keccak/quartet_component.zig` | `air/delegations/keccak/experimental/quartet.zig` |
| `air/crypto/keccak/bridge/*` | `air/delegations/keccak/bridge/*` |
| `air/crypto/secp256k1/*`, `bridge/*` | `air/delegations/secp256k1/*` |
| `air/crypto/main_storage.zig` | `air/delegations/common/main_storage.zig` |
| `air/arithmetic/division/*` | `air/delegations/division/*` (`cpu.zig` becomes the CPU-side adapter in the Word16 lane, not here) |
| `air/arithmetic/multiplication/*` | `air/delegations/multiplication/*` |
| `rv64_keccak_sources.zig`, `rv64_keccak_native_diagnostic.zig`, `rv64_keccak_fixture_main.zig`, `rv64_keccak_cpu_verify_main.zig`, test roots | `integrations/riscv_cpu/delegations/keccak/{sources,native,fixture_main,verify_main,test_root}.zig` |
| `rv64_secp_sources.zig`, `rv64_ethereum_secp_context.zig`, `rv64_secp_fixture_main.zig`, test root | `integrations/riscv_cpu/delegations/secp256k1/{sources,context,fixture_main,test_root}.zig` |
| `rv64_division_native.zig`, `rv64_division_verify_main.zig`, test root | `integrations/riscv_cpu/delegations/division/` |
| `rv64_multiplication_native.zig`, `rv64_multiplication_verify_main.zig`, test root | `integrations/riscv_cpu/delegations/multiplication/` |
| `rv64_service_journal.zig`, `rv64_service_proving_sources.zig`, `rv64_borrowed_services.zig` | `integrations/riscv_cpu/delegations/common/{journal,proving_sources,borrowed}.zig` |
| `rv64_keccak_cpu.zig` (740 lines: the joined CPU+services PCS) | stays, but its per-family constants move to the registry |

`air/mod.zig` keeps `rv.crypto.*` and `rv.arithmetic.*` as compatibility
aliases to the new paths for one release so the legacy CPU and its tests
need no edits; the Word16 lane imports `rv.delegations.*` directly.

## 5. Planned delegations (directories created with a README only)

| Delegation | Replaces | Guest cost today | Shape sketch |
| --- | --- | ---: | --- |
| `sha256` | soft compress, 4,048 instructions per block | 11.2M | one row per round, 64 rows per compression, byte lookups |
| `memcpy` | `stwo-rv64-mem` word loops | 15.3M | DMA machine: one row per 8 bytes moved, two RAM tuples per row |
| `arith256` | secp field inverse/sqrt hints, modular mul | about 9M | one row per 256-bit product mod p, 16-bit limbs |
| `ecrecover` | 44.9k ADD/DOUBLE bus crossings per block | | full recovery as one service over `arith256` |

Each is added by copying the template, filling the registry row, and
qualifying with the family's own fixture and the coordinator's batch-0
measurement.
