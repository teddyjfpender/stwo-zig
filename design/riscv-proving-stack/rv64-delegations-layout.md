# Delegations: layout and contract

The existing independently sized DIV/REM, MUL, Keccak and secp256k1 providers
have one physical owner: `src/frontends/riscv/rv64/air/delegations/`. This is a
source-layout change. Polynomial authorities, committed layouts, runtime
profiles, transcripts and admission policies remain unchanged.

## Provider ownership

Each implemented family keeps its concrete files and helpers. Existing split
files are retained rather than combining unrelated algorithms during a move.
There are no empty files or future-family directories to match a template.

| Owner | Existing responsibilities |
| --- | --- |
| `delegations/division/` | DIV/REM layout, provider, trace, component, legacy CPU policy and adapter |
| `delegations/multiplication/` | MUL layout, provider, trace, component and CPU bus |
| `delegations/keccak/` | paired permutation, lookup tables, native interaction and packed/domain kernels |
| `delegations/secp256k1/` | concrete modular arithmetic, immutable programs, native traces and packed/domain kernels |
| family `bridge/` | existing authenticated service RAM bridge |
| `delegations/main_storage.zig` | shared allocation/span admission helper |

The existing Keccak quartet remains an explicitly experimental component at
`keccak/quartet_component.zig`. Ordinary registry geometry refers to the paired
component; no production selection changes as a consequence of relocation.
Generic range tables, CPU control, RAM policy and PCS orchestration keep their
own owners outside these family directories.

`rv64_air.delegations` exposes the physical modules. Existing
`rv64_air.arithmetic.{division,multiplication}` and
`rv64_air.crypto.{keccak,secp256k1,main_storage}` remain aliases to exactly the
same modules, preserving public type identity.

## Registry authority

`air/delegations/registry.zig` inventories existing physical widths from the
family layout constants. Arithmetic routing derives the actual immutable
`OPCODES` sets. The raw decoded FUNCTION coordinates are:

- MUL: 49 through 52, and MULW 57.
- DIV/REM: 53 through 56, and 58 through 61.

These sets are interleaved. The earlier proposed contiguous MUL48/DIV64 ranges
are not this protocol. Existing pure ALU0..9, BINARY16..18 and SHIFT32..37
vocabularies remain under their own authorities. New full-CPU JALR delegation
and its normalized zero-immediate case belong to that concrete CPU protocol,
not to a source-layout registry accepting unknown operations.

Service tags come from `rv64/execution_profile.zig`, including Keccak0x10001,
byte-format secp0x20001/0x20002 and word-format secp0x20011/0x20012. No tags are
reserved or admitted merely by adding a registry row. The registry is not an
accepting receiver: concrete protocols still own profile admission, expected
geometry, lookup-mass bounds and every physical claim closure.

## Integration ownership

Existing sources and entry roots mirror their provider families under
`src/integrations/riscv_cpu/delegations/`:

| Existing file | Physical destination relative to `delegations/` |
| --- | --- |
| `rv64_keccak_sources.zig` | `keccak/sources.zig` |
| `rv64_keccak_native_diagnostic.zig` | `keccak/native.zig` |
| `rv64_keccak_fixture_main.zig` | `keccak/fixture_main.zig` |
| `rv64_keccak_cpu_verify_main.zig` | `keccak/verify_main.zig` |
| Keccak ordinary/CPU/quartet test roots | `keccak/{test_root,cpu_test_root,quartet_test_root}.zig` |
| `rv64_secp_sources.zig` | `secp256k1/sources.zig` |
| `rv64_ethereum_secp_context.zig` | `secp256k1/context.zig` |
| secp fixture CLI and test root | `secp256k1/{fixture_main,test_root}.zig` |
| `crypto/{secp_fixture,secp_bridge_fixture}.zig` | `secp256k1/{fixture,bridge_fixture}.zig` |
| DIV native/receiver/test root | `division/{native,verify_main,test_root}.zig` |
| MUL native/receiver/test root | `multiplication/{native,verify_main,test_root}.zig` |
| `rv64_service_journal.zig` | `common/journal.zig` |
| `rv64_service_proving_sources.zig` | `common/proving_sources.zig` |
| `rv64_borrowed_services.zig` and test root | `common/{borrowed,borrowed_test_root}.zig` |
| `rv64_arithmetic_diagnostic.zig` | `common/arithmetic_diagnostic.zig` |

This moves 24 existing files, including the two existing secp fixture helpers.
`rv64_keccak_cpu.zig` stays as the legacy joined coordinator. Request,
batch-receipt and distributed-manifest authorities stay in their existing
locations. Their importers are not silently moved into a delegation family.

Nested standalone roots need the owning integration package as their Zig module
boundary. Two package-root entry shims select only statically registered nested
sources through typed build options. `riscv_delegation_entry.zig` rejects
unregistered paths and wrong test/tool kinds; the shims contain literal imports
for the actual entries. Existing nested test files are compiled in the root
module, so their tests are discovered. Exporting tests through a dependency
module is deliberately avoided: that compiles an empty test shell. Each moved
suite's guard floor increases by one for the additional entry-shim test.
Executable target names and CLI argument contracts remain unchanged.

## Qualification and future work

The AIR move and integration move have separate qualification receipts. Each
compares every moved body with its pinned predecessor after normalizing import
literals, then runs the existing native/AIR and concrete family proof suites.
The integration slice additionally builds and runs relocated CLI receivers in
fresh processes against independently retained artifacts.

Future providers need an actual constraint authority, complete physical claim
closure and their own qualified fixture before a directory or registry entry
is introduced. SHA, memcpy, wide arithmetic and full recovery proposals do not
create accepting interfaces or placeholder directories here. New Word16,
shared-alpha and recursion protocols retain their separate qualification scope.
