# OP Stack product integration

Status: design of record for porting PR #372 onto `main`. Implementers copy this
file to `design/opstack/integration.md`, and copy its companion
`integration-map.tsv` (one row for each of the 1,885 branch files) to
`design/opstack/integration-map.tsv`.

| Input | Value |
|---|---|
| Source branch | `origin/codex/rv64-opstack-study` @ `089bc2437` (PR #372), merge base `93036ac93` |
| Target | `origin/main` @ `e625fd582` or newer |
| Branch diff [M] | 1,885 files (1,705 added, 180 modified, 0 deleted), +342k lines |
| Plan of record | `design/repository/restructure-plan.md` §3, §6.2, §6.3; `ENGINEERING_STANDARDS.md` §1, §5–§7 |
| Archive for anything not ported | `https://github.com/starknet-innovation/stwo-zig/tree/089bc2437` (the PR head; do not delete the branch until the owner archives it) |

Measurements are labelled [M] (measured from git trees), [D] (derived from
measurements) or [E] (estimated).

---

## 0. Decisions that shape everything else

1. **Two parallel parts, four stages.** PART ASSETS (non-`src`) and PART SRC
   (`src`, wiring and conformance) own disjoint files (§9). Stages:
   - **S0 (assets):** the guest, tools, fixtures, golden vectors, inventory and docs.
   - **S1 (product core):** needs **no owner decision**. It adds only new packages,
     plus wiring rows in shared catalog files.
   - **S2 (BN254 sparse-tower service and RV64 fixes):** waits on RFC-2 to RFC-4
     and their CB-2 budget rows.
   - **S3 (pure-P2 recursion, waist/engine, circuit and settlement):** waits on
     RFC-5 to RFC-9.

   This integration delivers S0 and S1, and opens the RFC issues for S2 and S3.
   The S2/S3 source stays on the PR head, mapped file by file in
   `integration-map.tsv`.
2. **The S1 product proves without any shared-code edit.** The S1 acceptance blocks
   use the Kona `sha` and `canonical` guest variants. These need only main's
   admitted `ethereum_services_v3` services: CPU, Keccak, SHA-256, secp, arith256,
   bulk memory and sponge. The branch measured 120794432 this way: "CPU + Keccak +
   SHA, exact 43-byte result, fresh receiver" (`opstack/COMPLETION.md`) [M].
   - The BN254 sparse-tower packet (`.tower`, `OP_TOWER_TAG 0x0004_0001`) is an
     S2 optimisation for the `pairing*` guest variants.
   - The pure-P2 recursion lanes are S3.
3. **No Ethereum edits, ever.** Nothing under `src/products/ethereum`,
   `guests/ethereum` or `tests/fixtures/ethereum` changes. Every OP edit the branch
   made inside Ethereum files is replaced (§4).
4. **Shared code is product-neutral and additive.** S1 creates exactly two
   packages:
   - `stwo_opstack_statement` (`src/products/opstack/statement`, layer `product`).
   - `stwo_riscv_rv64_pipeline` (`src/integrations/riscv_cpu/rv64_pipeline`, layer
     `integration`).

   New packages have no previous ceiling, so no `package_budget_changes` row is
   needed (`package_budget.review_errors`: `previous.returncode → continue`).
   Every existing shared package is at its ceiling [M]: riscv_cpu 949/949 files,
   rv64 526/526, precompiles 86/86 and Ethereum 427/427. Any edit to one of them is
   an S2/S3 item.
5. **One product package first.** This follows the Ethereum precedent, which is one
   package holding `frontend/`, `cpu/` and `cuda/` component roots. OP Stack starts
   as `src/products/opstack/statement` with `frontend/` and `cpu/` roots.
   - `products/opstack/cuda` (job driver) and `products/opstack/settlement_air`
     arrive with S3, each as its own package.
   - No `build_support/products/opstack/catalog.zig` is created. Every OP step lives
     in the package `build.zig`, so the root catalog and
     `check_build_configure_closure.py` are not touched.
6. **There is no Lean on the branch.** `opstack/kona/lean` is a Rust "lean" guest
   variant. `formal/opstack/` is reserved: the S0 layout creates no files there, and
   it gains `lean-toolchain` plus a `toolchain.json lean["formal/opstack"]` pin only
   when a proof is written.
7. **Evidence stays out of the tree.** None of the 628 `vectors/reports/rv64-opstack-*`
   files comes over. The six files that live code reads become small golden
   fixtures with SHA-256 hashes (§2, rules G1–G4, G6). Everything else is linked at
   the PR head.

---

## 1. Target tree

```text
src/products/opstack/statement/              stwo_opstack_statement  (product, owner opstack-statement)   [S1]
  package.contract.json  build.zig.zon  build.zig  README.md
  mod.zig                                    primary module: frontend, cpu, hooks, statement
  frontend.zig  cpu.zig                      component roots (pattern of products/ethereum/statement)
  build_components.zig                       binds component imports (Ethereum pattern)
  frontend/guest_abi.zig                     OP/Kona guest ABI: Symbols, 4..32 MiB power-of-two input window, load()
  frontend/statement.zig                     43-byte transition output: decode, expected-output binding
  frontend/services_session.zig              v3 services session on neutral rv64 APIs (exception E-2)
  frontend/execution.zig                     execution runner + report (oracle comparison input)
  cpu/hooks.zig                              OpStackHooks: implements rv64_pipeline.ProductHooks
  cpu/native_main.zig                        executable `stwo-opstack-native` (subcommands §6.1)
  tests/{guest_abi,statement,hooks_contract,e2e_probe}_test.zig
  (S2) frontend/bn254_candidate.zig, tests/bn254_tower_test.zig
  (S3) cpu/recursion/  (rv64_op_* roots, public fold, group roots, OP producer glue)
src/products/opstack/cuda/                   (S3) job driver; settlement AIR fixture main
src/products/opstack/settlement_air/         (S3) only if the settlement verifier needs Zig-side fixtures

src/integrations/riscv_cpu/rv64_pipeline/    stwo_riscv_rv64_pipeline (integration, owner riscv-cpu-integration) [S1, RFC-1]
  package.contract.json  build.zig.zon  build.zig  README.md
  mod.zig                                    Pipeline(Hooks), ProductHooks contract, assertHooks
  hooks.zig  request.zig  image.zig          Config(Hooks), Request, Owner(Hooks)
  plan.zig  truth_plan.zig  cpu_plan.zig  capture*.zig  input_timeline.zig  cpu_prestage.zig
  keys.zig  receiver*.zig  receiver_setup.zig  receiver_batch.zig  native_batch.zig
  resources.zig  setup_cache*.zig  terminal.zig  telemetry.zig  profile_selection.zig
  native.zig                                 native-only production and reception entry (no recursion deps)
  tests/

src/frontends/riscv/precompiles/bn254/       (S2, RFC-2) stwo_riscv_bn254 std/core-only primitive package

guests/opstack/                              [S0] Rust guests (no package contract; `guests` CI rule)
  README.md  rust-toolchain.toml (nightly-2026-08-08 + rust-src)
  kona/{Cargo.toml,Cargo.lock,src/,guest/,lean/,tests/}   Kona execution crate, RV64 guest, "lean" variant
  mantle/{Cargo.toml,Cargo.lock,src/,guest/,tests/}       Mantle pilot (OP-Stack chain)
  runtime/exact_layout_allocator_v2.rs                     fork with the volatile-store fix (E-3)
  vendor/{ark-ff,ark-bn254,ark-bls12-381,kona-mpt,kona-protocol,op-revm,revm-bytecode}/  + LICENSE/UPSTREAM.json
  abi_probe/                                 NEW tiny no_std guest on the OP ABI for hosted end-to-end tests
tools/opstack/                               [S0] tooling root `opstack` in conformance/tooling-surface-v1.json
  README.md  requirements-host.txt  .gitignore
  *.py                                       build/mainnet/benchmark/cpu/cpu_batch/capture/... harnesses
  capture_host/{blob_check,slot_search}/     Rust crates (rust-toolchain.toml + toolchain.json pins)
  presets/  recovery/  pairing_schedule/  g2_subgroup/  mac6/  mac12/  (analysis tools)
  settlement/{src,test,tools}/               Solidity + JS verifier, capture patches (not run in CI)
  tests/                                     unittest suites (run by the opstack lane)
tests/fixtures/opstack/                      [S0] system-test fixtures + MANIFEST.json (sha256, bytes, source)
  fixtures.json  mainnet-fixtures.json       upstream Kona fixture pins (fetched, not committed)
  mainnet-corpus.json  heavy-mainnet-plan.json  pairing-schedule/*.json  transition-159257842-receipt.json
  transition-159321794/{README.md,manifest.json}   input.opd.gz (13.9 MB) fetched by sha256, not committed
  settlement/*.json(.gz)  *.json(.zlib)
vectors/opstack/                             [S0] golden vectors only, every file in vectors/MANIFEST.json
  abi-probe.elf  abi-probe.json              prebuilt probe guest + {sha256, toolchain, source tree hash}
  kona-guest-identity.json                   variant -> ELF sha256, Cargo.lock sha256, toolchain (read by tests)
  transition-outputs.json                    pinned block -> expected 43-byte output (read by statement_test)
formal/opstack/                              reserved; empty until a Lean proof exists
design/opstack/                              integration.md (this), integration-map.tsv, ported OP notes
third_party/INVENTORY.json                   + 7 entries for guests/opstack/vendor/* (§2, rule F1/C1)
```

---

## 2. Mapping: branch file → target

`integration-map.tsv` holds the full mapping (`archive@089bc2437` = not ported; read it at the PR head), one row for each of the 1,885 files.
It is generated by applying the ordered rules below, where the first match wins.
The generator fails if any file is unmatched, and every rule matches at least one
file [M]. Columns: `branch_path, class, status, added, removed, main_path, target,
action, stage, part, rfc_or_exception, rule`.

Actions:
- **port:** copy as-is, then rewrite paths.
- **adapt:** port, then edit names, paths or imports.
- **fork:** copy main's file and apply the branch delta beside the shared original.
- **replace:** do not apply the branch edit; implement the stated replacement.
- **replace-with-golden:** a small hashed fixture.
- **replace-with-link:** not committed; the manifest keeps a hash and a PR URL.
- **rfc:** waits on the named RFC.
- **defer:** the content waits on an RFC, at the new path shown.
- **drop.**

| Rule | Branch paths | Files [M] | +/− [M] | Target | Action | Stage / part |
|---|---|---:|---:|---|---|---|
| G1–G4 | 4 `vectors/reports/…` JSONs read by OP tools/tests | 5 | +662 | `tests/fixtures/opstack/{mainnet-corpus,heavy-mainnet-plan,pairing-schedule/*}.json` | replace-with-golden | S0 ASSETS |
| G5 | all other `vectors/reports/**` | 623 | +169,559 | PR-head link | drop | — |
| G6 | `opstack/transition-159257842-receipt.json` | 1 | +110 | `tests/fixtures/opstack/` | replace-with-golden | S0 ASSETS |
| G7 | `settlement/fixtures/native-deep-120794432-receipt.json` | 1 | +59 | PR-head link | drop | — |
| F1 | `opstack/kona/vendor/**` (ark-ff 50, kona-protocol 57, ark-bls12-381 29, ark-bn254 25, op-revm 24, kona-mpt 18, README) | 204 | +52,155 | `guests/opstack/vendor/**` + INVENTORY entries | port | S0 ASSETS |
| F2 | `opstack/kona/**` | 62 | +12,981 | `guests/opstack/kona/**` | port | S0 ASSETS |
| F3 | `opstack/mantle/**` | 13 | +4,034 | `guests/opstack/mantle/**` | port | S0 ASSETS |
| F4 | `opstack/tests/fixtures/transition-159321794/input.opd.gz` (13,885,356 B) | 1 | bin | not committed; sha256 + PR blob URL in manifest | replace-with-link | S0 ASSETS |
| F5 | `opstack/tests/fixtures/**` | 11 | +592 | `tests/fixtures/opstack/**` | port | S0 ASSETS |
| F6 | `opstack/tests/*.py` | 29 | +2,589 | `tools/opstack/tests/` | adapt | S0 ASSETS |
| F7 | `opstack/{capture_host,presets,recovery,tools}/**` | 46 | +3,966 | `tools/opstack/…` | adapt | S0 ASSETS |
| F8 | `opstack/README.md` | 1 | +446 | `tools/opstack/README.md` | adapt | S0 ASSETS |
| F9 | `opstack/*.md` (COMPLETION, CPU_TUNING, DESIGN, …) | 11 | +2,311 | `design/opstack/` | adapt | S0 ASSETS |
| F10 | `opstack/*.py`, `*.json`, `.gitignore`, `requirements-host.txt` | 30 | +5,889 | `tools/opstack/` | adapt | S0 ASSETS |
| F11 | `settlement/fixtures/**` | 13 | +2,270 | `tests/fixtures/opstack/settlement/` | port | S0 ASSETS |
| F12 | `settlement/tools/export_deep_vector.zig` | 1 | +149 | S3 settlement package step | defer (RFC-9) | S3 |
| F13 | `settlement/**` (sol, mjs, py, md, patches) | 47 | +5,925 | `tools/opstack/settlement/` | port | S0 ASSETS |
| D1–D2 | `design/riscv/**` OP and generic notes | 38 | +3,475 | `design/opstack/` | port | S0 ASSETS |
| C1 | `guests/ethereum/rv64/vendor/revm-bytecode/**` edits | 6 | +974/−322 | `guests/opstack/vendor/revm-bytecode/` | fork (E-3) | S0 ASSETS |
| C2 | `guests/ethereum/rv64/src/keccak_sponge_service.rs` | 1 | +57 | `guests/opstack/kona/guest/src/` | fork (E-3) | S0 ASSETS |
| O1 | `guests/exact_layout_allocator_v2.rs` (LTO volatile fix) | 1 | +9/−3 | `guests/opstack/runtime/` | fork (E-3) | S0 ASSETS |
| H1 | `build_support/products/{riscv_op_tests,step_catalog,riscv_cpu*,riscv_recursion,product_specs,circuit_recursion_cpu}.zig` | 8 | +243/−8 | package `build.zig` steps | replace | S1 SRC |
| H2 | riscv_cpu/riscv_cuda `build.zig`, `build.zig.zon`, contract | 4 | +17/−2 | — | drop | S1 |
| H3–H5, H7 | `conformance/{ci-touchpoints,rv64-flags,rv64-productionisation-budget}.json`, `scripts/tests/test_ci_package_graph.py` | 4 | +238/−4 | same files, redone on main (§7) | replace | S1 SRC |
| H6, H8–H10 | `ci.yml`, `test_opstack_ci_contract.py`, `dev_test.py`, `ci_scope_plan.py`, `test_dev_test.py`, `rv64_resident_basket.py` | 6 | +297/−4 | — | drop | S1 |
| P1 | branch pipeline split: `word16_global_execution/ethereum/{capture_plan,capture_spill,cpu_plan,cpu_prestage,input_timeline,native_batch,profile_selection,receiver_batch,receiver_setup,resources,resources_test}.zig` | 11 | +1,182 | `src/integrations/riscv_cpu/rv64_pipeline/` | adapt (RFC-1, E-1) | S1 SRC |
| P2 | edits to Ethereum pipeline files (`gkr_main`→`gkr_request_execution`, `plan`, `capture*`, `direct`, `gkr_receiver`, `receiver_budget`, `setup_cache*`) | 11 | +319/−657 | delta applied **only** to the neutral copy in `rv64_pipeline` | replace (E-1) | S1 SRC |
| P3 | `rv64_word16_ethereum_native_main.zig` | 1 | +4 | `products/opstack/statement/cpu/native_main.zig` | adapt | S1 SRC |
| P4, P6 | `rv64_ethereum_request.zig`, `word16_execution/expected_image.zig` | 2 | +28/−5 | `rv64_pipeline/{request,image}.zig` (generic over Hooks) | replace | S1 SRC |
| P5, P7 | `rv64_ethereum_chain_test_root.zig`, `services/{v3,sponge}_fixture.zig` (now Ethereum files) | 3 | +54/−15 | — | drop | S1 |
| Q1–Q3 | `ethereum_contract.zig`, `ethereum_execution.zig`, `ethereum_services/session.zig` | 3 | +34/−14 | `products/opstack/statement/frontend/{guest_abi,execution,services_session}.zig` | replace (E-2) | S1 SRC |
| Q4–Q6 | `ethereum_services/{candidate_curves,montgomery_bn254,bn254_tower}.zig` | 3 | +233/−4 | `precompiles/bn254/{montgomery,sparse_tower}.zig`; OP `bn254_candidate.zig` | defer (RFC-2) | S2 |
| Q7 | `ethereum_services/tower_call.zig` | 1 | +49 | `frontends/riscv/rv64/services/bn254_tower_call.zig` | defer (RFC-3) | S2 |
| A1 | `rv64/air/delegations/bn254_*/**` | 84 | +9,549 | std/core-only closure → `precompiles/bn254/`; AIR → `rv64/air/delegations/bn254_*` | defer (RFC-2/3) | S2 |
| A2–A3 | loose `rv64_bn254_*_test_root.zig`, `rv64_op_*_test_root.zig`, `op_tower_test.zig` | 18 | +229 | focused steps in the owning package | defer | S2 |
| B1–B3 | serialized Keccak sponge, `parallel_rows_family`, `packed_fields`, `wide_sinks`, `program/setup` | 15 | +1,514/−99 | same paths | rfc (RFC-4) | S2 |
| B4 | rv64 tower plumbing: `compact_tape(_wire)`, `boundary_capture`, `execution_profile`, `curves/*`, `secp256k1/word16_bridge/*`, `air/mod`, `delegations/mod`, test roots | 18 | +465/−122 | same or main-moved paths, neutral names | rfc (RFC-3) | S2 |
| I1–I2 | `riscv_cpu/delegations/op_*/**`, `gkr_local/op_tower_{role,projection}.zig` | 57 | +10,030 | `delegations/bn254_*`, `gkr_local/bn254_tower_*` | defer (RFC-3) | S2 |
| I3–I6 | `services/**` (roster, protocol, gkr_local ×28, …), `word16_execution/{fixed_setup,prepared,sources}`, `rv64_program_authority` | 43 | +1,206/−187 | same paths; `.tower`/`op_only` threading → service-family hook, the rest → RFC-4 | rfc (RFC-3/4) | S2 |
| I7 | `riscv_cpu/rv64_op_*.zig` (roots, joins, public fold, pure-P2 roots) | 18 | +709 | `products/opstack/statement/cpu/recursion/` | defer (RFC-9) | S3 |
| I8 | `riscv_cpu/poseidon2_outer/**` (A 195 + B_new 116 + B 7) | 318 | +42,463/−96 | generic → same path, neutral symbols and domains; OP glue → product | defer (RFC-9) | S3 |
| I9–I11 | `outer_gkr/**`, `logup_gkr/**`, `rv64_recursion/**`, loose test roots, riscv_cpu README | 56 | +3,215/−43 | same paths | rfc (RFC-9) | S3 |
| I12 | `riscv_cuda/rv64_settlement_air_fixture_main.zig` | 1 | +64 | `products/opstack/cuda/` | defer (RFC-9) | S3 |
| W1–W2 | `waist/core` OM31 batch inversion; Poseidon2 sponge4 + packed Merkle | 7 | +347/−2 | same paths | rfc (RFC-5/6) | S3 |
| E1–E6 | `engine/prover/{lookups,air,pcs,poly,vcs_lifted,allocators}`, `backends/cpu_scalar/mod.zig` | 26 | +754/−78 | same paths | rfc (RFC-7a–f) | S3 |
| X1 | `integrations/circuit_cpu/**`, `frontends/{circuit,cairo}`, `products/cairo/tools/composition_cpu_codegen` | 22 | +1,237/−100 | owner packages | rfc (RFC-8) | S3 |

Totals by stage [M]:

| Stage | Files | What happens |
|---|---:|---|
| S0 | 520 | 388 port, 117 adapt, 8 fork, 6 golden, 1 link |
| S1 | 53 | 28 replace, 12 adapt, 13 drop |
| S2 | 239 | 163 defer, 76 rfc |
| S3 | 449 | 338 defer, 110 rfc, 1 drop |
| DROP | 624 | evidence and receipts |

---

## 3. Shared pipeline: how OP Stack plugs in without product names

### 3.1 Why a new neutral package

On main, the whole word16 block pipeline lives in
`src/products/ethereum/statement/cpu/word16_global_execution/ethereum/`: 39 files,
about 8.9k lines [M]. A product may not import another product
(`ALLOWED_DEPENDENCY_LAYERS["product"]` excludes `product`; RS-3). Measured
coupling to Ethereum:

| Coupling | Count [M] | Neutral equivalent |
|---|---:|---|
| `ethereum_frontend_component.rv64_air.*` | 22 | `@import("stwo_riscv_frontend").rv64_air.*` (Ethereum's `air.zig` only re-exports it) |
| `ethereum_frontend_component.rv64.{execution_profile,compact_tape,checkpoint}` | 7 | `@import("stwo_riscv_rv64").execution.*` |
| `rv64_ethereum_request.zig` (`Config.symbols`, `ethereum_contract.load`, `validateBudget`) | 7 imports | `Hooks.Symbols`, `Hooks.loadImage`, `Hooks.admitsProfile` |
| `expected_image.zig` (`MAX_INPUT_BYTES`, `fromEthereumElf`) | 7 imports | `Hooks.MAX_INPUT_BYTES`, `Image.Owner(Hooks)` |
| terminal spec (`halt_flag`, 43-byte expected output) | 1 | `Hooks.haltFlag`, `Hooks.OUTPUT_BYTES` |

Everything Ethereum-specific is the guest ABI, the admitted profiles and the
output binding, so a small hook set is enough. Copy the branch's own split files
and the native-only path into `stwo_riscv_rv64_pipeline`, then rewrite those
imports.

The package depends on exactly six packages: `stwo_core`, `stwo_prover_engine`,
`stwo_prover_api`, `stwo_riscv_frontend`, `stwo_riscv_rv64` and
`stwo_riscv_cpu_integration`. It has no `stwo_circuit_*`, CUDA or Metal
dependency, because S1 is native-only.

Size [E]: 6.5–8k lines, tests included. It contains no `getenv`. Every runtime
choice is an `Options`/`Resources` field set by the product CLI, so the package
budget has `rv64_registry_flags: 0`.

### 3.2 The hook interface (`src/integrations/riscv_cpu/rv64_pipeline/hooks.zig`)

The interface is comptime and duck-typed, validated by `assertHooks` at the
`Pipeline` instantiation, so it costs nothing at runtime. Names are neutral, and
`api_surface` contains no product name (P-3, `check_product_placement`).

```zig
const std = @import("std");
const rv = @import("stwo_riscv_rv64").execution;

/// A product line's guest contract. Everything here is statement-level: it
/// decides which guest, inputs and outputs a proof binds, never transcript
/// order, AIR shape or proof bytes.
pub fn assertHooks(comptime H: type) void {
    // Short product label: receipts, CLI help and error context only.
    // It MUST NOT be mixed into any transcript, domain separator or digest.
    _ = @as([]const u8, H.label);
    // Guest ABI symbol set; decoded from the request JSON by std.json.
    _ = H.Symbols;
    // Bytes of public output bound by the terminal AIR (Ethereum and OP: 43).
    _ = @as(usize, H.OUTPUT_BYTES);
    // Largest admitted input payload (window minus the 4-byte length prefix).
    _ = @as(usize, H.MAX_INPUT_BYTES);
    // Profiles this product proves. Pipeline rejects all others before capture.
    _ = @as(fn (rv.execution_profile.Profile) bool, H.admitsProfile);
    // Map ELF + input into the immutable initial image. Errors are the
    // product's own (`error.InvalidGuestIoLayout`); no partial image escapes.
    _ = @as(fn (std.mem.Allocator, H.Symbols, []const u8, []const u8) anyerror!rv.elf.LoadedImage, H.loadImage);
    // Address of the halt flag; the output page follows at +8 (terminal AIR spec).
    _ = @as(fn (H.Symbols) u64, H.haltFlag);
    // S2 extension point (RFC-3): extra service families registered by the
    // product. S1 products declare `&.{}`; the pipeline then uses the base
    // roster unchanged, so proof bytes are identical to the base pipeline.
    _ = @as([]const ServiceFamily, H.service_families);
}

/// S1: opaque marker; the shape is fixed by RFC-3 (S2). Empty slices only.
pub const ServiceFamily = struct { id: u16, name: []const u8 };

pub fn Pipeline(comptime H: type) type {
    comptime assertHooks(H);
    return struct {
        pub const Config = @import("request.zig").Config(H);   // request JSON schema
        pub const Request = @import("request.zig").Request(H);
        pub const Image = @import("image.zig").Owner(H);
        /// Native CPU production: capture → plan → prove → write bundle.
        pub fn prove(a: std.mem.Allocator, req: *const Request, res: Resources, out: std.fs.Dir) !Receipt { ... }
        /// Fresh reception: derives source keys and FIXED roots itself, refuses a
        /// persisted setup directory, checks file, statement, proof and endpoint.
        pub fn verify(a: std.mem.Allocator, req: *const Request, bundle: std.fs.Dir, opts: ReceiverOptions) !Report { ... }
        pub fn planCandidate(...) !Plan { ... }
        pub fn batchCandidate(...) !void { ... }        // native_batch.zig
        pub fn verifyBatchCandidate(...) !void { ... }  // receiver_batch.zig
    };
}
pub const Resources = @import("resources.zig").Resources;
pub const ReceiverOptions = @import("receiver_setup.zig").Options; // workers 1..8, mode identity-only|committed|resident
```

`api_surface` of `stwo_riscv_rv64_pipeline`, in this order: `Pipeline`,
`ProductHooks`, `ReceiverOptions`, `Resources`, `ServiceFamily`, `assertHooks`.
`ProductHooks` is a doc-only namespace holding `assertHooks`'s contract text and
the `ExampleHooks` used by tests. The package README carries the same contract.

Signature tests:
- `assertHooks` rejects a hook type missing any declaration.
- `Pipeline(ExampleHooks)` compiles.

Invariant tests:
- `label` never reaches a transcript. The test proves the probe twice with two
  labels and checks the proof bytes are identical.
- A profile rejected by `admitsProfile` fails before capture.
- An empty `service_families` gives the base roster.

### 3.3 The OP implementation (`src/products/opstack/statement/cpu/hooks.zig`)

```zig
pub const OpStackHooks = struct {
    pub const label = "opstack";
    pub const Symbols = @import("../frontend/guest_abi.zig").Symbols;
    pub const OUTPUT_BYTES = @import("../frontend/statement.zig").OUTPUT_BYTES; // 43
    pub const MAX_INPUT_BYTES = @import("../frontend/guest_abi.zig").INPUT_CAPACITY_MAX - 4; // 32 MiB window
    pub fn admitsProfile(p: Profile) bool { return p == .ethereum_services_v3; } // S1; S2 adds the BN254-tower profile
    pub const loadImage = @import("../frontend/guest_abi.zig").load;
    pub fn haltFlag(s: Symbols) u64 { return s.halt_flag; }
    pub const service_families: []const ServiceFamily = &.{};
};
pub const Pipeline = @import("stwo_riscv_rv64_pipeline").Pipeline(OpStackHooks);
```

`.ethereum_services_v3` is a pre-existing `stwo_riscv_rv64` enum literal, and it
names a services ABI rather than a product. Renaming it is out of scope. That
literal is the only allowed match in the grep proofs in §8.

The window is a power of two between `4 MiB` and `32 MiB`, exactly as the branch
patched `ethereum_contract.zig`, and checked by
`tests/guest_abi_test.zig::guest abi: windows 4..32 MiB admitted, 64 MiB rejected`.

### 3.4 Where Ethereum implements the hooks later (no behaviour change)

Ethereum is not touched in this integration. The follow-up migration is a separate
owner-gated change under RFC-1, and it retires exception E-1. Its shape:

- Add `src/products/ethereum/statement/cpu/rv64_pipeline_hooks.zig`:
  - `Symbols = ethereum_contract.Symbols`
  - `OUTPUT_BYTES = ethereum_contract.OUTPUT_BYTES` (43)
  - `MAX_INPUT_BYTES = INPUT_CAPACITY_MAX - 4` (16 MiB window)
  - `admitsProfile = p == .ethereum_services_v2 or execution_profile.isV3(p)`
    (today's `validateBudget`)
  - `loadImage = ethereum_contract.load`
  - `haltFlag = s.halt_flag`
  - `service_families = &.{}`
- Swap `rv64_ethereum_{plan,receiver,keys,terminal,gkr_main}` to
  `Pipeline(EthereumHooks)`. Delete the private copies.

Byte-identity CDC test, to be written first: for every block in
`tests/fixtures/ethereum/basket.json`, the native bundle and receiver report
produced through `Pipeline(EthereumHooks)` must equal the current Ethereum path
byte for byte. This test is owned by `products/ethereum` and runs in the
`riscv_rv64_pipeline` lane.

Ethereum-only behaviours that are not hooks stay as product code above the
pipeline:
- Zbb compact-decode toggles. They are a property of the admitted
  profile, so they can become a second admitted-profile predicate later.
- The early CPU0/early-segment GPU staging.
- The CUDA stages.

### 3.5 Every OP edit currently inside Ethereum files, and its replacement

| Branch edit (main path) | Replacement | Ethereum bytes |
|---|---|---|
| `ethereum_contract.zig`: `INPUT_CAPACITY_MAX` 16→32 MiB | `products/opstack/statement/frontend/guest_abi.zig` owns the OP window via `Hooks.MAX_INPUT_BYTES`/`loadImage` | unchanged |
| `ethereum_execution.zig`: `ethereum_services_op_v1` profile, `op_sparse034_calls` report | `products/opstack/statement/frontend/execution.zig` (S1, no tower); tower counters arrive with RFC-3 (S2) in OP code | unchanged |
| `ethereum_services/session.zig`: `.tower` event, `TowerCall`, `op_sparse034_calls` | S1: `frontend/services_session.zig` composes the neutral `stwo_riscv_rv64` `service_session` + `services/call_abi` and the `stwo_riscv_precompiles` primitives (E-2). S2: the tower event lands in `rv64/services/call_abi.zig` under RFC-3 with a neutral name | unchanged |
| `ethereum_services/candidate_curves.zig`: Arkworks Montgomery BN254 client (+71) | S2: `stwo_riscv_bn254.montgomery` + `products/opstack/statement/frontend/bn254_candidate.zig` (execution-only candidate) | unchanged |
| new `ethereum_services/{montgomery_bn254,bn254_tower}.zig` | S2: `src/frontends/riscv/precompiles/bn254/{montgomery,sparse_tower}.zig` (RFC-2) | n/a |
| new `ethereum_services/tower_call.zig` (imports rv64 machine/memory) | S2: `src/frontends/riscv/rv64/services/bn254_tower_call.zig` (RFC-3) | n/a |
| `rv64_ethereum_request.zig`: OP-native ROM notes, scratch capture cap | `rv64_pipeline/request.zig` `Config(Hooks)`; capture cap is `Resources.capture_options.spill` | unchanged |
| `word16_execution/expected_image.zig` | `rv64_pipeline/image.zig` `Owner(Hooks)` | unchanged |
| `gkr_main.zig` −453/+161, `plan.zig` −197/+29 (pipeline split) | the split is re-done in `rv64_pipeline` from main's current `gkr_request_execution.zig`/`plan.zig` (10 conflict hunks resolved there, not in Ethereum) | unchanged |
| `capture`, `capture_bench`, `capture_options`, `capture_ownership`, `direct`, `gkr_receiver`, `receiver_budget`, `setup_cache(+test)` deltas (scratch-backed capture, streaming census, parallel independent verification, fold admission budget, ordered column geometry) | applied to the `rv64_pipeline` copies only; Ethereum receives them at its migration | unchanged |
| `services/{v3_fixture,sponge_fixture}.zig` (now Ethereum test fixtures) | dropped; OP tests use their own probe and fixtures | unchanged |
| `rv64_ethereum_chain_test_root.zig` | dropped | unchanged |
| `rv64_word16_ethereum_native_main.zig` | `products/opstack/statement/cpu/native_main.zig` → executable `stwo-opstack-native` | n/a |
| `guests/ethereum/rv64/vendor/revm-bytecode/*`, `src/keccak_sponge_service.rs` | fork into `guests/opstack/vendor/revm-bytecode`, `guests/opstack/kona/guest/src/` (E-3) | unchanged |
| `guests/exact_layout_allocator_v2.rs` (volatile stores) | fork into `guests/opstack/runtime/`; issue G-1 reports the latent LTO hazard to the guest owner | unchanged |

### 3.6 Recorded exceptions (ENGINEERING_STANDARDS §1)

Each exception is filed in the named issue with owner, scope, reason, expiry,
retained checks and rollback.

| Id | Scope | Owner | Expiry / removal | Retained checks | Rollback |
|---|---|---|---|---|---|
| E-1 | `rv64_pipeline` duplicates the native subset of `products/ethereum/statement/cpu/word16_global_execution/ethereum` ([E] 6.5–8k lines) | riscv-cpu-integration (RFC-1) | Ethereum migration under RFC-1, or 2027-03-31, whichever is first | the Ethereum lanes are untouched; byte-identity CDC test at migration | `git mv` the package into `src/products/opstack/statement/cpu/pipeline/`. Contents are already neutral, and the product keeps working |
| E-2 | OP `services_session.zig`/`execution.zig` re-implement the v3 services session (Ethereum: 223 + 566 lines [M]) on neutral rv64 APIs | opstack-statement (RFC-4c) | when RFC-4c lands a neutral v3 session in `stwo_riscv_rv64` | the session admission tests mirror the Ethereum ones | none needed; product-local |
| E-3 | `guests/opstack` path-depends read-only on `guests/ethereum/rv64/{mem,vendor/{k256,ecdsa,revm-interpreter,sha2-rv64}}` and forks `revm-bytecode`, `keccak_sponge_service.rs` and `exact_layout_allocator_v2.rs` | opstack-statement (issue G-1) | when a shared `guests/rv64-runtime` crate is extracted | guest identity pins in `vectors/opstack/kona-guest-identity.json` | copy the deps under `guests/opstack/vendor` |

If the owner rejects RFC-1, apply E-1's rollback. The product, its tests and its
lanes still work, because only the package path, contract and lane change.

---

## 4. Waist, engine and other shared edits: RFCs

No RFC below is needed for S1, so the product works without any of them [M]. Uses
found by `git grep` on the PR head:
- The new engine/waist symbols are used only by recursion and BN254-delegation code:
  `commitOwnedMonolithicWithRecorder`, `use_scoped_pool`, `fixed4`,
  `native_four_tail`, `gkr_profile`, `hashChildrenWithSeed4` and `budget_limit`.
  The users are `poseidon2_outer`, `outer_gkr`, `circuit_cpu/om31` and
  `delegations/op_*`.
- `logup_prefix` and `om31_batch` have no consumer outside their own package.

How each RFC is filed:
- **Opening:** PART SRC opens each RFC with `.github/ISSUE_TEMPLATE/contract-change.yml`.
  The title starts `RFC: ` and the labels are `rfc` and `contract-change`. The first
  line of the body is `Status: pending owner decision`.
- **Isolation:** each RFC's code is one stacked branch and one PR on top of the
  product. It contains only that RFC's files from `integration-map.tsv`, plus its
  `package_budget_changes` row once the decision comment exists. Nothing is merged
  before the decision.

### RFC-1 — Neutral RV64 block pipeline package with product hooks (S1)

- **Owner:** riscv-cpu-integration.
- **Contract:** new package `stwo_riscv_rv64_pipeline` 0.1.0 (integration). Its API
  is §3.2. No existing contract changes.
- **Motivation:** plan of record §6.3. OP Stack needs the block pipeline, which today
  lives inside `products/ethereum` and cannot be imported (RS-3).
- **Rejected alternatives:**
  - Importing Ethereum (forbidden).
  - Editing Ethereum in the same change (owner directive).
  - A product-local copy. This is the fallback, but it would hide shared code
    inside a product.
- **Compatibility:**
  - Additive.
  - Ethereum keeps its private copy under exception E-1 until a separate migration
    change. That change carries a byte-identity CDC test over
    `tests/fixtures/ethereum/basket.json`.
  - The `label` hook is excluded from transcripts, which is tested.
- **Tests first:** `assertHooks` signature tests; probe prove/verify with two labels
  gives identical bytes; non-admitted profile rejection; empty-family roster
  identity.
- **Deprecation:** Ethereum's `word16_global_execution/ethereum/{plan,receiver,keys,…}`
  are removed only after migration. The removal is verified by zero importers.
- **Budget:** new package [E] +6.5–8k lines, 0 flags, 0 scripts. It falls back to −N
  when Ethereum migrates.

### RFC-2 — `stwo_riscv_bn254` primitive package (S2)

- **Owner:** riscv-frontend.
- **Contract:** new nested frontend package `src/frontends/riscv/precompiles/bn254`
  that depends only on `std` and optionally `stwo_core`. It contains:
  - `montgomery` (branch `montgomery_bn254.zig`, 75 lines, std-only).
  - `sparse_tower` math.
  - Fp/Fp2/Fp12, G2, Miller and residue reference arithmetic and vectors: the
    std/core-only import closure of `rv64/air/delegations/bn254_*`, about 32 of
    84 files [M].
- **Why not `precompiles` itself:**
  - Its budget is at the 86/86 ceiling.
  - `rv64` depends on `precompiles`, so AIR code that needs `rv64` evaluation cannot
    live there.
- **Compatibility:** additive. The package is not added to
  `frontend-package-families.json` because it has no peer edges.
- **CDC:** OP Stack consumes it in S2. Ethereum's ecPairing (0x08) is the named
  second consumer.
- **Golden vectors:** `vectors/riscv/bn254/` from the branch's Python oracles
  (`derive_pairing_residue.py`, `g2_subgroup/vectors.py`).

### RFC-3 — BN254 sparse-tower service call and service-family extension point (S2)

- **Owners:** riscv-frontend and riscv-cpu-integration.
- **`stwo_riscv_rv64`:**
  - `execution_profile`: one appended profile with a neutral name, such as
    `services_v3_bn254_tower` with string `rv64im-services-v3-bn254-tower-v1`. The
    tag namespace 4 (`0x0004_0001`) is disjoint from v3.
  - `services/call_abi.zig` gets a `bn254_tower` event.
  - `compact_tape(_wire)` gets a separate envelope; legacy `RV64TP01` bytes are
    unchanged.
  - `boundary_capture` changes.
  - `air/delegations/bn254_*` (about 52 AIR files) and `curves/spec` additions.
  - The branch names `TowerKind`, `op_sparse034` and `OP-only` are renamed to
    primitive names.
- **`stwo_riscv_cpu_integration`:**
  - Turn the branch's threaded `.tower`/`op_only` flags (roster, protocol,
    `gkr_local` ×28, `source_bounds` +320 lines, retention plan) into one
    service-family registry fed by `ProductHooks.service_families`.
  - `delegations/op_*` (55 files) → `delegations/bn254_*`.
- **Compatibility:** minor bumps. Products with no families get byte-identical
  tape, roster and proofs; golden tape vectors are added first.
- **Budget:** CB-2 rows for `stwo_riscv_rv64` and `stwo_riscv_cpu_integration`.
  Branch size is roughly +10k lines in each package [D], before the deduplication
  the registry allows.

### RFC-4 — Generic RV64 fixes and performance (S2; split 4a/4b/4c)

- **4a, correctness:**
  - Fixed-source ordered column geometry: `word16_execution/fixed_setup(+test)`,
    `setup_cache`, and `design/opstack/rv64-fixed-source-geometry.md`.
  - The OP heavy profiles needed this repair. It may be required for heavy-block
    acceptance (risk R-2).
- **4b, performance:**
  - Packed CPU accumulation (`gkr_local/challenges` +67, `rv64/air/packed_fields`).
  - Parallel rows family extraction.
  - Parallel receiver setup and independent proof checks (`gkr_local/execution`
    +83).
  - Streamed source tiles.
  - `terminal_view`.
  - Serialized Keccak sponge prototype (9 files).
- **4c, neutral v3 services session in `stwo_riscv_rv64`:** retires E-2. Ethereum
  migrates to it separately.
- **Budget:** CB-2 rows for rv64 and riscv_cpu.

### RFC-5 — `stwo_core`: aarch64 SIMD OM31 batch inversion (S3)

- **Owner:** protocol-core.
- **Change:** `fields/om31_batch.zig`, dispatched from `fields.batchInverse`.
  `om31_test` is extended.
- **Compatibility:** patch/minor. No wire or transcript change.
- **Tests first:** packed-vs-scalar property test (Debug and ReleaseFast, seeded) and
  zero/non-invertible handling.
- **Budget:** `stwo_core` CB-2 row, +91 lines [M].

### RFC-6 — `stwo_core`: 4-lane Poseidon2-M31 sponge and packed Merkle hashing (S3)

- **Owner:** protocol-core.
- **Change:** `crypto/poseidon2_m31_sponge4.zig` and
  `vcs/poseidon2_m31_merkle.zig::hashChildrenWithSeed4` (+leaf).
- **Compatibility:** claims to compute exactly the scalar protocol. Tests first:
  lane-by-lane equality with the scalar sponge and Merkle over random seeded inputs,
  and `vectors/waist` unchanged.
- **Consumers:** `frontends/riscv/recursion/poseidon2_channel`, RFC-7e.
- **Budget:** +256 lines [M].

### RFC-7 — `stwo_prover_engine` (+ `stwo_cpu_backend`) opt-in options (S3)

- **Owner:** prover-engine; cpu-backend for 7d.
- **Structure:** one issue with six independently decidable parts. Each part's
  defaults must be byte-identical, and a golden proof test is added first for
  each.

| Part | Change | Size [M] | Notes |
|---|---|---|---|
| 7a | `lookups`: `use_scoped_pool`; source tiles ≤512 facts; `fixed4` sumcheck coefficient encoding; coordinator-only `gkr_profile.zig` telemetry | +143/−37 | Default stays trimmed, and the verifier already accepts both. `gkr_circuit_field` conflicts with main and is re-done there |
| 7b | `air`: parallel two-wave LogUp prefix (`logup_prefix.zig`) | +174/−2 | — |
| 7c | `pcs`: `commitOwnedMonolithicWithRecorder` | +101/−9 | Also refuses openings on parked layers, and extends lifted-prefix reuse to the P2v2 suite |
| 7d | `poly/circle`: octic secure-composition interpolation and exact `zero_column` | +136/−20 | `backends/cpu_scalar/mod.zig` `interpolateSecureCompositionForField` |
| 7e | `vcs_lifted`: native four-lane tail | +182/−7 | Needs RFC-6 |
| 7f | `file_backed_allocator`/`host_budget_allocator` budget limit and peak tracking | +18/−3 | — |

Each part needs an engine (or cpu-backend) CB-2 row.

### RFC-8 — Circuit recursion OM31 kernels (S3)

- **Owners:** circuit-cpu-integration, circuit-frontend and cairo-frontend, plus the
  owner of `products/cairo/tools/composition_cpu_codegen`.
- **Changes:**
  - Pinned octic CPU domain kernels (`om31/{domain_program,native_program,shadow_columns,stage_capture}`).
  - Packed domain evaluation, compact beta1 views and shifted LogUp prefix waves.
  - Octic native evaluator hook (`frontends/cairo/proving/air/native_evaluator.zig`).
  - Authenticated source producers in `frontends/circuit/builder/context.zig`.
- **The Cairo codegen piece (`om31_writer`, `hybrid_om31_writer`, `om31_prelude.h`) moves to a
  circuit-owned generator.** A Cairo product tool must not serve RISC-V recursion.
- **Related:** the approved RFC #374 (Cairo dependency for OP recursion) applies to
  the S3 product edge.
- **Size:** +1,237/−100 lines [M].

### RFC-9 — Pure-P2 RV64 recursion lanes and OP recursion roots (S3)

- **Owner:** riscv-cpu-integration.
- **Changes:**
  - `poseidon2_outer` lanes `native_dot`, `native_omul`, `native_group`, `sponge_cpu`,
    `sponge_local_gkr`, `truth_local_gkr`, `miller_local_gkr` and
    `execution_hierarchy`: 318 files, +42.5k lines [M].
  - `outer_gkr/cpu_*` (20 files) and bounded `rv64_recursion` lanes.
  - Product-owned roots `rv64_op_*` (18 files) go to
    `products/opstack/statement/cpu/recursion`.
  - The settlement exporter and the CUDA settlement fixture go to
    `products/opstack/{statement,cuda}`.
- **Transcript-domain decision:** the branch hard-codes `opstack/...` domain strings
  in shared code (`poseidon2_outer/context.zig`, `native_*`, `terminal_blake/profile`).
  - Main has none of these lanes, so no main proof depends on those bytes.
  - Recommendation: neutral, versioned domains (`stwo-rv64/p2-outer/v1/...`) and
    regenerated golden vectors. Byte compatibility with PR-head receipts is
    deliberately given up, because those receipts are not imported.
  - Keeping the strings byte-identical would need a recorded exception.
- **Depends on:** RFC-5, 6, 7 and 8.
- **Flags:** the branch's `STWO_RV64_{CPU_WRAP_RECYCLE_BYTES, OUTER_GKR_NATIVE,
  OUTER_GKR_INTERPRETER, GROUP_ARITHMETIC, RECURSION_CPU_LANES}` would break the
  `<60` cap. They become `Options` fields or constants.

### Issue G-1 (not an RFC) — shared RV64 guest runtime

- Extract `guests/ethereum/rv64/{mem,vendor/*}` and
  `guests/exact_layout_allocator_v2.rs` into `guests/rv64-runtime/`. This retires
  E-3.
- Report the allocator LTO hazard: size-oriented LTO can drop free-list metadata
  stores, and the branch fixes it with `write_volatile`. Applying the fix changes
  Ethereum guest bytes, so the Ethereum guest owner decides.

---

## 5. Flags

The S1 target is **0 new `STWO_*` names, 0 change in live count** (59, cap `<60`)
and **0 new references in `src`**.

| Branch names [M] | Disposition |
|---|---|
| `STWO_OP_*` (about 150 names: `*_CONFIG`, `*_OUT`, `*_NATIVE`, `*_ROOT`, …) | Dropped. These are research-harness switches in test roots. S2/S3 tests become fixed focused steps, and their outputs go to the test tmp dir |
| `STWO_ZIG_RV64_RECEIVER_SETUP_THREADS`, `STWO_ZIG_RV64_RECEIVER_IDENTITY_ONLY_CPU` (undeclared) | CLI `--receiver-setup-workers N` (1–8, default 1) and `--receiver-setup committed\|identity-only\|resident` on `stwo-opstack-native` → `ReceiverOptions` |
| `STWO_ZIG_RV64_SETUP_CACHE`, `STWO_ZIG_RV64_SETUP_BUILD_THREADS`, `STWO_ZIG_GKR_TREE_CHECKPOINTS`, `STWO_ZIG_GKR_STREAM_BOTTOM`, `STWO_RV64_CAPTURE_DIGEST`, `STWO_RV64_CANON_RUNGS` (read by the copied Ethereum code) | The `rv64_pipeline` copy reads none. They become `Options` fields set by CLI arguments (`--setup-cache DIR`, `--setup-build-threads N`, …), so registry references do not grow. Ethereum keeps its own readers |
| `STWO_RV64_{OUTER_PROFILE,FOLD_ARITY,GPU_CPU_REPLAY}` set by OP Python harnesses | S1 harnesses do not set them. S3 decides with RFC-9 |
| `STWO_RV64_{CPU_WRAP_RECYCLE_BYTES,OUTER_GKR_NATIVE,OUTER_GKR_INTERPRETER,GROUP_ARITHMETIC,RECURSION_CPU_LANES}`, `STWO_CIRCUIT_OM31_{PROFILE_DIR,INTERPRETER}` | S3, as RFC-8/9 `Options`/constants; never live `STWO_RV64_*` |
| `STWO_EXPORT_*`, `STWO_NATIVE_{PCS,DEEP}_FIXTURE` (settlement capture patches) | Patches are kept as files but not applied in CI. Any S3 exporter takes CLI arguments |
| `STWO_PAIRING_*`, `STWO_MAC12_*`, `STWO_G2_*`, `STWO_DENSE_*`, `STWO_RESIDUE_OUT` | Dropped. Test outputs go to tmp dirs |
| `STWO_ADMITTED_*` in `opstack/build.py` (guest build knobs) | `tools/opstack/build.py` variant table constants. No environment |

The fallback, if a new name is truly unavoidable, is `STWO_OPSTACK_<NAME>` in
`conformance/rv64-flags.json` with:
- owner `opstack-statement`
- `default`
- `status`
- `date`
- `expires` (≤ 90 days)
- `default_evidence{path,text}`

The budget entry then needs `flags_added_budget: 1` and a CB-2 justification.
Expected count: 0.

Check: `python3 scripts/repo/check_source_conformance.py --check-rv64-flags
--strict-rv64-flags` passes, and `git grep -nE 'STWO_[A-Z0-9_]+' -- tools/opstack
tests/fixtures/opstack src/products/opstack src/integrations/riscv_cpu/rv64_pipeline`
lists only declared names.

---

## 6. Build and CI wiring (PART SRC)

### 6.1 Package steps (`src/products/opstack/statement/build.zig`)

| Step | Root / exe | Purpose | Floor |
|---|---|---|---|
| `test` (contract `ci.command`) | `mod.zig`, `tests/*_test.zig` | ABI, statement, hooks contract and tamper tests (Debug) | `TestCountFloor.addMany(b, runs, N)`, with N = the count measured at first green |
| `test-e2e-probe` | `tests/e2e_probe_test.zig` | ReleaseFast: prove `vectors/opstack/abi-probe.elf` with `Pipeline(OpStackHooks)`; fresh `verify` in a new process; 3 corruption trials reject | ≥ 4 |
| `opstack-native` | exe `stwo-opstack-native` from `cpu/native_main.zig` | subcommands: `prove`, `verify`, `plan-candidate`, `batch-candidate`, `verify-batch-candidate`, `execute` | — |

Fixture paths reach tests through a `b.addOptions()` module named
`opstack_fixture_paths`, with `vectors_root = b.pathFromRoot("../../../../vectors/opstack")`.
That module is declared in `injected_modules`. No environment variable is used, and
`@embedFile` never leaves the package.

`stwo_riscv_rv64_pipeline/build.zig` has the steps `test` (Debug) and
`test-releasefast`, using `ExampleHooks` and the same probe.

### 6.2 Workspace rows

The ownership files must match exactly. Each change is one row.

| File | Edit |
|---|---|
| `build.zig.zon`, `build_support/build.zig.zon` | `.stwo_opstack_statement` → `src/products/opstack/statement`; `.stwo_riscv_rv64_pipeline` → `src/integrations/riscv_cpu/rv64_pipeline` (with `../` in `build_support`) |
| `build_support/graph/package_ownership.zig` | enum `opstack_statement`, `riscv_rv64_pipeline`, plus two owner rows `{prefix, package, dependency_name}` |
| `.github/CODEOWNERS` | new block `# owner-role: opstack-statement` with exactly `/src/products/opstack/statement/package.contract.json @teddyjfpender` and `/src/products/opstack/statement/build.zig.zon @teddyjfpender`. Append the two `rv64_pipeline` paths to the existing `# owner-role: riscv-cpu-integration` block |
| `conformance/ci-touchpoints-v1.json` `lanes` | `opstack_statement` (linux, Debug `zig build test --build-file src/products/opstack/statement/build.zig -Doptimize=Debug -j2 --verbose --summary all`, plus `python3 -m unittest discover -s tools/opstack/tests -p 'test_*.py'`); `opstack_statement_releasefast` (`zig build test-e2e-probe … -Doptimize=ReleaseFast`); `riscv_rv64_pipeline` (Debug `zig build test --build-file src/integrations/riscv_cpu/rv64_pipeline/build.zig …`) |
| `conformance/ci-touchpoints-v1.json` `rules` | `guests/opstack`, `tools/opstack`, `tests/fixtures/opstack` → `["script_contracts","opstack_statement"]`; `vectors/opstack` → `["opstack_statement","opstack_statement_releasefast"]`; `design/opstack` → `["static"]`, because the `.tsv` map is not a `.md` doc suffix. Without a rule, a non-doc path fails open to all lanes |
| `conformance/tooling-surface-v1.json` `roots.opstack` | `{owner: "opstack-statement", role: "qualification-adapter", required_for: "Kona/Mantle guest build, fixture capture, CPU proof qualification and settlement verifier tests", live_callers: [tools/opstack/tests/test_cpu.py, tools/opstack/tests/test_build.py, …existing files], pr_lanes: <exactly the lanes the tools/opstack rule selects, plus "static" if always-on>, extraction: "move to a separate repository after the S3 settlement verifier stabilises (restructure plan §9)"}` |
| `toolchain.json` (owned by PART ASSETS) | `rust.crates["tools/opstack/capture_host/blob_check"]`, `[…/slot_search]` pins + `rust-toolchain.toml` in each; guests pin via `guests/opstack/rust-toolchain.toml` |
| `conformance/rv64-productionisation-budget.json` `entries` | `opstack_s1_rv64_pipeline` (`net_code_budget` = measured, [E] ≤ 8,000; `flags_added_budget: 0`; `scripts_added_budget: 0`; justification: "RFC-1 neutral pipeline for a second RV64 product; E-1 duplication expires at the Ethereum migration") and `opstack_s1_statement` ([E] ≤ 3,000; 0; 0; "OP Stack product statement, guest ABI, CLI; owner opstack-statement") |
| `scripts/tests/test_ci_package_graph.py` | `EXPECTED_PACKAGES` 37 → 39; `EXPECTED_EDGES` 190 → 190 + 6 (pipeline) + N(opstack, [D] 8) = 204; the lane-binding list gains `stwo_opstack_statement` ×2 and `stwo_riscv_rv64_pipeline` ×1; pinned selection sets gain the opstack and pipeline lanes wherever the reverse closure reaches (riscv frontend, riscv_cpu, core, engine changes) |
| `.github/workflows/ci.yml`, `scripts/tests/test_ci.py:445` | untouched unless a lane exceeds 30 min. Target: Debug lane ≤ 20 min [E] |

Contract budgets:
- **New packages** set `budget` to their measured values at first green. No CB-2
  row is needed.
- **`stwo_opstack_statement` dependencies, minimal set (8):**
  - `stwo_riscv_rv64_pipeline`
  - `stwo_riscv_cpu_integration`
  - `stwo_riscv_frontend`
  - `stwo_riscv_rv64`
  - `stwo_riscv_precompiles`
  - `stwo_riscv_isa`
  - `stwo_core`
  - `stwo_prover_engine`
- **Not depended on:** `stwo_metal_backend`, `stwo_riscv_cuda_integration` or any
  `stwo_circuit_*`. Each would widen lane selection (§5 of the layout map).

---

## 7. Deliberately dropped (archive: PR head `089bc2437`)

| What | Files [M] | Where it remains |
|---|---:|---|
| `vectors/reports/rv64-opstack-*` and other evidence | 623 (+169,559) | `https://github.com/starknet-innovation/stwo-zig/tree/089bc2437/vectors/reports` |
| `settlement/fixtures/native-deep-120794432-receipt.json` | 1 | PR head; `tools/opstack/settlement/README.md` links it |
| `opstack/tests/fixtures/transition-159321794/input.opd.gz` (13.9 MB) | 1 | PR blob URL plus sha256 in `tests/fixtures/opstack/transition-159321794/manifest.json`, fetched by `tools/opstack` on demand; the owner may attach it to a release asset |
| Root-catalog and shared build wiring (`build_support/products/*`, riscv_cpu/riscv_cuda `build.zig*`, `ci.yml`, `dev_test.py`, `ci_scope_plan.py`, `test_opstack_ci_contract.py`, `rv64_resident_basket.py`) | 18 | superseded by package-local steps (§6) |
| Ethereum-owned test wiring (`rv64_ethereum_chain_test_root.zig`, `services/{v3,sponge}_fixture.zig` deltas) | 3 | PR head |
| About 150 `STWO_OP_*` and other experiment switches | — | PR head; the tests return as fixed steps in S2/S3 |
| riscv_cpu `README.md` delta | 1 | rewritten with RFC-9 |
| Superseded experiments: R5/R6 recursion controls, the M7 recursive comparisons and `cuda-resident-8workers` preset usage on CPU | inside S3 rows | PR head; S3 ports only the R7/pure-P2 construction the owner approves |

---

## 8. Acceptance

### 8.1 Separation proofs (run on the product branch against `origin/main`)

```sh
# 1. No Ethereum edits
git diff --name-only origin/main...HEAD -- src/products/ethereum guests/ethereum tests/fixtures/ethereum   # empty
# 2. S1 touches src only in the two new packages
git diff --name-only origin/main...HEAD -- src | grep -vE '^src/(products/opstack/|integrations/riscv_cpu/rv64_pipeline/)'  # empty
# 3. No product names in shared paths (frontends/integrations)
git ls-files src/frontends src/integrations | grep -iE 'ethereum|opstack|starknet|tensor|kona'      # empty
# 4. Neutral pipeline contents
git grep -niE 'opstack|kona|mantle|\bop_' -- src/integrations/riscv_cpu/rv64_pipeline              # empty
git grep -ni 'ethereum' -- src/integrations/riscv_cpu/rv64_pipeline | grep -v 'ethereum_services_v' # empty
# 5. No product-to-product import
git grep -n 'stwo_ethereum' -- src/products/opstack src/integrations/riscv_cpu/rv64_pipeline       # empty
# 6. No evidence in tree
git diff --name-only origin/main...HEAD -- vectors/reports                                         # empty
git diff --name-only origin/main...HEAD -- vectors | grep -v '^vectors/opstack/\|^vectors/MANIFEST.json$'  # empty
# 7. Shared waist/engine untouched in S0/S1
git diff --name-only origin/main...HEAD -- src/waist src/engine src/backends src/frontends            # empty
```

### 8.2 Repository checks (cheap; no Zig build)

- `python3 scripts/repo/check_package_workspace.py --budget-report /tmp/opstack-budget.json`: zero findings. The report shows the two new packages at their declared ceilings, and every other package unchanged.
- `python3 -m unittest scripts.tests.test_ci_package_graph scripts.tests.test_package_workspace scripts.tests.test_package_budget scripts.tests.test_tooling_surface scripts.tests.test_vector_ownership scripts.tests.test_toolchain_pins scripts.tests.test_ci scripts.tests.test_ci_touchpoint_prefixes`
- `python3 scripts/repo/check_source_conformance.py --check-rv64-flags --strict-rv64-flags` (live count 59).
- `python3 scripts/ci.py --fast`.
- `python3 -m unittest discover -s tools/opstack/tests -p 'test_*.py'`.
- Locally on this 36 GB laptop, only `zig fmt --check`, `zig ast-check` and
  `~/Coding/ge-ops/bin/memguard run --gb 6 -- zig build -l --build-file <pkg>/build.zig`.
  Compilation is left to hosted CI.

### 8.3 Hosted CI lanes that must pass

- Always: `static`, `script_contracts`, `build_graph`.
- New: `riscv_rv64_pipeline`, `opstack_statement`, `opstack_statement_releasefast`.
- Selected by unchanged closure, which proves non-regression of shared code:
  `riscv_cpu_integration`, `riscv_rv64_package`, `riscv_frontend` and
  `ethereum_statement`. Their selection is not caused by S1 edits, but run them
  once on the PR to show they are untouched.
- Per the merge-gate practice (GitHub CI often cannot go fully green), the owner
  can accept the same commands run locally, but on a host with enough memory.

### 8.4 OP Stack correctness: CPU proofs with fresh receivers

This runs on an owner-chosen CPU host with ≥ 64 GB, under memguard. It does not
run on the GPU pod or on the 36 GB laptop during this campaign. Receipts go outside
the tree.

1. **Guest identity.** Build the Kona `sha` variant with
   `python3 tools/opstack/build.py --variant sha` at `nightly-2026-08-08`. Its ELF
   sha256 must equal `vectors/opstack/kona-guest-identity.json`.
2. **Fixtures.** Fetch the pinned upstream fixtures from
   `tests/fixtures/opstack/mainnet-fixtures.json` (OP Mainnet,
   `upstream_commit 85f22e11…`) and `fixtures.json` (OP Sepolia,
   `a271fd6b…`). Each must match its pinned sha256.
3. **Prove and receive.** For each block, run `stwo-opstack-native prove` and then
   `stwo-opstack-native verify` in a separate process. The receiver gets no setup
   directory and derives source keys and FIXED roots itself. It must check file,
   statement, proof and endpoint, and the 43-byte output must equal
   `vectors/opstack/transition-outputs.json`:

   | Block | Network | Role | Reference [M, branch receipts] |
   |---|---|---|---|
   | 120794432 | OP Mainnet | small; CPU + Keccak + SHA | 7,048,980-byte bundle, fresh receiver |
   | 121057303 | OP Mainnet | user transactions | branch preset `cpu-4workers`, `--batch-steps 1048575` |
   | 26207960 | OP Sepolia | upstream Kona fixture | — |
   | 121065789 | OP Mainnet | heavy | 91 CPU + 24 service proofs. Needs RFC-4a if it fails without the fixed-source geometry repair (risk R-2) |

4. **Adversarial checks.** For each block:
   - Three corruption trials (proof byte, statement byte, expected output) are
     rejected.
   - A non-admitted profile request is rejected before capture.
5. **Product isolation.** Run the same receivers again with the Ethereum lane
   binaries untouched, to show the products are isolated.

Pass criterion: every row passes both producer and fresh receiver, and every
corruption is rejected. Timing is not an acceptance criterion; report it with the
[M] label only.

---

## 9. Partition: who owns which files

The two parts run in parallel on the product branch with **no shared file**. If a
part needs a change in the other part's file, it asks that part's agent.

### PART ASSETS (non-`src`)

Owns exactly:

- `design/opstack/**` — `integration.md` (this doc), `integration-map.tsv`, and the
  ported notes (rules D1, D2, F9).
- `guests/opstack/**`:
  - Rules F1–F3, C1, C2, O1.
  - The new `abi_probe/` crate.
  - `README.md` and `rust-toolchain.toml`.
- `tools/opstack/**` — rules F6–F8, F10, F13.
- `tests/fixtures/opstack/**` — rules G1–G4, G6, F4, F5, F11, plus `MANIFEST.json`.
- `vectors/opstack/**` — `abi-probe.elf` and `abi-probe.json`,
  `kona-guest-identity.json`, `transition-outputs.json`.
- `vectors/MANIFEST.json` — adds the `vectors/opstack` group:
  - kind `golden_fixture`, owner `opstack-statement`.
  - Consumers: `src/products/opstack/statement/tests/e2e_probe_test.zig`,
    `src/products/opstack/statement/tests/statement_test.zig` and
    `src/products/opstack/statement/build.zig`.
  - These consumer paths are an interface with PART SRC; they must exist when both
    parts merge.
- `third_party/INVENTORY.json` — 7 entries:
  - ark-ff 0.6.0, ark-bn254 0.6.0 and ark-bls12-381 0.6.0 (MIT OR Apache-2.0).
  - kona-mpt 0.3.0 and kona-protocol (pinned optimism rev; LICENSE.md and LICENSE-MIT).
  - op-revm 20.0.0 (MIT OR Apache-2.0).
  - revm-bytecode (main's version, MIT).
  - Each entry has `tree_sha256` and per-file hashes.
  - Add the `UPSTREAM.json` files that ark-bls12-381 and kona-protocol lack.
  - Check no licence is AGPL, GPL, SSPL or BUSL.
- `toolchain.json` — `rust.crates` pins for the two `tools/opstack/capture_host`
  crates and any other `tools/opstack/*/Cargo.toml`.

The interface PART ASSETS must honour:
- Harnesses call `zig-out/bin/stwo-opstack-native` with the §6.1 subcommands and
  the §5 CLI flags. No `STWO_*` names other than ones already declared.
- Keep JSON request schema compatibility with the branch's `*-proof-config.json`.
  PART SRC's `rv64_pipeline/request.zig` parses that schema with the OP `Symbols`.

### PART SRC

Owns exactly:

- `src/products/opstack/statement/**`.
- `src/integrations/riscv_cpu/rv64_pipeline/**`.
- `build.zig.zon`, `build_support/build.zig.zon` and
  `build_support/graph/package_ownership.zig`.
- `.github/CODEOWNERS`.
- Conformance files:
  - `conformance/ci-touchpoints-v1.json`
  - `conformance/tooling-surface-v1.json`
  - `conformance/rv64-productionisation-budget.json`
  - `conformance/rv64-flags.json`, only if a reference refresh is needed (expected
    no change).
- `scripts/tests/test_ci_package_graph.py`.
- `.github/workflows/ci.yml` and `scripts/tests/test_ci.py`, only on the 30-minute
  timeout exception.
- Opening the GitHub issues: RFC-1 to RFC-9, G-1, and the exception records E-1 to
  E-3. Each issue's first line is `Status: pending owner decision`.

PART SRC must not touch `src/frontends/**`, `src/waist/**`, `src/engine/**`,
`src/backends/**` or any other `src/integrations/**` path outside `rv64_pipeline`,
and must never touch `src/products/ethereum/**`.

### Not owned by either part in this integration

Every S2 and S3 row of `integration-map.tsv` is not ported. These rows wait for the
RFC decisions and stay on the PR head.

### Merge order

1. PART SRC's package skeleton and wiring.
2. PART ASSETS's vectors, fixtures, guest and tools.
3. Together, the hosted lanes in §8.3.

Each commit is a small Conventional Commit carrying the CB-1 block.

---

## 10. Risks

| Id | Risk | Mitigation |
|---|---|---|
| R-1 | The neutral pipeline copy drifts from Ethereum's before migration | E-1 expiry; byte-identity CDC test at migration; RFC-1 asks for a migration date |
| R-2 | The heavy block 121065789 needs the fixed-source geometry repair (RFC-4a) | accept small/user blocks in S1; prioritise RFC-4a; record heavy as pending, not passed |
| R-3 | Kona inputs above 16 MiB hit an Ethereum-sized assumption deeper in the pipeline | the `MAX_INPUT_BYTES` hook is threaded through `image.zig`; a 32 MiB window ABI test; the 13.9 MB-compressed transition input is not an S1 acceptance item |
| R-4 | Guest path-deps into `guests/ethereum` break when Ethereum changes its guest | E-3 identity pins fail loudly; issue G-1 |
| R-5 | The S1 net code growth (about 10k lines [E]) needs owner acceptance under CB-2 | the budget entries carry the justification; E-1 makes the growth temporary |
