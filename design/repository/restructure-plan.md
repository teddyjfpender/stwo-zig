# Repository restructuring plan

This plan applies [ENGINEERING_STANDARDS.md](../../ENGINEERING_STANDARDS.md)
to this repository. It covers every root directory and `src/` package, gives
each product line its own place in the tree, defines the thin waist, and
orders the work into Phases 0–3 with exit criteria and the CI checks that keep
each result in place.

**Measurement basis.** Unless a row says otherwise, numbers were measured at
`51897dc26` (branch `codex/rv64-gpu-hygiene`, the base of this PR), using
`git ls-files`, `git grep`, `wc -l` and `scripts/check_package_workspace.py`.
`origin/main` is `4e260db96`, which merges PR #314 and contains `51897dc26`.
Figures marked *reported* come from the hygiene receipts or the team and were
not re-measured here. Figures marked *census@4a4d01bd5* come from
[rv64-gpu-hygiene.md](../riscv/rv64-gpu-hygiene.md).
`autoresearch/` is excluded from source counts unless named, because this PR
retires it.

---

## 1. Decisions

| # | Decision |
|---|---|
| D1 | **Stay one monorepo for code. Move non-code evidence out now.** Package boundaries are enforced by the Zig package workspace that already exists (27 `package.contract.json`, 31 `build.zig.zon`). A product line moves to its own repository only when the criteria in §9 are met. |
| D2 | **Five layers, one direction.** `support` → `waist` → `engine` → `backend` / `frontend` → `integration` → `product`. Products depend on their frontend's integrations, the backends they target and the waist. **A product never depends on another product.** Shared code enters a lower layer only through the API change protocol (standards §6). |
| D3 | **Integrations are product-neutral.** `src/integrations/<frontend>_<backend>` binds one frontend to one backend. Workload-specific code (Ethereum block statement, Starknet aggregation, OP Stack settlement) moves to `src/products/<line>/`. CI enforces this: no path or public identifier under `src/frontends` or `src/integrations` may name a product (`ethereum`, `opstack`, `starknet`, `tensor`). |
| D4 | **No loose source in a container directory.** `src/`, `src/frontends/`, `src/integrations/`, `src/products/`, `src/backends/`, `tests/`, `tools/` and `guests/` hold only directories (plus one README). Test roots, CLIs and code generators move into the package that owns what they exercise. The single repository root module `stwo` exports the waist and the engine, not frontends or products. |
| D5 | **The RISC-V frontend becomes 8 sub-packages** (§5.3) after versioned copies are collapsed. It is 3,091 Zig files and 800,359 lines today. |
| D6 | **The waist is semver-stable from Phase 1:** fields, circle, channel, Merkle/VCS, PCS/FRI, AIR framework, proof wire, prover API and backend contracts. It gets stable error codes, consumer-driven contract (CDC) tests, property tests run in Debug and ReleaseFast, and hash-pinned golden vectors (§7). |
| D7 | **The build graph is generated from the contracts.** `build_support` stops hand-wiring `addImport` edges that the contracts do not declare. At this commit, 374 undeclared named imports compile because of that hand-wiring. Each product line gets its own build catalog file, so product work never edits a shared catalog. |
| D8 | **Evidence leaves the source tree.** `vectors/reports/` (14,772 files, ≈1.97 GB), dated `conformance/*.md` and design receipts go to an evidence repository or artifact store. Only golden vectors, fixtures and the current receipt per gate stay next to code. |
| D9 | **`design/` is documentation only.** Build inputs and runtime presets that live in `design/` today move into `src/` (build inputs) or `conformance/` (machine-read presets). |

---

## 2. Census at `51897dc26`

### 2.1 Root directories

| Directory | Files | Size | Role | Live references (code → dir) |
|---|---:|---:|---|---|
| `autoresearch/` | 17,816 | 719 MB | research harness, notes, guests, perf CLI | being retired in this PR |
| `vectors/` | 15,291 | 2.19 GB | golden vectors **and** receipts (`reports/` = 14,772 files, 1.97 GB) | 1,331 grep lines; 181 `src` files; 36 code files reference `vectors/reports` |
| `src/` | 7,580 | 82 MB | Zig packages (7,065 `.zig`, 1,694,371 lines) | — |
| `scripts/` | 778 | 8.4 MB | Python tooling: 755 `.py`, 207 loose at top level, 221 tests, ≈40 `*_lib/` packages | entry points `dev_test.py`, `ci.py`, `rv64_gate.sh`, `rv64_m8_bench15.py` |
| `design/` | 646 | 11.6 MB | design notes **plus build inputs and presets** | 70 code files |
| `tools/` | 263 | 3.5 MB | 18 tool roots, 13 Rust crates (all with `Cargo.lock`), oracles, collectors | product build steps, scripts |
| `formal/` | 260 | 10.4 MB | Lean RISC-V refinement (`formal/riscv-refinement`) | `riscv-refinement.yml`, `riscv-sail-formal.yml` |
| `tests/` | 136 | 2.1 MB | `tests/cuda` (127 native C++/Python smokes), 7 loose `native_cuda_*.zig` | 423 grep lines (≈363 *reported*); 21 script/build files |
| `conformance/` | 97 | 2.5 MB | machine-read policy (`*.json`) mixed with 15 dated `.md` goals and audits | 99 code files, 4,452 grep lines |
| `build_support/` | 87 | 0.7 MB | build graph: 16,433 lines; `products/catalog.zig` has 396 steps (249 scoped `riscv_cpu`) | `build.zig` (6 lines) delegates here |
| `third_party/` | 15 | 0.2 MB | `bzip2` (C), `poseidon2_plonky3` (Rust reference, `PINNED.json`) | interop, crypto tests |
| `soundness/` | 11 | 0.3 MB | soundness docs plus `air-ir-v2.schema.json` | docs |
| `.github/` | 7 | 0.1 MB | 7 workflows. Action SHAs are pinned. No secret, licence or dependency scanning | — |
| `bench/` | 6 | 1.5 MB | benchmark site (`bench/site`) | `benchmark_pages_lib` |
| `archive/` | 2 | 32 KB | `archive/cairo/legacy_claim_registry.zig` | none |
| `.githooks/` | 2 | — | local hooks | `CONTRIBUTING.md` |

Root files: `build.zig`, `build.zig.zon` (no `minimum_zig_version`),
`README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`,
`.gitattributes`, `.gitignore`, `.mailmap`. There is no toolchain pin file,
devcontainer, Nix flake or CUDA image digest. Zig `0.15.2` and Python `3.13`
are pinned only inside workflow YAML. Rust toolchains are pinned in 5 of the 13
tool crates and in 4 guest crates.

### 2.2 `src/` subdirectories

| `src/…` | Files | Zig lines | Package(s) | Notes |
|---|---:|---:|---|---|
| `frontends/` | 3,711 | 984,818 | `riscv` (3,105 files, 800,359 lines), `sm83` (290 / 117,826), `cairo` (193 / 42,466), `circuit` (122 / 24,148) | `mod.zig` loose |
| `integrations/` | 2,121 | 402,161 | 13 packages; `riscv_cpu` 1,127 / 170,128; `riscv_cuda` 347 / 95,551; `native_cuda` 281 / 49,268; `cairo_cuda` 141 / 43,095 | `circuit_cuda` has no contract; `native/` (2 files) has no package |
| `backends/` | 722 | 80,818 (+63k CUDA C++, +85k Metal/ObjC) | `cpu_scalar`, `metal`, `cuda` | `metal_surface.zig`, `mod.zig` loose; `cuda/native/rv64` = 137 product-named files in a backend |
| `prover/` | 295 | 75,642 | `stwo_prover_engine` | 75 loose files, 34 of them `*_test_root.zig` / benchmark roots |
| `tests/` | 153 | 37,231 | none (root-graph tests via `src/tests.zig`) | `riscv` 96, `native` 24, `metal` 22, `cairo` 9 |
| `tools/` | 129 | 31,189 | `metal_session` + 19 tool dirs | product tools under a shared dir |
| `core/` | 158 | 28,435 | `stwo_core` | contains product modules `cairo_air_layout.zig`, `circuit_proof_shape.zig` |
| `examples/` | 53 | 13,756 | `stwo_native_examples` | — |
| `products/` | 88 | 12,259 | 15 product dirs, none of them a package | — |
| `interop/` | 49 | 11,959 | `proof_wire`, `circuit_recursion` | 10 loose files (io helpers, Cairo/RISC-V artifacts) |
| `prover_api/` | 20 | 5,778 | `stwo_prover_api` | — |
| `backend/` | 20 | 3,386 | `stwo_backend_contracts` | — |
| `artifact_store/` | 14 | 2,277 | `stwo_artifact_store` | — |
| `bench/` | 8 | 1,245 | none | Metal and Cairo-Metal bench roots |
| `std_shims/` | 2 | 166 | none | — |
| `tracing/` | 1 | 150 | none | — |

Plus 35 loose `.zig` files at `src/` (§5.1).

### 2.3 Boundary health

`python3 scripts/check_package_workspace.py` **fails with 830 findings**. It runs
only in `package-release.yml`, so no PR is blocked by it.

| Finding class | Count | Main sources |
|---|---:|---|
| undeclared named import | 374 | `riscv_cuda → riscv_cpu` 138; `riscv_cpu → circuit_frontend` 89; `riscv_cpu → circuit_cpu` 48; `riscv_cuda → circuit_cpu` 35; `riscv_cuda → circuit_frontend` 23; `riscv_frontend → cpu_backend` 12; `riscv_cpu → cairo_frontend` 3; `cuda_backend → prover_engine` 3 |
| API contract source missing | 216 | `stwo_sm83_frontend` 215 (stale test paths) |
| relative import enters another owner | 50 | loose `src/*_test_root.zig` / `*_codegen.zig` reaching into packages |
| build dependency / README drift | 15 | `riscv_cpu`, `circuit_cpu` |
| public API differs | 12 | `cpu_backend`, `cuda_backend`, `metal_backend`, `core` (`proof_suites`) |
| relative import target missing | 8 | `riscv_frontend` guest-precompile tests |

The declared layer table (`ALLOWED_DEPENDENCY_LAYERS`) lets `integration`
depend on **every** layer, including other integrations. Product-to-product
edges are therefore legal today. The existing ones:

| Edge | Kind | Target |
|---|---|---|
| `cairo_cuda → native_cuda` integration | Cairo line → Native line | extract the shared native-CUDA runtime into `backends/cuda` |
| `circuit_metal → cairo_cpu, cairo_metal` integrations | recursion → Cairo | Cairo leaf adapters move to `products/cairo/recursion` |
| `circuit_cpu → cairo_frontend` | recursion → Cairo | same |
| `riscv_cpu → cairo_frontend` (`witness.composition_bundle.Component`) | RISC-V → Cairo | move `composition_bundle` into `engine` via RFC |
| `riscv_* → circuit_frontend, circuit_cpu` | RISC-V → shared recursion | **legitimate**; declare `circuit` as a shared frontend |
| `riscv_metal → riscv_cpu`, `riscv_cuda → riscv_cpu` | same line | legitimate; extract a `riscv_host` package |

### 2.4 Complexity indicators

| Indicator | Value |
|---|---:|
| `.zig` files with `_vN` / `_partN` in the basename (`src/`) | 776 of 7,065 (636 in `frontends/riscv`, 381 of those in `recursion`) — *reported* 748 of 7,044 on the hygiene branch |
| `*_test_root.zig` files | 597 |
| distinct `STWO_RV64_*` literal tokens (excluding `autoresearch`) | 348 (283 in `src`); *census@4a4d01bd5* 294; *reported* 292 |
| flags declared in `conformance/rv64-flags.json` | 297: 135 runtime, 94 retire-after-native-default, 28 qualification, 3 frozen (= **260 live**), 34 constant, 3 reference-only |
| directories with more than 40 direct files | 35 (worst: `frontends/riscv/recursion/air` 449, `recursion` 445, `integrations/riscv_cpu` 333) |
| Zig files over 1,000 lines / over 2,000 lines | 45 / 0 (a 2,000-line ceiling already holds) |
| remote branches / `archive/*` tags | 538 / 243 |
| open PRs | 54 (*reported*) |
| broad Python suite | ≈47 failures, 49 errors (*reported*) |

---

## 3. Target architecture

### 3.1 Layers and allowed dependencies

| Layer | Packages (target) | May depend on |
|---|---|---|
| `support` | `src/support/{io,shims,tracing}` | `std` only |
| `waist` | `src/waist/{core,backend,prover_api,proof_wire,recursion_wire}` (layers `protocol`, `contract`, `api`, `interchange`) | `support`, earlier waist packages (`core` first) |
| `engine` | `src/engine/{prover,artifact_store}` | waist, support |
| `backend` | `src/backends/{cpu_scalar,metal,cuda}` | engine, waist, support |
| `frontend` | `src/frontends/{cairo,circuit,riscv/*,sm83,tensor}` | engine, waist, support (**no backend**; tests that need one live in an integration) |
| `integration` | `src/integrations/<frontend>_<backend>` | **one** frontend (plus declared `shared_frontends`), its backends, engine, waist, support; sibling integrations of the same frontend only through an explicit `<frontend>_host` package |
| `product` | `src/products/<line>/<target>` | integrations of the line's frontend(s), backends, engine, waist, support, and packages of the **same** product line |

Rules the checker enforces:

1. **P-1:** a `product` dependency target has the same `product_line` or a
   lower layer.
2. **P-2:** `product_line` values: `waist`, `engine`, `backend`, `riscv`,
   `circuit`, `cairo`, `ethereum`, `opstack`, `sm83`, `native`, `tensor`.
   Frontend lines (`riscv`, `circuit`) are shared and may serve several
   product lines.
3. **P-3:** no product names in frontend or integration paths or `api_surface`
   (D3).
4. **P-4:** `injected_modules` must be generated artifacts declared with their
   generator. Hand-written injection edges are rejected.

### 3.2 Legitimate overlaps

| Overlap | Mechanism |
|---|---|
| RISC-V frontend shared by Ethereum and OP Stack | `frontends/riscv/*` and `integrations/riscv_{cpu,cuda,metal}` stay product-neutral. Ethereum lives in `products/ethereum/*`, OP Stack in `products/opstack/*`, and each consumes the integrations through their public modules. A new RV64 service that OP Stack needs (for example BN254 Montgomery arithmetic) lands in `frontends/riscv/precompiles` under a primitive name, through an RFC, with a contract test from **both** consumers. Ethereum files are not edited. |
| Circuit recursion shared by Cairo and RISC-V | `frontends/circuit` + `integrations/circuit_*` become a shared recursion frontend (`product_line: circuit`). Cairo-leaf parsing moves to `products/cairo/recursion`, so `circuit_*` stops depending on Cairo. |
| Native-CUDA runtime shared by Native examples and Cairo-CUDA | `integrations/native_cuda/common` (26 files, 9,345 lines) moves to `backends/cuda/native_runtime`. Then `cairo_cuda` depends on a backend, not on another line. |
| Guests | `guests/<line>/` Rust crates, built by `tools/` scripts and consumed by products as hashed artifacts, not as source imports. |

### 3.3 How the build graph enforces it

| Mechanism | Today | Target |
|---|---|---|
| `package.contract.json` | schema v2: package, version, layer, owner, `public_modules`, `dependencies`, `injected_modules`, `api_surface`, `ci` | **v3** adds `product_line`, `shared_frontends`, `stability` (`stable` / `unstable`), `invariant_owner`, `error_codes` (waist), `budget` (§8 M-table), `consumers` (CDC registrations), `exceptions` (edge, issue, expiry) |
| `scripts/check_package_workspace.py` | checks layers (integration = any), imports, embeds, API ledger; red with 830 findings; release workflow only | adds P-1…P-4, the structure rule (RS-1: no loose source in containers), budget evaluation and exception expiry; runs in `scripts/ci.py --fast` on every PR; blocking |
| `build_support/graph/*.zig` | hand-written `addImport` wiring (for example `integrations.zig:176` injects `stwo_cairo_frontend`) | `package_ownership.zig` and module wiring are **generated** from the contracts (`scripts/ci_package_graph.py --emit-zig`). An import the contract does not declare has no module to resolve and fails to compile |
| `build_support/products/catalog.zig` | one file, 396 steps; every product edits it (the OP Stack branch adds steps here) | `build_support/products/<line>/catalog.zig` per line plus a 20-line aggregator. CODEOWNERS on each line's file |
| Root `build.zig.zon` | lists all 27 packages | lists the waist, engine and backends eagerly; frontends, integrations and products as `.lazy = true`; `zig build -Dline=<line>` builds one line's closure |
| Per-package `build.zig.zon` | exists for 31 roots | required for every package; `circuit_cuda` and every `src/products/<line>/<target>` gain a contract |

---

## 4. Target tree

```
build.zig  build.zig.zon  toolchain.json  ENGINEERING_STANDARDS.md  …
src/
  support/{io,shims,tracing}/
  waist/{core,backend,prover_api,proof_wire,recursion_wire}/
  engine/{prover,artifact_store}/
  backends/{cpu_scalar,metal,cuda}/            (metal/session, metal/tools, cuda/native_runtime)
  frontends/{cairo,circuit,sm83,tensor}/
  frontends/riscv/{isa,air_lang,rv32,rv64,precompiles,memory,recursion,recursion_air,testing}/
  integrations/{cairo,circuit,riscv,sm83,native,tensor}_{cpu,metal,cuda}/  (+ riscv_host, riscv_cpu_recursion)
  products/
    cairo/{shared,cpu,metal,cuda,aggregate,recursion}/
    ethereum/{statement,cpu,metal,cuda}/        (cuda = job service/driver)
    opstack/{statement,cpu,cuda,settlement_air}/
    riscv/{cpu,metal,tools}/                    (generic ELF prover, bench, trace)
    sm83/{cpu,metal}/
    native/{cpu,metal,cuda}/
    tensor/{cpu,metal,cuda}/
    stwo/                                       (root module facade)
guests/{ethereum,opstack,testing}/              (Rust guest crates)
tools/{waist,cairo,riscv,perf}/<crate>/         (oracles, adapters, collectors)
scripts/  (4 entry points + scripts/<area>/ libraries + scripts/tests/)
tests/{cairo,ethereum,riscv,native,cuda}/       (system tests and fixtures only)
vectors/{waist,cairo,riscv,circuit,starknet,sm83}/  (golden vectors only, MANIFEST.json)
conformance/  (machine-read policy, pins, presets, schemas — JSON only)
design/{repository,riscv,cairo,typed-air,…}/    (docs only)
formal/{riscv-refinement,tensor,opstack}/
bench/{site,<line>}/   third_party/   .github/   .claude/skills/
```

`src/products/stwo/root.zig` is the `stwo` root module. It exports `core`,
`backend`, `prover_api`, `proof_wire`, `recursion_wire` and `prover`. It does
not export `frontends`, `integrations` or `examples`; those come from product
facades.

---

## 5. Directory by directory

### 5.1 The 35 loose files in `src/`

Why they exist: under Zig 0.15, a root file can import relative paths only
inside its own directory tree. Files at `src/` can therefore reach any
subtree, and several say so explicitly (for example `riscv_bench_cli.zig`:
*"Zig 0.15 package-root compatibility facade"*). The fix is to replace every
cross-tree relative import with a named-module import, as RS-2 already
requires. After that, each root can live inside its owner.

| File | Lines | Live references | Action → target |
|---|---:|---|---|
| `stwo.zig` | 21 | `internal_build.zig`, `catalog.zig`, `cuda_tools.zig`, `compatibility_tools.zig` | move → `src/products/stwo/root.zig`; narrow exports to waist + engine (§4) |
| `tests.zig` | 42 | `catalog.zig`, `product_specs.zig`, `riscv_cpu.zig`, `benchmarks/metal.zig` | split: Metal tests → `backends/metal/tests/root.zig` and `integrations/cairo_metal/tests/`; Cairo → `integrations/cairo_cpu/tests/`; RISC-V → `integrations/riscv_cpu/tests/`; delete the file |
| `stwo_cairo_cpu.zig`, `stwo_cairo_metal.zig`, `cairo_cuda.zig` | 28 / 28 / 13 | `products/cairo_*.zig`, `matrix.zig` | move → `src/products/cairo/{cpu,metal,cuda}/root.zig` |
| `stwo_aggregate_cpu.zig`, `stwo_aggregate_metal.zig` | 32 / 16 | `products/aggregate*.zig` | move → `src/products/cairo/aggregate/{cpu,metal}.zig` |
| `stwo_native_cpu.zig`, `stwo_native_metal.zig` | 25 / 26 | `products/native_*.zig`, `check_native_*_product.py` | move → `src/products/native/{cpu,metal}/root.zig` |
| `stwo_deep.zig` | 38 | `gates/native.zig`, `gates/release.zig`, `release_evidence.py` | move → `src/products/native/cuda/deep_root.zig` (it imports `stwo_native_cuda_integration`) |
| `stwo_riscv_cpu.zig` | 22 | `riscv_cpu_*.zig`, `check_riscv_cpu_product.py` | move → `src/products/riscv/cpu/root.zig` |
| `riscv_bench_cli.zig`, `riscv_trace_cli.zig`, `riscv_metal_bench_cli.zig` | 5 each | `catalog.zig`, `riscv_cpu_executables.zig`, `riscv_metal.zig` | delete the facades; point build steps at `src/products/riscv/tools/{bench,trace}/main.zig` and `src/products/riscv/metal/bench_main.zig` (moved from `src/tools/riscv/*`) |
| `metal_arena_plan_cli.zig` | 7 | `benchmarks/metal.zig`, `catalog.zig` | delete; build step → `src/backends/metal/tools/arena_plan/main.zig` |
| `metal_{circle_lde,composition_pool,fri,quotient_allocation,sampled}_budget_codegen.zig` (5) | 30–72 | **none** (only design notes) | delete; the pending post-merge hygiene change already deletes them. If revived: `src/backends/metal/codegen/` |
| `metal_*_test_root.zig` (8) | 49–595 | **none** | delete with the codegen, or move → `src/backends/metal/tests/` and register in the package contract |
| `riscv_native_polynomial_aot_{export,test_root}.zig` | 51 / 125 | each other only | delete (pending hygiene); if revived → `src/integrations/riscv_metal/aot/` |
| `rv64_recursion_budget_test_root.zig` | 64 | none | move → `src/integrations/riscv_cpu_recursion/tests/` and register, or delete |
| `shared_external_{memory,pcs_budget}_test_root.zig` | 276 / 96 | design note only | move → `src/engine/prover/tests/` and register |
| `borrowed_proof_capture_test_root.zig` | 5 | none | fold into `src/waist/core/tests/root.zig` |
| `std_shims_freestanding.zig` | 8 | `gates/release*.zig`, `release_evidence.py` | move → `src/support/shims/freestanding.zig` |

Result: `src/` holds 8 directories and `README.md`. Gate: structure rule RS-1.

### 5.2 `src/` packages

| Current | Target | Action |
|---|---|---|
| `core/` | `waist/core/` | move. Move `cairo_air_layout.zig` → `frontends/cairo/air_layout.zig` and `circuit_proof_shape.zig` → `waist/recursion_wire/` (both via RFC; both are product types inside the protocol core). Move the 34 loose test roots → `tests/` with one `tests/root.zig` |
| `backend/` | `waist/backend/` | move; no content change |
| `prover_api/` | `waist/prover_api/` | move |
| `interop/proof_wire/`, `interop/circuit_recursion/` | `waist/proof_wire/`, `waist/recursion_wire/` | move; `interop/` dissolves |
| `interop/{atomic_file,bzip2,output_transaction}.zig` | `support/io/` | new `support` package (std-only; bzip2 binds `third_party/bzip2`) |
| `interop/{felt_json,cairo_prover_parameters}.zig`, `interop/postcard*` | `frontends/cairo/interop/` and `waist/recursion_wire/` | split by consumer |
| `interop/{riscv_artifact*,examples_artifact*}`, `interop/parity/` | `products/riscv/artifact/`, `products/native/artifact/`, `vectors/waist/` + `waist/core/tests/parity/` | parity vectors become waist golden vectors |
| `prover/` | `engine/prover/` | move; 34 loose test and benchmark roots → `tests/` and `bench/` subdirs; collapse `*_family.zig` pairs in Phase 2 |
| `artifact_store/` | `engine/artifact_store/` | move |
| `std_shims/`, `tracing/` | `support/shims/`, `support/tracing/` | move |
| `backends/{cpu_scalar,metal,cuda}` | same | `backends/mod.zig` and `metal_surface.zig` → `backends/metal/surface.zig`. `cuda/native/rv64` (137 files) → `integrations/riscv_cuda/kernels/`, `cuda/native/cairo` (9) → `integrations/cairo_cuda/kernels/` (kernels that know a frontend's AIR are integration code). Move the 18 loose files in `cuda/` into `abi/`, `runtime/`, `codegen/` |
| `tools/metal_session`, `tools/metal_arena_plan`, `tools/metal_core_aot`, `tools/metal_prover_session` | `backends/metal/{session,tools/*}` | `metal_session` stays a package |
| `tools/cairo*` (9 dirs) | `products/cairo/tools/` | move |
| `tools/riscv`, `tools/riscv_opcode_manifest` | `products/riscv/tools/`, `frontends/riscv/isa/tools/` | move |
| `tools/{interop,prove,native_proof_bench,circuit_cuda_air_aot,cuda_native_ec_composite_oracle}` | `products/native/tools/`, `products/stwo/tools/`, `integrations/circuit_cuda/aot/` | move by owner |
| `bench/` (8) | `backends/metal/bench/`, `integrations/cairo_metal/bench/` | move |
| `tests/` (153) | owners' `tests/` | `tests/riscv` (96) → `integrations/riscv_cpu/tests/` and `products/riscv/cpu/tests/`; `tests/native` (24) → `products/native/*/tests/`; `tests/metal` (22) → `backends/metal/tests/`; `tests/cairo` (9) → `integrations/cairo_*/tests/`; `tests/cuda` (2) → `backends/cuda/tests/` |
| `examples/` | `products/native/examples/` (package `stwo_native_examples`) | move; 14 loose example files → one dir per example |
| `products/*` (15 dirs, no packages) | `products/<line>/<target>/` packages | each target gets `package.contract.json` and `build.zig.zon` (§6) |
| `frontends/*`, `integrations/*` | per §5.3–5.4 and §6 | — |

Moves use one PR per package: a `git mv`-only commit, then a reference-fixup
commit. The old public module name stays as a forwarding facade for one minor
version (§7.2).

### 5.3 `src/frontends/riscv` (3,105 files, 800,359 lines, 221 loose files including 176 test roots)

| Sub-package (target) | Current sources | Files / lines (current) | Notes |
|---|---|---:|---|
| `riscv/isa` (`stwo_riscv_isa`) | `isa/`, `common/`, `access_clock.zig`, opcode manifest, `compat_manifest_tool.zig` | ≈25 / 4k | Sail-authority boundary; stable before the others |
| `riscv/air_lang` (`stwo_riscv_air_lang`) | `air/lang/` | 399 / 145,108 | typed AIR language; 0 users outside RISC-V. Candidate for later promotion into the waist AIR framework, via RFC only |
| `riscv/rv32` (`stwo_riscv_rv32`) | `runner/` (minus guest precompiles), `air/{block,extract,program,semantics,lookups,trace_columns,transcript,preprocessed}`, `prover/` (minus guest precompiles and shards), `host/`, `infra_trace/`, `diagnostics/`, `aggregation/` | ≈420 / ≈150k | RV32IM zkVM (`rv32im-zkvm-v1`) |
| `riscv/rv64` (`stwo_riscv_rv64`) | `rv64/` minus `ethereum_services/` | 491 / ≈70k | RV64IM AIR and execution |
| `riscv/precompiles` | `air/guest_precompile`, `prover/guest_precompile`, `runner/guest_precompile`, `rv64/ethereum_services` (renamed `rv64_services`) | ≈325 / ≈99k | names by primitive (keccak, sha256, secp256k1, bn254), never by product |
| `riscv/memory` | `air/memory_commitment`, `prover/memory_provider_shards`, `block_memory*` | ≈90 / ≈30k | — |
| `riscv/recursion` + `riscv/recursion_air` | `recursion/` (445 loose, 381 versioned) + `recursion/air` (595) | 1,093 / 311,009 | **collapse versions first** (Phase 2), then split; target ≤100k lines each |
| `riscv/testing` | `testing/` + shared fixtures | 3 / 1.1k | test-only (`stability: unstable`) |
| → `products/ethereum/statement` | 197 `ethereum*`-named files (for example `ethereum_block_execution.zig`, `ethereum_candidate_*`, `ethereum_omit_protocol_v1.zig`, `incremental_ethereum_*`) | ≈197 / est. 50k | product code leaves the frontend (P-3) |

`src/frontends/riscv/mod.zig` remains for one minor version as the umbrella
`stwo_riscv_frontend`, re-exporting the sub-packages; then it is removed. Each
sub-package owns `tests/` and one `tests/root.zig`, which replaces the 176
loose test roots. `build_focused_tests.zig` becomes generated from the
contracts' `ci` blocks.

### 5.4 Integrations

| Current | Target | Action |
|---|---|---|
| `riscv_cpu` (1,127 files; 333 loose: 129 test roots, 57 `_main.zig`) | `integrations/riscv_cpu` (word16, word16_execution, composition_ir, logup_gkr, outer_gkr, proof_adapter, delegations, poseidon2_outer, word16_index) | product-neutral RV32/RV64 CPU proving |
| | `integrations/riscv_cpu_recursion` | `rv64_recursion/`, `word16_recursion/`, 67 `recursive_segment_*` files |
| | `integrations/riscv_host` | the host-side surface that `riscv_cuda` (138 imports) and `riscv_metal` use, declared |
| | `products/ethereum/cpu` | `word16_global_execution/ethereum/`, 21 `rv64_ethereum_*` files, Ethereum mains |
| | delete / collapse | `rv64_distributed_v1` + `rv64_distributed_execution_v1`, `word16_setup_audit`, diagnostic mains without a build-step consumer |
| `riscv_cuda` (347; 57 loose, 33 mains) | `integrations/riscv_cuda` (`rv64/` runtime, native stages, kernels from `backends/cuda/native/rv64`) + `products/ethereum/cuda` (`rv64/jobs/driver*`, job service, basket integration) | legacy sweep (§8 Phase 2) deletes `admission_runtime.zig` 766, `global_admission.zig` 885, `native_stage1_admission.zig` 165, `native_hybrid.zig` 1,112, `jobs/native_hybrid_jobs.zig` 426, the hybrid part of `outer_job_factory.zig` (1,898), `m8_feeder.zig` 200, `jobs/provider.zig` 320 (5,772 lines in those files; the contract estimates 20–30k with dependents) |
| `riscv_metal` (15) | same | stops importing `riscv_cpu` directly; uses `riscv_host` |
| `cairo_cpu`, `cairo_metal`, `cairo_cuda` | same | `cairo_cuda` drops the `native_cuda` dependency (§3.2); 38 loose files → `executor/`, `planning/` |
| `circuit_cpu`, `circuit_metal`, `circuit_cuda` | same, `product_line: circuit` | Cairo-leaf code → `products/cairo/recursion`; `circuit_cuda` gains a contract |
| `native_cuda`, `native/` | `integrations/native_cuda` | `common/` → `backends/cuda/native_runtime`; `native/` (2 files) merges into it |
| `sm83_cpu`, `sm83_metal` | same | — |
| `integrations/mod.zig` | delete | the root module no longer aggregates integrations |

### 5.5 Other root directories

| Directory | Target | Action |
|---|---|---|
| `autoresearch/` | — | retired in this PR. Live parts → `tools/perf/`, `guests/ethereum/`, `tests/fixtures/<product>/`, `bench/<product>/`, `.claude/skills/`; history behind an archive tag |
| `vectors/` | `vectors/<line>/` golden only | `reports/` (14,772) → evidence store (Phase 3). `fixtures/` (177) → `vectors/<line>/fixtures`. `riscv_guests/` (28 Rust) → `guests/testing/`. `riscv_elfs/`, `riscv_csp/` → `vectors/riscv/`. `cairo/`, `cairo_traces/` → `vectors/cairo/`. `starknet/` (116 MB) → `vectors/starknet/` behind an LFS or artifact pointer. `rv64-m5/`, `rv64-m6/` → evidence. `fields.json`, `constraint_expr.json`, `air_derive.json` → `vectors/waist/`. Add `vectors/MANIFEST.json` (path, sha256, generator, generator pin, consumers) |
| `design/` | docs only | `typed-air/artifacts/` (36 files, 3.3 MB, `*.zig` embedded by `product_specs.zig:63-65` and `riscv_shared_shell.zig:143-157`) → `src/frontends/riscv/air_lang/artifacts/` as an owned generated-artifact module. `riscv-proving-stack/m7-handoff/` (75 files, read by `rv64_gate.py`, `rv64_m7_integration_stack.py`, `source_conformance_lib/rv64_flags.py`) → `conformance/rv64/presets/`. 404 loose `riscv-proving-stack/*.md` → `design/riscv/{current,decisions}` plus the evidence store for dated receipts. `typed-air/{receipts,performance,notes}` → evidence store |
| `conformance/` | JSON policy, pins, schemas, presets | 15 dated `.md` goals and audits → `design/decisions/` or evidence; `evidence/` (32) → evidence store; `circuit_slot_order/` (a package with `build.zig.zon`) → `src/waist/recursion_wire/tests/slot_order/` |
| `tests/` | `tests/<line>/` system tests | 7 loose `native_cuda_*.zig` → `tests/native/cuda/`; `tests/cuda/rv64` (79) → `tests/ethereum/cuda/`; `tests/scripts/` → `scripts/tests/`; `tests/fixtures/<product>/` stays |
| `scripts/` | 4 entry points at top + `scripts/<area>/` packages | 207 loose scripts → `scripts/{ci,riscv,cairo,native,cuda,metal,evidence,tensor}/`; prefixes today: `riscv_` 138, `rv64_` 53, `native_` 35, `cuda_` 27, `check_` 21, `metal_` 9, `riscv64_` 9, `cairo_` 8. Unreachable scripts are deleted (reachability test exists) |
| `tools/` | `tools/{waist,cairo,riscv,perf}/` | waist oracles: `stwo-vector-gen`, `stwo-cf-vector-gen`, `stwo-air-derive-vector-gen`, `stwo-interop-rs`, `stwo-trace-digest`, `stwo-circuit-oracle-rs`. Cairo: `stwo-cairo-*` (5), `cairo-witness-compiler`, `stwo-eval-program-abi`, `starknet-aggregator-rs`, `starknet-block-collector`. RISC-V: `rv64-cuda-callsites`, `rv64-cuda-counters`. `stwo-cuda-adapter-rs`: owner audit, then `tools/cairo` or `tools/waist`. Every crate gets `rust-toolchain.toml` |
| `formal/` | `formal/{riscv-refinement,tensor,opstack}` | Tensor and OP Stack Lean move here from their branches |
| `soundness/` | `design/soundness/` | `air-ir-v2.schema.json` → `conformance/schemas/` |
| `bench/` | `bench/{site,<line>}` | — |
| `archive/` | delete | `legacy_claim_registry.zig` is unreferenced; keep it recoverable through an archive tag |
| `third_party/` | same | add `third_party/INVENTORY.json` (name, version, licence, upstream, hash); licence gate reads it |
| `.github/` | + `standards.yml` (this PR), `CODEOWNERS`, `dependabot.yml` | CODEOWNERS maps each `product_line` directory to its invariant owner |
| root | + `toolchain.json`, `build.zig.zon .minimum_zig_version = "0.15.2"` | §8 Phase 0 |

---

## 6. Product by product

### 6.1 Cairo / Starknet

| Current | Target |
|---|---|
| `frontends/cairo` (193 / 42k) | `frontends/cairo` (+ `air_layout.zig` from core) |
| `integrations/cairo_{cpu,metal,cuda}` | same; `cuda` loses `native_cuda` edge; `backends/cuda/native/cairo` → `cairo_cuda/kernels` |
| `products/cairo{,_cpu,_metal,_cuda}`, `src/stwo_cairo_*.zig`, `src/cairo_cuda.zig` | `products/cairo/{shared,cpu,metal,cuda}` |
| `src/stwo_aggregate_*.zig`, `products/circuit_recursion_*` (Cairo leaf wrap/fold) | `products/cairo/{aggregate,recursion}` |
| `src/tools/cairo*` | `products/cairo/tools` |
| `tools/stwo-cairo-*`, `starknet-*`, `cairo-witness-compiler`, `stwo-eval-program-abi` | `tools/cairo/` |
| `vectors/{cairo,cairo_traces,starknet}`, `design/starknet-proving-pipeline`, `archive/cairo` | `vectors/{cairo,starknet}`, `design/cairo`, archive tag |

Cairo code depends on no RISC-V package (0 imports today; keep it that way
with P-1).

### 6.2 Ethereum (RISC-V RV64)

| Current | Target |
|---|---|
| 197 `ethereum*` files in `frontends/riscv` | `products/ethereum/statement` |
| `integrations/riscv_cpu/word16_global_execution/ethereum`, `rv64_ethereum_*` | `products/ethereum/cpu` |
| `integrations/riscv_cuda/rv64/jobs/*` (driver, worker, request, serve, probe) | `products/ethereum/cuda` |
| guest (`autoresearch/benchmarks/guest_runtime/ethereum`, 259 files) | `guests/ethereum/` (this PR) |
| `tests/fixtures/ethereum`, `tests/cuda/rv64` | `tests/ethereum/` |
| `scripts/rv64_*` (53), `riscv64_*` (9) | `scripts/riscv/` and `scripts/ethereum/`; entry points unchanged |

### 6.3 OP Stack (branch `origin/codex/rv64-opstack-study`, merge base `4a4d01bd5`, 81 commits, 649 files, +168,915)

What the branch touches, read-only inspection:

| Area | Files | Problem |
|---|---:|---|
| `opstack/kona/{src,guest,vendor,tests,lean}` | 213 | new root dir; vendored Rust (116) without inventory |
| `settlement/` (JS/TS + fixtures) | 55 | new root dir |
| `vectors/reports/rv64-opstack-*` | ≈315 | receipts in the source tree |
| `src/integrations/riscv_cpu/word16_global_execution/ethereum/*` | ≈25 | **edits Ethereum product code** (for example `gkr_main.zig` −567 lines, new `cpu_plan.zig`, `receiver_setup.zig`) |
| `src/frontends/riscv/rv64/ethereum_services/{candidate_curves,montgomery_bn254}.zig` | 2 | adds a shared primitive under an Ethereum name |
| `src/prover/{poly,lookups,file_backed_allocator}`, `backends/cpu_scalar/mod.zig`, `integrations/circuit_cpu/om31/prove.zig` | 9 | waist-adjacent and engine changes without RFC |
| `build_support/products/{catalog,riscv_cpu,riscv_recursion}.zig`, `scripts/rv64_resident_basket.py` | 4 | shared catalog edits; removes the `rv64-word16-ethereum-gkr` tool |

Target: `guests/opstack/` (kona guest + host crates; `vendor/` listed in
`third_party/INVENTORY.json`), `products/opstack/{statement,cpu,cuda,settlement_air}`
(Zig: OP public fold, settlement AIR fixture), `tools/opstack/settlement/` (or
its own repository, §9), `formal/opstack/`, `build_support/products/opstack/catalog.zig`.
The `word16_global_execution/ethereum` pipeline is split before the branch
lands. The product-neutral RV64 block pipeline (plan, receiver setup, resources,
native batch) goes to `integrations/riscv_cpu/rv64_pipeline` with a
`ProductHooks` interface. Ethereum and OP Stack then each implement the hooks
in their own product package. BN254 Montgomery arithmetic goes to
`frontends/riscv/precompiles/bn254`. Each change is an RFC with CDC tests from
both products. After the split, an OP Stack PR's diff touches only
`products/opstack`, `guests/opstack`, `tools/opstack`, `formal/opstack` and its
catalog. CODEOWNERS plus P-1 make any other edit visible and owner-gated.

### 6.4 Tensor (branch `origin/codex/tensor-frontend`, PR #321, merge base `04bad4833`, 218 commits, 1,303 behind the PR #314 line)

| Area | Files | Problem |
|---|---:|---|
| `src/tensor/*` | 71 | flat loose package at `src/` level (CLIs, tests, CUDA, Metal mixed) |
| `src/core/fields/{qm31,om31}.zig` | 2 | waist edit: OM31 helpers (additive), and **`QM31.mul` changed from `inline` to a normal function** — a hot-path performance contract change |
| `src/prover/lookups/gkr_prover_fast.zig` (+253), `prover/poly/circle/mod.zig` | 2 | engine edits |
| `scripts/tensor_*` | 8 | loose scripts |
| `design/tensor-frontend`, `formal/tensor-frontend`, `vectors/reports/tensor-frontend-*` | 15 / 15 / 45 | docs, Lean, receipts |

Target: `frontends/tensor`, `integrations/tensor_{cpu,metal,cuda}` (from
`src/tensor/{cuda,metal}`), `products/tensor/*` (`serve.zig`, `verify_cli.zig`),
`scripts/tensor/`, `design/tensor/`, `formal/tensor/`, receipts in evidence.
The field change becomes two RFCs. The additive OM31 API is a minor bump. The
`inline` removal needs a field microbenchmark plus a bench15 delta, or it is
rejected. The GKR change is an engine RFC. The Tensor line depends on nothing
in RISC-V, Cairo or Ethereum.

### 6.5 Circuit recursion, SM83 and Native examples

| Line | Current | Target |
|---|---|---|
| Circuit recursion (shared) | `frontends/circuit` (122), `integrations/circuit_{cpu,metal,cuda}` (110), `interop/circuit_recursion`, `conformance/circuit_slot_order` | `frontends/circuit`, `integrations/circuit_*`, `waist/recursion_wire`; Cairo-specific code → `products/cairo/recursion`; `product_line: circuit`, declared `shared_frontends` for `riscv_*` |
| SM83 | `frontends/sm83` (290 / 118k; 97 + 108 loose; 215 stale contract entries), `integrations/sm83_{cpu,metal}`, `scripts/sm83_*` (4) | `frontends/sm83/{cpu_model,air,prover}` sub-dirs, `products/sm83/{cpu,metal}`, `scripts/sm83/`; fix the contract first (Phase 0) |
| Native examples | `examples` (53), `integrations/native_cuda` (281), `integrations/native`, `products/native_*`, `src/stwo_native_*.zig`, `src/stwo_deep.zig`, `tests/native_cuda_*.zig` (7), `src/tests/native` (24), `scripts/native_*` (35) | `products/native/{examples,cpu,metal,cuda}`, `integrations/native_cuda`, `backends/cuda/native_runtime`, `tests/native/` |

---

## 7. The thin waist

### 7.1 Membership

| Package (target path) | Contents | Current lines | Layer |
|---|---|---:|---|
| `stwo_core` (`waist/core`) | `fields` (M31, CM31, QM31, OM31, packed forms), `circle`, `fft`, `poly`, `channel` (transcript), `vcs`, `vcs_lifted` (Merkle verifier), `pcs`, `fri` (verifier), `queries`, `proof_of_work`, `proof`, `verifier`, `verifier_types`, `air`, `constraint_framework`, `constraints`, `fraction`, `crypto`, `protocol_revision`, `preprocessed_tables` | 28,435 | protocol |
| `stwo_backend_contracts` (`waist/backend`) | backend capability interface (15 exports: `Capabilities`, `Column`, `field_ops`, `fri_ops`, `merkle_ops`, `line_evaluation`, `resident_storage`, …) | 3,386 | contract |
| `stwo_prover_api` (`waist/prover_api`) | prover transaction, `ProveOptions`, diagnostics, task-profile schema (21 exports) | 5,778 | api |
| `stwo_proof_wire` (`waist/proof_wire`) | proof wire encode/decode, JSON and binary (19 exports) | 1,176 | interchange |
| `stwo_recursion_wire` (`waist/recursion_wire`) | recursion request and registry wire (10 exports) + `circuit_proof_shape` | 2,747 | interchange |

The waist is ≈41k lines, 2.4 % of Zig source. `stwo_prover_engine` (75,642
lines: PCS/FRI provers, task graph, allocators) sits **above** the waist as
`engine`. It is semver-versioned but `stability: unstable` until Phase 2,
because performance work changes it constantly. AIR authoring (`air/lang`)
stays a RISC-V package until a second frontend needs it.

Out of the waist: `core/cairo_air_layout.zig` (→ Cairo frontend),
`core/test_utils.zig` (→ `waist/core/testing`, `stability: unstable`), and
`proof_suites` (undeclared API drift; declare it or remove it).

### 7.2 Semver and compatibility

| Rule | Policy |
|---|---|
| Version source | `package.contract.json.version`. Phase 1 exit sets waist packages to `1.0.0` |
| Major | removal or signature change of an `api_surface` entry; change to wire bytes, transcript order or field encoding; changed error code meaning |
| Minor | additive API, new error code, new wire version that readers accept alongside the old one |
| Patch | no API ledger change and golden vectors unchanged |
| Wire compatibility | the verifier reads the current and previous `protocol_revision`; a new revision ships with a reader for N−1 and golden vectors for both |
| Deprecation | `@deprecated` marker plus ledger entry; removal no earlier than the next major and ≥30 days on trunk; forwarding facades for moved modules live one minor version |
| Check | `check_package_workspace.py` compares the API ledger diff against the version bump and rejects a ledger change without the matching bump |

### 7.3 Error model

Each waist package exposes one public `Error` set and an `error_codes.zig`
table `{tag, code: u16, class, since}`. Classes are `invalid_input`,
`verification_failed`, `resource_exhausted`, `unsupported` and `internal`.
Codes are append-only and never reused; a golden test pins the table. CLIs map
classes to exit codes, and JSON receipts carry `{code, class}`, not free text.
At this commit the waist has 43 `error{…}` declarations and no stable codes.

### 7.4 Consumer-driven contract tests

Each consumer package declares `consumers` in the provider's contract and owns
`contract_tests/<provider>_test.zig`, which exercises only the provider APIs
it imports. The provider's CI lane runs every registered consumer's contract
tests, so a waist change runs Cairo, RISC-V, circuit, SM83, native and every
backend contract test before merge. Initial consumers: 4 frontends, 3
backends, the engine, and `proof_wire` users (`examples`, `native_cuda`).

### 7.5 Property tests and golden vectors

| Invariant | Property test (Debug **and** ReleaseFast) | Golden vector |
|---|---|---|
| Field arithmetic M31/CM31/QM31/OM31 | ring axioms, inverse, Frobenius, packed vs scalar equality, canonical encoding round-trip | `vectors/waist/fields.json` (from `vectors/fields.json`, generator `tools/waist/stwo-vector-gen`) |
| Circle domain | group law, coset and twin-coset membership, bit-reversal involution, FFT ∘ IFFT = id | `vectors/waist/circle.json` (new) |
| Channel / transcript | determinism, mix/draw order, PoW verification boundary | `vectors/waist/channel.json` (from `interop/parity`) |
| Merkle / VCS | commit → decommit → verify round-trip; any single-bit tamper is rejected | `vectors/waist/vcs.json` (`parity/vectors/proof_vcs.zig`) |
| FRI | fold commutes with evaluation; fold at random alpha matches a reference; ReleaseFast result equals Debug result. The ReleaseFast-only FRI projection bug found during the hygiene work is the regression seed | `vectors/waist/pcs_fri.json` (`parity/vectors/pcs_fri.zig`) |
| Proof wire | encode∘decode = id; canonical bytes; N−1 revision readable | `vectors/waist/proof_wire/*.bin` |
| Constraint framework / AIR | `constraint_expr` evaluation matches the reference | `vectors/waist/{constraint_expr,air_derive}.json` |

Property tests use a seeded PRNG. The seed is printed on failure and stays
fixed in CI. `std.testing.fuzz` targets cover proof-wire decode and
recursion-wire decode. Every waist lane runs at `-Doptimize=Debug` and
`-Doptimize=ReleaseFast`.

---

## 8. Phases

### Phase 0 — trunk and gates (≈1–2 weeks)

Already done by the current hygiene work (*reported* unless measured):

| Item | Result |
|---|---|
| Working copies | 163 worktrees → 1 |
| M8/M9 branches | 72 remote branches retired behind 241 archive tags (243 `archive/*` tags measured) |
| Code | −67,618 lines: 150 unreachable scripts, 63 research consumers, 59 test files |
| Historical reports | 7,004 report files staged for retirement on a local branch |
| `autoresearch/` | retired in this PR (17,816 files) |
| Trunk | `origin/main` = `4e260db96` merges PR #314 (1,304 commits) and contains `codex/rv64-m7-integrate` (0 commits ahead) — **main is now the trunk** (measured) |
| Standards | `ENGINEERING_STANDARDS.md`, `standards.yml` (secret scanning, dependency/licence job), PR and issue templates (this PR, parallel work) |

Remaining:

| Work item | Specifics | Effort |
|---|---|---|
| Land hygiene | merge the post-merge hygiene change (deletes 11 loose `src/` codegen and test roots), the 7,004-file report retirement and this PR to `main` | 1–2 d |
| Branch retirement | 538 remote branches (264 `codex/rv64*`, 45 `codex/tensor*`, 18 `autoresearch/metal*`): any branch with no open PR and no commit in 30 days → `archive/<branch>` tag pushed to the evidence remote, then delete. Target ≤30 live branches. Triage the 54 open PRs: rebase or close; OP Stack and Tensor stay open as designated product branches | 2–3 d |
| Toolchain pins | `toolchain.json` (zig 0.15.2 + sha256 per host; Python 3.13; Rust toolchains per crate; Lean 4 versions; CUDA image `@sha256` digest; minimum driver); `build.zig.zon .minimum_zig_version`; `rust-toolchain.toml` in all 13 crates; `scripts/ci.py --check-toolchains` fails on drift; workflows read the file instead of literals | 2 d |
| Security gates | gitleaks on PR diff plus a full-history baseline scan; `cargo-deny` (advisories, licences, sources) on 17 `Cargo.lock`; `third_party/INVENTORY.json` licence check; GitHub dependency review | 1–2 d (partly in this PR) |
| Boundary gate green | make `check_package_workspace.py` pass: declare the true edges (circuit as `shared_frontends`, `riscv_host`), fix 215 stale SM83 entries and 8 missing targets, delete or move the 50 owner-entering loose roots, record each disallowed product edge (§2.3) as an `exception` with issue and expiry. Then run it in `scripts/ci.py --fast` as a blocking check | 3–4 d |
| CPU CI green | fix or quarantine (with issue and expiry) the ≈47 failures and 49 errors in the broad Python suite; one command `python3 scripts/ci.py` runs the whole CPU suite; seeded randomness; no network or home-directory state | 3–5 d |
| GPU gate | the `focused-cuda` job on `[self-hosted, linux, x64, cuda]` is required for paths under `backends/cuda`, `integrations/*_cuda`, `products/*/cuda`. Fallback: `scripts/rv64_gate.sh` emits a receipt `{commit, image digest, driver, gate, result}` that a bot posts as a commit status | 2–3 d |

Exit: `main` protected (required checks: fast CI, package workspace,
standards, CPU suite, conditional GPU gate); ≤30 branches; toolchains pinned;
scanners blocking.

### Phase 1 — thin waist (≈2–4 weeks)

| Work item | Specifics | Effort |
|---|---|---|
| Waist packages | move to `src/waist/*` and `src/support/*` (§5.2); extract `cairo_air_layout` and `circuit_proof_shape`; contracts v3 with `stability: stable` | 3–4 d |
| Semver and ledger gate | API-ledger diff ⇒ required bump (§7.2); waist at `1.0.0` | 2 d |
| Error codes | `error_codes.zig` per waist package; CLI and receipt mapping; golden table test | 3 d |
| CDC tests | consumer contract tests for 4 frontends, 3 backends and the engine; provider lanes run them | 4–5 d |
| Property tests + goldens | §7.5 suite in Debug and ReleaseFast; `vectors/waist/` with `MANIFEST.json` and generator pins | 4–5 d |
| Generated build graph | `ci_package_graph.py --emit-zig` produces `package_ownership.zig` and module wiring; per-line catalogs | 3–4 d |
| Complexity budgets | `budget` block per contract, initialised at current values rounded down to a ratchet; `check_package_workspace.py --budgets` evaluates files, lines, `api_surface` size, dependency count, flags, versioned files, loose files, and a branch-count proxy for cyclomatic complexity on `hot: true` files (threshold 15 per function); allocation and latency ceilings reference the bench15 receipt for hot packages. An increase needs a CB-2 entry (benefit, containment, rollback/flag) | 3 d |
| Product-line rules | P-1…P-4 blocking; CODEOWNERS per line | 1–2 d |

Exit: waist `1.0.0`; every waist change runs every consumer's contract tests;
budgets enforced; no undeclared edges; exceptions only with unexpired issues.

### Phase 2 — complexity paydown (≈4–8 weeks)

| Work item | Specifics | Effort |
|---|---|---|
| Versioned copies | 776 `_vN` / `_partN` basenames → one live version per concept. Versioned **readers** required by supported artifacts are kept and listed in the contract (`versioned_readers`). Order: `frontends/riscv/recursion` (381), `air` (109), `prover` (77), `integrations/riscv_cpu` (84), `backends/metal` (28). Each batch: `dev_test.py` + one `rv64_gate.sh` | 2–3 wk |
| Flags | 260 live → <60. Registry fields add `expiry` and owner-as-package; CI rejects undeclared **and** expired flags. The 94 `retire-after-native-default` flags go with the legacy sweep; the 28 qualification flags become build options or presets; extend the registry to other `STWO_*` families | 1–2 wk (overlaps) |
| RISC-V split | §5.3 sub-packages after the version collapse; §5.4 integration split; Ethereum code → `products/ethereum` | 2 wk |
| GPU-native promotion + legacy sweep | per the hygiene contract order: 3+3 comparison on blocks 24628607 and 26235168 → setup-miss path → 15-block basket → default promotion → one sweep deleting `admission_runtime.zig`, `global_admission.zig`, `native_stage1_admission.zig`, `native_hybrid*.zig`, the `outer_job_factory` hybrid, `m8_feeder.zig`, `jobs/provider.zig`, the owner-callback path, their flags and receipts | 1–2 wk |
| OP Stack / Tensor landing prep | `rv64_pipeline` + `ProductHooks` split (§6.3); field and GKR RFCs (§6.4); both branches rebase onto the new layout | 1 wk |
| Loose files and fan-out | 0 loose source in containers; ≤40 direct files per directory | continuous |

Exit: §10 targets for versioned copies, flags, package size and loose files met.

### Phase 3 — evidence out, process in (≈1–2 weeks, then ongoing)

| Work item | Specifics | Effort |
|---|---|---|
| Evidence store | new `stwo-zig-evidence` repository (or an object store with a content-addressed index): `vectors/reports/` (14,772 files, ≈1.97 GB), `design/**/receipts`, `conformance/evidence/` (32), dated `conformance/*.md`. The source tree keeps `current/` receipts per gate (≤1 per gate and product) plus golden vectors. 36 code files referencing `vectors/reports` read `EVIDENCE_DIR` from `toolchain.json` | 3–4 d |
| Source identity | `scripts/riscv_recursive_product.py` hashes the build closure from the generated package graph plus `toolchain.json`, not whole `design/` and `conformance/` trees | 1 d |
| History | evidence removal is a normal commit; optional history rewrite only after the evidence repo is verified and tagged | — |
| Process | issues-first; RFC issue template for waist and engine changes; decision recorded in `design/decisions/NNNN-*.md`; named invariant owner per package (`invariant_owner` in contract, CODEOWNERS); quarterly budget review ratchets budgets down | ongoing |

Exit: no receipt directories in the source tree; clone size reduced from
≈3 GB tracked (≈2.2 GB `vectors/`, 0.7 GB `autoresearch/`) to ≈0.2 GB
(estimate).

---

## 9. Monorepo vs split

**Recommendation:** keep one repository for code, with enforced package
boundaries. Split out non-code evidence and research now (Phase 3).
Reasons: the waist is not yet stable, and cross-line refactors (recursion
wire, native-CUDA runtime, `rv64_pipeline`) are cheaper as atomic commits;
the Zig package workspace already gives package-level boundaries; and one
CI and toolchain is easier to keep reproducible.

A product line moves to its own repository only when **all** of these hold:

| # | Criterion |
|---|---|
| S1 | The waist has been at a stable major version for ≥2 minor releases with no breaking change, and the line depends only on published waist, engine and backend versions (no `exceptions`) |
| S2 | The line has had zero commits touching other lines' paths for ≥8 weeks |
| S3 | The line's CI is ≥20 % of total CI time or needs hardware or toolchains that others do not (for example Solidity settlement, a Lean/Mathlib stack, a dedicated GPU fleet) |
| S4 | The line has a separate release cadence, or separate access or licence requirements |
| S5 | The waist and its golden vectors are published as a versioned Zig package (tagged `build.zig.zon` dependency with hash) |

Likely first candidates: `tools/opstack/settlement` (non-Zig toolchain;
already meets S3/S4) and the Tensor line (no shared product code). Ethereum
and Cairo stay until S1/S5.

---

## 10. Hazards found

| Hazard | Evidence | Mitigation |
|---|---|---|
| `design/` holds build inputs | `product_specs.zig:63-65` and `riscv_shared_shell.zig:143-157` embed `design/typed-air/artifacts/{embedded,h009_embedded,h010_embedded}.zig` (36 files, 3.3 MB) | move to `src/frontends/riscv/air_lang/artifacts/` before any `design/` cleanup |
| `design/` holds runtime presets | `design/riscv-proving-stack/m7-handoff/` (75 files) read by `rv64_gate.py`, `rv64_m7_integration_stack.py`, `source_conformance_lib/rv64_flags.py`, `test_rv64_flags.py` | move to `conformance/rv64/presets/` in one PR with the readers |
| Source identity covers docs | `riscv_recursive_product.py:35-36` hashes `build.zig`, `build.zig.zon`, `build_support`, `src`, `scripts`, `design`, `conformance` | a doc move changes product identity; switch to closure hashing (Phase 3) **before** evidence moves, and record the identity break once |
| `vectors/` mixes goldens and receipts | 14,772 `reports/` files next to 177 fixtures; 36 code files read `vectors/reports`; 181 `src` files reference `vectors/`; `.gitattributes` has per-receipt rules | `vectors/MANIFEST.json` first; move receipts only after readers use `EVIDENCE_DIR` |
| `tests/` and `conformance/` are widely referenced | 423 grep lines for `tests/` (≈363 *reported*); 4,452 for `conformance/` (99 code files) | path moves via generated path constants (`build_support/paths.zig` + `scripts/repo_paths.py`); one directory per PR |
| The boundary gate exists but is red and not on PRs | 830 findings; runs only in `package-release.yml`; the standards text describes TW-2 as enforced | Phase 0 item "Boundary gate green" |
| Build wiring bypasses contracts | `build_support/graph/integrations.zig` and `benchmarks/metal.zig` inject `stwo_cairo_frontend` and others; 374 undeclared imports compile | generated graph (Phase 1) |
| The layer table allows integration → any layer | `ALLOWED_DEPENDENCY_LAYERS["integration"] = LAYERS` | P-1/P-2 rules |
| Product types in the protocol core | `core/mod.zig:18-19` exports `cairo_air_layout`, `circuit_proof_shape` | RFC move (Phase 1) |
| Zig 0.15 module-root rule | loose `src/*_cli.zig` facades exist only to reach subtrees | named-module imports first, then move |
| OP Stack edits Ethereum code | ≈25 files under `word16_global_execution/ethereum/`, `ethereum_services/montgomery_bn254.zig`, engine and backend files | `rv64_pipeline` hooks split before landing (§6.3) |
| Tensor changes the waist hot path | `QM31.mul` loses `inline`; OM31 API additions; `gkr_prover_fast.zig` +253 | field and GKR RFCs with benchmark evidence (§6.4) |
| Single shared build catalog | `catalog.zig` 396 steps; both product branches edit it | per-line catalogs (Phase 1) |
| Product kernels inside the backend | `backends/cuda/native/rv64` 137 files, `native/cairo` 9 | move to integrations (Phase 2) |
| Vendored code without inventory | OP Stack `opstack/kona/vendor` (116 files); Ethereum guest vendors `revm-bytecode`; `.gitattributes` references `src/backends/cuda/vendor/**` | `third_party/INVENTORY.json` + licence gate; vendored crates under `third_party/` or `guests/<line>/vendor` listed |
| Toolchain pins scattered | Zig `0.15.2` repeated in workflow YAML; Python 3.13 in CI vs local 3.14; 8 of 13 Rust tool crates unpinned; no CUDA image digest | `toolchain.json` (Phase 0) |
| Branch drift on product branches | Tensor merge base is 1,303 commits behind the PR #314 line; OP Stack base predates the #314 merge | rebase onto the new layout after Phase 1, not before |

---

## 11. Metrics and enforcement

| Metric | Today (`51897dc26`) | Target | Phase | Enforcing check |
|---|---:|---:|---|---|
| Loose source files in `src/` | 35 | 0 | 0–1 | `check_package_workspace.py` structure rule (RS-1) |
| Loose source files in any container dir (`src/{frontends,integrations,backends,products}`, `tests/`, `tools/`) | 1 + 1 + 2 + 0 + 7 + 0 | 0 | 1 | same |
| Directories with >40 direct files | 35 | 0 | 2 | budget `max_dir_fanout: 40` |
| Largest package (files / lines) | `frontends/riscv` 3,105 / 800,359 | ≤400 / ≤100,000 | 2 | contract `budget.max_files`, `budget.max_lines` |
| Zig files >1,000 lines / >2,000 | 45 / 0 | ≤20 / 0 | 2 | source-conformance file ceiling (exists) + budget |
| Versioned copies (`_vN`, `_partN`) | 776 | ≤50, all listed `versioned_readers` | 2 | budget `max_versioned_files` + listed readers |
| `*_test_root.zig` files | 597 | ≤1 test root per package (+ declared focused roots) | 2 | structure rule |
| Live `STWO_RV64_*` flags | 260 (297 declared; 348 literal tokens) | <60, each with expiry | 2 | `check_source_conformance.py` strict promotion check (exists) + expiry |
| Top-level scripts in `scripts/` | 207 (755 `.py` total) | ≤10 (entry points) | 2 | `test_script_reachability.py` + productionisation budget `scripts_added_budget: 0` |
| Receipt files in source tree | 14,772 (`vectors/reports`) + 32 (`conformance/evidence`) | ≤1 current per gate and product (≈100) | 3 | `check_evidence_layout.py` (new): no new files under `vectors/reports` |
| Tracked size of `vectors/` | 2.19 GB | ≤200 MB | 3 | same + `MANIFEST.json` size budget |
| Package workspace findings | 830 | 0 (exceptions with unexpired issues only) | 0 | `check_package_workspace.py` in `ci.py --fast` |
| Undeclared named imports | 374 | 0 | 0–1 | same + generated build graph |
| Product → product edges | 4 (§2.3) | 0 | 1–2 | P-1 |
| Waist packages with stable error codes / CDC tests / goldens | 0 / 0 / partial | 5 / 5 / 5 | 1 | contract v3 `error_codes`, `consumers`; golden manifest check |
| Waist lanes in ReleaseFast and Debug | ReleaseFast only (core `ci.command`) | both | 1 | contract `ci.optimize: [Debug, ReleaseFast]` |
| Remote branches | 538 | ≤30 | 0 | weekly branch-retirement job (archive tag, then delete) |
| Open PRs | 54 (*reported*) | ≤15, none >30 days without activity | 0 | stale-PR job |
| Toolchain pins | Zig/Python in YAML only; 5/13 crates pinned; no CUDA digest | one `toolchain.json`, 13/13, digest | 0 | `ci.py --check-toolchains` |
| Secret / dependency / licence scanning | none in 7 workflows | gitleaks, cargo-deny, licence inventory, dependency review | 0 | `standards.yml` |
| CPU CI on `main` | rarely green; ≈47 failures / 49 errors (*reported*) | green on every merge | 0 | branch protection required checks |
| GPU gate | self-hosted `focused-cuda` job, not required | required for CUDA paths, or a posted pod-gate receipt | 0 | path-filtered required status |
| Shared build catalog edits per product PR | 1 file for all lines (396 steps) | 0 (per-line catalogs) | 1 | CODEOWNERS + P-1 |

---

## 12. Execution rules for the moves

1. One package or directory per PR. Commit 1 is `git mv` only; commit 2 fixes
   references. Moves count as neither added nor removed lines (CB-1).
2. Before a move: list its readers with `git grep` (paths, embeds, scripts,
   workflows, `.gitattributes`) and add them to the PR description. After the
   move: `scripts/dev_test.py`, `scripts/ci.py --fast`, the package workspace
   gate, and `scripts/rv64_gate.sh` when RISC-V or CUDA paths moved.
3. Public module names that consumers import stay as forwarding facades for
   one minor version and are listed in the contract as `deprecated_modules`.
   File paths get no forwarding.
4. Source-identity changes caused by a move are recorded once in the current
   receipt. Pins and ceilings are never relaxed to make a move pass.
5. Product branches (OP Stack, Tensor) rebase after the Phase 1 layout lands.
   Their landing PRs must show a diff limited to their own line's paths, plus
   RFC-approved waist, engine or frontend changes.
