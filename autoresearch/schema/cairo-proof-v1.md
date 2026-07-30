# Cairo proof benchmark report v1

`cairo_proof_v1` is the fail-closed report contract consumed by the `cairo_cpu`
and `cairo_metal` workload groups (TRACKS §2, §8 wave 1). It is a **harness
envelope name, not a product report version**: the focused Cairo CLIs
(`stwo-cairo-cpu`, `stwo-cairo-metal`) already emit a `schema_version: 2`
proving report and a `schema_version: 1` stage profile, and this document pins
exactly how the harness reads them. Nothing in this schema was invented for the
harness; every field below is emitted today by
`src/products/cairo/shared/application.zig` and
`src/prover_api/stage_profile.zig`.

| identity | value |
|---|---|
| manifest `report_schema` | `cairo_proof_v1` |
| `manifest.REPORT_SCHEMA_VERSIONS["cairo_proof_v1"]` | `1` (envelope) |
| product report `schema_version` | `2` (`runner.CAIRO_PRODUCT_REPORT_SCHEMA_VERSION`) |
| stage profile `schema_version` | `1` (`runner.CAIRO_STAGE_PROFILE_SCHEMA_VERSION`) |
| parser | `runner._parse_cairo_report`, `runner._parse_cairo_stage_profile` |
| arm driver | `runner._bench_cairo`, dispatched from `runner.bench_once` |

## How one arm is measured

The Cairo CLIs prove exactly **one statement per process**. There is no
`--warmups`, no `--samples`, and no `--repeat`. The harness therefore owns the
loop: `_bench_cairo` runs `warmups + samples` cold processes, discards the
warmups, and measures each scored sample as one complete cold process. One
sample is one cold process by construction.

The `{warmups}` / `{samples}` registry placeholders are consequently **absent
from Cairo workload `args`** — there is no CLI flag to bind them to, and
inventing one would mean editing the product. Sampling is expressed only in the
group's `gates_policy`.

The mandatory phase profile is recorded on the **last discarded warmup**
(`--stage-profile-out`), so scored samples run uninstrumented and the profile's
cache/residency state is the closest available match to the first scored
sample. The envelope records this explicitly in `phase_profile_source`; phase
seconds are diagnostic telemetry and are never scored (TRACKS §3.2).

`--proof`, `--stage-profile-out`, and `--report-out` are owned by the runner
and are rejected if a manifest workload tries to set them. The report is read
from stdout (the CLI writes it to stdout exactly when `--report-out` is
omitted).

## Scored boundary (TRACKS §3.1)

| boundary | source | field |
|---|---|---|
| cold process | harness-measured subprocess wall time | `ArmResult.request_ms` (median), `mean_cold_process_seconds` |
| prove island | `report.timing.prove_ns` | `ArmResult.prove_ms` (median) — **diagnostic only** |

`prove_ms` is demoted to telemetry on every v3 track. The **scored** Cairo
boundary is the cold-process boundary: before process creation → after exit,
with the product's own independent verification (`--verify`, checked as
`verification.requested && verification.zig`) inside it. That is a strict
superset of PR6's verified-request boundary, so this track is never laxer than
PR6 (TRACKS §3.1); see [Gaps](#gaps-in-the-current-product-cli) for why the
tighter in-process request span does not exist yet.

## Product report (`schema_version: 2`)

Exact field set; any missing or unknown field fails closed.

```
schema_version          u32, must equal 2
product                 object (below)
frontend                "cairo"
backend                 non-empty string, equals product.backend
backend_evidence        object (below)
preprocessed_cache      object (below)
profile                 non-empty string (proving-profile name)
execution               null for `prove`; object for `run-and-prove` (below)
input.sha256            canonical lowercase SHA-256 of the prover input
proof.format            "json" | "binary" | "cairo-serde"; must equal the
                        format requested by the workload args
proof.bytes             positive integer; must equal the retained artifact size
proof.sha256            canonical SHA-256; must equal the retained artifact hash
timing.execute_ns       non-negative integer (0 for `prove`)
timing.prove_ns         positive integer
timing.verify_ns        positive integer
verification.requested  must be true
verification.zig        must be true
```

`product`:

```
schema_version              u32, 2
name                        must equal basename(group.binary)
frontend                    "cairo"
backend                     equals report.backend
role                        "cli"
protocol_features           non-empty string
protocol_manifest_sha256    canonical SHA-256
identity_sha256             canonical SHA-256
source.repository           https://github.com/teddyjfpender/stwo-zig
source.commit               full lowercase Git commit
source.tree                 full lowercase Git tree
source.dirty                boolean
source.dirty_content_sha256 SHA-256 when dirty, else null
zig_version                 non-empty string
target.arch/os/abi/cpu_model        non-empty strings
target.cpu_features_sha256          canonical SHA-256
optimize                    must equal "ReleaseFast"
runtime.manifest/sdk/aot            non-empty strings
upstream.stwo_cairo_revision        must equal correctness_oracle.commit
upstream.stwo_revision              must equal correctness_oracle.stwo_commit
upstream.cairo_language_version     non-empty string
upstream.cairo_vm_version           non-empty string
```

The two `upstream` checks are the oracle binding: a measured Cairo product must
be built against exactly the official Stwo-Cairo pair the manifest pins as the
final validator, or the sample is refused.

`backend_evidence`:

```
execution                     non-empty string ("cpu-simd", ...)
classification                non-empty string ("host-only", ...)
metal_dispatches              non-negative integer
cpu_fallbacks                 non-negative integer; MUST be 0
runtime_initializations       non-negative integer
runtime_shutdowns             non-negative integer
commit_source_arena_aliases   non-negative integer
commit_source_arena_memcpys   non-negative integer
commit_source_uploads         non-negative integer
```

`preprocessed_cache` (availability accounting only; never reaches a key, a
transcript, or a proof byte): `enabled` (bool) plus non-negative integers
`budget_bytes`, `hits`, `misses`, `stores`, `evictions`, `loaded_bytes`,
`stored_bytes`, `evicted_bytes`, `directory_bytes`, `eviction_ns`.

`execution` (only for `run-and-prove`): `program_type`, `program_sha256`,
`arguments_sha256` (nullable), `adapter_sha256`, `wall_ns`; `wall_ns` must equal
`timing.execute_ns`.

## Named phase cutpoints (TRACKS §3.2)

The stage profile is a hierarchical tree; the harness classifies its **roots**
into the eight named cutpoints. An unclassified root fails closed, so a product
that adds a stage forces a harness update instead of silently dropping proving
time. A missing mandatory root also fails closed.

| cutpoint | source |
|---|---|
| `execute` | `report.timing.execute_ns` |
| `witness` | `preprocessed_plan`, `preprocessed_table_build`, `base_trace_build`, `air_template_instantiation` |
| `commit` | `preprocessed_materialize_and_commit`, `main_trace_commit` |
| `interaction` | `interaction_trace_build`, `interaction_trace_commit` |
| `composition` | `draw_random_coeff`, `composition_trace_extract`, `composition_evaluation`, `composition_interpolate_and_split`, `composition_commit` (+ optional Metal roots `composition_device_admission`, `composition_device_declined`, `composition_device_components`, `composition_device_host_components`, `composition_device_fallbacks`) |
| `fri` | `oods_point_and_mask_points`, `sampled_value_evaluation`, `sampled_value_channel_mix`, `fri_quotient_build_and_commit`, `proof_of_work`, `fri_decommit`, `trace_decommit`, `constraint_check_and_assembly` |
| `serialize` | **not instrumented — emitted as `null`** |
| `verify` | `report.timing.verify_ns` |

## Mechanism telemetry

`mechanism_telemetry.required_fields` is manifest data, validated against
`manifest.CAIRO_MECHANISM_FIELDS`. The subset in
`manifest.CAIRO_STABLE_MECHANISM_FIELDS` is semantics rather than
implementation and must be identical across measured samples (and, once the
paired comparison is wired, across the A and B arms):

- stable: `profile`, `input_sha256`, `proof_format`, `proof_bytes`,
  `proof_sha256`, `stwo_cairo_revision`, `stwo_revision`
- identity: `product_identity_sha256`, `protocol_manifest_sha256`
- timing: `mean_execute_seconds`, `mean_prove_seconds`, `mean_verify_seconds`,
  `mean_cold_process_seconds`
- phases: `phase_seconds` (mandatory)
- Metal lane: `metal_dispatches`, `cpu_fallbacks`

## Retained evidence

`_bench_cairo` writes one envelope per arm per round at
`<out_dir>/<workload>.<tag>.json`:

```
schema                  "cairo_proof_v1"
workload / group / board
warmups / samples
measurement_boundary    "cold_process"
phase_profile_source    {invocation_index, scored: false, note}
phase_seconds           the eight named cutpoints
mechanism               exactly the manifest-declared required fields
measured_samples        one normalized record per scored sample
product_reports         the raw product reports, verbatim
```

Warmup proofs are deleted; measured-sample proofs are retained next to the
envelope so the official verifier can be pointed at them.

## Workload basket

Committed, runnable (TRACKS §3.3):

| workload | class | fixture | committed cells | note |
|---|---|---|---|---|
| `cairo_all_opcodes` | small | `vectors/cairo/official/all_opcodes.prover_input.json` (177 KiB) | 97,420,320 | campaign portfolio entry 1 |
| `cairo_all_builtins` | wide | `vectors/cairo/official/all_builtins.prover_input.json` (900 KiB) | — | builtin-saturating killer workload |

Both use official security parameters through their committed
`*.params.json` profiles (`all_opcodes` → `official-live-cairo-canonical-small`,
`all_builtins` → `official-live-cairo-canonical`). No functional-mode scoring
exists on Cairo.

Every Cairo class is a **standard** resource class. The Cairo CLIs have no
`--resource-profile` flag, so `xlarge`/`huge`/`extreme` (which the manifest
requires to pass `--resource-profile`) cannot be used until the product gains
that flag.

The acceptance corpus is `vectors/cairo/cairo_program_matrix.json` (pinned
`zksecurity/zkvm-benchmarks` @ `6d9d1e5e5a8086e6b3a52b03017421159f65ee6e`),
wired as `acceptance_corpus` with a `sha256` that `manifest.load()` verifies
against the committed bytes on every load. It is acceptance material, never a
scored basket.

### Large-fixture provisioning

Six of the seven campaign-portfolio workloads have prover inputs that are
host-local and far above any sane repository fixture budget (`memory-7m` alone
is 7,367,979 VM steps and needs roughly 17–18 GiB resident memory to prove).
They are declared in `workload_registry.groups.cairo_cpu.workload_provisioning.pending`
so their absence is loud, and they are not runnable workloads.

Regenerating one on a provisioning host:

```sh
# 1. Build the pinned official Cairo VM adapter (it is the only admissible
#    execution sidecar; its identity is checked by the product at run time).
cargo build --locked --release \
  --manifest-path tools/stwo-cairo-vm-adapter-rs/Cargo.toml

# 2. Execute the compiled Cairo program into an official ProverInput.
STWO_CAIRO_VM_ADAPTER=$PWD/target/release/stwo-cairo-vm-adapter \
  ./target/release/stwo-cairo-vm-adapter run \
    --program /path/to/<workload>.compiled.json \
    --program-type json \
    --arguments /path/to/<workload>.arguments.json \
    --prover-input-out /path/to/<workload>.prover_input.json

# 3. Prove and verify it with the released product to confirm the fixture.
zig build stwo-cairo-cpu -Doptimize=ReleaseFast
./zig-out/bin/stwo-cairo-cpu prove \
  --prover-input /path/to/<workload>.prover_input.json \
  --params vectors/cairo/official/all_builtins.params.json \
  --proof /path/to/<workload>.proof.json \
  --stage-profile-out /path/to/<workload>.stages.json \
  --verify

# 4. Confirm with the pinned official Rust verifier before trusting it.
cargo run --locked --release \
  --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml -- verify \
  --proof /absolute/path/<workload>.proof.json \
  --channel blake2s --proof-format json \
  --result /absolute/path/<workload>.verdict.json
```

A fixture only enters the manifest with an adjacent provenance record naming
the compiled program, its digest, the adapter identity, and the pinned
Stwo-Cairo revision — the shape already used by
`vectors/cairo/programs/official_corpus.provenance.json`.

## Correctness oracle

Both Cairo groups pin the official Stwo-Cairo verifier as `final_validator`:

```
authority        official-stwo-cairo-verifier
repository       https://github.com/starkware-libs/stwo-cairo
commit           82f21252a68ec006d73e299f5bf1ce6d4db0ee78
stwo_repository  https://github.com/starkware-libs/stwo
stwo_commit      7b211edde786775016ef3eecb837a6240d8fe792
adapter          tools/stwo-cairo-official-verifier-rs
build_command    cargo build --locked --release \
                   --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml
```

Those revisions are the ones declared by
`tools/stwo-cairo-official-verifier-rs/Cargo.toml`
(`[package.metadata.official-verifier]`), bound to full commits by its
`Cargo.lock`, and recorded in the Cairo Lane of `conformance/upstream.md`. Zig
scalar, SIMD, Metal, trace-oracle, or Zig-verifier agreement never overrides an
official-verifier rejection.

### How the judged path runs it

`runner.rust_oracle_check` dispatches `cairo_proof_v1` to
`_cairo_official_verifier_check`, which is the same authority the Cairo build
gates run (`build_support/products/cairo_cpu/oracle_gate.zig`) — the harness
just runs the release profile instead of the gate's debug one.

It verifies the **retained candidate proof**, not a freshly minted one:
`_latest_cairo_candidate_artifact` picks the last measured sample of the last
candidate round (`<workload>.b<round>.i<index>.proof`) and requires its bytes to
hash to the `proof_sha256` and match the `proof_bytes` recorded in that round's
`cairo_proof_v1` envelope. The bytes the official verifier accepts are exactly
the bytes that were scored.

```sh
# 1. only if the release binary is absent — the manifest owns the flags, and
#    the harness refuses a build_command that is not a locked release build of
#    the pinned adapter manifest.
cargo build --locked --release \
  --manifest-path tools/stwo-cairo-official-verifier-rs/Cargo.toml

# 2. bind the built adapter to the pins and the committed lockfile
tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier identity

# 3. verify the retained scored proof
tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier verify \
  --proof   <out_dir>/<workload>.b<round>.i<index>.proof \
  --channel  blake2s \
  --proof-format json \
  --result  <out_dir>/<workload>.cairo-oracle-verdict.json
```

The `identity` response must be `schema_version: 1`, `adapter_version:
stwo-cairo-official-verifier/1`, carry `stwo_cairo` / `stwo` repository and
revision equal to the manifest pins, a `cargo_lock_sha256` equal to the
committed `Cargo.lock` (proving the adapter was built from the pinned
dependency graph), an `executable_sha256` equal to the binary the harness just
ran, and the `blake2s` channel among its supported channels.

The verdict is validated field-for-field against an exact key set:
`verified: true`, `error: null`, `schema_version: 1`, both revisions equal to
the manifest pins, `channel` and `proof_format` equal to what was requested, and
`proof_sha256` equal to the scored proof digest. The adapter binary is re-hashed
afterwards and the retained proof is re-read, so neither can change during
validation.

**Judge-host provisioning.** The adapter package pins no toolchain of its own,
so the manifest's `build_command` runs under the host's *default* toolchain and
that default must be able to compile the pinned upstream. Measured on
2026-07-29: `stable` fails (`stwo-cairo-common` uses the unstable `lazy_get`
feature) and `nightly-2025-07-14` — the toolchain the Native/CUDA oracle pins —
fails on a `ruint` const-fn that is too new for it; `nightly-2026-01-29` builds
it. The judged path treats a build failure as a hard failure with the command in
the message, never as a skip. The same constraint already applies to the
`test-cairo-cpu-oracle` build gate, which invokes plain `cargo build --locked`.

Adapter exit codes are load-bearing: `0` accepted, `3` rejected, `2` adapter or
invocation failure. `_run` raises on any non-zero status, so a rejection and an
adapter failure both fail the judged run. **There is no skip**: an absent
adapter, a build that produces no binary, a missing lockfile, an unpinned oracle
block, or an unverifiable transport all raise instead of returning a pass.

Transport mapping: `json` → `json`, `binary` → `binary`. The `cairo-serde` proof
format has no Rust-verifier transport — the felt array targets the Cairo
verifier and this adapter deliberately rejects it — so a `cairo-serde` workload
fails closed rather than going unverified.

### Cross-arm mechanism drift

`paired_rounds` compares `manifest.CAIRO_STABLE_MECHANISM_FIELDS` between the A
and B arms of every round and against the first round's values:

| field | what it pins |
|---|---|
| `input_sha256` | the statement — both arms proved the same prover input |
| `proof_sha256`, `proof_bytes`, `proof_format` | the proof identity and transport |
| `stwo_cairo_revision`, `stwo_revision` | both arms are the same pinned official lane |
| `profile` | the same proving-profile manifest and preprocessed variant |

Backend identity does not need a separate stable field: `_parse_cairo_report`
already requires `report.backend == product.backend` and `product.name ==
basename(group.binary)` per sample, so an arm cannot silently be a different
product. Counters that a legitimate optimization may move — `metal_dispatches`
— are reported but deliberately not stable-compared; `cpu_fallbacks` is pinned
to zero at parse time.

An absent mechanism, a mechanism missing any stable field, an A/B divergence, or
a between-round change all raise `RunError`, exactly as on the RISC-V track.

## Promotion

Neither Cairo board is promotion eligible. `cairo_cpu` runs and records
evidence with `promotion_eligible: false` and a `promotion_blocked_reason`;
`manifest._validate_cairo_group` refuses any Cairo group that sets
`promotion_eligible: true`, and `_validate` refuses any live group that is
unpromotable without stating why. The gate opens only after per-(board, class)
A/A dispersion and anchors are measured on the designated Apple M5 Max judge
host and frozen (TRACKS §7).

## Gaps in the current product CLI

These are real, and none of them is papered over:

1. **No request-scoped span.** `timing.prove_ns` starts *after* the prover
   input, witness programs, feed topology, fixed tables, relation templates,
   and AIR template library are read, and stops before the proof is encoded and
   written. The product emits no timestamp pair covering read → verify, so the
   harness scores the strictly wider cold-process boundary instead. Closing
   this needs a `timing.request_ns` in
   `src/products/cairo/shared/application.zig` (product ownership, not harness).
2. **No `serialize` cutpoint.** Proof encoding, compression, writing, and
   hashing all happen outside the stage recorder. `phase_seconds.serialize` is
   `null`.
3. **No resource telemetry.** The Cairo report carries no RSS, energy,
   instruction, or cycle counters, so `peak_rss_mib`, `energy_j`,
   `instructions`, and `cycles` are `None` and `resources_complete` is `false`.
   `all_builtins` measured ~16.7 GiB peak footprint out of band; a Cairo
   equivalent of the RISC-V `resources` block would make G4/G5 resource gates
   usable on this track.
4. **No CPU-seconds.** TRACKS §3.2 asks for dual time units per cell (wall and
   CPU). The product reports wall time only.
5. **No `--resource-profile`.** Large resource classes are unreachable until
   the CLI accepts one.
6. **No holdout generator.** With two committed workloads there is no pool to
   jitter; TRACKS §3.3 wants the seeded pool extended to this group once the
   portfolio fixtures are provisioned.
