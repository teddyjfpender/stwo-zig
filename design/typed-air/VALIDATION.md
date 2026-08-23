# Validation and evidence plan

**Status:** required gate design
**Last updated:** 2026-08-15

## Principle

Validation is layered because no single green test answers every question.
Every change names which layers it affects and runs all corresponding gates.

## Evidence ladder

### V0 — structural IR

Answers: is the program well-formed?

- type and ID validation;
- function-graph acyclicity;
- hint binding;
- relation schema/role/arity;
- effect order and access ordinals;
- deterministic serialization;
- ownership and allocation failure.

### V1 — production equivalence

Answers: did compatibility lowering preserve the current program?

- root-by-root normalized expression comparison;
- concrete random replay;
- column names/count/order;
- lookup domain/role/arity/value/order;
- batch size and interaction placement;
- runtime polynomial program identity;
- AIR IR v2 identity;
- witness column equality.

### V2 — adversarial witness

Answers: does the proof reject targeted prover freedom?

- mutate every new materialization class;
- mutate every hint output and exceptional selector;
- omit, duplicate, or alter relation calls;
- activate padding;
- change multiplicity or component count;
- alias register accesses;
- violate clock gaps;
- change public/component boundaries.

Each negative records the expected rejection stage and, where possible, the
specific constraint or relation that is load-bearing.

### V3 — proof path

Answers: does production prove and independently verify?

- focused real proofs;
- separate-process verification;
- statement and transcript identity;
- malformed artifact negatives;
- CPU and Metal paths where applicable;
- no backend fallback.

### V4 — architectural and formal

Answers: does the admitted AIR retain its semantic authority and formal binding?

- pinned Sail/Spike differential;
- architectural tests;
- AIR IR regeneration;
- Lean build and axiom/source inventory;
- claim-ledger review;
- cross-row composition obligations.

### V5 — performance

Answers: did the change improve its stated resource without hiding another?

- verified samples only;
- baseline and candidate from clean comparable builds;
- trace cells and degree;
- stage time and total wall time;
- total CPU/GPU work;
- peak memory and concurrency;
- proof size and verification time;
- host, power, compiler, commit, and protocol identity.

### P-003/R-006 exact-work promotion gate

V2 work-profile transport and digest validation are necessary but do not prove
producer exhaustiveness. An `instrumented_exact` R-006 attempt may advance to
the real V4 schema only when all of the following hold:

- every executable producer uses a typed `Site` identity for both its planned
  and completed record; free-form marker comments are not coverage authority;
- compile-time `Site -> Boundary` aggregation and per-site expected/completed
  arrays reject a missing, duplicate, substituted, or unfinished site before
  the terminal coverage seal;
- every field-operation class in the P-003 closure ledger returns a checked
  exact delta for the schedule it actually executed; unsupported backend
  schedules make the counter unavailable rather than estimated;
- the counter-semantics version states whether guest execution, witness
  materialization, proof serialization, and independent verification are in
  the logical-work partition;
- FFT butterflies, FRI folds, and Merkle compressions have the same typed-site
  deletion and substitution protection as field operations; and
- one installed production binary emits a V4 attempt only after the proof has
  independently verified, then passes the strict fresh-process capture and
  raw-bundle replay validators.

At the 2026-08-15 checkpoint, only generic M31 polynomial-commit forward FFT
field work is exact. The ten-site/seven-boundary marker inventory is
provisional, normal production deliberately remains V3 without a work profile,
and V4 records are fixtures only. This is the required fail-closed state while
the typed-site ledger and remaining producer formulas are implemented.

## Focused development commands

Parallel development lanes must use the bounded compiler controller. It admits
at most three commands and injects a stable, exclusively locked Git-private
local cache for the exact command or named cache group. Related narrow and
broad gates share a cache group without using it concurrently:

```sh
python3 scripts/typed_air_zig_lane.py \
  --label <short-owner> --stage narrow --cache-group <owner> -- \
  zig build --build-file src/frontends/riscv/build.zig \
  <focused-step> -Doptimize=Debug
```

An exact development GREEN may be reused only when checkout closure, argv,
toolchain, host, environment, stage, timeout policy, and controller identity
still match. `--force` reruns it. Exit 74 means authority drift; exit 75 means a
slot, key, cache group, caller-specified global cache, or automatic heavy lock
is busy. Proof, benchmark, performance, capture, run, product-build, and
explicit `--evidence` commands never reuse GREEN and are automatically
host-serialized. The default Zig global cache remains intentionally shared;
caller-specified global caches are separately locked. Stable PATH-resolved
auxiliary tools remain a host trust boundary, while external toolchain/input
environment paths disable reuse. Gate receipts and retained logs are DevEx
records only, never protocol, performance, or release evidence.

The recursive binary path has independent edit-loop gates. Run the smallest
owner-specific gate first; the cohort gate is the first command that composes
all 36 rows and therefore must not be substituted with a source-only pass:

```sh
zig build --build-file src/frontends/riscv/build.zig \
  --cache-dir /tmp/stwo-zig-cache-recursion-row18 \
  --global-cache-dir "$HOME/.cache/zig" \
  test-recursion-binary-fri-row18 -Doptimize=Debug

zig build --build-file src/frontends/riscv/build.zig \
  --cache-dir /tmp/stwo-zig-cache-recursion-source \
  --global-cache-dir "$HOME/.cache/zig" \
  test-recursion-binary-fri -Doptimize=Debug

zig build --build-file src/frontends/riscv/build.zig \
  --cache-dir /tmp/stwo-zig-cache-recursion-closure \
  --global-cache-dir "$HOME/.cache/zig" \
  test-recursion-binary-closure -Doptimize=Debug

zig build --build-file src/integrations/riscv_cpu/build.zig \
  --cache-dir /tmp/stwo-zig-cache-recursion-cohort \
  --global-cache-dir "$HOME/.cache/zig" \
  check-recursive-binary-cohort -Doptimize=Debug

zig build --build-file src/integrations/riscv_cpu/build.zig \
  --cache-dir /tmp/stwo-zig-cache-recursion-cohort \
  --global-cache-dir "$HOME/.cache/zig" \
  audit-recursive-binary-cohort -Doptimize=Debug

# Only after the 47-domain audit closes: run the expensive proof and its
# independent verifier without executing unrelated cohort tests.
zig build --build-file src/integrations/riscv_cpu/build.zig \
  --cache-dir /tmp/stwo-zig-cache-recursion-cohort-proof \
  --global-cache-dir "$HOME/.cache/zig" \
  prove-recursive-binary-cohort -Doptimize=ReleaseFast

# On `ConstraintsNotSatisfied`, retain committed coefficients and print the
# exact first prover/verifier component differential. This intentionally uses
# more memory and is diagnostic evidence, not a benchmark invocation.
STWO_RECURSION_DIAGNOSE_COMPOSITION=1 \
zig build --build-file src/integrations/riscv_cpu/build.zig \
  --cache-dir /tmp/stwo-zig-cache-recursion-cohort-diagnostic \
  --global-cache-dir "$HOME/.cache/zig" \
  prove-recursive-binary-cohort -Doptimize=ReleaseFast

zig build --build-file src/integrations/riscv_cpu/build.zig \
  --cache-dir /tmp/stwo-zig-cache-recursion-cohort \
  --global-cache-dir "$HOME/.cache/zig" \
  test-recursive-binary-cohort -Doptimize=ReleaseFast
```

Concurrent agents never share one local cache, and they never compile a
source file while another agent owns a partial edit in that file. File
ownership is handed off explicitly before a downstream proof or timing lane
starts.

RISC-V package:

```sh
zig build test \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast -j2
```

Focused semantic tests while iterating:

```sh
zig build test-air-semantics \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseSafe
```

Production RISC-V product gate:

```sh
zig build test-riscv-cpu-product -Doptimize=ReleaseFast
```

Exhaustive proof/adversarial gate before removing an implementation:

```sh
zig build test-riscv-release-exhaustive -Doptimize=ReleaseFast
```

Formal AIR export:

```sh
zig build riscv-refinement-ir \
  -Driscv-refinement-ir-dir=zig-out/family-air
```

Typed-AIR compatibility artifact check:

```sh
zig build typed-air-manifest \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

An intentional reviewed replacement adds
`-Dtyped-air-manifest-mode=update`. Check is the default; tests never select
update mode.

H-010 authenticated evaluator admission:

```sh
zig build typed-air-layout-benchmark \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

H-010 checked vector and readable-index regeneration check:

```sh
zig build typed-air-layout-benchmark \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast -- \
  vector-artifacts check design/typed-air/artifacts/h010-poseidon-layout-v1
```

The explicit `vector-artifacts update` form is review-only and writes
atomically. The ordinary admission command and package tests never select it.
Install the isolated ReleaseFast child used by the host orchestrator with:

```sh
zig build typed-air-layout-benchmark-install \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

A timing cohort is collected only from that executable on a clean snapshot,
with a new output path and an explicit operator power-state declaration:

```sh
python3 scripts/typed_air_poseidon_benchmark.py \
  --output zig-out/h010/<new-run-id>.json \
  --power-state '<operator declaration>'
```

`--include-log-18` adds a separate non-receiptable stress cohort; it never
replaces either default log.

Lean source build:

```sh
(cd formal/riscv-refinement && lake build)
```

Live Sail and receipt commands remain those in
[`RISCV_FRONTEND_VERIFICATION_STATUS.md`](../../soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md).
They are required when architectural semantics, source binding, or published
formal artifacts change.

## Compatibility golden data

For each component, retain a machine-readable manifest with:

- logical program identity;
- accepted layout policy;
- main and interaction columns;
- direct roots and inferred degree;
- relation events and batching;
- hint recipes;
- formal/runtime program identity; and
- source revision.

Golden artifact tooling has two explicit modes:

- `check` regenerates in memory and requires byte identity;
- `update` atomically writes a proposed artifact.

Tests never update goldens automatically. A reviewer must be able to see why
every changed column or event moved. A-012 supplies the field-aware semantic
diff used for that review. Both bodies are validated first; check then reports
the first named generated-versus-on-disk difference together with file lengths
and SHA-256 identities before failing.

M2 established the report check half of this contract: the package test renders
[`m2-production-shadow-report-v1.tsv`](artifacts/m2-production-shadow-report-v1.tsv)
and its [readable view](artifacts/m2-production-shadow-report-v1.md) in memory
and requires byte identity. A-011 adds the explicit family-manifest check/update
command. A-012 parses that sectioned `compat-v1` object without allocation and
compares detailed layout, runtime, relation, degree, hint, and formal records
before their repeated identity digests.

A-006 additionally reconstructs the existing Sail-authoritative witness-layout
digest from `compat-v1` descriptors and compares every physical name directly
to reflected production fields. Separate tests resolve local references at
nonzero offsets and require exact agreement with the semantic and lookup
backend capabilities. Logical and physical names are compared as a mapping,
not assumed equal.

A-007 compares direct lowering against an independent linear-interning
normalizer rather than sharing the implementation's hash-consing machinery.
All 17 families require exact normalized node slices and all 545 ordered roots,
then compare every root again under four deterministic randomized M31
assignments per family. The owned result separately exercises deterministic
reconstruction, structural corruption, malformed replay buffers, and induced
allocation failure.

A-008 extends that oracle to production lookup-only programs. Canonical
topological relabeling makes comparison independent of constants first interned
by an unrelated direct section. Every family requires exact node and flattened
`numerator, tuple...` root identity; every event separately matches schema,
role, arity, ordinal, order, and role-signed liveness, while every batch matches
its four physical interaction references. Random replay covers all 242 events;
corruption, sign mismatch, deterministic reconstruction, and allocation failure
are separate gates.

A-009 requires exact canonical node, ordered-root, and column identity for the
direct runtime type across all 17 families. The lookup runtime type additionally
requires every entry numerator/tuple root and arity, batch count, parameter
count, and deterministic unused tail. Both exporters validate input and output;
malformed owners and induced allocation failure are explicit negatives.

A-010 requires whole-byte equality with the existing AIR IR v2 writer, not a
parsed-object comparison. The compatibility path independently reconstructs
selector-to-one placement, source node numbering/orientation, column roles,
event ordinals, opcode projection, and fixed-table metadata, then uses the one
existing encoder. LUI is the acceptance floor; every manifest opcode is tested.
Digest-bound raw provenance corruption and allocation failure are negatives.

A-011 emits 17 separately reviewable `STWAIRC\0` version-1 manifests in
production-family order. Their seven framed sections carry authority and
source identities, all physical column descriptors, complete direct and lookup
runtime bytes, named roots, typed event and physical batch metadata, final
degree records, hint recipes, and formal export identities. Runtime ownership
is revalidated before serialization. Every formal entry is admitted only after
the typed and production AIR IR v2 bodies compare byte for byte, then records
its opcode, mnemonic, exact byte length, and SHA-256. The aggregate TSV index
pins each whole manifest and its source/semantic, layout, runtime, degree, and
formal digests together with geometry, export counts, and maximum direct and
interaction degree.

The package suite regenerates all 17 binaries and the index in memory and
requires exact bytes from the embedded checked artifacts. Separate determinism
and family-order negatives fail closed. Allocation testing uses a stable scratch
allocator for the legacy panic-on-OOM production symbolic builder and injects
failure at every allocation owned by new runtime/receipt results, requiring all
partial owners to deinitialize. The standalone command exposes default `check`
and explicit atomic `update`; see
[ADR-0017](decisions/0017-sectioned-compatibility-manifests.md).

A-012 validates the generated and on-disk manifest independently before
comparison. Its structured result is equality, one borrowed first difference,
or a malformed-side diagnostic with a stable semantic path and byte offset.
Tests cover all 17 equal artifacts; logical and physical column names; moved
references; runtime nodes and named roots; lookup schema, role, event, and batch
records; degree/formal identity; malformed framing, UTF-8, optionals, runtime
programs, and trailing bytes; and expected-side precedence. The command was
also exercised end to end against a temporary corrupted LUI artifact: check
named `layout.main[16].physical_name`, update rendered the same difference
before atomic repair, and the following check passed. Invalid magic was
attributed to `actual/on-disk` at `header.magic`.

H-005, H-006, and H-008 add the Poseidon-specific V1/V2 bridge. H-005 compiles the
authenticated typed closure independently of the production witness generator
and compares all 445 final columns across every mode, deterministic randomized
traces, bit-reversed placement, and zero padding. Shape, alias, executable, and
slot corruptions must fail before a sentinel destination changes; construction
is swept under allocation failure. H-006 independently derives four relation
entries, two pairs, eight interaction columns, and two claims, then compares
each with production and rejects tuple, mode, multiplicity, order, role,
domain, geometry, column, claim, and carried-output forgeries. H-008 binds all
426 generic/physical identities in a canonical 37-field report with golden
SHA-256
`33eadd080a715fe09d1b3ed3ad8abc18cb35f71e56895e6ac62810a1dfeb0ef2`.

H-007 closes the V3 proof-path gate for the compatibility pilot. Its test-only
engine wrapper regenerates all 445 main columns into the live Tree-1 buffers,
derives all eight interaction columns from the live Fiat-Shamir challenges into
the Tree-2 buffers, mixes the typed total at the canonical transcript ordinal,
and installs both typed sums in the component before composition. The returned
output claim is reconciled to those sums after proving and before verification.
Focused CPU proof and corruption tests pass; the full CPU and authenticated-AOT
Metal product gates pass with resident Metal polynomial execution and no known
CPU fallback. A fresh unchanged production verifier specialization verifies the
honest proof. The immutable evidence and exact limits are recorded in the
[H-007 receipt](receipts/h007-poseidon-proof-equivalence-v1.json).

This is proof-path integration evidence, not production activation or a broad
soundness claim. The full-proof fixture is narrow-only, uses test-security PCS
parameters, and verifies in a fresh same-process verifier state. Claims are
transcript/AIR-bound rather than separate committed columns, and canonical
logical/layout/executor/relation identity is now co-attested by the final
[V-006 receipt](receipts/v006-poseidon-program-identity-v1.json). That identity
is returned beside the verified proof by the test-only authority; it is not
mixed into the transcript, public statement, proof commitment, or production
verifier contract.

H-009 adds an isolated proposal-artifact gate. Package tests decode the checked
`STWAIRM\0` binary, validate every digest and accounting invariant, and
regenerate its TSV and Markdown projections byte for byte without rerunning
the search. Reproducible search execution is owned by the explicit command:

```sh
zig build typed-air-frontier --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

The default is fail-closed `check`; only
`-Dtyped-air-frontier-mode=update` may atomically publish reviewed replacements.
Adversarial tests cover forged public cuts, safe-versus-trusted edit parity,
manifest truncation/corruption/canonicality, fixed-column aliasing, phase
emitter drift, late-root liveness, and root-by-root equality with production
fixed Poseidon constraints. A canonical neighbourhood test pins the exact 410
removals, 304 additions, and 410 swaps. The source-conformance scanner also
rejects proposal imports, public-surface access, or H-009 artifact fields from
unreviewed production sources; only an explicit authoring/test/tool allowlist
is accepted.

The immutable
[H-009 receipt](receipts/h009-poseidon2-cost-frontier-v1.json) records exact
artifact, search, cost-model, product-closure, and regression-gate identities.
Its structural plateau is negative optimization evidence, not a timing,
memory, proof-size, global-optimality, or production-activation result. H-010
was therefore required to measure the compatibility layout and retained
representatives under the complete performance vector before any policy
decision; the closure below does so without selecting a layout.

H-010 now supplies the isolated validation boundary for that measurement. Its
closed protocol authenticates the raw H-009 bytes and decoded identities,
recomputes the exact q0, lower-median q50, and q100 arm selection over all 126
proposals, and checks the fixed direct program through three independent
identity surfaces. Logs 10 and 14 decode checked `STWAIRB\0` vectors; their
internal seals, complete-file SHA-256 values, byte lengths, call digests,
output digests, and readable index are pinned. Generated log 18 carries a
separate non-receiptable storage class.

Before timing, every arm runs over logs 4 and 6 boundary fixtures and every row
of both checked default vectors. The candidate witness output must equal all
sixteen expected values recorded from the unchanged static Poseidon reference,
and all 430 direct roots must be zero on every row. For each arm, a canary row
then mutates every one of the 426 materialization cells and requires its first
owning equality root to become nonzero. Separate fixed-root cases mutate
`enabler`, `wide`, `io`, and their mutual exclusion. Artifact, geometry,
identity, seal, semantic-output, truncation, and coherently resealed corruption
tests fail closed.

The hot paths are prepared before their timers and reuse retained scratch; no
row-loop allocation is admitted. Per-arm trace digests pin candidate layout
regressions only. They are deliberately not used as correctness oracles, which
remain the independently generated expected outputs and complete zero-root
evaluation. The process-RSS adapter rejects zero or ambiguous values, preserves
the native Darwin-byte or Linux-KiB unit, normalizes to bytes, and is exercised
against a known 64-MiB page-touched allocation.

Each sample explicitly reports that proof, verification, hash-component shell,
LogUp, commitment, PCS, Metal candidate execution, production layout change,
and promotion authority are absent. The host accepts only one exact JSON line
from each fresh child, rotates four arms serially through three warmup and
eleven measured rounds per default log, retains every value, rejects retries
and partial cohorts, and writes a new report atomically. This is V1/V2-style
microbenchmark correctness and resource evidence, not V3 proof-path evidence.

H-010 closes on clean implementation commit
`82bf6b9cd5eb1ab48edd6fb7c0c88a3be687e8c6`, tree
`8cbb9300fa9b820baa079eeb94addf71db97f130`. The locally retained
ignored `v2` report is 337,144 bytes with SHA-256
`98abdf472818e21e43ff0e3cc3d509598558a6df6c1c215ea789a997fb5bc25d`;
the independent `v3-confirm` report is 337,146 bytes with SHA-256
`eabeba5d67b26574dbe4246f8924411fe7c1df252452d078688ae6a0bcb5682a`.
Both are valid and complete, contain all 112 required sample children, and
record zero failures, retries, or drops under identical executable,
source-closure, and `AC/100%/powermode0` identities.

Clean evidence reruns record 792 passing of 793 collected frontend tests with
one intentional skip in both ReleaseFast and ReleaseSafe; aggregate, CPU, and
Metal product closures of 567, 520, and 577 sources with respective SHA-256
digests
`5137a2f7e587f2b80af44950f545ca70e003bdf4de71944aa71f47fba5ac11d0`,
`a64b61790c33988efc7ad1b5f14b5910b6fe830ff20980a735645b7ba0001ad8`,
and `e4f0fd05906e062c61030b4ac7d5340c306981c1a441aef58ae501fdc8a507b7`;
118 authenticated Metal AOT exports; a 21-package/70-edge workspace; 14 of 14
H-010/orchestration-isolation Python tests; and 35 of 35 source-conformance unit
tests. The repository source-conformance command retains exactly its inherited
three warnings and eight errors and adds no H-010 finding.

The two reports show no meaningful repeatable layout regression and select no
layout. Proof, verification, Metal-candidate, production-layout, and promotion
claims remain false. The
[H-010 receipt](receipts/h010-authenticated-poseidon-layout-benchmark-v1.json)
names this bounded evidence; it does not alter the V3 or production boundary.

## Differential design

Expression comparison should not rely solely on node IDs. Normalize or compare
structural DAGs with explicit operation/type/operand identity. For every root:

1. compare structural form;
2. replay fixed boundary values;
3. replay deterministic random M31 values;
4. compare production QM31 evaluation where applicable; and
5. report the first divergent source path.

Witness comparison uses exact M31 values in canonical committed row order. It
does not compare only final outputs.

## Mutation design

Mutations are generated from typed metadata:

- committed witness column;
- hint output;
- selector;
- call field;
- liveness/multiplicity;
- effect clock;
- output/boundary value.

Each mutation record contains:

- component and row;
- semantic value and physical column;
- original and forged values;
- expected guard;
- actual rejection stage;
- proof existence; and
- verification result.

A mutation rejected by an unrelated bus may be useful coverage but is not
attribution. Row-local or isolated-relation tests remain required.

## Precompile-specific cases

The Poseidon precompile must test:

- zero calls;
- one call;
- duplicate equal calls;
- distinct calls with equal output lane;
- maximum admitted calls;
- inactive padding;
- wrong input;
- wrong output;
- wrong mode/domain;
- omitted supplier;
- duplicated supplier;
- incorrect multiplicity;
- changed component geometry;
- cross-transcript relation summary, when recursion exists; and
- native software versus precompile output equivalence.

## Backend evidence

A backend accelerator receives the canonical lowered program identity and
declares the exact capability it implements. Required tests:

- reference evaluator versus backend on deterministic random rows;
- all-zero, all-one, and maximum canonical field cases;
- active and inactive rows;
- every constraint root and relation entry;
- mismatched program identity rejects;
- missing authenticated Metal artifact rejects;
- no CPU fallback in a Metal product.

## Clean-tree milestone receipt

At M3 and later milestones, record:

- commit and clean-tree state;
- Zig, Python, Lean, and Sail versions as applicable;
- logical and layout manifests;
- exact commands;
- test counts and results;
- proof/verifier receipt identities;
- benchmark report identity; and
- known open claims.

The receipt describes evidence. It does not promote the claim ledger by itself.
The first concrete instance is the
[M3 compatibility receipt](receipts/m3-compatibility-v1.json), which records
green compatibility and focused proof evidence together with the broad
prover-core and formal-artifact gates that remain red.

The [H-010 receipt](receipts/h010-authenticated-poseidon-layout-benchmark-v1.json)
records the clean H-010 implementation tree, both exact locally retained
report identities, the independently rerun gates, and the no-selection
conclusion. It does not convert the microbenchmark into proof-path or
production evidence.

## A-013 generated-composition production exit

The A-013 V3 gate must execute two independent proofs over the same real
17-family statement. Its reference backend aliases every production CPU
operation except the optional composition hooks; the generated arm uses the
ordinary production `CpuBackend`. The gate rejects unless:

- generated execution telemetry records one admission, 17 eligible pairs, and
  zero declines;
- the produced V1 statement itself owns 17 components and exactly 688 Tree-2
  columns, without depending on A-014 inspection or activation APIs;
- statement, interaction claim, canonical proof bytes, and terminal transcript
  are exact between arms; and
- both independently generated proofs verify through the ordinary production
  engine.

The final Debug and ReleaseFast gates pass. Canonical proof size is 51,581
bytes, SHA-256 is
`3a93cb594f9021f1d0625c3f31431401a668ab266d6502ade64129e0a10f783a`,
and terminal transcript digest is
`3690d6814dbdf9ec02a85c3a59cb16d2ed87036291fed3e531c740b546c08293`.

```text
python3 scripts/typed_air_zig_lane.py --label a013-final-drift-guarded-debug -- /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig test-riscv-generated-composition-native-proof -Doptimize=Debug -j1 --summary all
Build Summary: 4/4 steps succeeded; 1/1 tests passed

python3 scripts/typed_air_zig_lane.py --label a013-generated-composition-releasefast-proof -- /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig test-riscv-generated-composition-native-proof -Doptimize=ReleaseFast -j1 --summary all
Build Summary: 4/4 steps succeeded; 1/1 tests passed
```

Elapsed times from these single-process executions are attribution only. They
are not V5 evidence; A-013 retains a paired global P-004 performance gate.

## A-014 authenticated lookup-V2 CPU proof

The A-014 V3 gate holds the real all-family execution, public statement, PCS
profile, and CPU engine fixed while proving compatibility V1 and authenticated
lookup V2. It requires independent verification in both protocols and
reciprocal cross-protocol rejection. Exact accepted geometry is 620 to 548
opcode interaction columns with 68 infrastructure columns unchanged: 688 to
616 total (-72, -10.47% total and -11.61% opcode). Canonical proof size is
51,863 to 50,256 bytes (-1,607, -3.10%). Manifest, statement, and activation
identities are:

- `f205a9fb631bbab2b93efbb961fe662c5a2c0ee55d7d60d606d49d030a2de849`;
- `8b1b08f4635daa583a55d91914103c49ad15a7db996a4290e23b6686109eeff0`;
- `d5771e0a86bb81a25f4e6d0a3b52e6a88766c3be3c1115d39f9846443a50fd51`.

```text
python3 scripts/typed_air_zig_lane.py --label a014-full-cohort-real-proof-final -- /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig test-riscv-lookup-v2-native-proof -Doptimize=Debug -j1 --summary all
Build Summary: 1/1 steps succeeded

python3 scripts/typed_air_zig_lane.py --label a014-releasefast-real-proof -- /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig test-riscv-lookup-v2-native-proof -Doptimize=ReleaseFast -j1 --summary all
Build Summary: 1/1 steps succeeded

python3 scripts/typed_air_zig_lane.py --label a014-full-lookup-debug -- /usr/bin/time -l zig build --build-file src/frontends/riscv/build.zig test-lookup-batching -Doptimize=Debug -j1 --summary all
Build Summary: 3/3 steps succeeded; 326/326 tests passed
```

The exact structural and proof-byte reductions are admitted evidence. Debug
and ReleaseFast single-sample timing directions disagree, so no speed claim is
admitted. Native Metal V2 and a no-CPU-fallback receipt remain required.

## Required gates by change class

| Change class | V0 | V1 | V2 | V3 | V4 | V5 |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| IR-only, no lowered change | yes | targeted | targeted | no | source check | benchmark if hot |
| Compatibility lowering | yes | full | targeted | focused | AIR IR | yes |
| Constraint/relation change | yes | semantic diff | full | full | full | yes |
| Witness implementation | yes | witness full | full | full | Sail if architectural | yes |
| Layout/materialization | yes | manifest full | full | full | regenerate | full |
| Precompile ABI/component | yes | component | full | full | profile/formal review | full |
| Parallel scheduler | structural | byte/protocol | failure injection | full | no semantic drift | full |
| Recursive aggregation | yes | summaries | full cross-proof | full | theorem review | full |
