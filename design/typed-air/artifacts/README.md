# Checked compatibility artifacts

This directory pins deterministic evidence emitted by the isolated typed-AIR
compatibility implementation. Artifacts are reviewed protocol data, not
benchmark output and not production-activation receipts.

## P-003 whole-prover exact-work closure

- [`p003-work-profile-closure-v1/matrix-v1.json`](p003-work-profile-closure-v1/matrix-v1.json)
  is the canonical sixteen-family CPU/Metal closure authority. It binds schema
  9's 23 typed sites and currently validates at 16 complete / 0 partial / 0
  absent for CPU, Metal, and joint coverage.
- [`p003-work-profile-closure-v1/scaling-blocker-v1.json`](p003-work-profile-closure-v1/scaling-blocker-v1.json)
  is the independently replayable current R-006 blocker. It contains no P-003
  closure blocker; the retained Aug-20 preflight misses only the quiet-host
  median-idle threshold. Its R-006 scaling receipt is null and its terminal V4
  seal is not authorized.

The matrix SHA-256 is
`b1eef5ccf8405de9373c11b8fe9bd505a331add0601ab1904a1b038df0ee24d1`.
The bound inventory SHA-256 is
`13807efba664c2abc49325a80d8bc67c15896e7250ea48416e0d58e0f029982f`.
The real CPU `N=1/2/4` work-authority and receipt SHA-256 values are
`df914f214597393737a7795fc988680df17ca0e5ba09d9d577930260cb703b14`
and `9e99ccedbe8302548ef7c95babd445b48f270b355a26090badcec64388350f68`;
the Blake2s shell receipt is
`864d550670c284c36dd79fc8521852504b2dd6221410d47cfffceeb56473b46f`.
The real-device Metal gate passed 3/3 with 118 authenticated AOT exports,
AOT/JIT parity, exact-once producer completion, independent verification,
305.58 seconds wall time, and 4,967,989,248-byte maximum RSS. It did not emit a
separate proof, transcript, work, or shell identity; no CPU identity is reused
or inferred for Metal.

## Real temporal parent correctness receipt

- [`recursive-temporal-parent-v1/receipt-v1.json`](recursive-temporal-parent-v1/receipt-v1.json)
  pins the 94,740-byte parent proof plus publication, cohort, interaction-audit,
  and closure identities reproduced by both the ReleaseFast adversarial test
  and lean production runner. It is development correctness evidence, not a
  timing promotion or proof-system-soundness receipt.

The exact SHA-256 identities are proof
`a43d756e1b1832105922579ccef1df55b73e9cd861c8e9dfcf7ea87845b7203b`,
publication
`2a6bf58a8ca8006f01df44a86120519fa28ad3a18b9f0ec06410b5e8c04fa867`,
cohort authority
`e9fb54b38946066ca4f8a87cce90ce076316b57850dc437c899cdc069aca95be`,
interaction audit
`71ac4304cc3cb3811cc0d9764bd304184ddec889a12e7c3b0463a00aab9be54f`,
and closure receipt
`a678ca532443de395bcbfc2b72707462c0991e7111c2da44c9626c71b50b63a0`.
Rows 18--19 are the real binary pair computation; rows 20--35 retain the
authenticated suffix and statement-owned provider. The receipt asserts
`temporal_parent_verified=true`, while whole-frontend verification and
proof-system soundness remain false.

## M2 production shadow report

- [`m2-production-shadow-report-v1.tsv`](m2-production-shadow-report-v1.tsv)
  is the machine-readable, tab-separated record for all 17 opcode families.
- [`m2-production-shadow-report-v1.md`](m2-production-shadow-report-v1.md)
  is the corresponding human-readable view.

Both files are rendered from `air/lang/protocol_report.zig`; `embedded.zig`
exposes them to the otherwise isolated RISC-V package test. Any semantic change
therefore fails the golden comparison until the versioned artifact is
deliberately reviewed and regenerated. The report
describes the current production program imported in shadow mode; it does not
authorize a generated lowering or alter production proving behavior.

## P-002 native typed-family static profiles

- [`p002-native-family-static-profile-v1/profiles-v1.tsv`](p002-native-family-static-profile-v1/profiles-v1.tsv)
  is the canonical family-ordered machine report. Each of its 17 rows carries
  the complete P-001 static-profile schema after explicit inventory and
  authority metadata.
- [`p002-native-family-static-profile-v1/profiles-v1.md`](p002-native-family-static-profile-v1/profiles-v1.md)
  is the deterministic human review view and aggregate.

Generation builds each concrete native typed definition directly, with
`typed_addi` representing `base_alu_imm`, and independently regenerates the
A-005 production-shadow report. Physical width, direct roots, lookup count,
batch size/count, interaction columns, and direct/numerator/denominator/final
interaction degrees must agree for every family before either projection is
admitted. Native DAG and closure facts remain native facts; they are not
relabeled as production-shadow importer counts.

The report SHA-256 is
`0dd67acd8705f77a5c482a8d3706b38929d799091b3971e995b20dcc44f56772`.
The TSV and Markdown file SHA-256 values are respectively
`d4b187cbdf5baee61f4eb2541acf1d69e8e84ddae91007b574ec4a6663a18c6b`
and
`52bf9cff23de5ea05da9588846a1af2e21be67ad16379fd580bb4057cab34d1c`.
The fail-closed check is:

```sh
zig build typed-air-static-profile --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

An intentional reviewed replacement adds
`-Dtyped-air-static-profile-mode=update`. Update writes both files atomically;
ordinary tests and check mode never replace reviewed bytes. This is static
shadow/profile evidence only. Production activation is explicitly
`not_assessed`, and the files contain no runtime timing, memory, or proof claim.

## M3 `compat-v1` family manifests

- [`m3-compat-v1/index-v1.tsv`](m3-compat-v1/index-v1.tsv) is the readable
  family-ordered whole-manifest, source/semantic, layout, runtime, degree, and
  formal digest index together with geometry, export counts, and maximum
  degrees.
- `m3-compat-v1/*.stwairc` are the 17 canonical section-framed binary
  identities described by
  [ADR-0017](../decisions/0017-sectioned-compatibility-manifests.md).

Each `STWAIRC\0` version-1 binary has seven ordered, length-framed sections:
identity, physical layout, direct runtime program and roots, lookup runtime
program/events/batches, complete degree analysis, hint recipes, and formal AIR
IR v2 exports. Direct and lookup runtime bodies are embedded exactly. Formal
entries retain opcode, mnemonic, byte length, and SHA-256 after the typed and
production emitters have compared the complete AIR IR body byte for byte.

The package suite regenerates and byte-compares every file in memory. Run the
same fail-closed check directly with:

```sh
zig build typed-air-manifest --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

An intentional reviewed replacement uses the same command with
`-Dtyped-air-manifest-mode=update`. Update mode writes atomically and never runs
from an ordinary test. During allocation-failure testing, the legacy production
symbolic builder uses stable scratch storage while every allocation introduced
by the runtime/receipt result boundary is exhaustively failed and cleaned up.
Normal generation uses one allocator. These receipts remain compatibility
evidence, not a production activation or proof-protocol change.

The A-012 comparator parses and validates both complete v1 bodies without
allocation. It reports the first changed semantic path, including expected
logical and physical names where available. Check mode renders that result and
fails closed. Explicit update mode renders the same generated-versus-on-disk
result before atomically replacing the file; malformed or oversized existing
artifacts are never silently accepted. The TSV index remains a raw byte/digest
comparison because it is the readable projection rather than a second binary
protocol object.

The exact clean-snapshot commands, tool versions, aggregate identities, proof
results, and deliberately open release gates are recorded separately in the
[M3 milestone receipt](../receipts/m3-compatibility-v1.json). The receipt does
not change or supersede these compatibility artifacts.

### Current M3 receipt readiness

The linked V-008 receipt is immutable historical evidence for its named
detached snapshot. Its red findings must not be rewritten, and its existence
must not be mistaken for a receipt covering the current shared checkout.

The following M3 readiness snapshot was captured on 2026-08-13. Later
2026-08-20 recursion evidence in this section does not rewrite these
historical M3 counts:

- the package workspace passes `21/21` packages and 70 dependency edges;
- all `17/17` compatibility manifests regenerate and compare exactly;
- frontend Debug reports 2,149 passes and one intentional skip;
- recursion reports `583/583` in Debug, ReleaseSafe, and ReleaseFast;
- the real rows-29/33 native PCS/FRI proof gate is now correctly owned by the
  RISC-V CPU integration package and passes all three modes with an exact
  5,184-byte proof estimate and identical transcript output;
- RISC-V CPU integration passes `17/17` in ReleaseFast; and
- the final formal reseal is green `59/59`, with formal digest
  `375b77cc4c11c2af324b3d66a989fd1e69a58c809dbb68e444d6b6a25fdeba86`
  and source closure
  `c9bc6c362663ce20aac44b9a004a4d86e71f9888bf2a809512116733db0a8bb2`.

No clean top-level receipt has yet been minted for these results. M3 is ready
for that immutable capture, not complete by assertion. Historical V-008 must
retain its `2/46` Level-1 pilot and `3/36` recursion proof-gate boundaries
unchanged. A new V-009 receipt must separately record the current complete
39-component SegmentV2 leaf and independently verified temporal parent rather
than inherit those historical absences. It must still set
`whole_frontend_verified = false` and `proof_system_soundness = false`.

## H-009 Poseidon2 materialization cost frontier

- [`h009-poseidon2-cost-v1/frontier.stwairm`](h009-poseidon2-cost-v1/frontier.stwairm)
  is the canonical section-framed search receipt.
- [`h009-poseidon2-cost-v1/frontier-v1.tsv`](h009-poseidon2-cost-v1/frontier-v1.tsv)
  is its exact tabular review projection.
- [`h009-poseidon2-cost-v1/frontier-v1.md`](h009-poseidon2-cost-v1/frontier-v1.md)
  is the human review view.

The binary receipt authenticates the semantic program, fixed direct-polynomial
program, complete cost model, search configuration, accounting, seed, and 126
retained proposals. The TSV and Markdown deliberately select the fields useful
for review; they are byte-exact projections, not alternate complete encodings.
The complete one-pass neighbourhood is a structural cost
plateau: every retained proposal has the exact seed vector. It is evidence for
H-010 benchmark selection, not a speedup claim and not production activation.

The package suite decodes the binary and regenerates both readable views byte
for byte. These files are exposed only through the dedicated test bridge
[`h009_embedded.zig`](h009_embedded.zig); the compatibility-artifact bridge
does not carry them. The same fail-closed command is:

```sh
zig build typed-air-frontier --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

An intentional reviewed replacement adds
`-Dtyped-air-frontier-mode=update`. Update is explicit and writes each file
atomically; ordinary tests and check mode never update artifacts.

## H-010 Poseidon layout benchmark vectors

`h010-poseidon-layout-v1/vector-log10.stwairb` and
`vector-log14.stwairb` are the checked default-input artifacts for the isolated
H-010 CPU layout experiment. Each canonical `STWAIRB\0` v1 stream records the
generator and semantic identities, every sixteen-lane input, the enabler/wide/io
roles, and sixteen outputs from the unchanged static Poseidon reference, then
ends in a SHA-256 seal over all preceding bytes.

[`h010-poseidon-layout-v1/index-v1.tsv`](h010-poseidon-layout-v1/index-v1.tsv)
is the readable projection. It pins the complete vector metadata plus rows 0,
1, and the final row for each checked vector. Its file SHA-256 is
`1c881a3a944794943f872ea85678a4809db68a96021b06abbc15ef42d878fd19`.

| Log | Bytes | File SHA-256 | Internal seal |
| --- | ---: | --- | --- |
| 10 | 143,490 | `2d90fa647d55758f1fdf7be46de5232ee006ac3682ab0371ec1108c95c8f14ee` | `27be0de8a88a36ac9cb686c40da6442abdd18950bc4cb45a93773f45de4fb113` |
| 14 | 2,293,890 | `b2f84aa4ecc9f017932a2ca81fd89060d1fccb8bfaf90c9843ac9013cb6f83d8` | `b9ce7ca07edee474d0ca9da8e2a4dcdd24d300b6a99c1a1c5305a90da9a3c11d` |

The tool regenerates and byte-compares both vectors and the index without
candidate execution:

```sh
zig build typed-air-layout-benchmark \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast -- \
  vector-artifacts check design/typed-air/artifacts/h010-poseidon-layout-v1
```

Replacing reviewed bytes requires the same command with `update`; writes are
atomic and ordinary benchmark/check commands never update them. The dedicated
`h010_embedded.zig` bridge is injected only into package tests and the isolated
benchmark executable. Log 18 is deliberately not checked here: it is a large,
generated, opt-in stress vector whose results are marked non-receiptable. These
vectors authenticate benchmark inputs; they do not activate a layout or alter
the proof protocol.
