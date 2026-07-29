# Sail provisioning: a CI capability, not a laptop prerequisite

Status: normative for how the pinned Sail 0.20.2 toolchain is provisioned and
for what a green provisioning run does and does not upgrade. Companion to
[`TEAM_B_SAIL_REFINEMENT_CONTRACT.md`](TEAM_B_SAIL_REFINEMENT_CONTRACT.md)
section 0, whose claim boundary this document never widens.

## 1. The problem this solves

Every Team B architectural capsule is labelled "reviewed capsule", and stays
non-publication-level until the pinned Sail 0.20.2 toolchain actually runs
against this repository. Until now the only way to run it was a local build on
one developer machine. That made the Sail-present gate
(`zig build riscv-refinement-pilot` with live evidence, and
`scripts/riscv_refinement.py receipt`) a laptop prerequisite: unverifiable by
reviewers, unrepeatable by CI, and hostage to one machine's opam switch.

The supported path is now hosted CI:
[`.github/workflows/riscv-sail-formal.yml`](../.github/workflows/riscv-sail-formal.yml)
provisions Sail 0.20.2 from the hash-pinned upstream release binary (the exact
mechanism `riscv-sail-differential.yml` already uses -- no opam bootstrap runs
in CI), builds the pinned workspace, regenerates the Sail Lean theorem backend
from the exact `rv32im-zkvm-v1` configuration, runs the full pilot gate, and
mints the live-evidence refinement receipt as a build artifact.

The workflow runs on schedule, on `workflow_dispatch`, and on pushes to
`main`. It does not run on pull requests: a cold run rebuilds the Sail
simulator, Spike, the Lean backend, and the whole proof tree, which is far too
slow for a per-PR required check. It has **no skip path**: if Sail cannot be
downloaded, hash-verified, or built, the job is RED, never skipped.

## 2. What each command establishes

The workflow runs these commands in order. Each one upgrades a specific claim
from "asserted in a pinned JSON profile" to "demonstrated on hosted,
reproducible infrastructure".

| Command | Claim it upgrades |
| --- | --- |
| hash-pinned install of `sail-Linux-x86_64.tar.gz` from release `0.20.2-binary` (sha256 `26b59bca...`) | "Sail compiler 0.20.2 (pinned)" stops being a version string in `conformance/riscv/rv32im-sail-profile.json` and becomes an executed binary with a pinned digest. Both refinement scripts reject any other version. |
| `python3 scripts/riscv_formal_tools.py prepare --workspace <dir> --sail-compiler <sail>` | The pinned `sail-riscv` revision `8c7f2da5` (tag `2026-07-20-8c7f2da`) actually builds with that compiler; the simulator's `--build-info` reports the pinned model tag and compiler; the RVFI transport patch is the only working-tree change; Spike and riscv-arch-test are materialized at their pinned revisions. The verified provisioning receipt is uploaded with the run. |
| `python3 scripts/riscv_refinement.py prepare-sail --sail-riscv-dir <dir>/source/sail-riscv --sail-bin <sail>` | The merged exact `rv32im-zkvm-v1` configuration passes the pinned simulator's `--validate-config` and reports ISA string `rv32im`, and the Sail **Lean theorem backend is regenerated from that exact configuration** by the pinned compiler -- in CI, not on somebody's laptop. |
| `zig build riscv-refinement-pilot` (with `STWO_SAIL_RISCV_DIR`/`SAIL` set) | The digest pins in `scripts/riscv_refinement_lib/sail.py` (`GENERATED_DEFINITION_HASHES`, `SOURCE_SLICE_HASHES`) and the committed generated artifacts are checked against the **freshly generated** backend, not re-asserted from committed hashes; plus the full pilot gate: fresh symbolic AIR export, byte-identical artifacts, coverage, negative controls, Lean build, proof-escape scan, axiom audit. |
| `python3 scripts/riscv_refinement.py receipt --sail-riscv-dir ... --sail-bin ...` | A release receipt signed with **live** Sail evidence (`semantic_toolchain` binds the compiler and simulator binary sha256s) can be minted on hosted CI. The receipt command refuses `--reuse-committed-sail-evidence` and `--no-export-air`, so a green receipt step is by construction a live-toolchain run. |

## 3. What a green run upgrades -- and what it does not

Be precise here, because "the Sail toolchain ran in CI" is easy to over-read.

**Upgraded when the job is green:**

- The Level-1 pilot's digest binding. `RiscvRefinement/Sail/Generated/Pilot.lean`
  pins `execute_UTYPE`/`execute_ITYPE` digests; a green run means those digests
  were re-derived from a freshly generated backend on hosted infrastructure.
  The statement "digest-pinned against generated Sail" stops carrying the
  silent footnote "...as last checked on one laptop".
- The receipt's evidence grade. "Release receipts require live Sail toolchain
  evidence" stops meaning "release receipts require one specific developer
  machine". Any maintainer can dispatch the workflow and obtain a fresh
  live-evidence receipt artifact.
- The provisioning caveat in
  `.github/workflows/riscv-team-b-refinement.yml` ("the Sail-bound Level-1
  pilot gate remains the separate, locally-run `zig build
  riscv-refinement-pilot`") is retired in substance: the Sail-present run is a
  hosted capability.

**NOT upgraded -- no wording changes anywhere:**

- **No file stops saying "reviewed capsule" because this job is green.** The
  four Team B family capsules
  (`RiscvRefinement/Sail/Reviewed/{LoadStore,Shifts,Multiply,Div}.lean`) remain
  reviewed capsules. Their headers say "no Sail compiler is installed in this
  environment"; provisioning removes that *excuse*, not the *obligation*.
  Upgrading them requires extracting the generated definition slices for the
  load/store, shift, multiply, and division clauses, pinning their digests,
  and re-proving every `*_refines` theorem against the generated definitions
  unchanged. None of that work has happened, and none of it falls out of
  provisioning.
- **The generated-monad normalization theorem stays open**, including for the
  pilot's LUI/ADDI. The generator now derives a fail-closed AST translation
  receipt from the exact generated `execute_UTYPE`/`execute_ITYPE` slices, and
  a green live-toolchain run reproduces that receipt. It still does not prove
  the capsule is the observable result of the generated Sail step monad. That
  is Lean work
  (`TEAM_B_SAIL_REFINEMENT_CONTRACT.md` sections 0 and 5), not provisioning
  work, and the `claim_boundary` recorded in every manifest and receipt
  (`lean_generated_sail_monad_normalization: false`) is unchanged.
- The serialized-M31 AIR interpreter theorem stays open, unchanged.
- `team-b-coverage.json`'s claim boundary ("no entry here is
  publication-level") is unchanged.

## 4. Known first-run state: RED -- and the design flaw behind it

The first hosted run fails at the pilot gate with
`generated artifact drifted: generated-manifest.json`. The immediate cause:
the committed `formal/riscv-refinement/generated-manifest.json` records
`"evidence_source": "carried-committed-sail-evidence"` -- it was last
regenerated *without* a live Sail toolchain -- while a live-toolchain run
renders `"evidence_source": "live-toolchain"` into the manifest bytes.

Do not read this as one stale committed file. The evidence grade participates
in the manifest's identity twice: as the visible `sail.evidence_source` field,
and inside `canonical_digest`, which `render.artifacts` computes over the
whole manifest including that field. Every verification path
(`riscv_refinement.py verify` / `check-generated` -> `render.check_artifacts`)
re-renders the manifest with *this run's* evidence grade and demands byte
identity with the committed file. The consequence is that the two grades are
mutually incompatible states rather than an ordered pair where live strictly
upgrades carried:

- A live-toolchain run (this workflow) can never verify a carried-grade
  committed manifest, even when every Sail input, output digest, and artifact
  byte agrees. That is this workflow's first-run RED.
- Symmetrically, once live-grade artifacts are committed, every
  carried-evidence run -- `--reuse-committed-sail-evidence`, which is what
  `scripts/riscv_team_b_refresh.py` passes and what every no-Sail machine
  must use -- fails the same byte check in the other direction.
- `verify-receipt` has the same defect at a third site: it compares the
  committed manifest's `sail` block against `sail.provenance(<this run's
  evidence>)` including the grade, so a live receipt can never be verified
  against a carried-grade manifest.
- Worse, `generate --reuse-committed-sail-evidence` after a live-grade commit
  would rewrite the manifest back to the carried grade *with zero content
  change* -- silently downgrading the evidence record, moving
  `canonical_digest`, and thereby invalidating the freshly minted live
  receipt's `generated_manifest_digest` binding.

So the committed tree can be green for exactly one of the two evidence modes
at a time, and each mode's regeneration step revokes the other's green. The
durable fix -- excluding the grade marker from byte identity while keeping it
visible in the artifact -- is specified precisely in section 7. It belongs in
`scripts/riscv_refinement_lib/`, which this document's owners do not edit.

Until that fix lands, the interim procedure is unchanged:

```sh
python3 scripts/riscv_refinement.py generate \
  --sail-riscv-dir <workspace>/source/sail-riscv --sail-bin <sail>
# commit the regenerated artifacts, then re-run the workflow; its receipt
# step re-mints formal/riscv-refinement/refinement-receipt.json from live
# evidence for the follow-up commit.
```

-- with eyes open: that commit makes THIS workflow green and turns the
carried-evidence leg red until section 7 lands. The RED itself is fail-closed
behavior ("the committed evidence was not minted by a live toolchain run" is a
true statement); the flaw is that the grades cannot hand over to each other.
Do not add a skip or a tolerance to either leg; fix the identity (section 7),
not the gate.

## 5. The macOS story

There is **no macOS release binary** for Sail 0.20.2. The upstream
`0.20.2-binary` release ships exactly three assets: `sail-Linux-x86_64.tar.gz`
(the one CI pins), `sail-Linux-aarch64.tar.gz`, and `sail-Windows-AMD64.zip`
(verified against `gh api repos/rems-project/sail/releases`, 2026-07-29).

**CI is the supported path.** On Apple Silicon there is no hash-pinned binary
to install; local Sail requires building through opam:

```sh
brew install opam gmp zlib pkgconf cmake dtc z3   # dtc: Spike's device-tree
                                                  # dep; z3: Sail's runtime
                                                  # constraint solver
opam init --yes
opam switch create sail-0.20.2 5.2.1           # a dedicated switch keeps the
eval "$(opam env --switch=sail-0.20.2)"        # pinned version isolated
opam install --yes sail.0.20.2
sail --version                                  # must report: Sail 0.20.2
```

Then the same commands the workflow runs:

```sh
python3 scripts/riscv_formal_tools.py prepare \
  --workspace /tmp/stwo-riscv-formal \
  --sail-compiler "$(opam var bin)/sail"
python3 scripts/riscv_refinement.py prepare-sail \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv \
  --sail-bin "$(opam var bin)/sail"
STWO_SAIL_RISCV_DIR=/tmp/stwo-riscv-formal/source/sail-riscv \
  SAIL="$(opam var bin)/sail" \
  zig build riscv-refinement-pilot
```

An opam build is a source build: its binary digest will differ from the pinned
Linux release binary, which is fine -- the compiler *version* (0.20.2) and the
generated output digests are what the gates pin; receipts additionally record
whichever compiler binary actually ran. Nothing requires a developer to do
this. It exists for local iteration on the Sail-facing scripts; the verdict
that counts is the hosted workflow's.

## 6. Cache and identity notes

- The workflow caches the built workspace at
  `${RUNNER_TOOL_CACHE}/stwo-zig/riscv-formal`, keyed on the digests of the
  formal profile, the RVFI transport patch, and the two Sail configuration
  overrides -- the same pin set `riscv-sail-differential.yml` keys on. It uses
  its own key epoch (`riscv-formal-refinement-v1-`) because its workspace also
  carries the generated Lean backend, and falls back to the differential's
  exact key so a warm differential toolchain seeds the first run.
- Cache contents are never trusted: `riscv_formal_tools.py prepare` re-verifies
  checkout revisions, working-tree state, patch identity, and simulator
  `--build-info` on every run, and `prepare-sail` regenerates the backend
  whenever the exact configuration changed. A poisoned cache is discarded by
  bumping the key epoch; a stale one fails identity checks and the job goes
  RED rather than building from unpinned state.

## 7. Specified fix: grade-blind manifest identity

This section is the precise change list for the owners of
`scripts/riscv_refinement_lib/` (`render.py`, plus one site in
`scripts/riscv_refinement.py`). It resolves the section 4 flaw. Target
invariant: **two rendered manifests whose only difference is
`sail.evidence_source` have equal `canonical_digest` and verify against each
other's bytes; any other byte difference stays RED.** The grade stays in the
artifact -- visible and auditable -- but stops being load-bearing for
identity. Receipts continue to refuse carried evidence, unchanged.

1. **`render.artifacts`** -- compute `canonical_digest` with the grade
   excluded:

   ```python
   unsigned = copy.deepcopy(manifest)
   del unsigned["sail"]["evidence_source"]   # KeyError here is a real bug
   manifest["canonical_digest"] = codec.content_digest(unsigned)
   ```

   `codec.content_digest` itself is unchanged (it still strips only
   `canonical_digest`). After this, a carried-grade and a live-grade manifest
   with identical content differ in exactly one visible JSON line.

2. **`render.validate_committed_manifest`** -- recompute the digest the same
   grade-stripped way, and additionally require
   `manifest["sail"]["evidence_source"] in (sail.LIVE_EVIDENCE,
   sail.CARRIED_EVIDENCE)`. An unknown grade is RED, never normalized.

3. **`render.check_artifacts`** -- byte-compare every artifact exactly as
   today EXCEPT `generated-manifest.json`, which is compared modulo that one
   field: parse the committed bytes with `codec.load_json` (duplicate keys
   stay fatal); reject any grade outside the two pinned constants; substitute
   the committed grade into the freshly rendered manifest dict; require
   `codec.pretty_bytes(substituted) == committed bytes`. Because of (1),
   `canonical_digest` needs no substitution -- it already agrees whenever
   everything else agrees. Every other divergence (an artifact hash, a
   proof-source digest, formatting) still fails, byte for byte.

4. **`render.write_artifacts`** (the `generate` path) -- the grade is sticky
   upward: if the destination manifest differs from the new bytes ONLY per
   rule (3) and the committed grade is `live-toolchain` while the render is
   carried, keep the committed file. A carried run re-verifies; it does not
   re-mint. A live render always writes `live-toolchain`; a carried render
   that changed any *other* byte writes the carried grade, because those bytes
   were not produced under live evidence.

5. **`riscv_refinement.py` `verify_receipt`** -- the comparison
   `manifest.get("sail") != sail.provenance(evidence(args, paths))` must
   exclude `evidence_source` from both sides, mirroring the round-trip check
   `sail.carried_evidence` already performs (it pops `evidence_source` before
   comparing). `generated_manifest_digest` binds the stored -- now
   grade-blind -- `canonical_digest` on both sides and needs no further
   change.

6. **Unchanged, deliberately:** `sail.carried_evidence`'s pinned-constant and
   round-trip checks; `sail._refuse_minting_sail_artifacts` (carried evidence
   still cannot mint or alter one byte of Sail output); `sail.toolchain`'s
   refusal of carried evidence, so release receipts still require the live
   toolchain.

7. **Tests** (`scripts/tests/test_riscv_refinement.py`): a live-grade render
   passes `check_artifacts` against a carried-grade committed manifest with
   identical content and vice versa; `canonical_digest` is equal across the
   two grades and unequal under any other mutation; a mutated non-grade byte
   still fails; an unknown `evidence_source` in the committed manifest is
   RED; `generate` under carried evidence does not rewrite a live-grade
   manifest when nothing else changed.

8. **Sequencing:** land this fix BEFORE any live-toolchain regeneration
   commit. Then the first green run of `riscv-sail-formal.yml` requires no
   commit at all: it verifies the committed carried-grade manifest under live
   evidence and uploads a live receipt that binds it. The committed grade
   flips to `live-toolchain` naturally the next time content actually changes
   and is regenerated with the live toolchain.
