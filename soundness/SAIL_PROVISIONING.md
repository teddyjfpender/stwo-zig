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
  pilot's LUI/ADDI. A green run proves the capsule's digests match generated
  output; it does not prove the capsule is the observable result of the
  generated Sail monad. That is Lean work
  (`TEAM_B_SAIL_REFINEMENT_CONTRACT.md` sections 0 and 5), not provisioning
  work, and the `claim_boundary` recorded in every manifest and receipt
  (`lean_generated_sail_monad_normalization: false`) is unchanged.
- The serialized-M31 AIR interpreter theorem stays open, unchanged.
- `team-b-coverage.json`'s claim boundary ("no entry here is
  publication-level") is unchanged.

## 4. Known first-run state: the job starts RED, and that is correct

The committed `formal/riscv-refinement/generated-manifest.json` currently
records `"evidence_source": "carried-committed-sail-evidence"` -- it was last
regenerated *without* a live Sail toolchain -- and the committed
`refinement-receipt.json` no longer binds the committed manifest's digest. A
live-toolchain run renders `"evidence_source": "live-toolchain"` into the
manifest bytes, so the pilot gate's byte-identical artifact check will report
`generated artifact drifted: generated-manifest.json` until a maintainer
regenerates the artifacts with the live toolchain and commits them:

```sh
python3 scripts/riscv_refinement.py generate \
  --sail-riscv-dir <workspace>/source/sail-riscv --sail-bin <sail>
# commit the regenerated artifacts, then re-run the workflow; its receipt
# step re-mints formal/riscv-refinement/refinement-receipt.json from live
# evidence for the follow-up commit.
```

This is fail-closed behavior working as designed. The job being RED says "the
committed evidence was not minted by a live toolchain run", which is exactly
the condition this workflow exists to detect. Do not add a skip or a
tolerance; fix the evidence.

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
