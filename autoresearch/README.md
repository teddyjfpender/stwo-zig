# stwo-perf: the autoresearch harness

**Start here: [TASK.md](TASK.md)** — the campaign index, one row per track.
Then open your track's brief in [tasks/](tasks/): its objective, era, scored
basket, editable surface, guards, ladder, and loop, written to be handed to a
coding agent verbatim. Briefs are generated from `MANIFEST.json` and
`ledger/epochs.json` (`stwo-perf task --board <board>`), so they cannot drift
from the contract the runner gates on (TRACKS §8).

Implementation of the harness contract in
the performance-extraction playbook (Part F; archived in `stwo-zig-og-docs`),
Part F. One CLI governs the optimization search from workspace creation to
submission; the judge — never the searcher — decides scores; and this git
repository is the source of truth: promoted efforts are merged commits whose
submission directories carry the note, claimed and judged verdicts, deltas,
and redacted agent transcripts, with the append-only ledger deriving the
Pareto frontier.

Standalone by design: nothing in here modifies or is imported by the prover
implementation. Python 3.11+ stdlib only; no packages to install.

> **Repository policy:** autoresearch is owner-operated local tooling. Its
> workflow templates are not installed in `.github/workflows/`, its tests are
> not production merge checks, and its ledgers do not gate Zig package or
> product releases. Install the optional automation only in a dedicated
> research fork or after an explicit governance change.

```text
autoresearch/
  MANIFEST.json        editable paths + rung map, locked paths, workload
                       registry, gate policy — the machine-readable contract
  skills/              algorithm selection plus Zig, Metal, and CUDA
                       profiling, performance design, and kernel engineering
  tasks/cuda/          ordered CUDA architecture and activation work
  README.md            this file
  schema/              local/remote submission, qualification, queue, verdict,
                       scoring, and ledger schemas
  ledger/              promotions.tsv (append-only) + epochs.json
  submissions/         one directory per submission, landed by PR
  notes/               standalone working notes (searchable via the CLI)
  cli/                 stwo-perf (harness) and stwo-prof (profiling) CLIs
  scripts/             owner-operated research policy entrypoints
  benchmarks/          legacy comparisons and diagnostic benchmark drivers
  tools/               peer/profiling helpers used only by autoresearch
  backend/             GitHub identity, scoped keys, intake store, and queue workers
  bots/                validate / qualify / intake / judge / promote entrypoints
  workflows/           GitHub Actions to copy into .github/workflows/
  tests/               unit tests (python3 -m unittest discover -s autoresearch/tests)
```

## Quickstart (searcher)

```bash
alias stwo-perf="$PWD/autoresearch/cli/stwo-perf"

stwo-perf update                   # fast-forward the checkout; the CLI is
                                   # repo-resident, so this IS the reinstall
stwo-perf benchmark                # the fixed suite, gates, ledger state
stwo-perf frontier                 # promotions ledger + Pareto frontier
stwo-perf clone ../ws-quotient     # your workspace (git worktree)
cd ../ws-quotient && stwo-perf setup

# iterate inside editable paths only (MANIFEST.json), then score paired:
stwo-perf run --scope s3 --class small --dimension time \
  --predecessor /path/to/promoted-head-worktree

# package: schema-checked note + claimed verdict + redacted transcripts
stwo-perf submit --slug quotient-batching \
  --note-file note.md --verdict autoresearch/.runs/latest/verdict.json \
  --transcripts ./transcripts --model "Claude Fable 5"

# then: commit the submission dir + your diff on a branch and open a PR.
# The canonical repository uses normal human review and merge; no research
# bot or hosted judge is installed there by default.
stwo-perf submissions              # pending / promoted / rejected
stwo-perf sync                     # jump back to the promoted frontier
stwo-perf notes add --title "tile size sweep" --note-file findings.md
stwo-perf feed                     # compile site/feed.json — the repo->website
                                   # contract (schema/site-feed.md); refuses
                                   # dirty inputs
```

## Fork-funded remote autoresearch

The remote path is for frequent, low-review submissions without spending the
canonical repository's hosted-runner budget on every attempt. A participant
fork pays for public qualification; the canonical service spends controlled
machine time only after cheap central tree validation.

```bash
# In a current fork, commit only MANIFEST.json editable paths. Obtain the exact
# canonical tip (not merely the last source commit in the performance ledger):
stwo-perf config --set api_url=https://api.autoresearch.fun
FRONTIER=$(stwo-perf remote-frontier --board core_cpu --class small)

# Run autoresearch-qualify-fork in the fork's Actions UI with FRONTIER and
# download its autoresearch-qualification artifact. Then authenticate the CLI:
stwo-perf login --client-id <github-oauth-app-client-id>
stwo-perf apikey
stwo-perf whoami

stwo-perf submit-remote \
  --receipt qualification/receipt.json \
  --repository https://github.com/<your-login>/stwo-zig \
  --ref refs/heads/<optimization-branch> \
  --note-file note.md \
  --coauthor <collaborator-login>

stwo-perf submission-status
# Each requested collaborator uses their own GitHub-bound key:
stwo-perf coauthor-accept <submission-id>
```

`STWO_PERF_API_KEY` can replace the stored key for headless agents. The same key
authenticates `whoami`, `submit-remote`, `submission-status`, co-author consent,
and withdrawal; `stwo-perf apikey-revoke` invalidates it centrally. See
`schema/qualification.md`, `schema/remote-submission.md`, and
`schema/remote-queue.md` for the wire and state contracts.
The CLI computes the attested receipt's SHA-256 directly from the downloaded
file; `--attestation-url` is optional audit metadata, not a verification input.

### Algorithm-selection gate

Before hand-rolling or replacing an algorithm, apply
`skills/match-algorithmic-problems`. It requires a sourced mapping from the
project task to canonical problems and computational models, distinguishes
algorithmic reductions from hardness proofs, and compares transferable prior
work against the real parameter regime. The output includes a falsifiable
performance or quality prediction. Preserve reusable matches as durable
`stwo-perf notes`; the selected implementation then enters the measured
profiling loop.

### Profiling inner loop (S1)

`stwo-prof` isolates code outside the repo and measures it with in-process
hardware counters — the S1 rung of the scope ladder and the start of F.8
item 1:

```bash
stwo-prof zig isolate mykernel      # scratch harness in ~/.cache/stwo-prof
stwo-prof zig run mykernel          # instructions/op, cycles/op, IPC, energy
stwo-prof zig asm mykernel          # codegen: NEON share, branches, memory ops
stwo-prof zig compare base cand     # ABBA A/B with bootstrap CI
stwo-prof metal run mydemo --entry k --grid 1048576   # real GPU ms + reflection
stwo-prof metal trace -- <command>  # Metal System Trace capture
stwo-prof cuda report report.json   # rank product CUDA-event stages
stwo-prof cuda systems -- <command> # Nsight Systems lifecycle/concurrency
stwo-prof cuda compute -- <command> # dominant-kernel counters only
```

Methodology and reading guides live in `skills/match-algorithmic-problems`,
the Zig/Metal skills, and the CUDA profiling, performance-design, and
kernel-engineering skills. Use a design skill to turn trace/counter evidence
into feature-gated architecture changes; kernel-scope results remain
diagnostics and never enter the promotions ledger.

The CLI output is fully formatted for terminals (colors honor `NO_COLOR` and
disappear when piped).

## The trust model

| actor | may do | may never do |
| --- | --- | --- |
| searcher (human or agent) | edit `editable_paths`, run claimed evaluations, submit, write notes | touch locked paths in a submission PR, mint `kind: judged`, append the ledger |
| fork qualification CI | run locked public tests/build/benchmark in the participant account, emit an optional attested receipt | establish trust merely because a check is green |
| intake worker | fetch a GitHub-owned fork, pin its source object, recompute ancestry/path/mode/tree/digest policy | execute participant code or trust fork-supplied pass booleans |
| judge (self-hosted runner) | paired judged runs under the host lock, comment verdicts, publish **HMAC-signed** verdicts to the `judge-verdicts` branch | edit source, edit existing ledger rows, write into the PR branch |
| remote judge/promoter | create an exact-tree canonical commit, run secret holdout, verify signed promotion, add verified co-author trailers and append one row | merge a stale frontier, altered tree, unsigned verdict, or unconsented attribution |
| promotion bot (legacy PR flow) | fetch the signed verdict, verify the signature, append one outcome row | append anything unsigned; anything else |

Enforced mechanically by the owner-operated tooling: `stwo-perf submit`
refuses locally; `bots/validate_action.py` can re-check a candidate tree
(locked paths, append-only ledger byte-prefix, note schema, transcript hashes,
secret scan, and judged-verdict forgery guards); and
`bots/promote_action.py` refuses any verdict whose
`JUDGE_HMAC_SECRET` signature does not verify. Governance PRs (anchor freeze,
`epochs.json`, workflow updates, harness fixes) pass validation and are
governed by human review instead — that is the deliberate exception.

## Scoring (playbook F.1, condensed)

- Both arms are **rebuilt and interleaved** (ABBA rounds) in one session —
  frozen reports are provenance, never a denominator.
- Ratio estimate: Hodges-Lehmann over paired round ratios; 95% bootstrap CI
  (seeded, deterministic).
- Promotion needs the declared-objective CI entirely below `1 − θ`, where
  `θ = max(floor, 2 × per-class A/A dispersion)` from `ledger/epochs.json`.
  Inside the band → confirmed-neutral: recorded, not promoted.
- Gates G1–G5 reject rather than score; per-gate detail is diagnostic only.
- Regression budgets are charged against the **frozen anchor**
  (`MANIFEST.json → harness.anchor_commit`), never the predecessor.

**v1 honesty notes** — recorded here so nobody mistakes scope: (1) pairing is
at round level because the bench schema exposes medians, not raw samples;
(2) G3 mechanism binding is declared in the note but its telemetry
verification awaits playbook F.8 item 2 (wait/dispatch counters in the native
report); (3) `native_mhz`/`peak_rss_mib` ledger cells are `0.0` in v1 — the
per-dimension medians live in the verdict evidence, and wiring them into rows
is a small follow-up; (4) judged promotion stays disabled until the anchor is
frozen and A/A dispersion is measured (`stwo-perf run --aa`, recorded in
`epochs.json` by reviewed PR) — exactly the playbook's own precondition;
(5) the near-threshold winner's-curse confirmation re-run (F.1) is not yet
automated — the judge workflow must be re-dispatched manually for CIs landing
within theta/2 of the bar.

## GitHub as the source of truth

A legacy PR promotion is, permanently and in one place:

1. the **merged commit** with the editable-path diff;
2. its **submission directory** — `note.md` (public reasoning), `verdict.json`
   (claimed, advisory), `delta.json` (predecessor + file/transcript digests),
   `transcripts/` (redacted sessions);
3. the **signed judged verdict** on the `judge-verdicts` branch — the one that
   counts, HMAC-signed by the judge runner and verified before any append;
4. its **ledger row** (with `outcome` promoted/neutral/rejected) appended by
   the promotion bot, from which `stwo-perf frontier` recomputes the Pareto
   frontier and anchor drift.

Reading the repo history *is* reading the research record; `sync`/`reset`
reconstruct any promoted state. Because ledger rows and `sync` reference the
judged PR-head commit, `main` must use **merge commits** (disable squash and
rebase merging) so those SHAs stay reachable forever.

A remote promotion preserves the same four things with a different envelope:
the first canonical commit contains only the exact editable-path tree delta and
verified participant trailers; its child adds the append-only ledger row and a
v2 submission directory containing the note, remote identity/source record,
tree delta, qualification receipt, and signed judged verdict. Both commits are
fast-forwarded together, so source and evidence cannot land separately.

## Optional automation for a research fork

The production repository deliberately does not install these workflows. A
dedicated research fork may opt in with:

```bash
cp autoresearch/workflows/*.yml .github/workflows/     # commit via normal review
```

- `validate.yml` — every PR; hosted runner; invariants + unit tests.
- `judge.yml` — installed under `.github/workflows/`; PRs labeled `submission`;
  **self-hosted macOS runner labeled `stwo-judge` only** (the timing
  contract requires controlled Apple hardware); one judgment at a time via
  the concurrency group + host lock.
  Note the concurrency queue keeps only one pending run: if several PRs are
  labeled while a judgment executes, re-trigger the skipped ones (re-label or
  push) after it finishes.
- `promote.yml` — on merge; verifies the signature and appends the outcome
  row; pushes with `[skip ci]`.
- `qualify-fork.yml` — inherited and run in participant forks; public test,
  release build, paired benchmark, receipt upload, and artifact attestation.
- `remote-queue.yml` — optional scheduled, self-hosted alternative to the local
  queue daemon; centrally revalidates, judges, records, and fast-forwards one.

Installing them changes that fork's governance and CI surface. The workflow
installation, online runner, and secret names do not by themselves
activate judged authority. Branch protection is still required on `main`:
require `autoresearch-validate` **and**
`autoresearch-judge` (an unlabeled PR reports the judge check as skipped,
which satisfies it), require review, forbid force pushes, allow only merge
commits, and add the promote workflow identity to the required-pull-request
**bypass list** — without that exemption the bot's ledger push is rejected
and no row ever lands. Secrets required: `JUDGE_HMAC_SECRET` (same value for
judge and promote workflows). The remote worker additionally uses an
independent `JUDGE_HOLDOUT_SECRET`; never expose either secret to fork CI.

## Backend (optional)

The legacy PR flow works with no backend. Remote fork submissions use the HTTP
service plus a worker sharing one store file:

```bash
STWO_PERF_HMAC_SECRET=$(openssl rand -hex 32) GITHUB_CLIENT_ID=<oauth app id> \
  python3 autoresearch/backend/server.py --repo . --port 8787 \
  --store /var/lib/stwo-perf/backend-store.json

JUDGE_HMAC_SECRET=<independent-secret> JUDGE_HOLDOUT_SECRET=<independent-secret> \
  python3 autoresearch/backend/worker.py --repo . \
  --store /var/lib/stwo-perf/backend-store.json \
  --push-remote origin --branch main
```

The OAuth app must enable GitHub Device Flow and requests only `read:user`.
The backend exchanges the CLI's
GitHub token only for `/user`, stores no GitHub credential, and issues a scoped,
revocable HMAC key bound to the stable numeric GitHub ID. API endpoints include
`POST /v1/auth/github/keys`, `POST /v1/keys/revoke`, `GET /v1/me`,
`POST/GET /v1/submissions`, consent/withdrawal actions, leaderboard/frontier,
client ID, and health. The service binds to 127.0.0.1; put authenticated TLS,
request rate limits, backups, and process isolation in front of it in production.
CLI credentials live in `~/.config/stwo-perf/config.json` with mode 600.
An always-on worker also needs `GH_TOKEN` access to verify attestations; the
scheduled workflow receives its repository token automatically.

For a zero-idle-daemon deployment, `remote-queue.yml` runs one cycle every five
minutes on the existing self-hosted `stwo-judge` machine and consumes no hosted
runner minutes. Set repository variable `AUTORESEARCH_STORE_PATH` to the shared
absolute store path and grant the workflow's bot a protected-branch bypass for
its exact fast-forward + research-record push. The daemon gives lower latency
and avoids scheduled Actions entirely.

## Verification before staging

The pre-staging suite is stdlib-only, hermetic, and part of the normal
`unittest discover` workflow:

```bash
# Full harness suite
python3 -m unittest discover -s autoresearch/tests -p 'test_*.py'

# Focused operational contract
python3 -m unittest \
  autoresearch/tests/test_queue_state_machine.py \
  autoresearch/tests/test_failure_injection.py \
  autoresearch/tests/test_hermetic_e2e.py -v
```

The queue test checks every source/target state pair, terminal-state
immutability, reachability, compare-and-swap claims, and attribution freeze.
Failure injection covers unavailable attestation/clone services, crashed
benchmarks, absent signing keys, stale frontiers, tampered verdicts, partial
disk writes, concurrent claimers, and interrupted/resumed pushes. The
end-to-end test drives the actual CLI command handlers and API-key config,
production HTTP handler, co-author consent, durable queue, local Git fork,
tree canonicalization, signed verdict, two-commit promotion, research record,
and ledger. GitHub's attestation service and the costly benchmark executable
are deterministic boundary doubles; exercising those two real integrations is
the purpose of staging, not a hidden assumption in the hermetic suite.

## Activation checklist (in order)

1. Freeze the anchor: set `harness.anchor_commit` + `anchor_report` in
   `MANIFEST.json` (human-reviewed commit, after the conformance goal's
   baseline-freeze phase).
2. Measure A/A dispersion per board and class on the judge host; record in
   `ledger/epochs.json`.
3. In a dedicated research fork, install workflows, add the `stwo-judge`
   self-hosted runner, and protect its research branch.
4. First promotion follows the quickstart above end to end.

Until 1–2 are done every verdict is claimed/advisory — by design, not by gap.
