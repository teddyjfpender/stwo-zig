# RISC-V release evidence execution

**Status:** ARCHIVED. The pre-Sail owner-dispatched jobs described below are
disabled, their workflow inputs have been removed, and their receipts cannot
authorize a release. The current external ISA gate is
[`riscv-sail-differential-gate.md`](riscv-sail-differential-gate.md); the
current release runner is `scripts/riscv_release_gate.py --strict`.

This document historically defined the hosted CP-13 execution contract for the
[RISC-V release goal](2026-07-18-riscv-release-goal.md). It separates periodic
exhaustive evidence from the per-candidate secure challenge so a promotion
decision does not rebuild the pinned Rust oracle or rerun the 45-minute suite.

## Service-level objective

| Path | Purpose | Frequency | Limit |
|---|---|---:|---:|
| Exhaustive anchor producer | Run the canonical CP-13 plan and publish a reusable oracle/policy anchor | Periodically and after policy, oracle, schema, or compatibility change | `90` minute fail-safe |
| Fresh candidate challenge | Build the focused static candidate, prove a nonce-derived cross-shard program, and compare it to the anchor and Rust oracle | Every release decision | Hard `3` minute job timeout |

The candidate and anchor are deliberately separate identities. An unexpired
anchor may name commit `A` while a challenged implementation names commit `B`.
The fast gate accepts that relationship only when the current trusted-main
release-policy domain is byte-identical to the anchor policy domain. Candidate
implementation changes under `src/` remain possible; workflow, build, scripts,
tests, conformance policy, autoresearch policy, and RISC-V vector corpus drift
requires a new trusted policy revision and then a new exhaustive anchor.

The focused static prover and diagnostic pair build cold in approximately
`29-30s` and warm in approximately `0.14s` on the measured host. The current
131,107-step secure challenge proof completes in `3.52s` locally with about
`1.36GB` peak RSS; independent secure verification also passes. These are
diagnostic measurements, not a hosted-run SLA claim. The Actions job has a
hard three-minute timeout covering setup, cache restore, build, artifact
transport, challenge execution, validation, and evidence upload.

## Trust root

Both jobs execute `.github/workflows/ci.yml` from `refs/heads/main`. Admission
fails closed unless all of the following hold:

- repository `teddyjfpender/stwo-zig`, numeric ID `1152389958`;
- `workflow_dispatch` at `refs/heads/main`;
- numeric owner ID `92999717` for actor and triggering actor;
- full candidate and tree identities in the canonical repository;
- explicit candidate and anchor `refs/heads/*` refs whose current heads are
  the respective commits;
- requested candidate/promoted phase equals the checked-out capability-owned
  release state;
- current candidate release-policy domain equals current trusted main; and
- reusable anchor release-policy domain equals current trusted main.

GitHub currently reports `main` as `.protected=false`. Branch protection and
restricted workflow changes remain administrator hardening TODOs. Until then,
the owner-dispatched workflow and immutable numeric identities are the trust
root. The challenge's canonical SHA-256 identifier detects corruption; it is
not a signature and does not authenticate evidence outside the uniquely
successful trusted workflow run.

## Exhaustive anchor

First ensure the reviewed release-policy and controller revision is on canonical
`main`; anchor and candidate refs may differ from it only outside the policy
domain. Dispatch the producer from the canonical repository, preferably against
a dedicated anchor branch that remains at the produced commit:

```sh
candidate_sha=$(git rev-parse HEAD)
candidate_short=$(git rev-parse --short=12 HEAD)
candidate_branch=riscv-release-anchor-$candidate_short
candidate_ref=refs/heads/$candidate_branch
git push origin main
git push origin "$candidate_sha:$candidate_ref"

gh workflow run ci.yml --ref main \
  -f gate=riscv-produce-candidate \
  -f candidate_sha="$candidate_sha" \
  -f candidate_ref="$candidate_ref"
```

Wait for that dispatch to finish, record its numeric run ID, and require the
`RISC-V exhaustive release evidence` job to succeed before starting a fast
challenge:

```sh
gh run list --workflow ci.yml --event workflow_dispatch --branch main --limit 10
producer_run_id=<successful-producer-run-id>
gh run watch "$producer_run_id" --exit-status
```

Use `riscv-produce-promoted` only when that source contains the promoted
capability and artifact release state. The producer runs the complete canonical
plan:

1. format, upstream-pin, source-conformance, structure, purity, and layering gates;
2. full Python and transitive Zig release gates with no skipped required tests;
3. exhaustive RISC-V CLI proof, verification, mutation, and admission coverage;
4. pinned Stark-V public statement, witness, relation, and boundary comparisons;
5. immutable receipt validation and exact source/toolchain content identities.

The `riscv-release-bundle-v3` artifact contains the exhaustive receipts plus:

- the anchor `stwo-zig` verifier;
- the pinned Rust `cp11_dump` oracle executable; and
- the anchor RISC-V trace diagnostic.

Each executable digest must equal the digest recorded during exhaustive oracle
comparison. The archive is retained for 30 days and binds producer run,
attempt, workflow commit, anchor commit/tree/phase, policy domain, oracle build
identity, command coverage, and every file digest.

## Fast candidate challenge

Dispatch the consumer with the explicit reusable producer run ID:

```sh
candidate_branch=<candidate-branch>
candidate_sha=$(git rev-parse HEAD)
git push origin "$candidate_sha:refs/heads/$candidate_branch"

gh workflow run ci.yml --ref main \
  -f gate=riscv-candidate \
  -f candidate_sha="$candidate_sha" \
  -f candidate_ref="refs/heads/$candidate_branch" \
  -f producer_run_id="$producer_run_id"
```

Use `riscv-promoted` for promoted source. The workflow requires exactly one
successful `RISC-V exhaustive release evidence` job and one live v3 bundle in
the selected run/attempt. It downloads by exact artifact ID, compares the raw
ZIP digest to the GitHub API digest, and performs bounded regular-file
extraction with the trusted policy tool.

The fast gate then:

1. validates the anchor's live producer API identity, current branch head,
   lifetime, schema, policy domain, coverage, oracle receipt, and executables;
2. builds only `stwo-zig-riscv-cpu-x86_64-linux-musl` and its RISC-V diagnostic;
3. rejects either candidate tool if it is oversized, non-ELF, or has `PT_INTERP`;
4. issues a 32-byte CSPRNG nonce bound to repository, candidate commit/tree,
   workflow SHA/run/attempt, exact candidate executables, anchor commit/tree,
   anchor manifest, oracle identity, and 180-second expiry;
5. deterministically derives and byte-records a fresh RV32I challenge ELF;
6. proves it with the secure protocol in an isolated candidate sandbox;
7. verifies the proof with the distinct anchor verifier process;
8. executes the same ELF with pinned Rust `cp11_dump` and requires exact public
   data, final PC/clock, and ordered cumulative relation-sum agreement; and
9. retains all inputs, proof, diagnostics, receipts, timings, and file digests.

The challenge executes 16 nonce-derived ADDI instructions before the known
65,536-iteration cross-shard loop. It publishes four seed-derived `u32` words
as public output, so the candidate identity and nonce affect the committed
program root and algebraically bound public statement. Signed `MULH`/`MULHSU`
remain excluded under the documented pinned-oracle limitation.

Nonempty public input is admitted by the proof system. The focused nine-byte
public-I/O fixture, including a partial final word, passes production prove and
verify while its nonzero public `memory_access` term closes independently. The
release oracle machine-gates that same deterministic ELF and input against the
pinned Rust runner: full public data, all 27 component prefixes, all 12 relation
domains, tuple streams, input and binding digests, nonzero public compensation,
and the zero final aggregate must agree. The fast challenge still selects empty
input and binds its digest in the challenge and proof; that is a
challenge-grammar choice, not an AIR limitation. Expanding the grammar must
preserve Rust-oracle parity and must not weaken the proof or relation check.

## Candidate isolation

Candidate-controlled binaries never see anchor executables or Rust output. The
trusted workflow copies only the static candidate prover, candidate diagnostic,
derived ELF, and empty input into a read-only chroot. It runs as UID/GID
`65534:65534` with:

- a new network, mount, and PID namespace with a private `/proc` needed only
  for candidate self-executable measurement;
- `--kill-child=SIGKILL` and `no_new_privs`;
- CPU `160s`, address-space `3GiB`, output-file `128MiB`, and process `256` hard limits;
- one writable output directory; and
- bounded file and captured diagnostic reads.

The candidate proof and diagnostics are collected and rehashed before trusted
anchor verification and Rust comparison begin. Candidate and anchor binaries,
ELF, and input are rehashed again after execution.

Before the real challenge, the job compiles and runs a separate static
adversarial probe in the same sandbox. The probe fails the gate if it can read
an anchor path or establish an external connection. It also forks a delayed
writer; PID-namespace teardown must kill that child before it can publish an
extra output.

## Build cache

The focused Zig build cache is restored only after the candidate policy has
matched current trusted main. Its versioned restore prefix is scoped to the
canonical owner-dispatched job, pinned Zig `0.15.2`, Linux product, and exact
build policy. The primary key also contains the candidate SHA. A warm prior
candidate supplies content-addressed compilation objects, while Zig still
recomputes dependency identities for the new source. Cache contents never
authorize a result: executable digests are measured after build, embedded in
the fresh challenge, checked before and after execution, and independently
checked by the anchor and Rust comparisons.

## Limits and renewal

Fresh random sampling complements the exhaustive anchor; it does not replace
it. The same trusted worker hosts the sandbox and trusted comparisons. The
anchor verifier is independent of the candidate source and process, but proof
compatibility across source revisions is still required. A new anchor is
mandatory when any of these changes or fails:

- anchor expiry or branch-head ownership;
- trusted release-policy domain;
- pinned Rust oracle or helper identity;
- proof wire, verifier compatibility, bundle, challenge, or product schema;
- periodic exhaustive revalidation; or
- an observed challenge/oracle divergence.

An external multi-run challenge service would additionally require OIDC-bound
issuance and a durable atomic nonce-consumption store. That is future
hardening, not a property claimed by this same-job workflow.

RISC-V autoresearch remains disabled. Neither anchor nor challenge evidence may
promote that lane until its separate enablement contract is satisfied.
