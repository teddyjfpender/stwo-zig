# Build-monorepo performance baseline v2 protocol

This document describes the repository-owned implementation of the
[epoch-3 authority amendment](2026-07-21-performance-authority-epoch-3-amendment.md).
The machine authority is
[`build-monorepo-performance-baseline-v2-protocol-v2.json`](build-monorepo-performance-baseline-v2-protocol-v2.json).

No epoch-2 measurements are committed yet, so the separate future autoresearch
promotion remains `NO-GO`. This protocol defines how those measurements are
captured and judged; it is not evidence that they passed. Architecture BG-14
and BG-15 do not execute or consume this protocol.

## Components

| Component | Owner | Responsibility |
| --- | --- | --- |
| Protocol manifest | `conformance/build-monorepo-performance-baseline-v2-protocol-v2.json` | Frozen authority, workloads, hosts, lanes, statistics, budgets, and bounds |
| CLI | `scripts/performance_epoch_gate.py` | Thin command dispatch and machine-readable results |
| Plan | `performance_epoch_gate_lib/plan.py` | Deterministic host plan with fixed baseline `A` and candidate `B` ownership |
| Capture | `performance_epoch_gate_lib/capture.py` | Bounded no-shell execution, raw evidence, append-only journal, and atomic publication |
| Validator | `performance_epoch_gate_lib/receipt.py` | Independent schema, identity, artifact, statistical, and budget verification |
| Statistics | `performance_epoch_gate_lib/statistics.py` | Authenticated import of the frozen autoresearch implementation |

Capture and validation are separate. The capture controller does not decide a
budget verdict. The validator does not execute a benchmark.

## Authority

The manifest pins the amendment, immutable v1 receipt, autoresearch runner,
autoresearch statistics implementation, and workload registry by SHA-256. The
loader also fixes their expected paths and digests in the version-1 protocol
implementation. Editing both a source file and its manifest digest cannot
silently create a new version-1 statistical policy.

The validator imports `autoresearch/cli/stwo_perf/stats.py` after authenticating
its digest. It does not contain another Hodges-Lehmann or bootstrap
implementation.

## Plans

Create one plan on each allocated host. A plan binds:

- the exact historical repository, commit, tree, and clean state;
- the exact candidate repository, commit, tree, and clean state;
- a protected session nonce;
- non-aliasing baseline and candidate worktrees;
- separate initially empty local and global cache roots;
- ordered build and proof command argument arrays; and
- the host's build, backend, workload, AOT, or challenge allocation.

The historical arm is always `A`; the candidate is always `B`. Plan validation
reconstructs the plan from the protocol and rejects a changed command, role,
path, arm, workload, or ordering.

## Capture

`capture-host` verifies both planned worktrees with Git before executing. The
controller uses `subprocess.Popen` with an argument array and never invokes a
shell. Every attempt records:

- host-local contiguous sequence number;
- planned command and fixed arm;
- stage, workload, paired round, and order position;
- start and end timestamps, exit code, and classified status;
- stdout, stderr, proof, verifier, timing, and resource artifact references;
- the previous attempt digest; and
- the canonical current attempt digest.

Each attempt is appended to a JSONL journal and fsynced before the controller
continues. Sealing preserves both that journal and a canonical ledger. Product
failures, timeouts, and interruptions are terminal receipt failures.
Infrastructure failures may be retried, but remain in both files.

Native proof capture requires the pinned Rust Stwo oracle binary. The capture
hook accepts a sample only after the benchmark reports local verification and
the pinned Rust verifier accepts the exact proof artifact. It records the
canonical proof digest, proof and request times, Metal device dispatches, and
CPU fallback counters as raw verifier/timing evidence.

## Raw bundle

Every raw file has a bounded relative path, kind, byte count, and SHA-256. The
validator rejects duplicate identifiers or paths, symlinks, path traversal,
missing files, size drift, digest drift, unsupported kinds, duplicate JSON
fields, noncanonical evidence JSON, and non-finite numbers.

Atomic publication first moves the sealed staging directory to its raw-bundle
content address. It then writes a temporary receipt, invokes the independent
validator, and hard-links only a passing receipt to its content-addressed final
path. Failed raw evidence is retained rather than overwritten.

## Protected terminal binding

An unkeyed digest cannot prove that an operator did not delete the last failed
attempt and recompute every following digest. The protocol does not pretend
otherwise.

Each host's protected producer attests:

- plan digest and session nonce;
- attempt count and terminal attempt-chain digest;
- host, toolchain, conditions, and cache digests; and
- the complete raw-bundle content digest.

The aggregate validator requires the attestation digest through a separate
trusted input supplied by a future protected autoresearch workflow. An
attestation embedded only in the receipt is not authority. That promotion
runner remains responsible for authenticating repository, workflow SHA, ref,
event, run, job, and artifact transport before passing those digests to this
validator.

## Derived verdicts

The validator derives every accepted result from raw evidence:

- exact workload descriptor, numerator, functional security profile, runtime,
  executable, source, and host;
- at least 10 excluded verified warmups;
- at least 10 verified proofs per arm per paired round;
- at least three complete rounds with workload-derived first order and strict
  alternating `AB`/`BA` order;
- byte-stable proofs, local verification, and pinned Rust Stwo acceptance;
- candidate Metal device dispatch with exactly zero CPU fallbacks;
- candidate throughput divided by historical throughput;
- frozen 95% Hodges-Lehmann bootstrap confidence interval;
- peak candidate RSS divided by peak historical RSS;
- cold and warm build time from raw timing artifacts;
- installed files, no-op rebuilds, source closure, and link surface from
  versioned raw artifacts;
- authenticated AOT identity and no runtime compilation; and
- exact-candidate RISC-V product and link closure; semantic correctness remains
  owned by the separate pinned Sail/Spike release gate.

The throughput lower bound must be at least `0.97`; peak RSS must be at most
`1.05x`. Native CPU and RISC-V focused cold builds must not exceed their
available historical denominator. The RISC-V static build must also remain at
or below 60 seconds cold and 2 seconds warm, and its complete hosted challenge
must remain at or below 180 seconds. Binary byte counts are retained as
diagnostics. The acceptance rule for binary/link focus is semantic: the source
and link evidence must contain no unrelated frontend or backend growth.

## Architecture interface

Successful validation returns a `build-monorepo-performance-validation-v1`
object with:

```json
{
  "candidate_commit": "<40 lowercase hex>",
  "content_sha256": "<receipt content digest>",
  "protocol_sha256": "<protocol file digest>",
  "receipt_path": "<validated canonical receipt path>",
  "receipt_sha256": "<exact receipt file digest>",
  "schema": "build-monorepo-performance-validation-v1",
  "verdict": "PASS"
}
```

`ValidatedReceipt.architecture_binding()` provides the same interface to
`scripts/architecture_host_gate`. Missing plans, hosts, raw evidence, protected
attestations, budget evidence, or a `PASS` verdict fail closed.

## Commands

```sh
python3 scripts/performance_epoch_gate.py create-plan --help
python3 scripts/performance_epoch_gate.py capture-host --help
python3 scripts/performance_epoch_gate.py validate-plan --help
python3 scripts/performance_epoch_gate.py validate-receipt --help
```

The capture command is intentionally not part of ordinary fast CI. The tests
use fixture executors and synthetic raw evidence; they do not run builds,
provers, Metal, or the Rust oracle.
