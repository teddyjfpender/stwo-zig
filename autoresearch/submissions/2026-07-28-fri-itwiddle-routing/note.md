# Reuse cached inverse twiddles for FRI line folds

## Model and harness

Model: OpenAI Codex. The measured candidate
`97cd41882ff7afa772be82c888b75597418092e4` is a source-only descendant
of frontier `cfd47be98a10598b90a898e787e5cd1c674b09e7`. The publication branch
later integrated current `main`; the performance numbers below remain bound
to the measured candidate. Qualification target: `core_cpu/small/time`,
Zig 0.15.2, ReleaseFast, paired S3.

## Hypothesis

Every FRI line-fold layer reconstructs bit-reversed coset x-coordinates and
runs a serial batch-inverse chain, although the prover's canonical twiddle
tower already stores the exact inverse coordinates for the same domain family.
Borrowing the matching tower slice should remove repeated fill and inversion
work without changing fold arithmetic.

## Changes

`FoldLineWorkspace` accepts an optional borrowed inverse-twiddle tower. For a
fold of half-length `h`, it reads the canonical slice
`[tower.len - 2*h .. tower.len - h]`; otherwise it retains the original
coordinate-fill and batch-inverse fallback. The PCS scheme obtains the tower
from its existing twiddle source and threads the borrowed slice through lazy
FRI commit. Ownership and deinitialization remain unchanged. When current
`main` changed proof-domain selection to use the final composition tree rather
than the largest tree, the publication merge retained that selector and routed
the matching final-domain inverse-twiddle tower into FRI.

## Results

Hosted current-frontier qualification is pending. A fresh local advisory S3
screen against the exact canonical frontier completed 20 paired rounds with
`R = 0.991108` and portfolio CI `[0.963264, 1.026027]`. All five local gates
passed, the pinned Rust oracle verified the scored workload, and proof bytes
were identical. The harness classifies the result as confirmed-neutral. The
screen used `--guards none` to avoid the known generic-runner guard-budget
defect; it is not a qualification receipt, attestation, judged result, or
improvement claim. A historical micro-measurement for the same exact-slice
mechanism suggested roughly 72 microseconds per deep proof, but the fresh
whole-proof result supersedes it for current prioritization.

After integrating current `main`, the combined tree passed the core and prover
library test products in ReleaseFast, including their 79-source and 186-source
transitive closure checks. This validates the semantic conflict resolution but
is not a new paired performance run. A publication-only conformance follow-up
also removes one non-semantic separator line from `scheme.zig`, restoring the
file to the repository's 850-line ceiling; formatting and source conformance
pass with no new violations. Hosted Linux CI remains authoritative for the
complete static lane because the local macOS replay is blocked by unrelated
SDK linkage failures.

## Caveats

The optimization depends on exact domain-family and bit-reversed slice
correspondence. The fallback remains active if the tower is absent or too
short. Proof-byte identity and whole-proof paired evidence are mandatory; the
historical micro-result is diagnostic only. The measured small-class result
does not support promotion on this host. Because the timing verdict predates
the `main` integration, the merged publication tree must be re-measured before
any performance ratio is attributed to that exact tree.
