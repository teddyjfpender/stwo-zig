# Session 02 — Phase 1: composition residency

Reasoning-first. Implementation model: Claude Opus 4.5. Orchestration:
Claude Fable 5. Budget: 150 minutes. Head: `bf03954c`, clean.

## Order of work

Predecessor binaries first and in the background — `bf03954c` is a notes-only
commit so the product sources are identical to `cfad207b`, but the identity
string differs and the brief asked for a pristine `bf03954c` zig-out, so I built
one rather than assuming equivalence. `identity` confirmed
`commit = bf03954c…`, `dirty = false`. Host load at open was 1.66, which is the
quietest this host has been across the three campaigns.

Then read the Phase 0 note and session-01 in full before touching code, then
walked the specific machinery Phase 0 mapped. That order mattered: the survey
question I needed to answer was not in the note.

## The seam was better than expected, and then it wasn't

Phase 0 §3.5 recommended adding an `Engine.evaluateComposition` hook. My first
finding was that it already exists and is already backend-dispatched:
`src/prover/prove.zig:275` calls
`component_provers.computeCompositionEvaluationForBackend(B, …)`, and
`component_prover.zig:307-322` dispatches to `B.computeCompositionEvaluation`
when the backend declares it, falling through to the host path when it returns
null. The Metal backend already declares it
(`commit_backend.zig:70` → `runtime/backend_composition.zig:8`). So there was no
hook to write at all — the hook is there, the Metal implementation is there, and
it returns null for Cairo because `recurrenceShape` requires exactly one
component (`secure_composition.zig:120`) and Cairo has 58.

For about ten minutes this looked like a one-line increment: teach
`secure_composition` a Cairo shape. That is the moment I went looking for how the
existing Cairo composition device path actually binds its inputs, rather than
assuming it would accept what the hook hands it.

## The fact that decided the increment

`arena_binding.zig:1470-1506` builds the Cairo composition recipe, and every
single input is an *arena offset*: LDE plans, transcript outputs, random powers,
accumulator base, inverse twiddles, output coefficient bindings. I followed that
down to the ABI and found the reason:

- `prepared_execution.zig:544` — `evalPrepared(self, arena: ResidentBuffer, plan)`
- `resource_plans.zig:172-184` — `EvalLayout` is eleven `u32` offsets **into that
  one arena**, covering trace, interaction, params, random coefficients,
  denominator inverses and all four output coordinates.

There is no host-pointer eval surface. The composition metallib's kernels cannot
address anything that is not inside one contiguous resident buffer. And the
product prove path hands composition **host** columns from
`scheme.trace(allocator)` (`prove.zig:250-262`), with no resident arena anywhere
in `prover/transaction.zig`.

So the choice was: pack the base and interaction LDE columns into a scratch arena
per proof, or build trace residency. I checked the volume before deciding, because
"probably too big" is not a finding. `max_evaluation_log_size = 24` from Phase 0
§6.2 makes one column 64 MB, Cairo composition reads the full base and
interaction column sets, and campaign 2 already priced the comparable transfer at
3,420 MB on memory-7m. Campaign 1's R4 rejection had also already recorded that
Cairo component execution produces independent allocations so Metal packs anyway.
That is R1 and R4 simultaneously, with prior measured rejections on both.

I want to be precise about what this does and does not overturn. Phase 0's four
premises for putting composition first are each true — the metallib exists, it is
log-size-independent, the bundle is claim-derived and in-product, the planner is
row-count-agnostic. The survey simply never reached the eval ABI, and the ABI is
what makes composition residency downstream of *trace* residency. Phase 1 is not
independent of Phase 2.

I also chased one hopeful lead to its end rather than leaving it as a maybe:
`scheme.backendResidencyHandles` sounded like the committed trace might already
be device-resident and addressable. It is not —
`scheme_views.zig:51-64` yields `B.quotientResidencyHandle`, and
`merkle_tree.zig:208-213` returns `resident.tree.handle`, the *hash* arena of a
committed tree. Composition cannot read its inputs from it. Worth recording
because the name invites the opposite conclusion, and because it is a correction
to §3.6.

## Why I stopped rather than forcing a number

The program gate — composition stage `>= 2.0x` on the two big rows — is the most
important output of this increment, and I could not measure it. The options were
to build a plane-sized pack path and measure that (which would have measured a
design both R1 and R4 forbid, and produced a number the program cannot use), or
to report the gate as not measured with the structural reason. I took the second.
A fabricated-in-spirit gate result — "2.0x if we ignore the transfer" — would be
worse than no result, because the gate exists to decide whether to commit
Phase 2's much larger cost.

So the increment delivered the two items the brief said stand on their own
merits, and returned the blocker with file:line evidence.

## Digest binding: the decisions inside it

This is the item I would defend hardest. §6.3.1 flagged that the composition
metallib is loaded with no integrity check; what makes it worth its own commit is
*why* by-name resolution is not a substitute. A library exporting correctly-named
kernels with substituted bodies resolves every pipeline and evaluates the wrong
AIR. The verifier catches it — but only after a full proving cost, and with no
artifact naming the swap. So the unit test corrupts a single byte in the middle
of the real 7.7 MB library and asserts the length is preserved, because a
truncation test would not have been the threat.

Three design calls:

**No unchecked variant.** `Policy` is `approved_manifest` / `pinned_digest` /
`report_only`. I wanted an escape hatch for CI-compiled libraries that predate a
manifest entry, and the honest form of that is "name the digest you expect", not
"skip the check". A malformed `STWO_ZIG_COMPOSITION_METALLIB_SHA256` is an error
rather than a silent downgrade — that is the specific way this kind of gate
usually fails open.

**`report_only` is a real concession and I named it as one.** `metal-eval-prepare`
operates on libraries it just generated, which cannot be in a checked-in
manifest, so requiring the manifest there would break the toolchain rather than
secure it. It still measures the file so the digest lands in the tool's evidence,
and it is documented as forbidden on any proving path with a `gates()` predicate
so a caller can assert it holds a gating policy. `metal_prover_session`'s prewarm
also takes it, and I recorded that as a limitation with the follow-up rather than
pretending the session is fully covered.

**Manifest in source, not in `vectors/`.** The right artifact is a provenance
JSON alongside the library, matching `air_template_library_v1.provenance.json`.
`vectors/` is protected in this increment, so the manifest is a source constant.
Flagged in the note.

The enforcement point moved during implementation, and for a good reason. I first
put the policy helper and the authenticated load inline in `arena_binding.zig`.
The pre-commit ceiling rejected it — that file has a 2,502-line baseline budget
and I was at 2,547. Forcing it under the limit by deleting comments would have
been the wrong fix. Library selection already lives in
`resident/composition/config.zig`, so integrity belongs there: `loadAuthenticated`
went there, `arena_binding` changed by exactly one line and landed at 2,502, and
the result is better than what I first wrote — there is now exactly one place a
`.metallib` can enter a resident composition and it cannot be reached without a
digest check. The line ceiling did useful architectural work.

## Telemetry: the counter I deliberately did not add

Adding `metal_relation_dispatch` and `metal_composition_eval_dispatch` to
`metalDispatchTotal` is mechanical. The judgement was on the fallback side.

The obvious move is to record `cpu_composition_evaluation` wherever host
composition runs. That would be wrong: composition on the host is the product's
declared *placement* (`capabilities.zig:23-27`), not a fallback. Recording it
there would make all four Phase 0 rows report a CPU fallback, flip every one from
`accelerated_without_fallbacks` to `accelerated_with_fallbacks`, and destroy the
meaning of the invariant the whole program is judged against. So it is recorded
only where a device path was structurally admitted and then declined — currently
only digest-authentication failure.

I verified the "untouched paths unchanged" requirement two ways: a unit test that
asserts a 74-dispatch hybrid profile still totals exactly 74 with the new
counters present, and the three real proofs, which came back at 75 / 74 / 79 —
identical to the Phase 0 baseline on every row.

## Commit ordering, and one thing I had to reorder

The brief specified digest binding first, telemetry second. But the digest
rejection path records `cpu_composition_evaluation`, which does not exist until
the telemetry commit — so commit 1 would not have built. Rather than invert the
order, I split the dependency: commit 1 is the digest binding without the counter,
commit 2 adds the counter and wires it into the rejection path. Both build
standalone and the brief's order holds. Commit 2's story is also better for it —
it is literally "make the evidence count this".

## What I would flag to the orchestrator as weakest

The fail-closed evidence is module-level, not end-to-end. The brief wanted a
corrupt-metallib run showing host fallback with the fallback counted in
`backend_evidence`, and that is unreachable because the product never loads the
metallib — the same finding, showing up as a gap in its own verification. I would
rather the orchestrator see that shape clearly than see a substituted test.

Second: `composition_aot.zig`'s tests are not reachable from any green build step.
`src/integrations/cairo_metal` is excluded from both aggregate closures and the
cairo_metal product owns only the `prover` subtree, and the one step that would
cover it (`metal-prover-session-test`) is pre-existing-broken at `bf03954c` — I
confirmed that by stashing everything and reproducing the same 5 errors. I ran
them with `zig test` directly. A security fix whose tests no CI step runs is half
a fix, and I would put that follow-up ahead of the security review rather than
after it.

Third: single cold runs at host load 4.73, so the prove times in the note are
recorded for completeness and support no comparison. I claim nothing from them.
