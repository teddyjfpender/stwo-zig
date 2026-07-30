# Session 03 — Phase 1.5: the resident trace arena (stopped mid-increment)

Reasoning-first. Implementation model: Claude Opus 4.5. Orchestration:
Claude Fable 5. Budget: 150 minutes. Head: `ef8e0c2c`, clean.
Stopped on orchestrator instruction before measurement, so the branch can be
rebased onto a modularity refactor that moves these seams.

## Order of work

Predecessor binaries first and in the background — `ef8e0c2c` is the branch head
and the tree was clean, so one build served as both predecessor and starting
point; `identity` confirmed `commit = ef8e0c2c…`, `dirty = false`,
`core-aot-manifest-sha256 = 0bc89238…`, i.e. the bundle flag took.

Then the Phase 0 note in full and session-02, then the machinery. The order
mattered for one specific reason: session-02's blocker was that the eval ABI is
single-arena-only, and I wanted to know whether the *commit* side already had a
single-arena surface before designing one. It does, and finding that first
changed the whole shape of the increment.

## The seam already existed, and that was the useful discovery

Session-02 found `evalPrepared(arena, plan)` and stopped there. Walking the
commit path found the mirror image, already implemented:

- `runtime/circle_legacy.m:227-229` computes `source_is_base` by comparing every
  source column pointer against the coefficient arena, and when it holds the
  entire fused-upload encoder is skipped.
- `combined_commit.zig:91-99` has `reuse_source`, gated on
  `columnsCoverContiguousBacking:320-332`.
- `engine.zig:125` already exposes `commitWithBacking`, and
  `scheme.zig:205` already threads `backing_buffers` down.

So the no-copy commit source is not something to build. It is something that
*declines* today, because `scheme.zig:290-298` **detaches** any backing before
the backend can see it — a full per-column copy — and because Cairo hands
`base.takeColumns()` with no backing at all.

That reframed the increment from "make a no-copy path" to "make the source
already be the arena the existing path wants". Which is exactly campaign 1's
recorded lesson, and it is why the layout is grouped by log size in
first-appearance order: that is the order `buildLogSizeGroupsFromColumns`
produces, so each commit-time group is one contiguous run and `source_is_base`
can hold per group.

## Why the CPU product is safe by construction

I did not want to rely on testing for this. `prepareColumnsCombinedForBackend:249`
only allocates a group coefficient arena when the backend lacks
`combined_base_in_place`; `cpu_scalar/mod.zig:39` declares it, and `:37-38` cap
the combined path at 256 columns, which the Cairo base trace exceeds. So the CPU
backend neither allocates nor can receive a group arena, and the product gate is
comptime on a declaration only Metal makes. The CPU codegen is unchanged.

## The fact that stopped the increment

The first wired build failed all-opcodes with `error: IncompleteClaimGeometry`.

A claim derived before witness execution still carries `deferred` per-component
log sizes — `claim_generator.LogSize` has a `.deferred` arm,
`deferredCount()` exists to count it, and `resolveFeedGeometry`'s own doc comment
calls itself "the witness-to-statement handoff". `template_binding.zig:42`
refuses a deferred log size outright.

So the layout is fine and the *timing* premise is wrong: the row counts the
layout needs are not known before the execution the layout is supposed to
precede. Phase 0 §3.2 was right that the planner is row-count-agnostic; it is the
row counts that are late. I would rather this be recorded as a measured refusal
from a real workload than as an argument, which is why I wired it and ran it
rather than reading the type definitions and inferring.

I then made the arena *fall back* on an incomplete claim rather than fail, so the
product is byte-identical and green while the finding stands. all-opcodes proves
`79ae76e1ac0c` on both lanes at 75 dispatches with zero fallbacks. I want to be
explicit that this verifies the machinery is **inert**, not that it is correct
when engaged — the arena does not execute on any live workload, so its write path
has unit coverage and no product coverage.

## What I would flag as weakest

**No paired evidence and no binding smoke test.** The increment's acceptance bar
was byte-exactness plus no regression plus a demonstrated `evalPrepared` binding
against a live arena. None of the three is delivered: byte-exactness is
demonstrated only on the fallback path, no A-B-B-A was run, and the smoke test
was not written. The template for it is
`tests/metal/backend/execution_graph_test.zig:234-322`, which already builds an
arena and dispatches `evalPrepared` — but against JIT-compiled source, not the
digest-verified metallib, and against a synthetic program, not a Cairo
component. Closing that gap is most of a session on its own.

**Two files hit the 850-line ceiling and the ceiling was right both times.**
`scheme.zig` was at exactly 850, so the adoption decision moved into
`backed_columns.zig` as `adoptOrDetach` / `freeSource` — which is better, because
the adopt-or-detach choice now lives beside the ownership helpers it is about
rather than inline in a long function. `commit_backend.zig` was also at exactly
850, so `recordSampledValueFallback` moved to `commit_policy.zig`; a declined
device route being a counted fallback is a commit-policy statement, so that is
its right home too. Same pattern session-02 recorded for `arena_binding.zig`.
Worth naming as a repo property: files sitting exactly at the ceiling force an
architectural decision on the next edit, and so far the decisions have been
improvements.

**Test reachability, avoided rather than repeated.** Session-02 recorded that
`composition_aot.zig`'s tests are not reachable from any green step. I hit the
same wall — `addTest` only collects tests from its root module's own files, so
tests beside the planner compile inside the product closure and never run. I
confirmed that by breaking an assertion and watching both `test-cairo-frontend`
and `test-cairo-cpu-product` still pass, then moved the tests into the frontend
test root where they do run, and confirmed *that* the same way.

## Conflict-sensitive knowledge for the rebase

The changes touch four shared seams that a modularity refactor is likely to
move, in dependency order: `backed_columns.zig` (new adoption helpers),
`scheme.zig`'s `commitOwnedPreparedWithRecorderAndBacking` (detach bypass),
`columns/preparation.zig` (`source_arena` parameter threaded to
`prepareColumnsCombinedForBackend`, plus `arenaGroupRun`), and three call sites
that gained a trailing `null` (`tree_builders.zig:113`, `:258`,
`deferred_commit.zig:72`). The invariant that must survive any move: an adopted
arena's column values must never be freed per column — `freeSource` and
`preparation.zig`'s end-of-function release exist only to enforce that, and the
arena must be released exactly once, as a coefficient backing.
