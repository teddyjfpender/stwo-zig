# Shared capture and parent preparation qualification

Both CPU and Metal/AOT pass 192 acceptance/rejection cases. All 21 tracked
artifacts match each other and the canonical baseline. The retained source snapshot
and compressed patch precede the post-qualification design note.

- `ownership.log`: 14 dependency checks, including the complete shared preparation
  closure and standalone verifier boundaries.
- `focused.log`: genuine leaf capture and expected-boundary tests pass.
- `contracts.log`: four adapter, four transcript and one routing test pass; the
  initial statement invocation skips because fixture paths were absent.
- `statement-test.log`: that statement test rerun with authenticated two-segment
  inputs passes, including 228 raw-word mutations and 45 arithmetic mutations.
- `recursive-tests.log`: recursive-parent capture and both preparation tests pass;
  9,116,105 contributions close, with failure cleanup, aliasing and retry checked.

The original named integration tests delegate to the shared test bodies so moving
code does not silently remove tests. Early local checks caught that discovery issue
and import/formatting mistakes before this qualification. Final unused-import and
shared geometry cleanup preceded the complete-proof gate.

This qualifies the shared detached capture/composition/parent preparation route on
the admitted q193 development fixture. Device interactions, larger useful workloads
and production-security qualification remain outside this checkpoint.
