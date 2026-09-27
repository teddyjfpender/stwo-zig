# Typed first-accepted-block controller

The controller consumes authenticated pending and acceptance bits. Four degree-two
constraints enforce both bits, selected=pending*accept, and
next_pending=pending-selected. A caller anchors initial pending=1 and terminal
pending=0. Each accepted candidate's scalar tuples are consumed, even after
selection; only the first accepted candidate emits the result and its ordinal.
The ordinal is the number of attempts consumed, not a complete u64 channel counter.
Single-QM31 mode consumes/emits four coordinates; bulk mode uses eight.

AIR: 12 main columns, 22 fixed columns, 4 direct roots, 20 relation events,
10 interaction batches / 40 columns, maximum degree 2. Semantic identity:
`bc7f9f9df841aae93d1cff37cd8a107c584d8ba40856075ff995b08206b449f5`.
Fixed columns do not depend on acceptance or selected values.

Existing draw witness code now also offers prepareAttempts/trustedAttempts.
These export each raw candidate and acceptance status without the ordered-draw
public status/output anchors. They share the existing hash/state/counter framing
implementation. They do not independently prove native retry behavior: a caller
must join a controller. Their next_draw denotes the end of the physical batch;
it must not be mistaken for the counter after the selected native draw. Legacy
prepare/trusted behavior is retained.

The complete CPU proof uses the pinned native rejection fixture with three raw
candidates: reject, accept, accept. It proves selection of the second block,
consumed count two, and disposal of the third accepted candidate. It checks a
wrong trusted count anchor as well. The unit enumerates all sixteen four-slot
acceptance patterns, verifies state/count selection and fixed columns, tests
state mutations and four-coordinate consumption, and authenticates typed export.
For padding after selection, either boolean status satisfies the local scan;
the status lookup binds it to the actual computed acceptance. The unit explicitly
tests this distinction instead of incorrectly requiring the scan alone to fix it.

Validation: initial zero-pin run generated the AIR identity. The integration run
passed the complete retry proof (4 s / 349 MiB) and legacy draw tests (495 ms /
4 MiB); one unit assertion about padding status was corrected as described above.
Final focused controller unit exited 0: 4/4 steps, 1/1 test, 633 ms / 2 MiB,
5 s compile. No AIR change accompanied that test correction. Four distinct tests
across controller, retry-proof and legacy-draw gates passed. Formatting and
`git diff --check` pass. Test times are diagnostics, not speedup measurements.

Remaining: checked private u64 counter transitions, counter bytes routed into
hash frames, first-success outputs joined into the full parent transcript,
verifier-owned capacity classes and overflow handling, lifted alias scheduling,
and production CPU/Metal key admission. This is a proved controller/hash fragment,
not a reusable complete-parent key or production migration. Production is unchanged.
