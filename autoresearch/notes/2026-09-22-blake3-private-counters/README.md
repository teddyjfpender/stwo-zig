# Checked private counters and bounded native retries

The typed counter step enforces counter_next=counter+pending through eight byte
addition equations, seven boolean carries, and a boolean increment. Input and
output bytes request existing byte-pair range checks. Final carry is zero, so
u64 wrap is impossible. It has 24 main / 9 fixed columns, 16 direct roots,
13 relation events, 7 interaction batches / 28 columns, and degree 2. Identity:
`ffff10e710fb18dd0e9d0f442ed4ac62a7458e774d90e8f22e05f060377794dd`.

Canonical draw framing now exposes its index through two LE word callbacks;
serialized bytes and the protocol identity are unchanged. The bounded draw
component combines existing hash/frame/challenge providers, first-acceptance
control, and checked counter steps. Pending remains one through the accepted
attempt and zero thereafter; padded slots hash the frozen counter and cannot
advance it. Initial state/counter are authenticated external ports. Final result
and counter have explicit output ports and read counts. The consumed ordinal
is discarded through a private authenticated sink. Initial pending=1 and terminal
pending=0 remain fixed constraints. Capacity exhaustion is an explicit error.

Fixed rows are independent of candidate acceptance, initial counter and selected
values at a fixed capacity. Native comparisons include the genuine rejection
fixture, starts 1 and 0xffffffff, and u64-max-minus-one with padding at u64-max.
A complete CPU proof checks a three-slot rejection/acceptance/padding fragment
with final counter two. This is a fragment with externally anchored inputs and
outputs, not the full parent transcript or a reusable production key.

Validation: 8 distinct tests across counter-step, bounded-draw, bounded-draw-proof,
framing, transcript-sequence, and legacy-draw gates passed. The main batch exited
0 with 20/20 steps and 6/6 tests; the final review exited 0 with 8/8 steps and
3/3 tests (counter repeated, two legacy draw tests added). Main runtimes were
459 ms counter, 455 ms bounded comparison, 4 s bounded proof / 354 MiB,
453 ms framing, and 4 s transcript / 394 MiB. Final counter review was 456 ms;
legacy draws were 720 ms. All used the serial wrapper and ReleaseSafe.
Formatting and git diff --check pass. Timings are test diagnostics, not speedups.

Initial identity preparation caught byte-range requests declared as generic
fields; input/output byte types were corrected before pinning the identity.
The following zero-pin run generated the committed digest. Final range tests
also demonstrate a modular byte alias that satisfies addition locally but is
excluded by the byte lookup requests. No equation changed after passing proof
qualification; the final edit only strengthened that unit assertion.

Next: integrate bounded secure operations into the full transcript, route each
counter output into the following operation, and initialize constrained zero
counters after absorptions. Preserve raw-query counter semantics separately from
secure rejection. Capacity classes/overflow admission, lifted alias scheduling,
production keys and CPU/Metal parent-of-parent qualification remain unfinished.
Production still uses Poseidon; no migration or end-to-end speed claim follows.
