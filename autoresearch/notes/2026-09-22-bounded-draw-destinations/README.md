# Bounded secure draws emit into transcript hash destinations

Bounded draws allocate or borrow exact G/XOR ranges for every configured attempt.
Frames write into those ranges directly; transcript preparation supplies its final
unused ranges. This removes frame-to-bounded-draw and bounded-draw-to-transcript
G/XOR copies. All configured attempts still emit, including slots after acceptance;
private counter stopping, retry selection and lookup multiplicities are unchanged.

Query batches and bounded draws now share the canonical equal-length draw layout
helper, checked count arithmetic and one output plan per batch. Owning/borrowed
bounded APIs share the same builder and validate exact destination lengths.
Smaller rows remain owned by the result arena; temporary frames have scoped
backing ownership. Failed generation can leave unpublished borrowed rows written,
but cannot free caller storage.

ReleaseSafe query/bounded/native gates pass 12/12 steps, 5/5 tests. Bounded tests
(3 s /3 MiB reported MaxRSS) cover native first-rejection/second-acceptance, counter
boundaries/exhaustion, fixed metadata, complete owned/borrowed row parity, selected
values, counter/read receipts, lifetime after destruction, invalid geometry before
writes and allocation failures. Query gate passes after the shared helper change
(1 s /3 MiB). Both independent parent proofs and codec/handoff checks pass in the
native gate (48 s /1 GiB). No allocator leaks are reported.

Preparation peak remains 382,427,223 bytes under 512 MiB; handoff remains
130,557,704; worker peak remains 982,008,191 bytes. No memory-peak or timing win is
claimed. Key remains `0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`;
codec remains 116,382 bytes. Security profiles are unchanged diagnostic profiles.

Fixed-attempt draws still use their prior staging path. Transcript/path G/XOR
buffers remain logical rows; final committed-column emission is not finished.
Production reusable keys, distinct-child and parent-of-parent qualification,
Metal/default migration and separately reviewed parameters remain incomplete.
