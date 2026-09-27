# Fixed-attempt and raw draws use direct hash destinations

Fixed-attempt draws now allocate or borrow exact G/XOR ranges, lend per-attempt
ranges to hash/frame writers, and reuse the shared draw layout/output plan.
Transcript fixed-attempt operations supply their final unused ranges. All transcript
operation branches now use direct hash destinations rather than G/XOR append copies.

Public-state fixed preprocessing uses actual encoded bytes through the canonical
fixed-row writer. Private-state frames retain authenticated routing. Raw-attempt
export keeps every status/output source and does not enforce selection itself.
Normal draws keep the existing first-acceptance and public-output boundary rules.
One/two-value consumption, checked counters and namespaces are unchanged.

Temporary public encoding/boundaries and private frame results have scoped backing
ownership. They cannot free borrowed G/XOR ranges. Owning and borrowed APIs share
one builder; exact geometry is checked before writes. Later failure may leave
unpublished caller rows written, without changing their ownership.

ReleaseSafe draw/sequence/native gates pass 12/12 steps, 7/7 tests. Draw tests
(4 s /3 MiB reported MaxRSS) cover public/private and normal/raw complete row and
receipt parity, lifetime after result destruction, malformed geometry, exhaustive
allocation failures, real rejection, false output/skipped acceptance and counter
wrap. Sequence tests (5 s /388 MiB) include a complete CPU transcript proof.
Native tests (47 s /1 GiB) independently verify both parent proofs and ownership.
No leaks reported. Only explanatory fixed-preprocessing comments changed afterward.

Preparation peak remains 382,427,223 bytes under 512 MiB; retention remains
130,557,704 and worker peak 982,008,191. Key remains
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`, codec 116,382 bytes.
No memory-peak or timing improvement is claimed for this stage.

The remaining large boundary is logical transcript/path rows to final committed
columns; direct witness generation is not finished. Smaller metadata/interaction
cohorts still have staging. Production reusable keys, distinct-child/parent-of-parent
proofs, Metal/default migration and reviewed parameters remain incomplete.
