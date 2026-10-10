# Canonical fold PAGE draft collection

This unqualified source cohort connects the qualified draft transport to the
existing selected CPU source-PAGE collector. It does not execute a PCS, STARK,
FRI, guest, segment, device, or benchmark. Actual producer/recommit/detached
load bodies are retained for the root's sole compiler lane.

`CPU SourcePages.collect` now traverses the original Fold.Cursor once into
private PAGE operand inodes. It no longer creates the whole fold spool. Its
original configuration, source admission, original source files and public
input, independently chosen row capacity, stream census, and final FoldPlan
remain mandatory. Existing spool APIs and the public `Options.spool` workload
caps are preserved. Those caps now limit the once-stored final PAGE transport;
there is no duplicate spool file to charge. No new proof-format version is
needed: the promoted files are original B5SFOPR1 bytes.

`Job.collectWithDrafts` uses the single existing `collectInternal` loop. Cold
collection and `collectWithOperations` retain their original behavior. In the
draft branch each PAGE still uses real `FoldOwner.collect`, its actual six
roots, original descriptors and exact circuit ordinals. Before promotion Job
calls the same `owner.require(admitted, plan, pin, proof.fold)` used by original
`FoldOwner.persist`, then derives that exact pin's identity. Only encoding and
writing the already-stored payload is replaced. The original raw collector,
setup leases, root roster, source epoch, Context and sealed phase are unchanged.

The typed Collection holds one synchronous Draft.Reader lease and the exact
success prefix. Every completed replay retains original decoder/order/hash/
length guards. Each original raw persistence success and fold promotion is
tracked immediately before any later failure. Failure closes the reader first
and deletes only those newly published raw/fold operand names. Original input
files and exclusive-publication collisions are preserved. Successful files
transfer to caller publication ownership only after complete original Job
Context/seal construction. Controller then releases draft metadata; Job retains
no drafts, source reader, whole input or callback-provided claim scalars.

Draft and Job metadata use the original caller allocator; identifiable caller
shared budgets remain retained through their existing owners. Job checks the
same allocator and directory, exact Store limits, staged file cap, and combined
draft/Job roster metadata cap before creating its own original bounded setup.
The canonical branch has no spool precharge. Each final raw and fold file is
added exactly once by the original per-PAGE FilesBudget checks. Metadata/control
capacity and file arithmetic remain checked before allocation or publication.

For E fold operations and P fold pages the selected path retains
`250*E + 96*P` fold operand bytes, instead of `500*E + 96*P + 208`. Record payload
is encoded/written once; two bounded headers per PAGE are written. Promotion
still rereads/hashes the records, PAGE collection still regenerates original
packed cores, and fresh detached reception still recommits/verifies original
proofs. These are structural work counts, not measured speedups.

New fixtures exercise successful ownership transfer, late callback failure,
mixed raw/fold rollback, collision preservation, every transport allocation
failure, closed/reused owner denial, independent original capacity/limits,
early denial before files/allocator/source access, and original filename parity.
They use explicitly unverified transport metadata and create no Fresh receipt.
Prior CPU source and Job fixtures remain in the focused root as regression
checks. Positive full proof execution and benchmark measurements are absent.

Source hashing, source/core/input closure, original challenge epochs, detached
policy/manifest reconstruction, PAGE aggregation, sorted RAM/range joins and
the later recursive requester/public/global obligations keep their original
authority requirements. Transport pins or a successful collection return do
not establish those proof obligations.
