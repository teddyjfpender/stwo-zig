# Fold PAGE draft transport

This source-only cohort adds an unimported collector, replay reader, and
same-inode promoter. It has not changed the canonical Controller or Job path.
It creates no proof receipts and invokes no PCS, FRI, STARK, guest, or device.

The existing collector writes every original 250-byte fold operation into a
whole-stream B5FSPL01 spool. Job then reads those operations and writes the same
records again into per-PAGE B5SFOPR1 operand files. Both sets remain stored.

`block_v5_memory_source_fold_draft_pages_v1.collect` instead traverses the
original bounded Fold.Cursor once, buffers at most 64 records, and writes
private per-PAGE files. PAGE capacity comes from the independently configured
row log, which the original FoldPlan already treats independently of census.
It reserves the original 96-byte header position, then writes the private
B5SFDRA1 header once the actual PAGE count is known. It checks original source
admission, stream census, ordinal ordering, PAGE/file/operation/metadata bounds,
and exact original record serialization. It retains only bounded PAGE pins.

The replay reader repeats header, length, original decoder, ordinal, payload
hash, and trailing-byte checks. It verifies the complete PAGE before returning
its final operation. Rewind supports the original two-pass planning procedure
and repeats all integrity checks; it is not an acceptance cache. Only one
reader may borrow the owner. An error poisons further replay/promotion.

Promotion requires exact original FoldPlan admission, the ordered replayed
PAGE prefix, and a nonzero PAGE identity. It rechecks every payload record and
hash, uses the original Store header serializer, overwrites only the reserved
header, syncs the inode, and publishes it with an exclusive hard link and
directory sync. Existing final files are preserved. The returned Store.Pin is
the original length/hash/identity transport type. It confers no source or proof
authority: integration must first require the actual six-root Fold owner/pin.
Original Store.load remains usable without a format change.

For E operations and P pages, retained operand bytes change from
`500*E + 96*P + 208` to `250*E + 96*P`. The new collector/promoter writes
`250*E + 192*P` logical bytes: record payload once and two bounded headers per
PAGE. Promotion still rereads and hashes each payload, as does fresh replay.
These are structural counts, not timing or filesystem-write measurements.

Successful final files belong to the caller publication inventory. Owner
teardown deletes only unpromoted private files. Collection failure removes
only its successfully created draft prefix; collisions preserve preexisting
drafts and final artifacts. The owner retains an identifiable caller shared
budget and frees all charged metadata before releasing that lease.

The focused fixtures compare two original Cursor passes, original Store
publication and load bytes/hashes, inode identity, empty/full-capacity/tail
geometry, all owner/load allocation failures, shared-budget teardown, and
mutation/collision/cleanup guards. Their PAGE identities are explicitly
unverified transport proposals. No fixture claims that a proof receiver ran.

After transport qualification, a separate cohort must connect draft replay to
Job's original operation-source path and replace its operand persistence with
promotion after genuine premix owner admission. Controller must select this
collector instead of creating the whole spool. Existing source challenges,
premix roots, PAGE proof, independently reconstructed durable policy, and
complete detached-reader authority remain unchanged and mandatory.
