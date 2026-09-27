# Direct query hash destinations through transcript assembly

Query batches now allocate or borrow exact G/XOR ranges and lend per-block ranges
to frame writers. One canonical draw hash plan supplies identical geometry/output
wires for all blocks; frame contents and masks remain private/live as before.
Transcript query operations reserve their unused G/XOR ranges and lend them to the
batch. This removes both frame-to-batch and batch-to-transcript hash-row copies.
Smaller batch rows still use their existing append path.

Owning and borrowed APIs share one builder. Destination geometry is independently
validated; sizing is not authority. Temporary frame results use scoped backing
allocation. Partial-block output multiplicities, state/counter reads, counter carry
and query output schedules remain unchanged. Errors may leave unpublished caller
rows partially written; ownership stays with the caller.

ReleaseSafe query/native gates pass 8/8 steps, 4/4 tests. Query tests (1 s /3 MiB
reported MaxRSS) cover counts 0,1,7,8,9,17, native masked outputs, fixed/live metadata,
owned/borrowed full G/XOR parity, lifetime after result destruction, malformed
destination before writing, and allocation failures. Native tests (46 s /1 GiB)
independently verify both parent proofs, codec, handoff parity and ownership.

Tracked preparation peak stays 382,427,223 bytes under the tested 512 MiB cap;
retention stays 130,557,704 and worker peak 982,008,191 bytes. No peak-memory or
latency win is claimed. Key remains
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`, codec 116,382 bytes.
An initial compile failure from a destination/counter-destination name collision
was corrected before qualification.

Next: direct secure-draw destinations, then final committed-column emission
across transcript/path assembly. Current destinations are logical rows. Production
profiles, reusable keys, distinct-child/parent-of-parent qualification, Metal and
reviewed parameter experiments remain incomplete.
