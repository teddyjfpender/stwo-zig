# Preserve ownership of combined FFT buffers in streaming PCS

Status: focused ReleaseSafe gate passed 5/5 tests (659 ms runtime, 3 MiB test MaxRSS). Canonical Metal v4 passed.

Canonical Metal parent v3 passed interaction commitment and reached core proof
opening/cleanup. The checked allocator then rejected a 64 MiB column-slice free
against its 512 MiB shared allocation and the process aborted. This is a failed
gate; the test server's 8/8 summary does not represent successful completion.

StreamingTreeBuilder retained descriptors from PreparedCommitmentColumns but
dropped column_backing_buffers and coefficient_backing_buffers. Combined FFT
backends return interior slices of aligned arenas. Independent-column teardown
therefore freed slices with incorrect lengths and lost backing ownership.

PreparedCommitmentColumns.detachBacking now converts one prepared batch into
independently owned column and coefficient entries, freeing its original buffers
with their recorded alignment. Partial failure leaves a deinitializable owner.
The builder calls this before transferring any entries. This adds bounded
per-batch copying, rather than retaining or duplicating a whole tree.

The existing real scalar FFT/adopting-backend fixture now also streams mixed-height
columns, compares roots, values, coefficient values and original ordering against
ordinary commitment, and injects every allocation failure with both always/never
coefficient retention. Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/prover test-pcs-owned-source -Doptimize=ReleaseSafe --summary all
```

The core proof may have been cleaning up after another error: no successful
canonical Ethereum parent proof or final worker peak is established by v3.

## Canonical Metal result

The full-width signer+Keccak leaf and recursive parent both verified independently
on CPU at 70 queries/26 PoW bits. Parent artifact: 907,988 bytes. Parent proving
performed 191 Metal dispatches with 2 CPU fallbacks. Tracked worker peak was
27,708,198,754 bytes under the unchanged 38,654,705,664-byte cap. Prepared rows
retained 10,150,562,296 bytes outside that cap. Worker and rows were released before
parent artifact round-trip verification. Checked-allocator cleanup passed.

Gate: 8/8 passed; test runtime 6 minutes/40 GiB MaxRSS, compile 3 minutes/8 GiB.
These ReleaseSafe qualification durations are not latency benchmark results.
This binary predates the subsequent compact-fixed-row change. That representation
requires its own qualification. Successful stateless-allocator parent proof and
canonical aggregation remain separate open checks.
