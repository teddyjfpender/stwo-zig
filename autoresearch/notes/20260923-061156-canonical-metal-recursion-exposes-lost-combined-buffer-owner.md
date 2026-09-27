---
title: Canonical Metal recursion exposes lost combined-buffer ownership in streaming PCS
author: Teddy Pender
created_utc: 2026-09-23T06:11:56Z
---

# Preserve ownership of combined FFT buffers in streaming PCS

Status: fix implemented; focused root/value parity and allocation-failure gate queued.

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
