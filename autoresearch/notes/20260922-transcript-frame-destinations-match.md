# Transcript mix and PoW frames emit into transcript G/XOR destinations

Task: eliminate frame-row concatenation for transcript mix/root/payload and PoW
operations. Use the canonical output hash plan (already needed for output wiring)
to reserve exact unused G/XOR list ranges before frame emission. Reuse its output
wire metadata after generation. Prior state producers are stored as row indices,
so list growth does not leave stale pointers. Finalize new rows only after writes.

Borrowed frame APIs share the existing live/fixed writers. Allocate frame receipts
and hash plans from the ordinary bounded backing allocator, and destroy them after
copying smaller boundary/routing rows and metadata. Install cleanup before fallible
payload-read append. Preserve state reset, zero/dynamic digest multiplicities,
PoW low-bit sinks, caller identities, and transcript operation order.

This is destination lifetime reuse and concatenation elimination; no alternative
hash equations, draw schedule, security profile or transcript bytes. Secure draws
and query batches retain their existing adapter paths for now. Memory benefit is
conditional on other preparation peaks; no latency claim without timing evidence.

Validate transcript-plan parity/failures and full native parent verification,
codec/key identity, handoff and tracked preparation/worker memory.

First measurement: transcript-plan gate passes; full native gate stops at its
stale expectation that 512 MiB preparation must fail. Preparation actually succeeds
with tracked peak 416,243,999 bytes. The unexpected-success assertion does not
release the returned owner, causing test-only leak output. Update the denial cases
to 1 byte/64 MiB and test successful bounded preparation at 512 MiB.

Follow-up lifetime review: queries, bounded secure draws and fixed-attempt draws
copy every row/output endpoint before Prepared.deinit. Their temporary arenas can
use bounded backing directly rather than remain nested in transcript metadata.
This changes ownership lifetime only; no caller retains a prepared slice.
