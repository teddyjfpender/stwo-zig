---
title: Native hash domains planned before live emission; ownership and proofs qualified
author: Teddy Pender
created_utc: 2026-09-22T08:19:24Z
---

# Combined native hash layout planned before live emission

Canonical native transcript replay now returns an owned Planned phase containing
operation payloads, trusted transcript preprocessing and the expected final channel.
Its hashCounts validates fixed-plan identity before exposing geometry. emit creates
the witness and checks the final digest/counter, transferring ownership only on
success. Error leaves the planning owner available for cleanup or retry. Arena-backed
operation/payload slices are finalized before copying arena ownership.

State computes the combined G/XOR layout between replay/planning and live transcript
emission. Path counts use canonical group sizing for trace columns/opening counts
and FRI fold geometry. Checked sums give combined domains and transcript counts give
path offsets. This is sizing only: existing capture, graph, path/root and independent
fixed checks remain. After paths emit, State compares actual counts and logs to the
complete plan before publishing it.

Measured diagnostic layout: transcript G 46,648; path G 39,816; total G 86,464;
total XOR 24,704; domain logs 17 and 15. All match actual emission. This supplies
parent-wide geometry needed by the main-column sink but does not yet route adapters
into those columns.

ReleaseSafe plan/native gates pass 8/8 steps, 5/5 tests. Plan tests (5 s /7 MiB
reported MaxRSS) cover retained ownership after allocation failure and failed final
channel validation, then successful retry/transfer. Native tests (47 s /1 GiB)
reject modified layout logs/counts and malformed capture geometry and independently
verify both parent proofs, codec, handoff and ownership. No leaks reported.

Preparation peak is 382,427,279 bytes (+56 bytes from the prior measurement), handoff
retention 130,557,704, worker peak 982,008,191. Successful preparation remains capped
at 512 MiB. Key remains
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`, codec 116,382 bytes.
No latency or memory improvement is claimed.

Next: allocate combined main domains from this layout, pass offset column/metadata
views through transcript/path adapters, preserve independently constructed fixed
metadata comparison and transfer column ownership into Prepared. Remove final G/XOR
projection only after these destinations are integrated. Production reusable keys,
distinct-child/parent-of-parent proofs, Metal/default migration and reviewed
parameters remain incomplete.
