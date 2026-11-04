# Resident PCS phase lifetimes

The imported-point, blowup-one PCS route keeps source coefficients resident and
reconstructs one source commitment tree at opening time. Its large rolling LDE
and Merkle buffers are needed only after FRI has fixed the query positions.
Allocating them before DEEP unnecessarily overlapped both memory phases.

The revised ownership schedule is:

| Phase | Keep | Retire after joined last reader |
|---|---|---|
| DEEP | Source coefficients, forward twiddles, ordered samples, DEEP output, FRI storage | Combined arena and its per-group log views, sample/point scratch, weights and linear terms |
| FRI fold/terminal | Full FRI columns/trees, terminal, channel state, compact roots | FRI alphas, folding twiddles, final small column |
| FRI openings | Queried FRI values/paths and compact root snapshots | Full FRI columns/trees |
| Source openings | Original source coefficients, source logs, forward twiddles, queried proof output | Rolling LDE/tree scratch remains ordinary temporary storage until the request ends |

Source forward twiddles upload once into their own plane. The rolling combined
extension uses the existing compact-column N2B primitive, with an explicit
coefficient-log/evaluation-log difference of one. Its eight log descriptors per
group occupy existing arena reservations and retire with that arena; the
separate source coefficient logs survive through source opening. The legacy
addressed primitive remains unchanged and keeps its required twiddles inside
its arena.

FRI roots are copied device-to-device before the full trees retire. The final
proof readback uses those snapshots, queried values/paths, terminal, nonce,
query positions and channel state. No field value returns to the host to drive
proving. Rolling segment pointers stay null metadata until the rolling buffers
exist, then bind before opening. Newly allocated async-pool memory is joined
before the compute lane uses it.

Native temporary retirement validates all whole, active reservations before
one phase join and before changing any cache block's state. It rejects partial,
duplicate, stale, leased, domain and protected source-coefficient reservations.
Logical active size is tracked separately from reusable block capacity. A new
reservation resets its protection tag; a protected physical block is therefore
reusable as normal scratch after a request ends. This internal helper does not
introduce a public allocation-generation ABI.

Retirement marks temporary cache blocks idle; it does not claim that CUDA has
immediately returned their backing pages. Existing bounded admission and OOM
recovery can reuse or evict those idle blocks. The existing cumulative
`allocated_bytes` diagnostic is not a simultaneous memory peak after phased
reuse. Actual cap enforcement and separately sampled physical memory remain
the evidence for capacity claims.

Qualification must include exact-reservation rejection and live-source
preservation, native CPU/old-GPU proof-byte parity on the new runtime, fresh CPU
receivers, and the previously blocked large shape under the same device cap.
