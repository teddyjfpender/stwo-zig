# Failure-only PCS pool diagnostics (CUDA unqualified)

The isolated idle-cache candidate now records the existing runtime async-pool used/reserved byte counters and query status at the first physical allocation failure and again if the bounded retry fails after unused upper blocks are released. Requested, retained, lease, idle, active, physical free/total and context token refer to the same failure point before exception cleanup. Pool query failure reports zero counters plus its nonzero status; it cannot replace the original allocation error. No synchronization, query or output is added to successful allocations. No ABI or numerical path changes.

The runtime exposes pool counters but no public sum-of-tracked-allocations API; this patch does not invent one or reinterpret pool used bytes as exact requested allocation bytes.

Largest V2 terminal evidence requested 16,844,328,872 bytes with retained 12,342,085,552, lease 12,105,697,200, idle zero, physical free 16,973,824. Requested plus retained is below the unchanged 30,064,771,072-byte admission cap. This motivates diagnostics, not a claim about the physical allocation cause. Existing runtime recovery already joins and trims its own async pool once.

CPU host mocks check successful counters, failed/partially-written queries, and preserved allocation status. No NVCC build, GPU execution, memory-fit or performance qualification is claimed.
