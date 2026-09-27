# Caller-owned destination for canonical full-hash witness generation

Task: let adapters reserve final typed row slices and generate hash rows in place,
without requiring an intermediate owned Rows object followed by append-copy.
Transfer the existing canonical graph evaluation loop unchanged into a destination
kernel. Both the owning convenience API and the new borrowed-destination API call
that kernel. Trusted preprocessing remains independently generated from the plan.

Destination lengths must exactly match the internally built plan before writes.
The caller owns destination lifetime; workspace remains allocator-owned and local.
No public caller-supplied graph authority is introduced. Allocation failures after
writes are not promised atomic, and this must be explicit. Existing digest vectors,
fixed-row parity and exact lookup closure remain oracles; destination mismatch
must reject before mutation. This API alone does not integrate direct column output.
