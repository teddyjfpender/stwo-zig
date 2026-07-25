# Task 04: CUDA Memory-Pass Reduction

Status: pending; trace commitment is the first measured target

## Objective

Reduce global-memory traffic, temporary materialization, and launch
fragmentation across commitment, Merkle, FFT, quotient, and FRI stages.

## Deliverables

- Per-stage pass ledger with input/output/reread/temporary bytes and launches.
- Resident commitment inputs consume existing coefficient/LDE arenas directly.
- Merkle design evaluates fused lower levels, retained tree layout, batched
  trees, and opening/decommitment reuse.
- FFT/radix variants minimize full-array passes without spills or parity loss.
- Quotient and FRI avoid redundant trace, domain, and tree rereads.
- Variant predicates are structural and tested at admission boundaries.

## Gates

- Forced-path differential comparison of every changed intermediate.
- Final proof is CPU/CUDA byte-identical and Rust-oracle accepted.
- Nsight Compute confirms predicted DRAM/L2 and occupancy movement.
- Nsight Systems confirms predicted launch/pass movement.
- No register-spill or occupancy regression outweighs saved traffic.
- No additional proof-sized temporary or unaccounted peak memory.
- Full structural ABBA meets the per-row ceiling.

## Exit Evidence

- Dominant-kernel roofline and pass ledger before/after.
- Complete-stage and verified-request delta.
- Accounted memory and launch topology delta.
- Retained rejected experiments, especially fusion variants that increase
  register pressure or lose concurrency.
