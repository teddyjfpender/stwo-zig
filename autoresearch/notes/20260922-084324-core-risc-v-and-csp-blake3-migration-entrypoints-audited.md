---
title: Core RISC-V and CSP BLAKE3 migration entrypoints audited
author: Teddy Pender
created_utc: 2026-09-22T08:43:24Z
---

# Core/RISC-V/CSP BLAKE3 migration entrypoints

User scope explicitly includes core commitments/transcripts, ordinary RISC-V,
guest-precompile/CSP proofs and CPU/Metal. This audit is local source evidence,
not a performance result or completed default switch.

- src/frontends/riscv/prover/types.zig chooses BLAKE2s Hasher/MerkleChannel/Channel.
  src/integrations/riscv_cpu/mod.zig builds CpuProverEngine from that frontend.
- src/integrations/riscv_metal/mod.zig selects backend MetalProverEngine and checks
  frontend engine compatibility. Migration must update both selections together.
- src/frontends/riscv/recursion/engine_protocol.zig selects Poseidon2 separately.
  Experimental blake3_engine_protocol.zig already supplies the new native suite.
- guest_precompile/proof_artifact_header.zig has explicit hasher IDs 1 (BLAKE2s)
  and 2 (Poseidon2), selected by format version. BLAKE3 needs a new admitted ID
  and format mapping; equal 32-byte digest sizes do not permit type substitution.
- guest_precompile/proof_artifact.zig currently exports format_version=1 and
  blake2s_merkle_hasher_v1. Ordinary/guest artifact codecs and fresh-process
  verification must migrate with engine types, not after changing defaults.
- proof_adapter/transcript_state.zig receiptDigest accepts a u32 draw count and
  uses a BLAKE2s structural receipt; BLAKE3 channels use u64 counters. Receipt
  format, benchmark JSON fields and validations must be explicitly updated.
- scripts/riscv_csp_benchmark_lib selects canonical CSP workloads including a
  guest Poseidon workload. Preserve that workload and guest precompile semantics;
  change prover hashing, then rerun CPU/Metal at 70 queries and 26 PoW bits.
- src/backends/metal/merkle_tree.zig, hash_domain.zig, recipes/merkle.zig and
  shaders/include/merkle.metal own device hash selection/dispatch. Require
  positive BLAKE3 device dispatch evidence, not an implicit host fallback.

Core BLAKE3 primitives/PCS tests already exist. Production suite admission,
versioned artifacts, default selection, device implementation and full-profile
performance are remaining implementation work. Native Poseidon-to-BLAKE3 hash
microbenchmark ratios do not predict ordinary BLAKE2s-to-BLAKE3 CSP speedups.
