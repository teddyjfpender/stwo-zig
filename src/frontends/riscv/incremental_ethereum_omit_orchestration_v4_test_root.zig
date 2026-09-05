//! Focused gate for the omitted-provider V4 orchestration and cold verifier.
//!
//! The end-to-end omitted proof needs a backend, an execution trace and a full
//! V4 witness, none of which this package's test lane owns; that arm lives in
//! `test-riscv-ethereum-incremental-omitted-leaf-proof-v1`. What this root
//! runs in seconds is the part a ten-minute product build would otherwise be
//! the first to notice: the admission prologue's refusal order, the projected
//! bridge placement both sides recompute, the exact pre-Tree0 transcript
//! order, and the bindings of the per-shard leaf authority.

comptime {
    _ = @import("prover/incremental_ethereum_omit_orchestration_v4_test.zig");
}
