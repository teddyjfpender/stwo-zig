//! stwo-cairo-zig: Cairo execution trace prover frontend.
//!
//! Converts authenticated Cairo executions and program-specific semantic
//! artifacts into Rust-oracle-accepted STARK proofs.
//!
//! ## Architecture
//!
//! ```
//! Cairo Program → cairo-vm → raw trace
//!   → authenticated semantic pack
//!   → prover.proveCairo(Backend, RustOracle, request) → ProofReceipt
//! ```
//!
//! ## Submodules
//!
//! - `adapter` — Instruction decoding, opcode classification, memory model
//! - `air` — AIR component constraints (~70 components)
//! - `common` — Felt252, CasmState, Memory, preprocessed tables

pub const adapter = @import("adapter/mod.zig");
pub const air = @import("air/mod.zig");
pub const common = @import("common/mod.zig");
pub const preprocessed = @import("preprocessed/mod.zig");
pub const proving = @import("proving/mod.zig");
pub const proof = @import("proof/mod.zig");
pub const prover = @import("prover.zig");
pub const rust_oracle = @import("rust_oracle.zig");
pub const prove_trace = @import("prove_trace.zig");
pub const proof_plan = @import("proof_plan.zig");
pub const claim_generator = @import("claim_generator.zig");
pub const claim_registry = @import("air/official_claim_registry.zig");
pub const statement = @import("statement/mod.zig");
pub const statement_bootstrap = @import("statement_bootstrap.zig");
pub const compact_protocol_geometry = @import("compact_protocol_geometry.zig");
pub const compact_verifier_interchange = @import("compact_verifier_interchange.zig");
pub const witness_scheduler = @import("witness_scheduler.zig");
pub const staged_arena_planner = @import("staged_arena_planner.zig");
pub const arena_lifetime = @import("arena_lifetime.zig");
pub const witness = @import("witness/mod.zig");
pub const conformance = @import("conformance/mod.zig");
pub const codegen = @import("codegen/mod.zig");

// Convenience re-exports.
pub const Felt252 = common.Felt252;
pub const CasmState = common.CasmState;
pub const ProverInput = adapter.ProverInput;
pub const proveCairo = prover.proveCairo;

test {
    _ = @import("witness/resident_geometry.zig");
    _ = @import("witness/resident_proof.zig");
    _ = @import("witness/resident_types.zig");
    _ = @import("witness/resident_verifier.zig");
}
