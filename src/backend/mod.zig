//! Backend abstraction layer for stwo-zig.
//!
//! A backend is a zero-sized marker type whose namespace declares
//! implementations for each operation category. The prover is generic
//! over `comptime B: type` — the compiler monomorphizes everything,
//! so backend selection has zero runtime overhead.
//!
//! ## Contract model
//!
//! Every backend has column storage and an explicit `Capabilities` value.
//! Required proof paths additionally validate the typed Merkle contract.
//! Optimizations such as host batch inversion and backend FRI folding are
//! opt-in: claiming them checks their concrete signatures, while not claiming
//! them requires the operation names to be absent. This keeps scaffolding and
//! no-op placeholders out of the production backend identity.
//!
//! ## Usage
//!
//! ```zig
//! const stwo = @import("stwo");
//! const CpuBackend = stwo.backends.CpuBackend;
//!
//! pub fn prove(comptime B: type, comptime H: type, comptime MC: type, ...) !StarkProof(H) {
//!     comptime assertBackendForChannel(B, H);
//!     // ...
//! }
//!
//! // Call site:
//! const proof = try prove(CpuBackend, Blake2sMerkleHasher, Blake2sMerkleChannel, ...);
//! ```

pub const column = @import("column.zig");
pub const capabilities = @import("capabilities.zig");
pub const field_ops = @import("field_ops.zig");
pub const fri_ops = @import("fri_ops.zig");
pub const merkle_ops = @import("merkle_ops.zig");
pub const recovery = @import("recovery.zig");
pub const arena_plan = @import("arena_plan.zig");
pub const line_evaluation = @import("line_evaluation.zig");
pub const resident_storage = @import("resident_storage.zig");
pub const secure_column = @import("secure_column.zig");
pub const proof_program = @import("proof_program.zig");

/// Convenience re-export: backend-specific column type.
pub const Column = column.Column;
pub const Capabilities = capabilities.Set;

/// Validates required storage and every explicitly claimed optional capability.
pub fn assertBackend(comptime B: type) void {
    comptime {
        column.assertColumnOps(B);
        const declared = capabilities.declared(B);
        field_ops.assertCapability(B, declared.host_batch_inverse);
        fri_ops.assertCapability(B, declared.fri_folding, declared.fri_multi_fold);
    }
}

/// Compile-time validation that `B` satisfies the full backend contract
/// including hash-function-specific Merkle operations for `H`.
pub fn assertBackendForChannel(comptime B: type, comptime H: type) void {
    comptime {
        assertBackend(B);
        merkle_ops.assertMerkleOps(B, H);
    }
}

test "api signature: backend accepts a truthful minimum capability set" {
    const MinimumBackend = struct {
        pub const capabilities: Capabilities = .{};

        pub fn ColumnType(comptime F: type) type {
            return []F;
        }
    };
    comptime assertBackend(MinimumBackend);
}

test "backend: contract modules compile" {
    // Smoke test — importing all contract modules triggers comptime validation.
    _ = column;
    _ = capabilities;
    _ = field_ops;
    _ = fri_ops;
    _ = merkle_ops;
    _ = recovery;
    _ = arena_plan;
    _ = line_evaluation;
    _ = resident_storage;
    _ = secure_column;
    _ = proof_program;
    _ = @import("proof_program_native_air_test.zig");
}
