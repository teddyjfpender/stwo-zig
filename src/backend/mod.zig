//! Backend abstraction layer for stwo-zig.
//!
//! A backend is a zero-sized marker type whose namespace declares
//! implementations for each operation category. The prover is generic
//! over `comptime B: type` — the compiler monomorphizes everything,
//! so backend selection has zero runtime overhead.
//!
//! ## Supported operation categories
//!
//! | Category | Contract | Concern |
//! |----------|----------|---------|
//! | ColumnOps | `B.ColumnType(F)` | Backend-specific field element storage |
//! | FieldOps | `B.batchInverse(...)` | Batch field arithmetic |
//! | PolyOps | `B.interpolate(...)` / `B.evaluateOnDomain(...)` | Polynomial FFT/eval |
//! | FriOps | `B.foldLine(...)` / `B.foldCircleIntoLine(...)` | FRI folding |
//! | QuotientOps | `B.accumulateQuotients(...)` | Constraint quotients |
//! | AccumulationOps | `B.accumulate(...)` | Domain evaluation accumulation |
//! | GkrOps | `B.genEqEvals(...)` / `B.nextLayer(...)` | GKR circuit proving |
//! | MerkleOps | `B.MerkleTree(H)` / `B.commitMerkle(H, ...)` | Typed Merkle ownership |
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
pub const field_ops = @import("field_ops.zig");
pub const poly_ops = @import("poly_ops.zig");
pub const fri_ops = @import("fri_ops.zig");
pub const quotient_ops = @import("quotient_ops.zig");
pub const accumulation_ops = @import("accumulation_ops.zig");
pub const gkr_ops = @import("gkr_ops.zig");
pub const merkle_ops = @import("merkle_ops.zig");
pub const recovery = @import("recovery.zig");
pub const arena_plan = @import("arena_plan.zig");
pub const line_evaluation = @import("line_evaluation.zig");
pub const resident_storage = @import("resident_storage.zig");
pub const secure_column = @import("secure_column.zig");
pub const proof_program = @import("proof_program.zig");

/// Convenience re-export: backend-specific column type.
pub const Column = column.Column;

/// Compile-time validation that `B` satisfies the full prover backend contract
/// (all ops except hash-specific Merkle).
pub fn assertBackend(comptime B: type) void {
    comptime {
        column.assertColumnOps(B);
        field_ops.assertFieldOps(B);
        poly_ops.assertPolyOps(B);
        fri_ops.assertFriOps(B);
        quotient_ops.assertQuotientOps(B);
        accumulation_ops.assertAccumulationOps(B);
        gkr_ops.assertGkrOps(B);
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

test "backend: contract modules compile" {
    // Smoke test — importing all contract modules triggers comptime validation.
    _ = column;
    _ = field_ops;
    _ = poly_ops;
    _ = fri_ops;
    _ = quotient_ops;
    _ = accumulation_ops;
    _ = gkr_ops;
    _ = merkle_ops;
    _ = recovery;
    _ = arena_plan;
    _ = line_evaluation;
    _ = resident_storage;
    _ = secure_column;
    _ = proof_program;
}
