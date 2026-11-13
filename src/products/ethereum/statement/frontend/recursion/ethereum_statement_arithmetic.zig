//! Immutable custody for authenticated statement and public-claim arithmetic.
//! Rows 11 and 15 supply the inputs; shared arithmetic AIR evaluates both DAGs.
const std = @import("std");
const statement = @import("stwo_riscv_recursion").statement_semantics_circuit;
const claim = @import("stwo_riscv_recursion").vm_public_semantics_circuit;
const public_source = @import("stwo_riscv_recursion").segment_public_outer_source;
const lowering = @import("stwo_riscv_rv32").recursion.air.verifier_arithmetic_lowering;

pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 2;

const native = @import("stwo_riscv_frontend").recursion.statement_arithmetic_preparation;

fn Policy(comptime kind: enum { segment, native_roots, initial_inputs }) type {
    return struct {
        pub const IDENTITY_DOMAIN = "stwo-zig/ethereum-statement-arithmetic/v4\x00";
        pub fn rebuild(allocator: std.mem.Allocator, shape: @TypeOf(@as(claim.ClaimReference, undefined).shape)) !claim.ClaimReference {
            return switch (kind) {
                .segment => claim.ClaimReference.initForSegmentV2(allocator, shape, public_source.CLAIM_CIRCUIT_ID),
                .native_roots => claim.ClaimReference.initForEthereumNativeRoots(allocator, shape, public_source.CLAIM_CIRCUIT_ID),
                .initial_inputs => claim.ClaimReference.initForEthereumInitialInputs(allocator, shape, public_source.CLAIM_CIRCUIT_ID),
            };
        }
    };
}

/// Ethereum's fixed claim admission. source() borrows the canonical native
/// capability only after policy reconstruction and deep validation succeed.
pub const Prepared = opaque {
    pub fn init(allocator: std.mem.Allocator, statement_circuit: *const statement.Circuit, statement_evaluation: *const statement.Evaluation, claim_reference: *const claim.ClaimReference, claim_prepared: *const claim.ClaimPrepared) !*Prepared {
        return @ptrCast(try native.ForClaimPolicy(Policy(.segment)).init(allocator, statement_circuit, statement_evaluation, claim_reference, claim_prepared));
    }
    pub fn initForEthereumNativeRoots(allocator: std.mem.Allocator, statement_circuit: *const statement.Circuit, statement_evaluation: *const statement.Evaluation, claim_reference: *const claim.ClaimReference, claim_prepared: *const claim.ClaimPrepared) !*Prepared {
        return @ptrCast(try native.ForClaimPolicy(Policy(.native_roots)).init(allocator, statement_circuit, statement_evaluation, claim_reference, claim_prepared));
    }
    pub fn initForEthereumInitialInputs(allocator: std.mem.Allocator, statement_circuit: *const statement.Circuit, statement_evaluation: *const statement.Evaluation, claim_reference: *const claim.ClaimReference, claim_prepared: *const claim.ClaimPrepared) !*Prepared {
        return @ptrCast(try native.ForClaimPolicy(Policy(.initial_inputs)).init(allocator, statement_circuit, statement_evaluation, claim_reference, claim_prepared));
    }
    pub fn source(self: *const Prepared) *const native.Prepared {
        return @ptrCast(self);
    }
    pub fn deinit(self: *Prepared) void {
        const value: *native.Prepared = @ptrCast(self);
        value.deinit();
    }
    pub fn lanes(self: *const Prepared) [LANE_COUNT]lowering.Lane {
        return self.source().lanes();
    }
    pub fn identity(self: *const Prepared) [32]u8 {
        return self.source().identity();
    }
    pub fn evaluations(self: *const Prepared) [LANE_COUNT]lowering.Evaluation {
        return self.source().evaluations();
    }
};
