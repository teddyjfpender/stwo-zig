const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const Program = @import("integrations/riscv_cuda/resident_parent_program_v1.zig");
const PCS = @import("integrations/riscv_cuda/resident_parent_pcs_v1.zig");
const Memory = @import("integrations/riscv_cuda/resident_parent_memory_v1.zig");
const Prover = @import("integrations/riscv_cuda/resident_parent_prover_v1.zig");
// Type-check complete native CUDA schedule without declaring a witness route.
const Unimplemented = struct {
    pub fn requirements(_: *const @This(), a: std.mem.Allocator, _: *const Program.Owned, _: *const PCS.Plans) ![]cuda.runtime.arena.Requirement {
        return a.alloc(cuda.runtime.arena.Requirement, 0);
    }
    pub fn bind(_: *const @This(), _: std.mem.Allocator, _: *cuda.runtime.proof_transaction.ResidentProofTransaction, _: *const Program.Owned, _: *const PCS.Plans, _: *const Memory.Views) !Bound {
        return .{};
    }
    const Bound = struct {
        pub fn deinit(_: *@This(), _: std.mem.Allocator) void {}
        pub fn prime(_: *@This(), _: *cuda.runtime.NativeSession) !void {}
        pub fn witness(_: *@This(), _: *cuda.runtime.NativeSession, _: *const Memory.Views) !void {
            return error.UnimplementedResidentWitness;
        }
        pub fn interactions(_: *@This(), _: *cuda.runtime.NativeSession, _: *const Memory.Views) !void {
            return error.UnimplementedResidentWitness;
        }
        pub fn composition(_: *@This(), _: *cuda.runtime.NativeSession, _: *const Memory.Views) !void {
            return error.UnimplementedResidentWitness;
        }
    };
};
test "resident parent complete CUDA schedule typechecks without CPU fallback" {
    const entry: *const fn (std.mem.Allocator, Prover.For(Unimplemented).Input) anyerror!Prover.Result = &Prover.For(Unimplemented).prove;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
