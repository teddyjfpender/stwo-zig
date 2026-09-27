//! The original caller verifier owns every immutable capture vector. This
//! wrapper retains the original B5SS prefix before SHA replaces recursion_wire.
const std = @import("std");
const core = @import("stwo_core");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Admission = @import("block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
pub const VerifiedCapture = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    original: Family.VerifiedCapture,
    proof: @FieldType(Family.VerifiedCapture, "proof"), // borrowed view; original owns
    receipt: Family.OpenReceipt,
    relations: Universal.UniversalRelations,
    extension_draws: [28]core.fields.qm31.QM31,
    final_channel: core.proof_suites.Blake3.Channel,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.original.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42354143, 1 });
        channel.mixRoot(self.original.seal);
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        Family.mixBinding(&channel, self.receipt.binding);
        channel.mixFelts(&.{self.receipt.open_sum});
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        channel.mixFelts(&self.extension_draws);
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        try self.original.validate(admitted.allocator, &admitted.statement, admitted.total_steps, admitted.binding, admitted.sealed, admitted.pins, admitted.entries);
        var channel = admitted.sealed.sharedChannel();
        const prefix = try Universal.UniversalRelations.draw(admitted.allocator, &channel);
        if (!std.meta.eql(self.seal, self.identity()) or !std.meta.eql(self.receipt, self.original.receipt) or !std.meta.eql(self.extension_draws, self.original.relations.draws()) or !std.meta.eql(self.relations, prefix) or !std.meta.eql(self.final_channel, self.original.final_channel) or !std.meta.eql(@import("proof_capture_sha256.zig").compute(&self.proof), @import("proof_capture_sha256.zig").compute(&self.original.proof))) return error.InvalidCallerRecursiveCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        fn wrap(admitted: *const Admission.Prepared, budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget, original: Family.VerifiedCapture) !VerifiedCapture {
            var owned = original;
            errdefer owned.deinit();
            var channel = admitted.sealed.sharedChannel();
            var result = VerifiedCapture{ .budget = budget, .original = owned, .proof = owned.proof, .receipt = owned.receipt, .relations = try Universal.UniversalRelations.draw(admitted.allocator, &channel), .extension_draws = owned.relations.draws(), .final_channel = owned.final_channel, .seal = undefined };
            result.seal = result.identity();
            try result.validate(admitted, admitted.template_id);
            return result;
        }
        pub fn verifyBorrowed(a: std.mem.Allocator, proof: *const Family.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            return wrap(admitted, budget, try Family.ForBackend(Backend).verifyCaptureBorrowed(budget.allocator(), proof, &admitted.statement, admitted.total_steps, admitted.binding.caller_key_id, admitted.binding.execution_instance_id, admitted.binding.execution_index, admitted.sealed, admitted.pins, admitted.entries));
        }
        pub fn verifyOwned(a: std.mem.Allocator, proof: Family.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            var received = proof;
            var transferred = false;
            defer if (!transferred) received.deinit(a);
            try admitted.validate(admitted.template_id);
            // Source proof teardown uses its original allocator; the borrowed
            // capture kernel owns independent vectors in the bounded allocator.
            const result = try verifyBorrowed(a, &received, admitted);
            received.deinit(a);
            transferred = true;
            return result;
        }
    };
}
