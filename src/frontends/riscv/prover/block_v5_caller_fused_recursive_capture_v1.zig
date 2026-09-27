//! State-compatible capture owned by the original B5CF verifier. Fresh caller
//! arithmetic is required at capture entry; the fused recursive leaf is open.
const std = @import("std");
const core = @import("stwo_core");
const Admission = @import("block_v5_caller_fused_recursive_admission_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Fused = Admission.Fused;
const Universal = @import("../recursion/air/universal_challenges.zig");
pub const VerifiedCapture = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    original: Fused.VerifiedCapture,
    proof: @FieldType(Fused.VerifiedCapture, "proof"), // borrowed; original owns
    relations: Universal.UniversalRelations,
    word_challenges: @import("block_v5_word_memory_protocol_v1.zig").Challenges,
    final_channel: core.proof_suites.Blake3.Channel,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.original.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42355843, 1 });
        channel.mixRoot(self.original.seal);
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |name| {
            const element = @field(self.word_challenges, name);
            channel.mixFelts(&.{ element.z, element.alpha });
        }
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        try self.original.validateAgainstBinding(admitted.allocator, admitted.binding, &admitted.statement, admitted.total_steps, admitted.frame, admitted.witness_root, admitted.sealed, admitted.pins, admitted.entries);
        var channel = admitted.sealed.sharedChannel();
        const prefix = try Universal.UniversalRelations.draw(admitted.allocator, &channel);
        if (!std.meta.eql(self.relations, prefix) or !std.meta.eql(self.word_challenges, self.original.word) or !std.meta.eql(self.final_channel, self.original.final_channel) or !std.meta.eql(self.seal, self.identity()) or !std.meta.eql(@import("proof_capture_sha256.zig").compute(&self.proof), @import("proof_capture_sha256.zig").compute(&self.original.proof))) return error.InvalidCallerFusedRecursiveCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyAfterFreshCaller(a: std.mem.Allocator, proof: *const Fused.Proof, fresh: *const Family.OpenReceipt, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            if (!std.meta.eql(fresh.binding, admitted.binding)) return error.UntrustedCallerFusedRecursiveBinding;
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            var original = try Fused.ForBackend(Backend).verifyCaptureBorrowedAfterFreshCaller(budget.allocator(), proof, fresh, &admitted.statement, admitted.total_steps, admitted.frame, admitted.witness_root, admitted.sealed, admitted.pins, admitted.entries);
            errdefer original.deinit();
            var channel = admitted.sealed.sharedChannel();
            var result = VerifiedCapture{ .budget = budget, .original = original, .proof = original.proof, .relations = try Universal.UniversalRelations.draw(a, &channel), .word_challenges = original.word, .final_channel = original.final_channel, .seal = undefined };
            result.seal = result.identity();
            try result.validate(admitted, admitted.template_id);
            return result;
        }
    };
}
