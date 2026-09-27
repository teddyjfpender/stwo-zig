//! State-compatible capture owned by the original B5IC verifier. Fresh caller
//! arithmetic is required at capture entry; the fused recursive leaf is open.
const std = @import("std");
const core = @import("stwo_core");
const Admission = @import("block_v5_caller_readonly_global_recursive_admission_v2.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Fused = Admission.Fused;
const Universal = @import("../recursion/air/universal_challenges.zig");
pub const VerifiedCapture = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    original: Fused.VerifiedCapture,
    proof: @FieldType(Fused.VerifiedCapture, "proof"), // borrowed; original owns
    relations: Universal.UniversalRelations,
    shared_classification: @import("block_v5_readonly_input_global_protocol_v2.zig").Challenges,
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
        channel.mixU32s(&.{ 0x42354a43, 2 });
        channel.mixRoot(self.original.seal);
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |name| {
            const element = @field(self.word_challenges, name);
            channel.mixFelts(&.{ element.z, element.alpha });
        }
        channel.mixFelts(&.{ self.shared_classification.classification.z, self.shared_classification.classification.alpha, self.shared_classification.read.z, self.shared_classification.read.alpha });
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        try self.original.validateAgainstBinding(admitted.allocator, admitted.binding, &admitted.statement, admitted.total_steps, admitted.frame, admitted.witness_root, admitted.sealed, admitted.pins, admitted.entries, admitted.readonly);
        var channel = admitted.sealed.sharedChannel();
        const prefix = try Universal.UniversalRelations.draw(admitted.allocator, &channel);
        const global = @import("block_v5_readonly_input_global_protocol_v2.zig");
        const shared = try global.draw(admitted.allocator, admitted.sealed, admitted.readonly.roster.epoch());
        if (!std.meta.eql(shared, self.shared_classification) or !std.meta.eql(try global.forGroup(shared, admitted.readonly.group_id), self.original.classification)) return error.InvalidGlobalCallerReadonlyChallenges;
        if (!std.meta.eql(self.relations, prefix) or !std.meta.eql(self.word_challenges, self.original.word) or !std.meta.eql(self.final_channel, self.original.final_channel) or !std.meta.eql(self.seal, self.identity()) or !std.meta.eql(@import("proof_capture_sha256.zig").compute(&self.proof), @import("proof_capture_sha256.zig").compute(&self.original.proof))) return error.InvalidCallerReadonlyRecursiveCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyAfterFreshCaller(a: std.mem.Allocator, proof: *const Fused.Proof, fresh: *const Family.OpenReceipt, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            if (!std.meta.eql(fresh.binding, admitted.binding)) return error.UntrustedCallerReadonlyRecursiveBinding;
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            var original = try Fused.ForBackend(Backend).verifyCaptureBorrowedAfterFreshCaller(budget.allocator(), proof, fresh, &admitted.statement, admitted.total_steps, admitted.frame, admitted.witness_root, admitted.sealed, admitted.pins, admitted.entries, admitted.readonly);
            errdefer original.deinit();
            var channel = admitted.sealed.sharedChannel();
            var result = VerifiedCapture{ .budget = budget, .original = original, .proof = original.proof, .relations = try Universal.UniversalRelations.draw(a, &channel), .shared_classification = try @import("block_v5_readonly_input_global_protocol_v2.zig").draw(a, admitted.sealed, admitted.readonly.roster.epoch()), .word_challenges = original.word, .final_channel = original.final_channel, .seal = undefined };
            result.seal = result.identity();
            try result.validate(admitted, admitted.template_id);
            return result;
        }
    };
}
