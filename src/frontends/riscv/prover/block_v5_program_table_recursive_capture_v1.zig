//! Actual borrowed complete-ROM verifier; seal guards mutations, not authority.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_program_table_proof_v1.zig");
const Admission = @import("block_v5_program_table_recursive_admission_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const suite = core.proof_suites.Blake3;
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    proof: core.verifier.ProofCapture(suite.Hasher),
    relations: universal.UniversalRelations,
    final_channel: suite.Channel,
    receipt: Native.VerifiedReceipt,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture, admitted: *const Admission.Prepared) [32]u8 {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42355043, Admission.VERSION, admitted.index, admitted.plan.log_size });
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(admitted.template_id);
        channel.mixRoot(admitted.sealed.digest);
        channel.mixRoot(self.receipt.program_root.bytes);
        channel.mixRoot(self.receipt.plan_digest);
        channel.mixRoot(self.receipt.sealed_channel_digest);
        for (self.receipt.first_roots) |root| channel.mixRoot(root);
        channel.mixU64(self.receipt.fetch_count);
        channel.mixFelts(&.{self.receipt.claim});
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        var channel = admitted.sealed.programSeal().sharedChannel();
        const digest = channel.digestBytes();
        const relations = try universal.UniversalRelations.draw(self.allocator, &channel);
        if (self.proof.commitments.len != 4 or !std.meta.eql(self.proof.commitments[0..2].*, admitted.roots) or !std.meta.eql(self.receipt.first_roots, admitted.roots) or !std.meta.eql(self.receipt.program_root, admitted.plan.program_root) or !std.meta.eql(self.receipt.plan_digest, admitted.sealed.program_plan_digest) or !std.meta.eql(self.receipt.sealed_channel_digest, digest) or self.receipt.fetch_count != admitted.plan.expected_fetches or !@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&self.receipt.claim) or !std.meta.eql(relations, self.relations) or !std.meta.eql(self.seal, self.identity(admitted))) return error.InvalidProgramRecursiveCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyBorrowed(a: std.mem.Allocator, received: *const Native.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&received.claim)) return error.InvalidProgramTableClaim;
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            var captured = try Native.ForBackend(Backend).verifyCaptureBorrowed(bounded, received, admitted.plan, admitted.sealed.programSeal(), admitted.plan.program_root, admitted.roots, admitted.config);
            errdefer captured.deinit(bounded);
            var channel = admitted.sealed.programSeal().sharedChannel();
            const relations = try universal.UniversalRelations.draw(bounded, &channel);
            var result = VerifiedCapture{ .allocator = bounded, .budget = budget, .proof = captured.proof, .relations = relations, .final_channel = captured.final_channel, .receipt = captured.receipt, .seal = undefined };
            result.seal = result.identity(admitted);
            return result;
        }
    };
}
