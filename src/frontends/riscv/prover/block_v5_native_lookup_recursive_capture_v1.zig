//! Genuine complete six-table borrowed capture; owned clone is independent of
//! the source proof. The seal guards mutations and never replaces verification.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_native_lookup_proof_v1.zig");
const Admission = @import("block_v5_native_lookup_recursive_admission_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const suite = core.proof_suites.Blake3;
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    proof: core.verifier.ProofCapture(suite.Hasher),
    relations: universal.UniversalRelations,
    final_channel: suite.Channel,
    receipt: Native.OpenReceipt,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture, admitted: *const Admission.Prepared) [32]u8 {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42354c43, Admission.VERSION, admitted.index });
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(admitted.template_id);
        channel.mixRoot(self.receipt.sealed_digest);
        channel.mixRoot(self.receipt.plan_id);
        for (self.receipt.roots) |root| channel.mixRoot(root);
        channel.mixFelts(&self.receipt.claims);
        channel.mixFelts(&.{self.receipt.total});
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        var channel = admitted.sealed.sharedChannel();
        const relations = try universal.UniversalRelations.draw(self.allocator, &channel);
        var total = core.fields.qm31.QM31.zero();
        for (self.receipt.claims) |claim| {
            if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim)) return error.InvalidLookupRecursiveCapture;
            total = total.add(claim);
        }
        if (self.proof.commitments.len != 4 or !std.meta.eql(self.proof.commitments[0..2].*, admitted.roots) or
            !std.meta.eql(self.receipt.roots, admitted.roots) or !std.meta.eql(self.receipt.sealed_digest, admitted.sealed.digest) or
            !std.meta.eql(self.receipt.plan_id, try admitted.plan.identity()) or !total.eql(self.receipt.total) or
            !std.meta.eql(self.relations, relations) or !std.meta.eql(self.seal, self.identity(admitted))) return error.InvalidLookupRecursiveCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyBorrowed(a: std.mem.Allocator, received: *const Native.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            var captured = try Native.ForBackend(Backend).verifyCaptureBorrowed(bounded, received, admitted.plan, admitted.roots, admitted.sealed, admitted.pins, admitted.entries);
            errdefer captured.deinit(bounded);
            var channel = admitted.sealed.sharedChannel();
            const relations = try universal.UniversalRelations.draw(bounded, &channel);
            var result = VerifiedCapture{ .allocator = bounded, .budget = budget, .proof = captured.proof, .relations = relations, .final_channel = captured.final_channel, .receipt = captured.receipt, .seal = undefined };
            result.seal = result.identity(admitted);
            return result;
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Native.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            var proof = received;
            defer proof.deinit(a);
            return verifyBorrowed(a, &proof, admitted);
        }
    };
}
