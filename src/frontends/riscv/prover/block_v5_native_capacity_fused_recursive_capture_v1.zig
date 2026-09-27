//! Owning recursive view of the genuine original B5CF verifier capture.
//! Every scalar/PCS value comes from the shared fresh verifier kernel. The
//! native binding remains an open companion-child obligation, not authority.
const std = @import("std");
const core = @import("stwo_core");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Admission = @import("block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Universal = @import("../recursion/air/universal_challenges.zig");
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    proof: core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher),
    metadata: Fused.CaptureMetadata,
    word_challenges: Word.Challenges,
    challenges: Bus.Challenges,
    relations: Universal.UniversalRelations,
    final_channel: core.proof_suites.Blake3.Channel,
    receipt: Fused.Verified,
    seal: [32]u8,
    fn take(capture: Fused.VerifiedCapture, budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget) VerifiedCapture {
        return .{ .allocator = capture.allocator, .budget = budget, .proof = capture.proof, .metadata = capture.metadata, .word_challenges = capture.word_challenges, .challenges = capture.challenges, .relations = capture.word_challenges.universal_prefix, .final_channel = capture.final_channel, .receipt = capture.verified, .seal = capture.seal };
    }
    /// Borrowed non-owning view; never deinitialize this temporary.
    pub fn original(self: *const VerifiedCapture) Fused.VerifiedCapture {
        return .{ .allocator = self.allocator, .proof = self.proof, .metadata = self.metadata, .word_challenges = self.word_challenges, .challenges = self.challenges, .final_channel = self.final_channel, .verified = self.receipt, .seal = self.seal };
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        if (!std.meta.eql(self.relations, self.word_challenges.universal_prefix)) return error.InvalidCapacityFusedRecursiveChallenges;
        const view = self.original();
        try view.validate(admitted.policy());
    }
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.receipt.deinit(self.allocator);
        self.metadata.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyOwned(a: std.mem.Allocator, received: Fused.Proof, admitted: *const Admission.Prepared, expected: [32]u8) !VerifiedCapture {
            var owned = received;
            // The received proof belongs to a, while captures belong to the
            // nested budget. Borrow the one original verifier kernel and free
            // the input through its real allocator on both success and error.
            defer owned.deinit(a);
            return verifyBorrowed(a, &owned, admitted, expected);
        }
        pub fn verifyBorrowed(a: std.mem.Allocator, received: *const Fused.Proof, admitted: *const Admission.Prepared, expected: [32]u8) !VerifiedCapture {
            try admitted.validate(expected);
            const policy = admitted.policy();
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            return VerifiedCapture.take(try Fused.ForBackend(Backend).verifyCaptureBorrowed(budget.allocator(), received, policy.sealed, policy.pins, policy.entries, policy.native, policy.index, policy.frame, policy.projections, policy.slots, policy.fixed_logs, policy.main_logs, policy.witness_root, policy.empty_entry, policy.shape, policy.external_retirements, policy.limits), budget);
        }
    };
}
