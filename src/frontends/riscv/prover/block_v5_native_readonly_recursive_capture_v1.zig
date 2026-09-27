//! Owned original verifier capture; borrowed/consuming source-proof variants
//! share exactly the same fixed-root, component, provider and FRI verification.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_readonly_input_proof_v1.zig");
const Protocol = @import("block_v5_readonly_input_protocol_v1.zig");
const Admission = @import("block_v5_native_readonly_recursive_admission_v1.zig");
const suite = core.proof_suites.Blake3;
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    proof: core.verifier.ProofCapture(suite.Hasher),
    challenges: Protocol.Challenges,
    final_channel: suite.Channel,
    receipt: Native.Open,
    counters: []u64,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.allocator.free(self.counters);
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture, admitted: *const Admission.Prepared) [32]u8 {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42354956, Admission.VERSION });
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(admitted.template_id);
        channel.mixRoot(self.receipt.sealed_digest);
        channel.mixRoot(self.receipt.plan_digest);
        channel.mixRoot(self.receipt.source_identity);
        inline for (.{ "source_sum", "mutable_sum", "classification_sum", "read_sum" }) |field| channel.mixFelts(&.{@field(self.receipt.claim, field)});
        channel.mixU64(self.receipt.claim.readonly_count);
        channel.mixU64(self.receipt.mutable_events);
        channel.mixU64(self.counters.len);
        for (self.counters) |counter| channel.mixU64(counter);
        for (self.challenges.word.universal_prefix.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |field| {
            const element = @field(self.challenges.word, field);
            channel.mixFelts(&.{ element.z, element.alpha });
        }
        inline for (.{ "classification", "read" }) |field| {
            const element = @field(self.challenges, field);
            channel.mixFelts(&.{ element.z, element.alpha });
        }
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        if (self.proof.commitments.len != 4 or !std.meta.eql(self.proof.commitments[0..2].*, admitted.roots) or !std.meta.eql(self.receipt.sealed_digest, admitted.sealed.digest) or !std.meta.eql(self.receipt.plan_digest, admitted.plan.digest) or !std.meta.eql(self.receipt.source_identity, admitted.pin.source_identity) or self.receipt.mutable_events != admitted.policy.native[admitted.index].census.mutable or self.receipt.claim.readonly_count != admitted.policy.native[admitted.index].census.readonly or !std.meta.eql(self.seal, self.identity(admitted))) return error.InvalidNativeReadonlyRecursiveCapture;
        const challenges = try Protocol.Challenges.draw(self.allocator, admitted.sealed, admitted.plan.digest, admitted.pin.source_identity, admitted.roots);
        if (!std.meta.eql(self.challenges, challenges)) return error.InvalidNativeReadonlyRecursiveCapture;
        try Native.checkProviders(admitted.plan, admitted.pin, self.receipt.claim, self.counters, &challenges);
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyBorrowed(a: std.mem.Allocator, received: *const Native.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            var actual = try Native.ForBackend(Backend).verifyCaptureBorrowed(bounded, received, admitted.pin, admitted.plan, admitted.sealed, admitted.pins, admitted.entries);
            errdefer actual.deinit(bounded);
            if (actual.receipt.mutable_events != admitted.policy.native[admitted.index].census.mutable or actual.receipt.claim.readonly_count != admitted.policy.native[admitted.index].census.readonly) return error.StaleReadonlyInputCensus;
            var result = VerifiedCapture{ .allocator = bounded, .budget = budget, .proof = actual.core_capture, .challenges = actual.challenges, .final_channel = actual.final_channel, .receipt = actual.receipt, .counters = actual.counters, .seal = undefined };
            result.seal = result.identity(admitted);
            return result;
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Native.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            var original = received;
            defer original.deinit(a);
            return verifyBorrowed(a, &original, admitted);
        }
    };
}
