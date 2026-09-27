//! Budget-owned original48 provider capture; range and source joins stay open.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Admission = @import("block_v5_readonly_provider_recursive_admission_v2.zig");
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    proof: core.verifier.ProofCapture(suite.Hasher),
    challenges: Global.Challenges,
    final_channel: suite.Channel,
    receipt: Provider.OpenRange,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture, admitted: *const Admission.Prepared) [32]u8 {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ Provider.TAG, Provider.VERSION, 0x43415054, self.receipt.pin.shape.index, self.receipt.pin.shape.group_id });
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(admitted.template_id);
        channel.mixRoot(self.receipt.epoch.plan_digest);
        channel.mixRoot(self.receipt.epoch.roster_digest);
        channel.mixRoot(self.receipt.sealed_digest);
        channel.mixRoot(self.receipt.pin.ordinal_digest);
        for (self.receipt.pin.roots) |root| channel.mixRoot(root);
        channel.mixFelts(&.{ self.receipt.claim.classification_sum, self.receipt.claim.read_sum });
        channel.mixFelts(&self.receipt.claim.range_sums);
        channel.mixU64(self.receipt.claim.counts.events);
        channel.mixU64(self.receipt.claim.counts.readonly);
        channel.mixU64(self.receipt.claim.counts.range_requests);
        for (self.challenges.word.universal_prefix.elements) |value| channel.mixFelts(&.{ value.z, value.alpha });
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |field| {
            const value = @field(self.challenges.word, field);
            channel.mixFelts(&.{ value.z, value.alpha });
        }
        inline for (.{ "classification", "read" }) |field| {
            const value = @field(self.challenges, field);
            channel.mixFelts(&.{ value.z, value.alpha });
        }
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        try Provider.requireClaim(admitted.pin, self.receipt.claim);
        if (self.proof.commitments.len != 4 or !std.meta.eql(self.proof.commitments[0..2].*, admitted.roots) or
            !std.meta.eql(self.receipt.pin, admitted.pin) or !std.meta.eql(self.receipt.epoch, admitted.authority.epoch()) or
            !std.meta.eql(self.receipt.sealed_digest, admitted.sealed.digest) or !std.meta.eql(self.seal, self.identity(admitted))) return error.InvalidReadonlyProviderRecursiveCapture;
        const shared = try Global.draw(self.allocator, admitted.sealed, admitted.authority.epoch());
        if (!std.meta.eql(shared, self.challenges)) return error.InvalidProviderReadonlyV2RecursiveCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyBorrowed(a: std.mem.Allocator, received: *const Provider.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            const budget = try Budget.createRetainingParent(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            var actual = try Provider.ForBackend(Backend).verifyCaptureBorrowed(bounded, received, admitted.pin, admitted.ordinals, admitted.authority, admitted.sealed, admitted.pins, admitted.entries, admitted.limits.table);
            errdefer actual.deinit(bounded);
            var result = VerifiedCapture{ .allocator = bounded, .budget = budget, .proof = actual.core_capture, .challenges = actual.challenges, .final_channel = actual.final_channel, .receipt = actual.open, .seal = undefined };
            result.seal = result.identity(admitted);
            return result;
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Provider.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            var proof = received;
            defer proof.deinit(a);
            return verifyBorrowed(a, &proof, admitted);
        }
    };
}
