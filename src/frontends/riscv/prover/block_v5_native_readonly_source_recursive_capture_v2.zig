//! Budget-owned actual B5IN2 verifier capture; public claims stay open to the
//! genuine group provider and native ALL-RW source equations.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Native = @import("block_v5_native_readonly_source_proof_v2.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Admission = @import("block_v5_native_readonly_source_recursive_admission_v2.zig");
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    proof: core.verifier.ProofCapture(suite.Hasher),
    challenges: Global.Challenges,
    final_channel: suite.Channel,
    receipt: Native.OpenProvider,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture, admitted: *const Admission.Prepared) [32]u8 {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ Native.TAG, Native.VERSION, 0x43415054, self.receipt.ordinal, self.receipt.group_id, self.receipt.index });
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(admitted.template_id);
        channel.mixRoot(self.receipt.source_identity);
        channel.mixRoot(self.receipt.epoch.plan_digest);
        channel.mixRoot(self.receipt.epoch.roster_digest);
        channel.mixRoot(self.receipt.sealed_digest);
        inline for (.{ "source_sum", "mutable_sum", "classification_sum", "read_sum" }) |field| channel.mixFelts(&.{@field(self.receipt.claim, field)});
        channel.mixU64(self.receipt.claim.readonly_count);
        channel.mixU64(self.receipt.census.all_rw);
        channel.mixU64(self.receipt.census.mutable);
        channel.mixU64(self.receipt.census.readonly);
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
        if (self.proof.commitments.len != 4 or !std.meta.eql(self.proof.commitments[0..2].*, admitted.roots) or self.receipt.ordinal != admitted.pin.ordinal or
            self.receipt.group_id != admitted.pin.group_id or self.receipt.index != admitted.pin.index or !std.meta.eql(self.receipt.census, admitted.pin.census) or
            self.receipt.claim.readonly_count != admitted.pin.census.readonly or !std.meta.eql(self.receipt.epoch, admitted.authority.epoch()) or
            !std.meta.eql(self.receipt.source_identity, admitted.pin.classifier.source_identity) or !std.meta.eql(self.receipt.sealed_digest, admitted.sealed.digest) or
            !std.meta.eql(self.seal, self.identity(admitted))) return error.InvalidNativeReadonlyV2RecursiveCapture;
        const shared = try Global.draw(self.allocator, admitted.sealed, admitted.authority.epoch());
        if (!std.meta.eql(shared, self.challenges)) return error.InvalidNativeReadonlyV2RecursiveCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyBorrowed(a: std.mem.Allocator, received: *const Native.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            const budget = try Budget.createRetainingParent(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            var actual = try Native.ForBackend(Backend).verifyCaptureBorrowed(bounded, received, admitted.pin, admitted.authority, admitted.sealed, admitted.pins, admitted.entries);
            errdefer actual.deinit(bounded);
            var result = VerifiedCapture{ .allocator = bounded, .budget = budget, .proof = actual.core_capture, .challenges = actual.challenges, .final_channel = actual.final_channel, .receipt = actual.open, .seal = undefined };
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
