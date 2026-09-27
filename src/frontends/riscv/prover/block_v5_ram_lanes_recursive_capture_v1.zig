//! Real original lane proof verifier capture, not a host receipt adapter.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Lane = @import("block_v5_ram_lanes_proof_v1.zig");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
const Component = @import("block_v5_ram_lanes_component_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Admission = @import("block_v5_ram_lanes_recursive_admission_v1.zig");
const suite = core.proof_suites.Blake3;
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    budget: *engine.host_budget_allocator.SharedHostBudget,
    proof: core.verifier.ProofCapture(suite.Hasher),
    challenges: Protocol.Challenges,
    final_channel: suite.Channel,
    receipt: Lane.OpenReceipt,
    seal: [32]u8,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture, admitted: *const Admission.Prepared) ![32]u8 {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42354c43, Admission.VERSION }); // B5LC
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(admitted.template_id);
        channel.mixRoot(try self.receipt.pin.identity());
        channel.mixRoot(self.receipt.sealed_digest);
        Lane.mixClaims(&channel, self.receipt.sums);
        for (self.challenges.universal_prefix.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |field| {
            const element = @field(self.challenges, field);
            channel.mixFelts(&.{ element.z, element.alpha });
        }
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, admitted: *const Admission.Prepared, expected: [32]u8) !void {
        try admitted.validate(expected);
        _ = try Interaction.normalize(self.receipt.sums, admitted.pin.claim);
        if (self.proof.commitments.len != 4 or !std.meta.eql(self.proof.commitments[0..2].*, admitted.roots) or
            !std.meta.eql(self.receipt.pin, admitted.pin) or !std.meta.eql(self.receipt.sealed_digest, admitted.sealed.digest) or
            self.receipt.sums.range_count != admitted.pin.request_count or
            !std.meta.eql(self.seal, try self.identity(admitted))) return error.InvalidRamRecursiveCapture;
        const actual = try Protocol.Challenges.draw(self.allocator, admitted.sealed);
        if (!std.meta.eql(self.challenges, actual)) return error.InvalidRamRecursiveCapture;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn verifyBorrowed(a: std.mem.Allocator, received: *const Lane.Proof, admitted: *const Admission.Prepared) !VerifiedCapture {
            try admitted.validate(admitted.template_id);
            _ = try Interaction.normalize(received.claim, admitted.pin.claim);
            if (received.claim.range_count != admitted.pin.request_count) return error.UntrustedV5RamLanesRangeCensus;
            const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_capture_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            var fixed = try Trace.FixedTrace.init(bounded, admitted.pin.claim, admitted.limits.proof.max_fixed_bytes);
            defer fixed.deinit();
            const challenges = try Protocol.Challenges.draw(bounded, admitted.sealed);
            const Api = @import("block_v5_word_pcs_v1.zig").For(Backend, Component.Spec);
            var columns: [Component.Spec.FIXED_COUNT]@import("block_v5_word_pcs_v1.zig").Column = undefined;
            for (&columns, 0..) |*column, i| column.* = .{ .log_size = admitted.pin.claim.row_log, .values = fixed.column(i) };
            const spec = Component.Spec{ .claim = admitted.pin.claim, .interaction_claim = received.claim, .challenges = &challenges };
            var captured = try Api.verifyCaptureBorrowed(bounded, &received.stark, spec, admitted.pin.claim.row_log, &columns, admitted.roots, admitted.config, Lane.firstChannel(admitted.pin.claim, admitted.pin.index, admitted.config), try Lane.proofChannel(bounded, admitted.sealed, admitted.pin, received.claim));
            errdefer captured.deinit(bounded);
            var result = VerifiedCapture{ .allocator = bounded, .budget = budget, .proof = captured.proof, .challenges = challenges, .final_channel = captured.final_channel, .receipt = .{ .pin = admitted.pin, .sums = received.claim, .sealed_digest = admitted.sealed.digest }, .seal = undefined };
            result.seal = try result.identity(admitted);
            return result;
        }
    };
}
