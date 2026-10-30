//! Bounded shared Keccak original STARK. This authenticates open accounting;
//! native-window, ROM, global table and RAM closure remain mandatory afterward.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Suite = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Source = @import("block_v7_keccak_batch_source_v1.zig");
const Native = @import("block_v7_native_source_v1.zig");
const Geometry = @import("block_v7_keccak_batch_geometry_v1.zig");
const Air = @import("block_v7_keccak_batch_air_v1.zig");
pub const Claims = @import("block_v7_keccak_batch_claims_v1.zig").Claims;
pub const Limits = @import("block_v7_keccak_batch_stage_v1.zig").Limits;
pub const Proof = struct {
    stark: Suite.Proof,
    claims: Claims,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.claims.controls);
        self.* = undefined;
    }
};
pub const Timings = struct { interaction_ns: u64 = 0, commit_ns: u64 = 0, prove_ns: u64 = 0 };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Stage = @import("block_v7_keccak_batch_stage_v1.zig").For(Backend);
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, Suite.Hasher, Suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(Suite.Hasher, Suite.MerkleChannel);
        pub const Prepared = @import("block_v7_keccak_batch_preparation_v1.zig").ForBackend(Backend);
        pub fn prove(a: std.mem.Allocator, stage: *Stage, natives: []const Native.Pin, epoch: E.Epoch, entries: []const E.Entry, pool: *engine.work_pool.WorkPool, timings: ?*Timings) !Proof {
            var timer = try std.time.Timer.start();
            const prepared = try Prepared.init(a, stage, natives, epoch, entries, pool);
            defer prepared.deinit();
            const claims = try prepared.cloneClaims(a);
            errdefer a.free(claims.controls);
            var ch = prepared.channel;
            if (timings) |t| t.interaction_ns = timer.lap();
            try stage.scheme.commitBorrowedStreaming(a, prepared.arithmetic_columns, 8, &ch);
            try stage.scheme.commitBorrowedStreaming(a, prepared.relation_columns, 8, &ch);
            if (timings) |t| t.commit_ns = timer.lap();
            stage.owns_scheme = false;
            const stark = try engine.prove.prove(Backend, Suite.Hasher, Suite.MerkleChannel, a, &.{prepared.owner.joint.asProverComponent()}, &ch, stage.scheme);
            if (timings) |t| t.prove_ns = timer.lap();
            return .{ .stark = stark, .claims = claims };
        }
        pub fn verify(a: std.mem.Allocator, proof: *const Proof, pin: Source.Pin, natives: []const Native.Pin, epoch: E.Epoch, entries: []const E.Entry, limits: Limits) !@import("block_v7_keccak_batch_closure_v1.zig").Open {
            const entry = try pin.require(a, natives, epoch, entries, limits.owners);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 6 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, epoch.config) or !std.meta.eql(roots[0..3].*, pin.roots ++ .{pin.access_root})) return error.UntrustedKeccakBatchProof;
            var geometry = try Geometry.Owned.init(a, pin, limits.owners);
            defer geometry.deinit();
            try requireFixedRoot(a, pin, &geometry);
            const drawn = try Source.draw(a, epoch, entry);
            var ch = drawn.channel;
            try proof.claims.record(pin, entry, &ch);
            const owner = try Air.Owner(false).init(a, pin, &geometry, &drawn, &proof.claims);
            defer owner.deinit();
            var verifier = try Verifier.init(a, epoch.config);
            defer verifier.deinit(a);
            var discarded = Suite.Channel{};
            for (0..3) |i| try verifier.commit(a, roots[i], geometry.logs[i], &discarded);
            for (3..5) |i| try verifier.commit(a, roots[i], geometry.logs[i], &ch);
            var capture: core.verifier.ProofCapture(Suite.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(Suite.Hasher, Suite.MerkleChannel, a, &.{owner.joint.asVerifierComponent()}, &ch, &verifier, &proof.stark, &capture);
            defer capture.deinit(a);
            return proof.claims.open(pin, owner.lookup.slots);
        }
        pub fn requireFixedRoot(a: std.mem.Allocator, pin: Source.Pin, geometry: *const Geometry.Owned) !void {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const fixed = try geometry.fixed(arena.allocator());
            var scheme = try Scheme.init(a, pin.config);
            defer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            var ch = Suite.Channel{};
            try scheme.commitBorrowedStreaming(a, fixed, 8, &ch);
            if (!std.meta.eql(scheme.trees.items[0].commitment.root(), pin.roots[0])) return error.UntrustedKeccakBatchFixedRoot;
        }
    };
}
