//! Original arithmetic and all caller relations in one genuine v7 STARK.
//! Three first roots are committed in the whole epoch before shared challenges;
//! all physical claims precede both interaction roots. Global claims are open.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Suite = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Source = @import("block_v7_caller_joint_source_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
const Components = @import("block_v6_caller_joint_components_v1.zig");
const Interaction = @import("block_v6_caller_joint_interaction_v1.zig");
pub const Pin = Source.Pin;
pub const Exports = Source.Exports;
// Storage shape only; the v7 source and transcript are explicitly distinct.
pub const Proof = @import("block_v6_caller_joint_proof_v1.zig").Proof;
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(Suite.Hasher),
    arithmetic: Profile.ExtensionClaim,
    claims: Fused.ClaimFrames,
    final_channel: Suite.Channel,
    receipt: Exports,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.claims.deinit(self.allocator);
        self.* = undefined;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, Suite.Hasher, Suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(Suite.Hasher, Suite.MerkleChannel);
        pub const Physical = Family.ForBackend(Backend).PhysicalFirstRound;
        pub const First = External.ForPackedBackend(Backend).FirstRound;
        pub fn prove(a: std.mem.Allocator, first: *First, physical: *Physical, inputs: []const External.Input, pin: Pin, epoch: E.Epoch, entries: []const E.Entry, pool: *engine.work_pool.WorkPool) !Proof {
            const entry = try pin.require(a, epoch, entries);
            if (!first.owns_scheme or !physical.owns_scheme or first.scheme.trees.items.len != 3 or physical.scheme.trees.items.len != 2 or
                !std.meta.eql(physical.witness.statement, pin.statement.*) or physical.total_steps != pin.total_steps or
                !std.meta.eql(physical.config, epoch.config) or !std.meta.eql(first.scheme.config, epoch.config) or !std.meta.eql(physical.roots, pin.roots) or
                !std.meta.eql(physical.key_id, try Protocol.keyId(pin.statement, pin.total_steps, pin.config, pin.roots[0]))) return error.InvalidV7CallerPhase;
            var roots = try first.scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 3 or !std.meta.eql(roots.items[0..3].*, pin.roots ++ .{pin.access_root})) return error.UntrustedV7CallerFirst;
            for (0..2) |tree| {
                const original = physical.scheme.trees.items[tree].columns;
                const leased = first.scheme.trees.items[tree].columns;
                if (original.len != leased.len) return error.UnsharedV7CallerFirst;
                for (original, leased) |left, right| if (left.values.ptr != right.values.ptr or left.values.len != right.values.len or left.log_size != right.log_size) return error.UnsharedV7CallerFirst;
            }
            var schedule = try Schedule.init(a, pin.statement, pin.total_steps, pin.frame, 1);
            defer schedule.deinit();
            if (!std.mem.eql(u32, first.fixed_logs, schedule.fixed) or !std.mem.eql(u32, first.main_logs, schedule.main)) return error.InvalidV7CallerFirstGeometry;
            const ranges = try schedule.projectionRanges();
            defer a.free(ranges);
            var columns = try Selected.Columns.init(a, &physical.scheme, schedule.fixed, schedule.main, ranges);
            defer columns.deinit(a);
            const drawn = try Source.draw(a, epoch, entry);
            var arithmetic = try Profile.interactions(a, physical.witness, &drawn.relations, pool);
            defer arithmetic.deinit(a);
            var fused = try Interaction.generate(a, &columns, &schedule, inputs, first.snapshots, &drawn.relations, &drawn.epoch.word);
            defer fused.deinit(a);
            var ch = try Source.channel(&drawn, pin, entry, &schedule, &arithmetic.claim, &fused.claims);
            const arithmetic_owner = try Profile.Assembly(.prover).createBlockV5Standalone(a, pin.statement, pin.total_steps, &drawn.relations, &arithmetic.claim);
            defer arithmetic_owner.destroy(a);
            const logs = try schedule.interactionLogs();
            defer a.free(logs);
            const access_logs = try schedule.witnessLogs();
            defer a.free(access_logs);
            const arithmetic_logs = try Protocol.columnLogs(a, pin.statement, .interaction);
            defer a.free(arithmetic_logs);
            var fused_owner = try Fused.Components.init(a, &schedule, &fused.claims, &drawn.relations, &drawn.epoch.bytes, &drawn.epoch.word, logs, access_logs, 1);
            defer fused_owner.deinit();
            const handles = try a.alloc(engine.air.component_prover.ComponentProver, fused_owner.memory.len + fused_owner.program.len + fused_owner.tables.len);
            defer a.free(handles);
            var at: usize = 0;
            inline for (.{ fused_owner.memory, fused_owner.program, fused_owner.tables }) |partition| for (partition) |*component| {
                handles[at] = component.asProverComponent();
                at += 1;
            };
            const joint = try Components.Owner(true).create(a, arithmetic_owner.active(), handles, .{ schedule.fixed, schedule.main, access_logs, arithmetic_logs, logs }, fused_owner.memory.len);
            defer joint.destroy();
            try first.scheme.commitBorrowedStreaming(a, arithmetic.columns, 8, &ch);
            try first.scheme.commitBorrowedStreaming(a, fused.columns, 8, &ch);
            const claims = try Fused.ClaimFrames.clone(a, &fused.claims);
            errdefer {
                var owned = claims;
                owned.deinit(a);
            }
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, Suite.Hasher, Suite.MerkleChannel, a, &.{joint.asProverComponent()}, &ch, first.scheme), .arithmetic = arithmetic.claim, .relations = claims };
        }
        pub fn verify(a: std.mem.Allocator, proof: *const Proof, pin: Pin, epoch: E.Epoch, entries: []const E.Entry) !Exports {
            var captured = try verifyCapture(a, proof, pin, epoch, entries);
            defer captured.deinit();
            return captured.receipt;
        }
        pub fn verifyCapture(a: std.mem.Allocator, proof: *const Proof, pin: Pin, epoch: E.Epoch, entries: []const E.Entry) !VerifiedCapture {
            const entry = try pin.require(a, epoch, entries);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, epoch.config) or roots.len != 6 or !std.meta.eql(roots[0..3].*, pin.roots ++ .{pin.access_root})) return error.UntrustedV7CallerProof;
            try requireFixedRoot(a, pin);
            var schedule = try Schedule.init(a, pin.statement, pin.total_steps, pin.frame, 1);
            defer schedule.deinit();
            const drawn = try Source.draw(a, epoch, entry);
            // Claim shape/canonicality/census checks precede component indexing.
            var ch = try Source.channel(&drawn, pin, entry, &schedule, &proof.arithmetic, &proof.relations);
            const arithmetic_owner = try Profile.Assembly(.verifier).createBlockV5Standalone(a, pin.statement, pin.total_steps, &drawn.relations, &proof.arithmetic);
            defer arithmetic_owner.destroy(a);
            const logs = try schedule.interactionLogs();
            defer a.free(logs);
            const access_logs = try schedule.witnessLogs();
            defer a.free(access_logs);
            const arithmetic_logs = try Protocol.columnLogs(a, pin.statement, .interaction);
            defer a.free(arithmetic_logs);
            var fused_owner = try Fused.Components.init(a, &schedule, &proof.relations, &drawn.relations, &drawn.epoch.bytes, &drawn.epoch.word, logs, access_logs, 1);
            defer fused_owner.deinit();
            const handles = try fused_owner.verifier();
            defer a.free(handles);
            const joint = try Components.Owner(false).create(a, arithmetic_owner.active(), handles, .{ schedule.fixed, schedule.main, access_logs, arithmetic_logs, logs }, fused_owner.memory.len);
            defer joint.destroy();
            var verifier = try Verifier.init(a, epoch.config);
            defer verifier.deinit(a);
            var initial = Suite.Channel{};
            for (0..3) |tree| try verifier.commit(a, roots[tree], joint.logs.items[tree], &initial);
            for (3..5) |tree| try verifier.commit(a, roots[tree], joint.logs.items[tree], &ch);
            var capture: core.verifier.ProofCapture(Suite.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(Suite.Hasher, Suite.MerkleChannel, a, &.{joint.asVerifierComponent()}, &ch, &verifier, &proof.stark, &capture);
            errdefer capture.deinit(a);
            const result = try Source.exports(&schedule, &proof.arithmetic, &proof.relations);
            if (!result.internal_residual.isZero()) return error.UnclosedV7CallerInternalRelations;
            return .{ .allocator = a, .proof = capture, .arithmetic = proof.arithmetic, .claims = try Fused.ClaimFrames.clone(a, &proof.relations), .final_channel = ch, .receipt = result };
        }
        pub fn requireFixedRoot(a: std.mem.Allocator, pin: Pin) !void {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const fixed = try Profile.preprocessed(arena.allocator(), pin.statement);
            var scheme = try Scheme.init(a, pin.config);
            defer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            var ch = Suite.Channel{};
            try scheme.commitBorrowedStreaming(a, fixed, 8, &ch);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 1 or !std.meta.eql(roots.items[0], pin.roots[0])) return error.UntrustedV7CallerFixedRoot;
        }
    };
}
