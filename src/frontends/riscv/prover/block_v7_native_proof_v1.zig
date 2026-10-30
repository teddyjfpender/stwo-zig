//! Genuine original native+ordinary-memory STARK under the v7 whole roster.
//! Proof verification returns typed OPEN source claims, never block admission.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Source = @import("block_v7_native_source_v1.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Components = @import("block_v7_native_components_v1.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Transition = @import("block_execution_transition_interaction_v2.zig");
const Universal = @import("block_v5_opcode_memory_interaction_v1.zig");
pub const Proof = Fused.Proof;
pub const Pin = Source.Pin;
const NativeCache = @import("block_v7_shared_quotient_cache_v1.zig");
pub const ProveOptions = struct {
    /// Producer-only row fusion. Verifier, transcript and PCS stay unchanged.
    fused_projection_rows: bool = false,
    quotient_executor: ?*const engine.pcs.QuotientExecutor = null,
    deep_group_budget: engine.pcs.DeepGroupBudget = .one_mib,
    recorder: ?*engine.stage_profile.Recorder = null,
    /// One proof-wide retained cap; zero uses the original uncached path.
    native_main_cache_bytes: usize = NativeCache.DEFAULT_RETAINED_BYTES,
    /// Filled only after core workers join. No timing or per-row recording.
    cache_stats: ?*NativeCache.Stats = null,
};
/// Owned verifier material; it retains neither wide producer rows nor a
/// borrowed claim slice. This is an OPEN source, not global block authority.
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(suite.Hasher),
    final_channel: suite.Channel,
    claims: []Fused.Claim,
    memory_claims: []Memory.Claim,
    open: Source.Exports,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.allocator.free(self.claims);
        self.allocator.free(self.memory_claims);
        self.* = undefined;
    }
};
pub fn channel(drawn: *const Epoch.Drawn, pin: Pin, entry: Epoch.Entry, slots: []const @import("block_v5_native_projection_fused_source_v1.zig").Slot, memory: []const Memory.Slot, claims: []const Fused.Claim, access: []const Memory.Claim) !suite.Channel {
    var ch = drawn.channel;
    try recordAfterChallenges(&ch, pin, entry, slots, memory, claims, access);
    return ch;
}
pub fn recordAfterChallenges(ch: anytype, pin: Pin, entry: Epoch.Entry, slots: []const @import("block_v5_native_projection_fused_source_v1.zig").Slot, memory: []const Memory.Slot, claims: []const Fused.Claim, access: []const Memory.Claim) !void {
    ch.mixU32s(&.{ 0x42374e50, 1, pin.index });
    entry.mix(ch);
    try Fused.recordClaims(ch, try pin.template.identity(), entry.identity, pin.index, slots, memory, claims, access);
}
pub fn For(comptime Backend: type) type {
    return struct {
        pub const First = Memory.ForPackedBackend(Backend).FirstRound;
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        pub fn prove(a: std.mem.Allocator, first: *First, native: *@import("blake3_execution_trace.zig").Owner, inputs: []const Memory.Input, pin: Pin, epoch: Epoch.Epoch, entries: []const Epoch.Entry) !Proof {
            return proveWithOptions(a, first, native, inputs, pin, epoch, entries, .{});
        }
        pub fn proveWithOptions(a: std.mem.Allocator, first: *First, native: *@import("blake3_execution_trace.zig").Owner, inputs: []const Memory.Input, pin: Pin, epoch: Epoch.Epoch, entries: []const Epoch.Entry, options: ProveOptions) !Proof {
            if (options.native_main_cache_bytes > NativeCache.MAX_RETAINED_BYTES) return error.InvalidV7QuotientCacheBudget;
            if (options.cache_stats) |stats| stats.* = .{};
            const entry = try pin.entry(a);
            try epoch.requireEntry(entries, entry);
            if (!std.meta.eql(pin.template.config, epoch.config) or !std.meta.eql(native.statement, pin.shape.*) or native.external_retirements != pin.template.external_retirements or !native.native_only_v5 or native.failed or !native.tables_ready or native.interaction_ready or !first.owns_scheme or !std.meta.eql(first.scheme.config, epoch.config)) return error.InvalidV7NativePhase;
            var roots = try first.scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != entry.root_count or !std.meta.eql(roots.items[0..2].*, pin.roots) or (entry.root_count == 3 and !std.meta.eql(roots.items[2], pin.access_root))) return error.UntrustedV7NativeFirst;
            var layout = try pin.layout(a);
            defer layout.deinit();
            const slots = try @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, pin.shape, pin.frame, 1);
            defer a.free(slots);
            if (inputs.len != slots.len or first.snapshots.len != slots.len) return error.InvalidV7NativeInputs;
            const claims = try a.alloc(Fused.Claim, layout.slots.len);
            errdefer a.free(claims);
            const access = try a.alloc(Memory.Claim, slots.len);
            errdefer a.free(access);
            var interaction: std.ArrayList(Column) = .empty;
            defer {
                for (interaction.items) |column| a.free(column.values);
                interaction.deinit(a);
            }
            const drawn = try epoch.draw(a);
            if (options.fused_projection_rows) {
                try interaction.ensureUnusedCapacity(a, 4 * layout.slots.len);
                var batch = try @import("block_v7_native_projection_batch_v1.zig").generate(a, native.main.items, layout.slots, &drawn.word.universal_prefix);
                defer batch.deinit();
                for (layout.slots, claims, batch.values) |slot, *claim, *generated| {
                    claim.* = .{ .sum = generated.sum, .row_count = slot.n_rows };
                    for (&generated.columns) |*values| {
                        interaction.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values.* });
                        values.* = &.{}; // Exact owner transfer, no column copy.
                    }
                }
            } else for (layout.slots, claims) |slot, *claim| {
                try interaction.ensureUnusedCapacity(a, 4);
                const generated = try Fused.generateProjection(a, native.main.items, slot, &drawn.word.universal_prefix);
                claim.* = .{ .sum = generated.sum, .row_count = slot.n_rows };
                for (generated.columns) |values| interaction.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values });
            }
            for (inputs, slots, first.snapshots, access) |input, slot, snapshot, *claim| {
                if (!std.meta.eql(input.descriptor, slot) or input.trace.register_custody_mode != 1) return error.InvalidV7NativeInputs;
                try interaction.ensureUnusedCapacity(a, @import("block_v7_native_access_interaction_v1.zig").COLUMN_COUNT);
                const generated = try @import("block_v7_native_access_interaction_v1.zig").generateWithScratch(a, a, input.trace, &drawn.word, snapshot);
                claim.* = .{ .transition_sum = generated.transition_sum, .universal_sum = generated.universal_sum, .range_claims = generated.range_claims, .active_count = generated.active_count };
                // Transfer every owned column once; no full-domain row arrays or copy.
                for (generated.columns) |values| interaction.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values });
            }
            const Frame = @import("block_v5_native_frame_v1.zig");
            if (Frame.required(pin.shape)) {
                if (claims.len != 0 or access.len != 0 or interaction.items.len != 0) return error.InvalidV7ExternalNativeEnvelope;
                const pad = try Frame.interactionColumns(a);
                defer a.free(pad);
                interaction.appendSlice(a, pad) catch |err| {
                    for (pad) |column| a.free(column.values);
                    return err;
                };
            }
            var components = try Components.Owner.init(a, pin, claims, access, &drawn);
            defer components.deinit();
            if (!std.mem.eql(u32, first.fixed_logs, components.fixed) or !std.mem.eql(u32, first.main_logs, components.main)) return error.InvalidV7NativeFirstGeometry;
            var combined = try components.proving();
            defer combined.deinit(a);
            var ch = try channel(&drawn, pin, entry, components.layout.slots, components.slots, claims, access);
            try first.scheme.commitBorrowedStreaming(a, interaction.items, 8, &ch);
            const cache = try NativeCache.Owner.createWithUsage(a, options.native_main_cache_bytes, options.cache_stats != null);
            components.setQuotientCache(if (cache) |c| &c.cache else null);
            defer {
                components.setQuotientCache(null);
                if (cache) |c| {
                    if (options.cache_stats) |stats| stats.* = c.stats();
                    c.destroy();
                }
            }
            first.owns_scheme = false;
            first.scheme.deep_group_budget = options.deep_group_budget;
            first.scheme.quotient_executor = options.quotient_executor;
            var result = try engine.prove.proveExWithRecorder(Backend, suite.Hasher, suite.MerkleChannel, a, combined.handles, &ch, first.scheme, false, options.recorder);
            result.aux.deinit(a);
            return .{ .stark = result.proof, .claims = claims, .memory_claims = access };
        }
        pub fn verify(a: std.mem.Allocator, proof: *const Proof, pin: Pin, epoch: Epoch.Epoch, entries: []const Epoch.Entry) !Source.Exports {
            var captured = try verifyAndCapture(a, proof, pin, epoch, entries);
            defer captured.deinit();
            return captured.open;
        }
        pub fn verifyAndCapture(a: std.mem.Allocator, proof: *const Proof, pin: Pin, epoch: Epoch.Epoch, entries: []const Epoch.Entry) !VerifiedCapture {
            const entry = try pin.entry(a);
            try epoch.requireEntry(entries, entry);
            if (!std.meta.eql(pin.template.config, epoch.config) or !std.meta.eql(proof.stark.commitment_scheme_proof.config, epoch.config)) return error.InvalidV7NativeConfig;
            try @import("block_v5_native_execution_proof_v3.zig").ForBackend(Backend).verifyFixed(a, pin.shape, pin.template, epoch.config);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != entry.root_count + 2 or !std.meta.eql(roots[0..2].*, pin.roots) or (entry.root_count == 3 and !std.meta.eql(roots[2], pin.access_root))) return error.UntrustedV7NativeFirst;
            const drawn = try epoch.draw(a);
            var components = try Components.Owner.init(a, pin, proof.claims, proof.memory_claims, &drawn);
            defer components.deinit();
            var verifier = try Verifier.init(a, epoch.config);
            defer verifier.deinit(a);
            var temporary = suite.Channel{};
            try verifier.commit(a, roots[0], components.fixed, &temporary);
            try verifier.commit(a, roots[1], components.main, &temporary);
            if (entry.root_count == 3) try verifier.commit(a, roots[2], components.witness, &temporary);
            var ch = try channel(&drawn, pin, entry, components.layout.slots, components.slots, proof.claims, proof.memory_claims);
            try verifier.commit(a, roots[entry.root_count], components.interactions, &ch);
            var combined = try components.verifying();
            defer combined.deinit(a);
            var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, combined.handles, &ch, &verifier, &proof.stark, &capture);
            errdefer capture.deinit(a);
            const open = try Source.exports(a, pin, proof, &drawn);
            const claims = try a.dupe(Fused.Claim, proof.claims);
            errdefer a.free(claims);
            const memory_claims = try a.dupe(Memory.Claim, proof.memory_claims);
            return .{ .allocator = a, .proof = capture, .final_channel = ch, .claims = claims, .memory_claims = memory_claims, .open = open };
        }
    };
}
