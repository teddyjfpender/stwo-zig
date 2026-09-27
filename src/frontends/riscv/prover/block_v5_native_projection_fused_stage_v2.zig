//! Canonical warm replacement for separate native projection + ordinary
//! memory callbacks. Native fixed/main are leased once, the collected access
//! witness is recommitted once, all local projections share one STARK.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const ProducerModule = @import("block_v5_block_producer_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const MemoryStage = @import("block_v5_native_memory_stage_v1.zig");
const Proof = @import("block_v5_native_projection_fused_proof_v2.zig");
const Receiver = @import("block_v5_native_projection_fused_receiver_v2.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Counter = @import("../air/lookups/tables/counter.zig");
const Snapshot = @import("../air/block/memory_range_interaction_v2.zig");
pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers ownership; on error the stage releases its proof.
    put_fused: *const fn (*anyopaque, u32, *Proof.Proof) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Producer = ProducerModule.ForLightweightBackend(Backend);
        const Api = Proof.ForBackend(Backend);
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        proposals: []const MemoryStage.Proposal,
        limits: MemoryStage.Limits,
        sink: Sink,
        next: u32 = 0,
        pub fn hooks(self: *Self) Producer.Hooks {
            return .{ .context = self, .on_first_round = onFirstRound, .fused_program_requests = true };
        }
        pub fn requireFinished(self: *const Self) !void {
            if (self.next != self.proposals.len) return error.IncompleteV5FullFusedStage;
        }
        fn onFirstRound(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmExecution) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            if (warm.index != self.next or warm.index >= self.proposals.len) return error.InvalidV5FullFusedStageOrder;
            const expected = &self.proposals[warm.index];
            const owner = warm.replay.owner;
            if (!warm.first.owns_scheme or warm.first.index != warm.index or warm.first.native != owner or
                !owner.native_only_v5 or !owner.tables_ready or owner.failed or owner.interaction_ready or
                warm.first.scheme.trees.items.len != 2 or !std.meta.eql(warm.first.pin, warm.replay.admission) or
                !std.meta.eql(warm.first.scheme.config, warm.pins.config) or warm.first.template.external_retirements != owner.external_retirements or
                self.limits.register_custody_mode != warm.sealed.register_custody_mode or expected.register_custody_mode != warm.sealed.register_custody_mode or
                !std.meta.eql(warm.first.roots, expected.native_roots) or !std.meta.eql(warm.first.template_id, expected.template_id))
                return error.UntrustedV5WarmFullFused;
            const pin = Receiver.InstancePin{ .shape = &owner.statement, .admission = warm.replay.admission, .template = warm.first.template, .template_id = warm.first.template_id, .profile = warm.replay.profile };
            const memory = Receiver.MemoryPin{ .frame = expected.frame, .expected_events = expected.ordinary_events, .witness_root = expected.witness_root };
            const roots = try Receiver.admit(a, warm.index, pin, memory, warm.sealed, warm.pins, warm.entries, warm.catalog);
            if (!std.meta.eql(roots, warm.first.roots)) return error.UntrustedV5WarmFullFused;
            try Native.admitEntry(warm.index, roots, warm.first.instance_id, warm.sealed, warm.entries);
            var source = try MemoryStage.Traces.init(a, owner, expected.frame, self.limits);
            defer source.deinit();
            if (source.slots.len != expected.slots.len or try source.census() != expected.ordinary_events) return error.V5FullFusedReplayMismatch;
            for (source.slots, expected.slots) |actual, proposed| if (!std.meta.eql(actual, proposed)) return error.V5FullFusedReplayMismatch;
            const projections = try Source.slotsFromShapeForMode(a, &owner.statement, owner.external_retirements, warm.sealed.register_custody_mode);
            defer a.free(projections);
            var counter = try Counter.Counter.init(a, .range_check_8_8);
            defer counter.deinit(a);
            if (projections.len == 0) {
                if (source.slots.len != 0 or !std.meta.eql(Snapshot.counterSnapshot(&counter), expected.byte_snapshot)) return error.UntrustedV5FullFusedTypedAbsence;
                // Both exact row schedules are absent. The genuine native
                // frame still proves; no local proof or synthetic claim exists.
                self.next += 1;
                return;
            }
            var first = if (source.slots.len == 0)
                try borrowProjectionFirstRound(a, &warm.first.scheme, expected.witness_root)
            else
                try MemoryStage.ForBackend(Backend).borrow(a, &warm.first.scheme, source.inputs, source.slots, &counter, warm.index, warm.first.template_id);
            defer first.deinit(a);
            if (!std.meta.eql(first.roots[2], expected.witness_root) or !std.meta.eql(Snapshot.counterSnapshot(&counter), expected.byte_snapshot)) return error.V5FullFusedReplayMismatch;
            var proof = try Api.proveForNativeFirstRound(a, &first, source.inputs, source.slots, projections, warm.sealed, warm.pins, warm.entries, warm.catalog, warm.first, warm.index, expected.frame, expected.witness_root);
            var owns = true;
            defer if (owns) proof.deinit(a);
            if (!warm.first.owns_scheme or warm.first.scheme.trees.items.len != 2) return error.ConsumedV5WarmFullFused;
            try self.sink.put_fused(self.sink.context, warm.index, &proof);
            owns = false;
            self.next += 1;
        }
        /// No access tree is fabricated for zero RW. The third roots field is
        /// the independently admitted typed-absence ID, not a PCS commitment;
        /// v2 alone accepts this two-tree first-round/three-tree proof layout.
        fn borrowProjectionFirstRound(a: std.mem.Allocator, native: *Scheme, absence_root: [32]u8) !Api.FirstRound {
            var channel = suite.Channel{};
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, native, &channel);
            errdefer scheme.deinit(a);
            const fixed = try treeLogs(a, scheme.trees.items[0].columns, scheme.config.fri_config.log_blowup_factor);
            errdefer a.free(fixed);
            const main = try treeLogs(a, scheme.trees.items[1].columns, scheme.config.fri_config.log_blowup_factor);
            errdefer a.free(main);
            const snapshots = try a.alloc(@import("block_execution_byte_range_v2.zig").SNAPSHOT, 0);
            errdefer a.free(snapshots);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            return .{ .scheme = scheme, .roots = .{ roots.items[0], roots.items[1], absence_root }, .fixed_logs = fixed, .main_logs = main, .snapshots = snapshots };
        }
    };
}
fn treeLogs(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation, blowup: u32) ![]u32 {
    const logs = try a.alloc(u32, columns.len);
    errdefer a.free(logs);
    for (columns, logs) |column, *log| log.* = try std.math.sub(u32, column.log_size, blowup);
    return logs;
}
