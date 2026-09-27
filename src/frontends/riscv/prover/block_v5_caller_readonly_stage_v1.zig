//! Warm same-root producer for the versioned classification composite. Caller
//! fixed/main trees stay live; byte and membership data share one access tree.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Batch = @import("block_v5_precompile_batch_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Readonly = @import("block_v5_caller_readonly_protocol_v1.zig");
const Proof = @import("block_v5_caller_readonly_proof_v1.zig");
const Witness = @import("block_v5_caller_readonly_witness_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const Source = @import("block_execution_external_trace_v2.zig");
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
const Range = @import("block_execution_byte_range_v2.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const Physical = struct {
    roots: [3][32]u8,
    selection_digest: [32]u8,
    all_rw_events: u64,
    readonly_events: u64,
    counter_digest: [32]u8,
    byte_snapshot: [32]u8,
};
pub const Sink = struct { context: *anyopaque, put_fused: *const fn (*anyopaque, u32, *Proof.Proof) anyerror!void };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Warm = Batch.ForBackend(Backend).WarmCaller;
        pub const Prepared = struct {
            columns: Selected.Columns,
            traces: []Source.Trace,
            inputs: []External.Input,
            metadata: []Witness.Metadata,
            first: Proof.ForBackend(Backend).FirstRound,
            physical: Physical,
            byte_snapshot: [32]u8,
            byte_demand: @import("block_v5_memory_byte_demand_v1.zig").Demand,
            pub fn deinit(self: *Prepared, a: std.mem.Allocator) void {
                self.first.deinit(a);
                for (self.metadata) |*metadata| metadata.deinit(a);
                for (self.traces) |*trace| trace.deinit();
                a.free(self.metadata);
                a.free(self.traces);
                a.free(self.inputs);
                self.columns.deinit(a);
                self.* = undefined;
            }
            pub fn registerCounter(self: *const Prepared, a: std.mem.Allocator, target: *Counter) !void {
                if (target.kind != .range_check_8_8) return error.InvalidV5CallerCounters;
                var local = try Counter.init(a, .range_check_8_8);
                defer local.deinit(a);
                for (self.traces) |*trace| _ = try Range.collectCounter(a, trace, &local);
                if (!std.meta.eql(@import("../air/block/memory_range_interaction_v2.zig").counterSnapshot(&local), self.byte_snapshot) or local.values.len != target.values.len) return error.V5CallerPhysicalReplayMismatch;
                for (target.values, local.values) |*value, addend| value.* = value.add(addend);
            }
            /// One genuine family11 prefix, one access commitment; no arithmetic
            /// matrix regeneration and no intermediate legacy access commitment.
            pub fn init(a: std.mem.Allocator, prefix: *Family.ForBackend(Backend).FirstRound, frame: Frame, authority: Readonly.Authority) !Prepared {
                var plan = try authority.admit(a);
                defer plan.deinit();
                return prepare(a, prefix, &prefix.witness.statement, prefix.total_steps, frame, plan.intervals, authority.selection.expected_digest, authority.limits, null);
            }
            /// Physical collection before final source files/native instance are
            /// known. Selection supplies values/caps, never a provisional Plan.
            pub fn initPhysical(a: std.mem.Allocator, prefix: anytype, statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, total_steps: u32, frame: Frame, selection: @import("block_v5_readonly_input_selection_v1.zig").Pins, input: []const u8, limits: Readonly.Limits) !Prepared {
                var admitted = try @import("block_v5_readonly_input_selection_v1.zig").admit(a, selection, input);
                defer admitted.deinit();
                return prepare(a, prefix, statement, total_steps, frame, admitted.intervals, admitted.digest, limits, null);
            }
            pub fn initPhysicalWithCounter(a: std.mem.Allocator, prefix: anytype, statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, total_steps: u32, frame: Frame, selection: @import("block_v5_readonly_input_selection_v1.zig").Pins, input: []const u8, limits: Readonly.Limits, target: *Counter) !Prepared {
                var admitted = try @import("block_v5_readonly_input_selection_v1.zig").admit(a, selection, input);
                defer admitted.deinit();
                if (target.kind != .range_check_8_8) return error.InvalidV5CallerCounters;
                return prepare(a, prefix, statement, total_steps, frame, admitted.intervals, admitted.digest, limits, target);
            }
            /// Proposal-only observed first pass, borrowing an already admitted
            /// immutable selection. Collector token finalization supplies the
            /// distinct stream digest only after these actual roots are known.
            pub const ObservedPhysical = struct {
                roots: [3][32]u8,
                selection_digest: [32]u8,
                all_rw_events: u64,
                readonly_events: u64,
                byte_snapshot: [32]u8,
            };
            pub const Observed = struct {
                prepared: Prepared,
                physical: ObservedPhysical,
                pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
                    self.prepared.deinit(a);
                    self.* = undefined;
                }
            };
            pub fn initPhysicalObserved(a: std.mem.Allocator, prefix: anytype, statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, total_steps: u32, frame: Frame, selection: *const @import("block_v5_readonly_input_selection_v1.zig").Owned, limits: Readonly.Limits, target: ?*Counter, observer: Witness.Metadata.Observer) !Observed {
                if (target) |counter| if (counter.kind != .range_check_8_8) return error.InvalidV5CallerCounters;
                const prepared = try prepareKernel(.observed, a, prefix, statement, total_steps, frame, selection.intervals, selection.digest, limits, target, observer);
                return .{ .prepared = prepared, .physical = .{ .roots = prepared.physical.roots, .selection_digest = prepared.physical.selection_digest, .all_rw_events = prepared.physical.all_rw_events, .readonly_events = prepared.physical.readonly_events, .byte_snapshot = prepared.physical.byte_snapshot } };
            }
            /// Genuine late-policy replay: source membership uses only the
            /// root-owned Plan, with no interval histogram or legacy digest.
            pub fn initOpenSource(a: std.mem.Allocator, prefix: *Family.ForBackend(Backend).FirstRound, frame: Frame, authority: @import("block_v5_caller_readonly_global_proof_v2.zig").Authority) !Observed {
                var plan = try authority.admit(a);
                defer plan.deinit();
                var context: u8 = 0;
                const prepared = try prepareKernel(.observed, a, prefix, &prefix.witness.statement, prefix.total_steps, frame, plan.intervals, authority.selection.expected_digest, authority.limits, null, .{ .context = &context, .observe = observeReplay });
                errdefer {
                    var owned = prepared;
                    owned.deinit(a);
                }
                const source = try authority.roster.source(authority.ordinal);
                if (!std.meta.eql(prepared.physical.roots, source.roots) or prepared.physical.all_rw_events != source.census.all_rw or prepared.physical.readonly_events != source.census.readonly) return error.ChangedGlobalCallerReadonlyReplay;
                return .{ .prepared = prepared, .physical = .{ .roots = prepared.physical.roots, .selection_digest = prepared.physical.selection_digest, .all_rw_events = prepared.physical.all_rw_events, .readonly_events = prepared.physical.readonly_events, .byte_snapshot = prepared.physical.byte_snapshot } };
            }
            fn observeReplay(_: *anyopaque, _: u32) !void {}
            const CounterFlavor = enum { histogram, observed };
            fn prepare(a: std.mem.Allocator, prefix: anytype, statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, total_steps: u32, frame: Frame, intervals: []const @import("block_v5_readonly_input_plan_v1.zig").Interval, selection_digest: [32]u8, limits: Readonly.Limits, target: ?*Counter) !Prepared {
                return prepareKernel(.histogram, a, prefix, statement, total_steps, frame, intervals, selection_digest, limits, target, null);
            }
            fn prepareKernel(comptime flavor: CounterFlavor, a: std.mem.Allocator, prefix: anytype, statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, total_steps: u32, frame: Frame, intervals: []const @import("block_v5_readonly_input_plan_v1.zig").Interval, selection_digest: [32]u8, limits: Readonly.Limits, target: ?*Counter, observer: ?Witness.Metadata.Observer) !Prepared {
                if (!prefix.owns_scheme or prefix.scheme.trees.items.len != 2 or total_steps != frame.cycle_count) return error.UntrustedCallerReadonlyWarmPrefix;
                if (!std.meta.eql(prefix.key_id, try Protocol.keyId(statement, total_steps, prefix.scheme.config, prefix.roots[0]))) return error.UntrustedCallerReadonlyWarmKey;
                var schedule = try Schedule.init(a, statement, total_steps, frame, 1);
                defer schedule.deinit();
                if (flavor == .histogram) try Proof.preflightCounts(&schedule, intervals.len, .{ schedule.program.len, schedule.program.len, schedule.tables.len, schedule.memory.len, schedule.memory.len }, limits) else try Proof.preflightCompactCounts(&schedule, intervals.len, .{ schedule.program.len, schedule.program.len, schedule.tables.len, schedule.memory.len, schedule.memory.len }, limits);
                var ranges: std.ArrayList(Selected.Range) = .empty;
                defer ranges.deinit(a);
                for (schedule.masks.fixed, 0..) |open, i| if (open) try ranges.append(a, .{ .fixed_offset = i, .fixed_width = 1, .main_offset = 0, .main_width = 0, .log_size = schedule.fixed[i] });
                for (schedule.masks.main, 0..) |open, i| if (open) try ranges.append(a, .{ .fixed_offset = 0, .fixed_width = 0, .main_offset = i, .main_width = 1, .log_size = schedule.main[i] });
                if (schedule.masks.state_offset) |offset| try ranges.append(a, .{ .fixed_offset = 0, .fixed_width = 0, .main_offset = offset, .main_width = @import("../air/guest_precompile/keccakf_witness.zig").state_cell_count, .log_size = schedule.main[offset] });
                var columns = try Selected.Columns.init(a, &prefix.scheme, schedule.fixed, schedule.main, ranges.items);
                errdefer columns.deinit(a);
                const traces = try a.alloc(Source.Trace, schedule.memory.len);
                errdefer a.free(traces);
                const inputs = try a.alloc(External.Input, schedule.memory.len);
                errdefer a.free(inputs);
                const metadata = try a.alloc(Witness.Metadata, schedule.memory.len);
                errdefer a.free(metadata);
                var traces_initialized: usize = 0;
                errdefer for (traces[0..traces_initialized]) |*trace| trace.deinit();
                var metadata_initialized: usize = 0;
                errdefer for (metadata[0..metadata_initialized]) |*value| value.deinit(a);
                var local = try Counter.init(a, .range_check_8_8);
                defer local.deinit(a);
                const snapshots = try a.alloc(Range.SNAPSHOT, schedule.memory.len);
                errdefer a.free(snapshots);
                var witness_columns: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
                defer witness_columns.deinit(a);
                var count: u64 = 0;
                for (schedule.memory, traces, inputs, metadata, snapshots) |slot, *trace, *input, *meta, *snapshot| {
                    trace.* = try Source.Trace.initSelected(a, slot, columns.fixed, columns.main);
                    traces_initialized += 1;
                    input.* = .{ .descriptor = slot, .trace = trace };
                    meta.* = if (flavor == .histogram) try Witness.Metadata.initIntervals(a, trace, intervals, limits) else try Witness.Metadata.initIntervalsObserved(a, trace, intervals, limits, observer orelse return error.MissingCallerReadonlyObserver);
                    metadata_initialized += 1;
                    count = try std.math.add(u64, count, meta.events);
                    snapshot.* = try Range.collectCounter(a, trace, &local);
                    for (trace.witness) |values| try witness_columns.append(a, .{ .values = values, .log_size = slot.log_size });
                }
                if (count != schedule.rw_events) return error.UntrustedCallerReadonlyEventCensus;
                // Match component order: existing 48 bytes first, then71 metadata.
                for (metadata) |meta| try witness_columns.appendSlice(a, &meta.columns);
                var channel = core.proof_suites.Blake3.Channel{};
                channel.mixU32s(&.{ Readonly.TAG, Readonly.VERSION, 0x50485953 });
                channel.mixRoot(Readonly.abiId());
                channel.mixRoot(selection_digest);
                var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, &prefix.scheme, &channel);
                errdefer scheme.deinit(a);
                try scheme.commitBorrowedStreaming(a, witness_columns.items, 16, &channel);
                var roots = try scheme.roots(a);
                defer roots.deinit(a);
                if (roots.items.len != 3 or !std.meta.eql(roots.items[0..2].*, prefix.roots)) return error.UnsharedCallerReadonlyPrefix;
                const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(statement, schedule.memory, 1);
                var mass: u64 = 0;
                for (local.values) |value| mass = try std.math.add(u64, mass, value.toU32());
                if (mass != demand.request_count) return error.UntrustedCallerReadonlyByteCensus;
                const fixed_logs = try a.dupe(u32, schedule.fixed);
                errdefer a.free(fixed_logs);
                const main_logs = try a.dupe(u32, schedule.main);
                errdefer a.free(main_logs);
                var readonly_events: u64 = 0;
                const counter_digest: [32]u8 = if (flavor == .histogram) histogram: {
                    // Exact old per-slot/interval digest order, retained verbatim.
                    var counter_hash = std.crypto.hash.sha2.Sha256.init(.{});
                    counter_hash.update("stwo-zig/block-v5/caller-readonly-physical-counters/v1\x00");
                    counter_hash.update(&selection_digest);
                    for (metadata) |meta| for (meta.counters, intervals) |counter_mass, interval| {
                        var bytes: [8]u8 = undefined;
                        std.mem.writeInt(u64, &bytes, counter_mass, .little);
                        counter_hash.update(&bytes);
                        if (interval.readonly) readonly_events = try std.math.add(u64, readonly_events, counter_mass);
                    };
                    break :histogram counter_hash.finalResult();
                } else observed: {
                    for (metadata) |meta| readonly_events = try std.math.add(u64, readonly_events, meta.readonly_events);
                    // Not exported in ObservedPhysical. The collector computes
                    // interval_stream_v2, never a renamed histogram hash.
                    break :observed @splat(0);
                };
                const snapshot = @import("../air/block/memory_range_interaction_v2.zig").counterSnapshot(&local);
                const physical = Physical{ .roots = roots.items[0..3].*, .selection_digest = selection_digest, .all_rw_events = count, .readonly_events = readonly_events, .counter_digest = counter_digest, .byte_snapshot = snapshot };
                if (target) |counter| {
                    if (counter.values.len != local.values.len) return error.InvalidV5CallerCounters;
                    for (counter.values, local.values) |*value, addend| value.* = value.add(addend);
                }
                return .{ .physical = physical, .columns = columns, .traces = traces, .inputs = inputs, .metadata = metadata, .byte_demand = demand, .byte_snapshot = snapshot, .first = .{ .scheme = scheme, .roots = roots.items[0..3].*, .fixed_logs = fixed_logs, .main_logs = main_logs, .snapshots = snapshots } };
            }
        };
        sink: Sink,
        frame: Frame,
        authority: Readonly.Authority,
        expected: Physical,
        pub fn proveWarm(self: *Self, a: std.mem.Allocator, warm: Warm) !void {
            try Protocol.admit(warm.first.binding(warm.sealed), warm.sealed, warm.pins, warm.entries);
            if (!std.meta.eql(warm.first.entry(), warm.record.entry()) or warm.sealed.register_custody_mode != 1) return error.UntrustedCallerReadonlyWarmRecord;
            var prepared = try Prepared.init(a, warm.first, self.frame, self.authority);
            defer prepared.deinit(a);
            try self.provePreparedWarm(a, &prepared, warm);
        }
        pub fn provePreparedWarm(self: *Self, a: std.mem.Allocator, prepared: *Prepared, warm: Warm) !void {
            if (!std.meta.eql(prepared.physical, self.expected) or !std.meta.eql(self.expected.selection_digest, self.authority.selection.expected_digest)) return error.ChangedCallerReadonlyWarmWitness;
            var proof = try Proof.ForBackend(Backend).proveForCallerFirstRound(a, &prepared.first, prepared.inputs, warm.first, self.frame, self.expected.roots[2], warm.sealed, warm.pins, warm.entries, self.authority, prepared.metadata);
            var owns = true;
            defer if (owns) proof.deinit(a);
            try self.sink.put_fused(self.sink.context, warm.record.execution.index, &proof);
            owns = false;
        }
    };
}
