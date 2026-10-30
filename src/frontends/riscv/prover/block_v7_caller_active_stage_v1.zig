//! One compact arithmetic/access commitment. A stage borrows the witness until
//! proving finishes; its arena holds raw columns only for this single caller.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const P = @import("blake3_ethereum_sha_profile.zig");
const W = @import("block_v5_precompile_witness_v1.zig");
const Source = @import("block_v7_caller_active_source_v1.zig");
const Layout = @import("block_v7_caller_active_layout_v1.zig").Layout;
const S = @import("block_v7_caller_active_schedule_v1.zig");
const Access = @import("block_execution_external_trace_v2.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const Counters = @import("../air/lookups/tables/counter.zig");
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
pub fn For(comptime Backend: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        witness: *const W.Witness,
        layout: Layout,
        schedule: S.Schedule,
        columns: Selected.Columns,
        traces: []Access.Trace,
        inputs: []External.Input,
        first: External.ForPackedBackend(Backend).FirstRound,
        index: u32,
        pub fn init(a: std.mem.Allocator, witness: *const W.Witness, frame: @import("../air/block/memory_event.zig").Frame, index: u32, config: core.pcs.PcsConfig, counter: *Counters.Counter) !*Self {
            return initProfiled(a, witness, frame, index, config, counter, null);
        }
        pub fn initProfiled(a: std.mem.Allocator, witness: *const W.Witness, frame: @import("../air/block/memory_event.zig").Frame, index: u32, config: core.pcs.PcsConfig, counter: *Counters.Counter, recorder: ?*engine.stage_profile.Recorder) !*Self {
            if (counter.kind != .range_check_8_8) return error.InvalidActiveCallerCounter;
            var witness_phase = try engine.stage_profile.StageScope.begin(recorder, "caller_source_witness", "Caller and memory access source columns");
            defer witness_phase.end();
            const self = try prepare(a, witness, frame, index);
            errdefer self.destroyRaw();
            var local = try Counters.Counter.init(a, .range_check_8_8);
            defer local.deinit(a);
            witness_phase.end();
            var commit_phase = try engine.stage_profile.StageScope.begin(recorder, "caller_first_commitments", "Caller and external access first commitments");
            defer commit_phase.end();
            self.first = try External.ForPackedBackend(Backend).commitFirstRound(a, self.columns.fixed, self.columns.main, self.inputs, self.schedule.memory, &local, index, @splat(0), config);
            errdefer self.first.deinit(a);
            const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(&witness.statement, self.schedule.memory, 1);
            var mass: u64 = 0;
            for (local.values) |v| mass = try std.math.add(u64, mass, v.toU32());
            var events: u64 = 0;
            for (self.traces) |*trace| for (0..trace.domainSize()) |row| {
                events = try std.math.add(u64, events, @intFromBool((try trace.row(row)).active));
            };
            if (mass != demand.request_count or events != demand.event_count or local.values.len != counter.values.len) return error.InvalidActiveCallerCensus;
            for (counter.values, local.values) |*v, delta| v.* = v.add(delta);
            self.index = index;
            return self;
        }
        fn prepare(a: std.mem.Allocator, witness: *const W.Witness, frame: @import("../air/block/memory_event.zig").Frame, index: u32) !*Self {
            try W.validateAdmission(a, &witness.statement);
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.allocator = a;
            self.arena = std.heap.ArenaAllocator.init(a);
            errdefer self.arena.deinit();
            const raw = self.arena.allocator();
            self.witness = witness;
            self.layout = try Layout.derive(&witness.statement, witness.total_steps);
            self.schedule = try S.derive(a, &witness.statement, witness.total_steps, frame);
            errdefer self.schedule.deinit();
            const full_fixed = try P.preprocessed(raw, &witness.statement);
            const full_main = try P.mainWitness(raw, witness);
            self.columns = .{ .fixed = try self.layout.columns(raw, 0, full_fixed), .main = try self.layout.columns(raw, 1, full_main.columns) };
            self.traces = try raw.alloc(Access.Trace, self.schedule.memory.len);
            self.inputs = try raw.alloc(External.Input, self.schedule.memory.len);
            for (self.schedule.memory, self.traces, self.inputs) |slot, *trace, *input| {
                trace.* = try Access.Trace.initSelected(raw, slot, self.columns.fixed, self.columns.main);
                input.* = .{ .descriptor = slot, .trace = trace };
            }
            self.index = index;
            return self;
        }
        /// Takes the restored scheme only on success. No interpolation or
        /// Merkle construction occurs; original AIR verification authenticates
        /// both restored columns and the raw witness used for interactions.
        pub fn fromRestored(a: std.mem.Allocator, witness: *const W.Witness, frame: @import("../air/block/memory_event.zig").Frame, index: u32, roots: [3][32]u8, scheme: *@import("block_v6_cpu_checkpoint_codec_v1.zig").Scheme) !*Self {
            if (Backend != @import("stwo_cpu_backend").CpuBackend) return error.UnsupportedActiveCheckpointBackend;
            const self = try prepare(a, witness, frame, index);
            errdefer self.destroyRaw();
            if (scheme.trees.items.len != 3) return error.InvalidActiveCallerGeometry;
            for (scheme.trees.items, roots) |tree, root| if (!std.meta.eql(tree.commitment.root(), root)) return error.InvalidActiveCallerGeometry;
            const fixed = try a.dupe(u32, self.schedule.fixed);
            errdefer a.free(fixed);
            const main = try a.dupe(u32, self.schedule.main);
            errdefer a.free(main);
            const Range = @import("block_execution_byte_range_v2.zig");
            const snapshots = try a.alloc(Range.SNAPSHOT, self.traces.len);
            errdefer a.free(snapshots);
            var counter = try Counters.Counter.init(a, .range_check_8_8);
            defer counter.deinit(a);
            for (self.traces, snapshots) |*trace, *snapshot| snapshot.* = try Range.collectCounter(a, trace, &counter);
            self.first = .{ .scheme = scheme.*, .roots = roots, .fixed_logs = fixed, .main_logs = main, .snapshots = snapshots };
            scheme.* = undefined;
            return self;
        }
        fn destroyRaw(self: *Self) void {
            self.schedule.deinit();
            self.arena.deinit();
            self.allocator.destroy(self);
        }
        pub fn pin(self: *const Self, execution_index: u32, execution_identity: [32]u8) Source.Pin {
            return .{ .index = self.index, .execution_index = execution_index, .execution_identity = execution_identity, .statement = &self.witness.statement, .total_steps = self.witness.total_steps, .frame = self.schedule.memory[0].frame, .roots = self.first.roots[0..2].*, .access_root = self.first.roots[2], .config = self.first.scheme.config };
        }
        pub fn deinit(self: *Self) void {
            self.first.deinit(self.allocator);
            self.destroyRaw();
        }
    };
}
