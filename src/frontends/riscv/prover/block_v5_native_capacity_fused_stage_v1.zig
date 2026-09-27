//! Explicit warm B5CT producer seam. Driver migration is separate; this stage
//! accepts a genuine capacity FirstRound and never fabricates NativeV3 values.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Capacity = @import("block_v5_native_capacity_proof_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Native = @import("blake3_execution_trace.zig");
const Proof = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Receiver = @import("block_v5_native_capacity_fused_receiver_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const OriginalStage = @import("block_v5_native_memory_stage_v1.zig");
const Trace = @import("block_execution_sidecar_trace_v2.zig").Trace;
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Bytes = @import("block_execution_byte_range_v2.zig");
const Counter = @import("../air/lookups/tables/counter.zig");
const Snapshot = @import("../air/block/memory_range_interaction_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const Limits = struct { memory: OriginalStage.Limits, fused: Proof.Limits = .{} };
pub const Proposal = struct {
    allocator: std.mem.Allocator,
    slots: []Memory.Slot,
    index: u32,
    frame: Frame,
    register_custody_mode: u32,
    native_roots: Seal.Roots,
    template_id: [32]u8,
    public_digest: [32]u8,
    witness_root: [32]u8,
    byte_snapshot: [32]u8,
    event_count: u64,
    pub fn deinit(self: *Proposal) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }
    pub fn memoryEntry(self: *const Proposal, a: std.mem.Allocator, native: *const Capacity.Proposal, context: Public.Context) !Seal.Entry {
        if (native.index != self.index or !std.meta.eql(native.roots, self.native_roots) or !std.meta.eql(native.template_id, self.template_id) or
            !std.meta.eql(native.public_digest, self.public_digest) or context.first_cycle != self.frame.global_first_cycle or
            self.frame.cycle_count != native.shape.public_data.clock or context.register_custody_mode != self.register_custody_mode)
            return error.ChangedCapacityFusedProposal;
        const execution = try native.bind(context);
        const canonical = try Source.memorySlots(a, &native.shape, native.external_retirements, self.frame, self.register_custody_mode);
        defer a.free(canonical);
        if (canonical.len != self.slots.len) return error.ChangedCapacityFusedProposal;
        for (canonical, self.slots) |actual, proposed| if (!std.meta.eql(actual, proposed)) return error.ChangedCapacityFusedProposal;
        if (self.slots.len == 0) {
            const empty = try Source.emptyEntry(a, &native.shape, native.external_retirements, self.frame, execution, self.event_count, self.register_custody_mode);
            if (!std.meta.eql(empty.roots[0], self.witness_root)) return error.ChangedCapacityFusedProposal;
            return empty;
        }
        return Memory.packedEntry(execution.instance_id, execution.roots, self.witness_root, self.index, self.slots);
    }
    pub fn projectionEntry(self: *const Proposal, a: std.mem.Allocator, native: *const Capacity.Proposal, context: Public.Context) !Seal.Entry {
        _ = try self.memoryEntry(a, native, context);
        const execution = try native.bind(context);
        const projections = try Source.slotsFromShapeForMode(a, &native.shape, native.external_retirements, self.register_custody_mode);
        defer a.free(projections);
        return Proof.entry(self.template_id, execution.instance_id, execution.roots, self.witness_root, self.index, self.frame, projections, self.slots);
    }
};
pub const Sink = struct { context: *anyopaque, put_fused: *const fn (*anyopaque, u32, *Proof.Proof) anyerror!void };

pub const Traces = struct {
    allocator: std.mem.Allocator,
    slots: []Memory.Slot,
    traces: []Trace,
    inputs: []Memory.Input,
    initialized: usize = 0,
    pub fn init(a: std.mem.Allocator, owner: *Native.Owner, frame: Frame, limits: Limits) !Traces {
        try limits.fused.requireShape(&owner.statement, owner.external_retirements);
        const slots = try Source.memorySlots(a, &owner.statement, owner.external_retirements, frame, limits.memory.register_custody_mode);
        errdefer a.free(slots);
        const metadata = try std.math.add(usize, @sizeOf(Proposal), try std.math.mul(usize, slots.len, @sizeOf(Memory.Slot) + @sizeOf(Trace) + @sizeOf(Memory.Input)));
        if (slots.len > limits.memory.max_slots or metadata > limits.memory.max_metadata_bytes) return error.CapacityFusedResourceLimit;
        var cells: usize = 0;
        for (slots) |slot| cells = try std.math.add(usize, cells, try std.math.mul(usize, Integer.COLUMN_COUNT, @as(usize, 1) << @intCast(slot.log_size)));
        if (cells > limits.memory.max_witness_cells) return error.CapacityFusedResourceLimit;
        const traces = try a.alloc(Trace, slots.len);
        errdefer a.free(traces);
        const inputs = try a.alloc(Memory.Input, slots.len);
        errdefer a.free(inputs);
        var self = Traces{ .allocator = a, .slots = slots, .traces = traces, .inputs = inputs };
        errdefer for (self.traces[0..self.initialized]) |*trace| trace.deinit();
        for (slots, inputs, 0..) |slot, *input, index| {
            var offset: usize = 0;
            var found: ?usize = null;
            for (owner.statement.component_descs[0..owner.statement.n_components], 0..) |desc, component| {
                if (offset == slot.main_offset and desc.family == slot.family) {
                    found = component;
                    break;
                }
                offset += desc.n_columns;
            }
            self.traces[index] = try Trace.initForMode(a, slot.family, &owner.opcode_columns.components[found orelse return error.InvalidCapacityFusedSource], slot.slot, slot.log_size, frame, limits.memory.register_custody_mode);
            self.initialized += 1;
            input.* = .{ .descriptor = slot, .trace = &self.traces[index] };
        }
        return self;
    }
    pub fn deinit(self: *Traces) void {
        for (self.traces[0..self.initialized]) |*trace| trace.deinit();
        self.allocator.free(self.inputs);
        self.allocator.free(self.traces);
        self.allocator.free(self.slots);
        self.* = undefined;
    }
    pub fn census(self: *const Traces) !u64 {
        var count: u64 = 0;
        for (self.traces) |*trace| for (0..trace.domainSize()) |row| if ((try trace.row(row)).active) {
            count = try std.math.add(u64, count, 1);
        };
        return count;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        proposals: []const Proposal,
        limits: Limits,
        sink: Sink,
        next: u32 = 0,
        pub fn collect(a: std.mem.Allocator, owner: *Native.Owner, native: *const Capacity.Proposal, frame: Frame, global: *Counter.Set, limits: Limits) !Proposal {
            if (!owner.native_only_v5 or !owner.tables_ready or owner.failed or owner.interaction_ready or frame.clock_frame != .leaf_local or frame.global_first_cycle == 0 or
                frame.cycle_count != owner.statement.public_data.clock or !std.meta.eql(native.public_digest, Public.publicDigest(&owner.statement.public_data))) return error.InvalidCapacityFusedSource;
            try native.template.admit(&owner.statement, owner.external_retirements, native.template_id);
            if (native.external_retirements != owner.external_retirements or
                !std.meta.eql(try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(&native.shape, native.external_retirements), try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(&owner.statement, owner.external_retirements))) return error.InvalidCapacityFusedSource;
            var traces = try Traces.init(a, owner, frame, limits);
            defer traces.deinit();
            const projections = try Source.slotsFromShapeForMode(a, &owner.statement, owner.external_retirements, limits.memory.register_custody_mode);
            defer a.free(projections);
            try limits.fused.require(&owner.statement, owner.external_retirements, projections, traces.slots);
            var counter = try Counter.Counter.init(a, .range_check_8_8);
            defer counter.deinit(a);
            var scheme = try Scheme.init(a, native.template.config);
            defer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            var channel = Proof.firstChannel(native.template_id, @splat(0), native.index, projections, traces.slots);
            var columns: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            defer columns.deinit(a);
            for (traces.inputs) |input| {
                _ = try Bytes.collectCounter(a, input.trace, &counter);
                for (input.trace.witness) |values| try columns.append(a, .{ .log_size = input.descriptor.log_size, .values = values });
            }
            const events = try traces.census();
            const witness_root = if (traces.slots.len == 0) try Source.emptyWitnessRoot(limits.memory.register_custody_mode) else blk: {
                try scheme.commitBorrowedStreaming(a, columns.items, 8, &channel);
                var roots = try scheme.roots(a);
                defer roots.deinit(a);
                if (roots.items.len != 1) return error.InvalidCapacityFusedWitness;
                break :blk roots.items[0];
            };
            const slots = try a.dupe(Memory.Slot, traces.slots);
            // Commit all fallible collection work before merging the exact
            // shared-provider byte counters; pass2 never adds these again.
            for (global.get(.range_check_8_8).values, counter.values) |*value, addend| value.* = value.add(addend);
            return .{ .allocator = a, .slots = slots, .index = native.index, .frame = frame, .register_custody_mode = limits.memory.register_custody_mode, .native_roots = native.roots, .template_id = native.template_id, .public_digest = native.public_digest, .witness_root = witness_root, .byte_snapshot = Snapshot.counterSnapshot(&counter), .event_count = events };
        }
        /// Called before capacity-native proving consumes its source. Native
        /// remains live for its own real proof/capture. Success hands only the
        /// separate fused proof to the sink (or no file for typed absence).
        pub fn produce(self: *Self, a: std.mem.Allocator, native: *Capacity.ForBackend(Backend).FirstRound, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !void {
            if (native.index != self.next or native.index >= self.proposals.len) return error.InvalidCapacityFusedStageOrder;
            const proposal = &self.proposals[native.index];
            if (!native.owns_scheme or proposal.index != native.index or !std.meta.eql(native.roots, proposal.native_roots) or !std.meta.eql(native.template_id, proposal.template_id) or
                !std.meta.eql(native.public_digest, proposal.public_digest) or sealed.register_custody_mode != proposal.register_custody_mode or
                self.limits.memory.register_custody_mode != proposal.register_custody_mode) return error.ChangedCapacityFusedProposal;
            const pin = Receiver.InstancePin{ .shape = &native.source.statement, .external_retirements = native.source.external_retirements, .admission = native.pin, .template = native.template, .template_id = native.template_id, .profile = native.template.execution_profile, .limits = self.limits.fused };
            _ = try Receiver.admit(a, native.index, pin, .{ .frame = proposal.frame, .expected_events = proposal.event_count, .witness_root = proposal.witness_root }, sealed, pins, entries, catalog);
            try Capacity.admitWithCatalog(a, &native.source.statement, native.source.external_retirements, native.pin, native.template, native.template_id, native.instance_id, native.roots, native.index, sealed, pins, entries, catalog);
            var traces = try Traces.init(a, native.source, proposal.frame, self.limits);
            defer traces.deinit();
            if (traces.slots.len != proposal.slots.len or try traces.census() != proposal.event_count) return error.ChangedCapacityFusedProposal;
            for (traces.slots, proposal.slots) |actual, expected| if (!std.meta.eql(actual, expected)) return error.ChangedCapacityFusedProposal;
            const projections = try Source.slotsFromShapeForMode(a, &native.source.statement, native.source.external_retirements, sealed.register_custody_mode);
            defer a.free(projections);
            try self.limits.fused.require(&native.source.statement, native.source.external_retirements, projections, traces.slots);
            var counter = try Counter.Counter.init(a, .range_check_8_8);
            defer counter.deinit(a);
            if (projections.len == 0) {
                try Receiver.requireProofPresence(0, traces.slots.len, false);
                if (!std.meta.eql(proposal.byte_snapshot, Snapshot.counterSnapshot(&counter))) return error.ChangedCapacityFusedProposal;
                self.next += 1;
                return;
            }
            var first = if (traces.slots.len == 0)
                try borrowEmpty(a, &native.scheme, proposal.witness_root)
            else
                try OriginalStage.ForBackend(Backend).borrow(a, &native.scheme, traces.inputs, traces.slots, &counter, native.index, native.template_id);
            defer first.deinit(a);
            if (!std.meta.eql(first.roots[2], proposal.witness_root) or !std.meta.eql(proposal.byte_snapshot, Snapshot.counterSnapshot(&counter))) return error.ChangedCapacityFusedProposal;
            var proof = try Proof.ForBackend(Backend).proveForNativeFirstRound(a, &first, traces.inputs, traces.slots, projections, sealed, pins, entries, catalog, native, native.index, proposal.frame, proposal.witness_root, self.limits.fused);
            var owns = true;
            defer if (owns) proof.deinit(a);
            if (!native.owns_scheme or native.scheme.trees.items.len != 2) return error.ConsumedCapacityFusedNative;
            try self.sink.put_fused(self.sink.context, native.index, &proof);
            owns = false;
            self.next += 1;
        }
        pub fn requireFinished(self: *const Self) !void {
            if (self.next != self.proposals.len) return error.IncompleteCapacityFusedStage;
        }
        fn borrowEmpty(a: std.mem.Allocator, native: *Scheme, absence_root: [32]u8) !Proof.ForBackend(Backend).FirstRound {
            var channel = suite.Channel{};
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, native, &channel);
            errdefer scheme.deinit(a);
            const fixed = try treeLogs(a, scheme.trees.items[0].columns, scheme.config.fri_config.log_blowup_factor);
            errdefer a.free(fixed);
            const main = try treeLogs(a, scheme.trees.items[1].columns, scheme.config.fri_config.log_blowup_factor);
            errdefer a.free(main);
            const snapshots = try a.alloc(Bytes.SNAPSHOT, 0);
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
