//! Physical ordinary-memory proposals and warm native same-root production.
//! No fabricated public admission or receipt; all pass2 IDs bind actual plans.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Owner = @import("blake3_execution_trace.zig").Owner;
const physical = @import("block_v5_cpu_native_root_proposal_v1.zig");
const frame_mod = @import("../air/block/memory_event.zig");
const sidecar = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const slots_mod = @import("block_execution_sidecar_batch_v2.zig");
const trace_mod = @import("block_execution_sidecar_trace_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const bytes = @import("block_execution_byte_range_v2.zig");
const counters = @import("../air/lookups/tables/counter.zig");
const snapshot = @import("../air/block/memory_range_interaction_v2.zig");
const seals = @import("block_v5_source_seal_v1.zig");
const empty = @import("block_v5_empty_opcode_memory_v1.zig");
const producer = @import("block_v5_block_producer_v1.zig");
const Digest = [32]u8;
pub const Limits = struct { max_slots: usize, max_witness_cells: usize, max_metadata_bytes: usize, register_custody_mode: u32 = 0 };
pub const Sink = struct { context: *anyopaque, put_opcode: *const fn (*anyopaque, u32, *sidecar.Proof) anyerror!void };
pub const Proposal = struct {
    register_custody_mode: u32 = 0,
    a: std.mem.Allocator,
    slots: []sidecar.Slot,
    native_roots: seals.Roots,
    template_id: Digest,
    witness_root: Digest,
    byte_snapshot: Digest,
    ordinary_events: u64,
    index: u32,
    frame: frame_mod.Frame,
    pub fn deinit(self: *Proposal) void {
        self.a.free(self.slots);
        self.* = undefined;
    }
    pub fn bind(self: *const Proposal, native: *const physical.Proposal, execution: seals.Entry) !seals.Entry {
        if (self.frame.cycle_count == 0 or execution.family != .execution or execution.index != self.index or native.index != self.index or
            !std.meta.eql(execution.roots, self.native_roots) or !std.meta.eql(native.roots, self.native_roots) or
            !std.meta.eql(native.template_id, self.template_id) or native.first_cycle != self.frame.global_first_cycle or
            native.last_cycle != try std.math.add(u64, native.first_cycle, self.frame.cycle_count - 1)) return error.ChangedV5NativeMemoryProposal;
        try slots_mod.requireRwSlots(self.slots, self.register_custody_mode);
        if (self.slots.len == 0) return empty.firstRoundEntryForMode(self.a, &native.shape, self.frame, execution, self.ordinary_events, self.register_custody_mode);
        return sidecar.packedEntry(execution.instance_id, execution.roots, self.witness_root, self.index, self.slots);
    }
};
pub const Traces = struct {
    a: std.mem.Allocator,
    slots: []sidecar.Slot,
    traces: []trace_mod.Trace,
    inputs: []sidecar.Input,
    initialized: usize = 0,
    pub fn init(a: std.mem.Allocator, owner: *Owner, frame: frame_mod.Frame, limits: Limits) !Traces {
        const slots = try slots_mod.slotsFromStatementForMode(a, &owner.statement, frame, limits.register_custody_mode);
        errdefer a.free(slots);
        const metadata = try std.math.add(usize, @sizeOf(Proposal), try std.math.mul(usize, slots.len, @sizeOf(sidecar.Slot)));
        if (slots.len > limits.max_slots or metadata > limits.max_metadata_bytes) return error.V5NativeMemoryResourceLimit;
        var cells: usize = 0;
        for (slots) |slot| cells = try std.math.add(usize, cells, try std.math.mul(usize, integer.COLUMN_COUNT, @as(usize, 1) << @intCast(slot.log_size)));
        if (cells > limits.max_witness_cells) return error.V5NativeMemoryResourceLimit;
        const traces = try a.alloc(trace_mod.Trace, slots.len);
        errdefer a.free(traces);
        const inputs = try a.alloc(sidecar.Input, slots.len);
        errdefer a.free(inputs);
        var self = Traces{ .a = a, .slots = slots, .traces = traces, .inputs = inputs };
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
            self.traces[index] = try trace_mod.Trace.initForMode(a, slot.family, &owner.opcode_columns.components[found orelse return error.MissingV5NativeMemoryComponent], slot.slot, slot.log_size, slot.frame, limits.register_custody_mode);
            self.initialized += 1;
            input.* = .{ .descriptor = slot, .trace = &self.traces[index] };
        }
        return self;
    }
    pub fn deinit(self: *Traces) void {
        for (self.traces[0..self.initialized]) |*trace| trace.deinit();
        self.a.free(self.inputs);
        self.a.free(self.traces);
        self.a.free(self.slots);
    }
    pub fn census(self: *const Traces) !u64 {
        var total: u64 = 0;
        for (self.traces) |*trace| for (0..trace.domainSize()) |logical| if ((try trace.row(logical)).active) {
            total = try std.math.add(u64, total, 1);
        };
        return total;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Producer = producer.ForLightweightBackend(Backend);
        proposals: []const Proposal,
        limits: Limits,
        sink: Sink,
        next: u32 = 0,
        pub fn hooks(self: *Self) Producer.Hooks {
            return .{ .context = self, .on_first_round = onFirstRound };
        }
        pub fn requireFinished(self: *const Self) !void {
            if (self.next != self.proposals.len) return error.IncompleteV5NativeMemoryStage;
        }
        pub fn collect(a: std.mem.Allocator, owner: *Owner, frame: frame_mod.Frame, native: *const physical.Proposal, global: *counters.Set, limits: Limits) !Proposal {
            if (!owner.native_only_v5 or owner.failed or owner.interaction_ready or !owner.tables_ready or frame.cycle_count == 0 or
                frame.global_first_cycle != native.first_cycle or frame.cycle_count != owner.statement.public_data.clock) return error.InvalidV5NativeMemoryPhase;
            try native.template.admit(&owner.statement, native.template_id);
            if (!std.meta.eql(native.public_digest, @import("block_v5_native_public_admission_v1.zig").publicDigest(&owner.statement.public_data))) return error.InvalidV5NativeMemoryPhase;
            var source = try Traces.init(a, owner, frame, limits);
            defer source.deinit();
            var local = try counters.Counter.init(a, .range_check_8_8);
            defer local.deinit(a);
            var scheme = try Scheme.init(a, native.template.config);
            defer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            var channel = suite.Channel{};
            slots_mod.mixRoster(&channel, native.index, native.template_id, source.slots);
            var witness: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            defer witness.deinit(a);
            for (source.inputs) |input| {
                _ = try bytes.collectCounter(a, input.trace, &local);
                for (input.trace.witness) |values| try witness.append(a, .{ .log_size = input.descriptor.log_size, .values = values });
            }
            const events = try source.census();
            const root = if (source.slots.len == 0) empty.witnessRootForMode(limits.register_custody_mode) else blk: {
                try scheme.commitBorrowedStreaming(a, witness.items, 16, &channel);
                var roots = try scheme.roots(a);
                defer roots.deinit(a);
                if (roots.items.len != 1) return error.InvalidV5NativeMemoryWitness;
                break :blk roots.items[0];
            };
            const slots = try a.dupe(sidecar.Slot, source.slots);
            for (global.get(.range_check_8_8).values, local.values) |*value, addend| value.* = value.add(addend);
            return .{ .register_custody_mode = limits.register_custody_mode, .a = a, .slots = slots, .native_roots = native.roots, .template_id = native.template_id, .witness_root = root, .byte_snapshot = snapshot.counterSnapshot(&local), .ordinary_events = events, .index = native.index, .frame = frame };
        }
        fn onFirstRound(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmExecution) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            if (warm.index != self.next or warm.index >= self.proposals.len) return error.InvalidV5NativeMemoryStageOrder;
            const expected = &self.proposals[warm.index];
            if (self.limits.register_custody_mode != warm.sealed.register_custody_mode or expected.register_custody_mode != warm.sealed.register_custody_mode) return error.MixedV5OpcodeMemoryScope;
            if (!warm.first.owns_scheme or warm.first.native != warm.replay.owner or !std.meta.eql(warm.first.roots, expected.native_roots) or
                !std.meta.eql(warm.first.template_id, expected.template_id)) return error.V5NativeMemoryReplayMismatch;
            var source = try Traces.init(a, warm.replay.owner, expected.frame, self.limits);
            defer source.deinit();
            if (source.slots.len != expected.slots.len or try source.census() != expected.ordinary_events) return error.V5NativeMemoryReplayMismatch;
            for (source.slots, expected.slots) |actual, proposed| if (!std.meta.eql(actual, proposed)) return error.V5NativeMemoryReplayMismatch;
            if (source.slots.len == 0) {
                const entry = try empty.firstRoundEntryForMode(a, &warm.replay.owner.statement, expected.frame, warm.first.entry(), 0, warm.sealed.register_custody_mode);
                var found = false;
                for (warm.entries) |present| if (present.family == .execution_sidecar and present.index == warm.index) {
                    found = std.meta.eql(present, entry);
                };
                if (!found) return error.UntrustedV5EmptyOpcodeEntry;
                self.next += 1;
                return;
            }
            var counter = try counters.Counter.init(a, .range_check_8_8);
            defer counter.deinit(a);
            var first = try borrow(a, &warm.first.scheme, source.inputs, source.slots, &counter, warm.index, warm.first.template_id);
            defer first.deinit(a);
            if (!std.meta.eql(first.roots[2], expected.witness_root) or !std.meta.eql(snapshot.counterSnapshot(&counter), expected.byte_snapshot)) return error.V5NativeMemoryReplayMismatch;
            var proof = try sidecar.ForPackedBackend(Backend).proveForNativeFirstRound(a, &first, source.inputs, source.slots, warm.sealed, warm.pins, warm.entries, warm.catalog, warm.first, warm.index, expected.witness_root);
            var owned = true;
            defer if (owned) proof.deinit(a);
            if (!warm.first.owns_scheme or warm.first.scheme.trees.items.len != 2) return error.ConsumedV5WarmNativeMemory;
            try self.sink.put_opcode(self.sink.context, warm.index, &proof);
            owned = false;
            self.next += 1;
        }
        pub fn borrow(a: std.mem.Allocator, native: *Scheme, inputs: []const sidecar.Input, slots: []const sidecar.Slot, counter: *counters.Counter, index: u32, template_id: Digest) !sidecar.ForPackedBackend(Backend).FirstRound {
            var channel = suite.Channel{};
            slots_mod.mixRoster(&channel, index, template_id, slots);
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, native, &channel);
            errdefer scheme.deinit(a);
            const fixed_logs = try treeLogs(a, scheme.trees.items[0].columns, scheme.config.fri_config.log_blowup_factor);
            errdefer a.free(fixed_logs);
            const main_logs = try treeLogs(a, scheme.trees.items[1].columns, scheme.config.fri_config.log_blowup_factor);
            errdefer a.free(main_logs);
            const snapshots = try a.alloc(bytes.SNAPSHOT, slots.len);
            errdefer a.free(snapshots);
            var witness: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            defer witness.deinit(a);
            for (inputs, snapshots) |input, *pin| {
                pin.* = try bytes.collectCounter(a, input.trace, counter);
                for (input.trace.witness) |values| try witness.append(a, .{ .log_size = input.descriptor.log_size, .values = values });
            }
            try scheme.commitBorrowedStreaming(a, witness.items, 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 3) return error.InvalidV5NativeMemoryWitness;
            for (scheme.trees.items[0..2], native.trees.items) |lease, original| for (lease.columns, original.columns) |column, source_column| {
                if (column.values.ptr != source_column.values.ptr or column.values.len != source_column.values.len) return error.UnsharedV5NativeMemoryTrees;
            };
            return .{ .scheme = scheme, .roots = roots.items[0..3].*, .fixed_logs = fixed_logs, .main_logs = main_logs, .snapshots = snapshots };
        }
    };
}
fn treeLogs(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation, blowup: u32) ![]u32 {
    const out = try a.alloc(u32, columns.len);
    errdefer a.free(out);
    for (columns, out) |column, *log| log.* = try std.math.sub(u32, column.log_size, blowup);
    return out;
}
