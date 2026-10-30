//! Independently compiled heterogeneous verifier roster and exact live parity.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("block_v8_endpoint_group_join_source_v1.zig");
const P = @import("block_v8_endpoint_group_join_public_v1.zig");
const Graph = @import("block_v8_endpoint_group_join_graph_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Rebase = @import("air/blake3_parent_rebase.zig");
const Join = @import("air/blake3_parent_join.zig");
const Attach = @import("air/block_v5_recursive_fixed_graph_attach_v1.zig");
const LiveGraph = @import("air/block_v5_heterogeneous_scoped_graph_rows_v1.zig");
const GlobalG = @import("block_v8_endpoint_join_g_partition_v1.zig");
pub const Options = struct { global_g_repartition: bool = false };
const Lower = @import("air/verifier_arithmetic_lowering.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    compiler_state_live: bool = true,
    g_plan: ?GlobalG.Plan = null,
    cold: []Source.Cold,
    children: []Source.Value,
    values: P.Values,
    graph: Graph.Owned,
    closure: Attach.Owned,
    namespace: Namespace.Plan,
    fixed: Storage.FixedTuple(false),
    wires: []P.Wire,
    context: @import("blake3_execution_parent_protocol.zig").Context,
    pub fn derive(a: std.mem.Allocator, sources: []const Source.Source, extra: []const core.fields.qm31.QM31) !Owned {
        return deriveWithOptions(a, sources, extra, .{});
    }
    pub fn deriveWithOptions(a: std.mem.Allocator, sources: []const Source.Source, extra: []const core.fields.qm31.QM31, options: Options) !Owned {
        if (sources.len != 3) return error.InvalidEndpointJoinSources;
        if (sources[0] != .group or sources[1] != .bridge or sources[2] != .global) return error.InvalidEndpointGroupJoinSources;
        const n = sources[0].group.layout.n;
        if (extra.len != 264) return error.UntrustedEndpointJoinBoundary;
        const boundary = sources[sources.len - 1].global.scope.window.boundary;
        var expected_words: [66]u32 = undefined;
        expected_words[0] = boundary.initial_cpu.pc;
        @memcpy(expected_words[1..33], &boundary.initial_cpu.regs);
        expected_words[33] = boundary.final_cpu.pc;
        @memcpy(expected_words[34..66], &boundary.final_cpu.regs);
        for (expected_words, 0..) |word, i| for (0..4) |byte| if (!extra[4 * i + byte].eql(core.fields.qm31.QM31.fromBase(core.fields.m31.M31.fromCanonical((word >> @as(u5, @intCast(8 * byte))) & 255)))) return error.UntrustedEndpointJoinBoundary;

        try admit(sources);
        const cold = try a.alloc(Source.Cold, sources.len);
        errdefer a.free(cold);
        const children = try a.alloc(Source.Value, sources.len);
        errdefer a.free(children);
        var count: usize = 0;
        errdefer for (0..count) |i| {
            cold[i].deinit();
            children[i].deinit();
        };
        var next: u32 = 1;
        var wires: std.ArrayList(P.Wire) = .empty;
        defer wires.deinit(a);
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42386746, 1, @intCast(sources.len) });
        for (sources, 0..) |s, i| {
            cold[i] = try s.cold(a);
            children[i] = s.values(a) catch |err| {
                cold[i].deinit();
                return err;
            };
            count += 1;
            if (!std.meta.eql(cold[0].context.child_config, cold[i].context.child_config)) return error.EndpointJoinConfigMismatch;
            cold[i].namespace.original.first = next;
            next = try cold[i].namespace.end();
            const id = try cold[i].namespace.identity();
            try Namespace.apply(&cold[i].fixed, &cold[i].namespace, id);
            for (cold[i].wires) |w| try wires.append(a, .{ .circuit = cold[i].namespace.original.map(w.circuit) orelse return error.JoinMissingNamespace, .wire = w.wire, .uses = w.uses, .child = @intCast(i), .source = w.source, .coordinate = w.coordinate });
            ch.mixRoot(s.seal());
            ch.mixRoot(id);
            for (cold[i].context.graph_ids) |digest| ch.mixRoot(digest);
            ch.mixRoot(cold[i].context.transcript_plan_id);
        }
        const values = P.Values{ .children = children, .extra = extra };
        try values.validate();
        var graph = try Graph.Owned.compile(a, values, n);
        errdefer graph.deinit();
        var closure = try Attach.Owned.derive(a, &graph.circuit, graph.sources);
        errdefer closure.deinit();
        const lane = Lower.Lane{ .circuit_id = Attach.CIRCUIT, .active_in = .segment, .circuit_identity = graph.circuit.identity_digest, .graph = graph.circuit.graph() };
        var binary = lane;
        binary.circuit_id += 1;
        binary.active_in = .binary;
        const lanes = [_]Lower.Lane{ lane, binary };
        const reference = try Lower.Reference.seal(&lanes);
        var lower = try Lower.Plan.init(a, reference);
        defer lower.deinit();
        var namespace = try Namespace.prepareForArithmetic(a, closure.fixed, next, .{ .plan = &lower, .reference = reference, .kind = .segment_leaf });
        errdefer namespace.deinit();
        try namespace.requireIndependentMainPort();
        try Namespace.apply(&closure.fixed, &namespace, try namespace.identity());
        for (closure.wires) |w| {
            var out = P.fromGraph(w);
            out.circuit = namespace.original.map(w.circuit) orelse return error.JoinMissingNamespace;
            try wires.append(a, out);
        }
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        inline for (Storage.Airs, 0..) |Air, i| {
            var rows: std.ArrayList(Storage.FixedRow(Air)) = .empty;
            errdefer rows.deinit(a);
            for (cold) |c| try rows.appendSlice(a, c.fixed[i]);
            try rows.appendSlice(a, closure.fixed[i]);
            fixed[i] = try rows.toOwnedSlice(a);
        }
        ch.mixRoot(graph.circuit.identity_digest);
        ch.mixRoot(closure.identity);
        ch.mixRoot(try namespace.identity());
        const g_plan: ?GlobalG.Plan = if (options.global_g_repartition) try GlobalG.Plan.init(fixed) else null;
        if (g_plan) |plan| {
            try plan.applyFixed(a, &fixed);
            ch.mixRoot(plan.identity());
        }
        const seal = ch.digestBytes();
        const context = @import("blake3_execution_parent_protocol.zig").Context{ .child_key_id = seal, .child_config = cold[0].context.child_config, .graph_ids = .{ seal, graph.circuit.identity_digest, closure.identity }, .transcript_plan_id = seal };
        P.sort(wires.items);
        _ = try P.scheduleDigest(wires.items);
        return .{ .allocator = a, .cold = cold, .children = children, .values = values, .graph = graph, .closure = closure, .namespace = namespace, .fixed = fixed, .wires = try wires.toOwnedSlice(a), .context = context, .g_plan = g_plan };
    }
    pub fn live(self: *const Owned, a: std.mem.Allocator, sources: []const Source.Source, captures: []const Source.Capture) !Storage.Prepared {
        return self.liveWithWorkers(a, sources, captures, 1);
    }
    pub fn liveWithWorkers(self: *const Owned, a: std.mem.Allocator, sources: []const Source.Source, captures: []const Source.Capture, source_workers: u8) !Storage.Prepared {
        if (captures.len != sources.len or sources.len != self.cold.len) return error.InvalidEndpointJoinCaptureRoster;
        var batch = try Source.prepareBatch(a, sources, captures, source_workers);
        defer batch.deinit();
        const prepared = batch.entries;
        for (sources, 0..) |_, i| {
            try prepared[i].recursive.rows.partitionHashRows();
            try self.cold[i].namespace.validateLive(&prepared[i].recursive.rows);
            try Rebase.apply(&prepared[i].recursive.rows, &self.cold[i].namespace.original, try self.cold[i].namespace.identity());
            inline for (0..Storage.Airs.len) |j| {
                if (self.cold[i].fixed[j].len != prepared[i].recursive.rows.fixed[j].len) return error.JoinFixedParity;
                for (self.cold[i].fixed[j], prepared[i].recursive.rows.fixed[j]) |x, y| if (!std.meta.eql(x, y)) return error.JoinFixedParity;
            }
        }
        const inputs = try a.alloc(core.fields.qm31.QM31, self.graph.sources.len);
        defer a.free(inputs);
        for (inputs, self.graph.sources) |*v, w| v.* = core.fields.qm31.QM31.fromM31Array(try (P.View{ .values = self.values }).at(w));
        const eval = try a.alloc(core.fields.qm31.QM31, self.graph.circuit.nodes.len);
        defer a.free(eval);
        try self.graph.circuit.evaluateInto(inputs, eval);
        var closure = try LiveGraph.materializeLocallyAdmittedFor(a, .{ .circuit = &self.graph.circuit, .sources = self.graph.sources, .inputs = inputs, .values = eval }, P.View{ .values = self.values });
        defer closure.deinit();
        try self.namespace.validateLive(&closure.rows);
        try Rebase.apply(&closure.rows, &self.namespace.original, try self.namespace.identity());
        const rows = try a.alloc(*Storage.Prepared, sources.len + 1);
        defer a.free(rows);
        const ranges = try a.alloc(Join.Range, rows.len);
        defer a.free(ranges);
        for (prepared, 0..) |*v, i| {
            rows[i] = &v.recursive.rows;
            ranges[i] = .{ .first = self.cold[i].namespace.original.first, .end = try self.cold[i].namespace.end() };
        }
        rows[sources.len] = &closure.rows;
        ranges[sources.len] = .{ .first = self.namespace.original.first, .end = try self.namespace.end() };
        var joined = try Join.joinManyDraining(a, rows, ranges);
        errdefer joined.deinit();
        if (self.g_plan) |plan| try plan.applyDraining(&joined);
        inline for (0..Storage.Airs.len) |i| {
            if (joined.fixed[i].len != self.fixed[i].len) return error.JoinFixedParity;
            for (joined.fixed[i], self.fixed[i]) |x, y| if (!std.meta.eql(x, y)) return error.JoinFixedParity;
        }
        return joined;
    }
    /// Fixed/live parity and the retained committed key have no remaining
    /// borrow of cold compiler rows. Keep only authenticated public operands.
    pub fn releaseCompilerState(self: *Owned) void {
        if (!self.compiler_state_live) return;
        const a = self.allocator;
        for (self.cold) |*c| c.deinit();
        a.free(self.cold);
        self.cold = &.{};
        self.graph.deinit();
        self.closure.deinit();
        self.namespace.deinit();
        inline for (0..Storage.Airs.len) |i| {
            a.free(self.fixed[i]);
            self.fixed[i] = &.{};
        }
        self.compiler_state_live = false;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        self.releaseCompilerState();
        for (self.children) |*v| v.deinit();
        a.free(self.children);
        a.free(self.wires);
        self.* = undefined;
    }
    pub fn memoryCensus(self: *const Owned) !MemoryCensus {
        if (!self.compiler_state_live) return error.JoinCompilerStateReleased;
        var out: MemoryCensus = .{};
        inline for (Storage.Airs, 0..) |Air, i| {
            const rows = self.fixed[i].len;
            const log: u32 = if (rows < 2) 1 else std.math.log2_int_ceil(usize, rows);
            const padded = @as(u64, 1) << @intCast(log);
            const fixed = try std.math.mul(u64, rows, @sizeOf(Storage.FixedRow(Air)));
            const main = try std.math.mul(u64, padded, Air.PHYSICAL_MAIN_COLUMN_COUNT * @sizeOf(core.fields.m31.M31));
            out.airs[i] = .{ .slot = i, .name = @typeName(Air), .rows = rows, .padded_rows = padded, .main_columns = Air.PHYSICAL_MAIN_COLUMN_COUNT, .fixed_words = @typeInfo(Storage.FixedRow(Air)).array.len, .fixed_bytes = fixed, .main_bytes = main, .main_padding_bytes = try std.math.mul(u64, padded - rows, Air.PHYSICAL_MAIN_COLUMN_COUNT * @sizeOf(core.fields.m31.M31)) };
            out.aggregate_fixed_bytes = try std.math.add(u64, out.aggregate_fixed_bytes, fixed);
            out.predicted_joined_main_bytes = try std.math.add(u64, out.predicted_joined_main_bytes, main);
            out.predicted_joined_retained_bytes = try std.math.add(u64, out.predicted_joined_retained_bytes, fixed + main + Air.PHYSICAL_MAIN_COLUMN_COUNT * @sizeOf(@import("stwo_prover_engine").pcs.ColumnEvaluation));
            for (self.cold) |cold| out.cold_children_fixed_bytes = try std.math.add(u64, out.cold_children_fixed_bytes, try std.math.mul(u64, cold.fixed[i].len, @sizeOf(Storage.FixedRow(Air))));
            out.closure_fixed_bytes = try std.math.add(u64, out.closure_fixed_bytes, try std.math.mul(u64, self.closure.fixed[i].len, @sizeOf(Storage.FixedRow(Air))));
        }
        return out;
    }
};
fn admit(sources: []const Source.Source) !void {
    if (sources.len != 3 or sources[0] != .group or sources[1] != .bridge or sources[2] != .global) return error.InvalidEndpointGroupJoinSources;
    const group = sources[0].group;
    const n = group.layout.n;
    const bridge = sources[1].bridge;
    const global = sources[2].global;
    if (n == 0 or n > 32 or bridge.scope.batch_start != 0 or bridge.scope.sources.len != n or bridge.scope.roster_count != n or !std.meta.eql(bridge.scope.epoch, global.statement.input.epoch) or global.scope.cohortCount() != n or bridge.scope.endpoint_count != global.scope.event_count or group.statement.trusted.cohort_count != n) return error.UntrustedEndpointJoinCoverage;
    if (!std.meta.eql(group.statement.trusted.elf_sha256, global.scope.window.initial.elf_sha256) or !std.meta.eql(group.scope.image.root.bytes, global.scope.window.program_root)) return error.UntrustedEndpointJoinProgram;
    var cycle: u64 = 1;
    for (group.statement.input.members, bridge.scope.sources, 0..) |member, pin, i| {
        const derived = group.scope.source(i);
        if (member.cohort_ordinal != i or !std.meta.eql(pin.local_identity, derived.local_identity) or !std.meta.eql(pin.local_epoch, derived.local_epoch) or !std.meta.eql(pin.endpoint_root, derived.endpoint_root) or !std.meta.eql(pin.policy, derived.policy) or pin.endpoint_count != derived.endpoint_count) return error.UntrustedEndpointJoinLocalRoot;
        const frame = member.frame;
        if (frame.clock_frame != .leaf_local or frame.global_first_cycle != cycle or frame.cycle_count != member.shape.public_data.clock or frame.cycle_count > global.scope.window.span_mode.endpoint_cohorts.max_cohort_cycles) return error.UntrustedEndpointJoinClockChain;
        cycle = try std.math.add(u64, cycle, frame.cycle_count);
    }
    if (cycle - 1 != global.scope.window.boundary.cycles) return error.UntrustedEndpointJoinClockChain;
    const entry = try global.scope.entry(global.statement.input.roots);
    if (!std.meta.eql(entry, bridge.statement.input.global_memory)) return error.UntrustedEndpointJoinGlobalRoot;
}

pub const AirMemory = struct { slot: usize, name: []const u8, rows: usize, padded_rows: u64, main_columns: usize, fixed_words: usize, fixed_bytes: u64, main_bytes: u64, main_padding_bytes: u64 };
pub const MemoryCensus = struct { airs: [Storage.Airs.len]AirMemory = undefined, aggregate_fixed_bytes: u64 = 0, cold_children_fixed_bytes: u64 = 0, closure_fixed_bytes: u64 = 0, predicted_joined_main_bytes: u64 = 0, predicted_joined_retained_bytes: u64 = 0 };
