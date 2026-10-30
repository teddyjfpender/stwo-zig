//! Finite raw-input witness schedule. All numerical source values remain on
//! device. Borrowed original plans must outlive this schedule and its proof.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const Program = @import("resident_parent_program_v1.zig");
const Routes = @import("resident_parent_value_routes_v1.zig");
const Hash = @import("resident_parent_hash_plan_v1.zig");
const Arithmetic = @import("resident_parent_arithmetic_v1.zig");
const Framework = @import("resident_parent_framework_plan_v1.zig");
const Paths = @import("resident_parent_child_paths_runtime_v1.zig");
const Answers = @import("resident_parent_deep_answers_plan_v1.zig");
const FriExpand = @import("resident_parent_fri_expand_v1.zig");
const Child = @import("resident_parent_child_runtime_v1.zig");
const Resolve = @import("resident_parent_wire_resolve_v1.zig");
const Readonly = @import("resident_parent_readonly_v1.zig");
pub const Types = @import("resident_parent_composite_types_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 16384;
pub const Slot = enum(u32) { main, resident, writes, hash_rows, cohorts, calls, sources, fixed, hash_input, hash_sources, hash_calls, hash_levels, hash_phases, hash_wires, hash_g, hash_xor };
pub fn id(s: Slot) u32 {
    return FIRST_ID + @intFromEnum(s);
}
pub const Limits = struct { max_metadata_bytes: usize = 256 << 20, max_extra_bytes: usize = 32 << 30, max_tasks: usize = 1 << 20 };
pub const Plan = struct {
    arena: std.heap.ArenaAllocator,
    program: *const Program.Owned,
    routes: *const Routes.Plan,
    hash: *const Hash.Owned,
    arithmetic: *const Arithmetic.Cold.Plan,
    framework: Framework.Plan,
    readonly: ?*const Readonly.Cold.Plan,
    readonly_requirements: ?Readonly.Requirements,
    resolver: ?*const Resolve.Cold.Plan,
    child: ?Child.Plan,
    fri_expand: ?*const FriExpand.Plan,
    answers: ?*const Answers.Plan,
    paths: ?Paths.Plan,
    tasks: []const Types.Task,
    writes: []const Types.Write,
    hash_rows: []const Types.HashRow,
    cohorts: [23]Types.Cohort,
    requirements: []cuda.runtime.arena.Requirement,
    main_words: usize,
    pub fn init(backing: std.mem.Allocator, program: *const Program.Owned, routes: *const Routes.Plan, hash: *const Hash.Owned, arithmetic: *const Arithmetic.Cold.Plan, tasks: []const Types.Task, writes: []const Types.Write, hash_rows: []const Types.HashRow, row_counts: [23]usize, readonly: ?*const Readonly.Cold.Plan, resolver: ?*const Resolve.Cold.Plan, limits: Limits) !Plan {
        return initWithChild(backing, program, routes, hash, arithmetic, tasks, writes, hash_rows, row_counts, readonly, resolver, null, limits);
    }
    pub fn initWithChild(backing: std.mem.Allocator, program: *const Program.Owned, routes: *const Routes.Plan, hash: *const Hash.Owned, arithmetic: *const Arithmetic.Cold.Plan, tasks: []const Types.Task, writes: []const Types.Write, hash_rows: []const Types.HashRow, row_counts: [23]usize, readonly: ?*const Readonly.Cold.Plan, resolver: ?*const Resolve.Cold.Plan, child: ?Child.Plan, limits: Limits) !Plan {
        return initWithProducers(backing, program, routes, hash, arithmetic, tasks, writes, hash_rows, row_counts, readonly, resolver, child, null, limits);
    }
    pub fn initWithProducers(backing: std.mem.Allocator, program: *const Program.Owned, routes: *const Routes.Plan, hash: *const Hash.Owned, arithmetic: *const Arithmetic.Cold.Plan, tasks: []const Types.Task, writes: []const Types.Write, hash_rows: []const Types.HashRow, row_counts: [23]usize, readonly: ?*const Readonly.Cold.Plan, resolver: ?*const Resolve.Cold.Plan, child: ?Child.Plan, fri_expand: ?*const FriExpand.Plan, limits: Limits) !Plan {
        return initComplete(backing, program, routes, hash, arithmetic, tasks, writes, hash_rows, row_counts, readonly, resolver, child, fri_expand, null, limits);
    }
    pub fn initComplete(backing: std.mem.Allocator, program: *const Program.Owned, routes: *const Routes.Plan, hash: *const Hash.Owned, arithmetic: *const Arithmetic.Cold.Plan, tasks: []const Types.Task, writes: []const Types.Write, hash_rows: []const Types.HashRow, row_counts: [23]usize, readonly: ?*const Readonly.Cold.Plan, resolver: ?*const Resolve.Cold.Plan, child: ?Child.Plan, fri_expand: ?*const FriExpand.Plan, answers: ?*const Answers.Plan, limits: Limits) !Plan {
        return initFull(backing, program, routes, hash, arithmetic, tasks, writes, hash_rows, row_counts, readonly, resolver, child, fri_expand, answers, null, limits);
    }
    pub fn initFull(backing: std.mem.Allocator, program: *const Program.Owned, routes: *const Routes.Plan, hash: *const Hash.Owned, arithmetic: *const Arithmetic.Cold.Plan, tasks: []const Types.Task, writes: []const Types.Write, hash_rows: []const Types.HashRow, row_counts: [23]usize, readonly: ?*const Readonly.Cold.Plan, resolver: ?*const Resolve.Cold.Plan, child: ?Child.Plan, fri_expand: ?*const FriExpand.Plan, answers: ?*const Answers.Plan, paths: ?Paths.Plan, limits: Limits) !Plan {
        if (tasks.len == 0 or tasks.len > limits.max_tasks or limits.max_extra_bytes == 0) return error.InvalidResidentComposite;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        const p = program.view();
        const r = routes.view();
        const h = hash.view();
        const input_metadata = try std.math.add(usize, h.input_bytes, try std.math.mul(usize, try std.math.add(usize, arithmetic.input_words, r.bounds.resident_words), 4));
        const schedule_metadata = try std.math.add(usize, try std.math.mul(usize, tasks.len, @sizeOf(Types.Task)), try std.math.add(usize, try std.math.mul(usize, writes.len, @sizeOf(Types.Write)), try std.math.mul(usize, hash_rows.len, @sizeOf(Types.HashRow))));
        if (try std.math.add(usize, input_metadata, schedule_metadata) > limits.max_metadata_bytes) return error.ResidentCompositeResourceLimit;
        const hash_ready = try a.alloc(bool, h.input_bytes);
        @memset(hash_ready, false);
        const arithmetic_ready = try a.alloc(bool, arithmetic.input_words * 4);
        @memset(arithmetic_ready, false);
        var main_staged = std.AutoHashMap(u32, u32).init(a);
        var ready_rows = std.AutoHashMap(u64, u32).init(a);
        const resident_ready = try a.alloc(bool, r.bounds.resident_words * 4);
        @memset(resident_ready, false);
        var cohorts: [23]Types.Cohort = undefined;
        var main_words: usize = 0;
        for (p.cohorts[0..23], &cohorts, row_counts) |c, *out, active| {
            const rows = @as(usize, 1) << @intCast(c.trace_log);
            if (active > rows) return error.InvalidResidentComposite;
            out.* = .{ .first_word = main_words, .rows = @intCast(rows), .columns = c.columns[1] };
            main_words = try std.math.add(usize, main_words, try std.math.mul(usize, rows, c.columns[1]));
        }
        if (main_words != r.bounds.main_words or main_words > std.math.maxInt(u32) or r.bounds.arithmetic_words != arithmetic.value_words or r.bounds.hash_words != h.wire_count) return error.InvalidResidentComposite;
        var counts: [23]usize = @splat(0);
        for (r.calls) |c| counts[c.cohort] += 1;
        const g_seen = try a.alloc(bool, h.calls.len * 56);
        @memset(g_seen, false);
        const x_seen = try a.alloc(bool, h.calls.len * 16);
        @memset(x_seen, false);
        var destinations = std.AutoHashMap(u64, void).init(a);
        for (hash_rows) |m| {
            if (m.kind > 1 or m.destination_cohort >= 23 or m.destination_logical_row >= row_counts[m.destination_cohort]) return error.InvalidResidentComposite;
            const c = m.destination_cohort;
            if (if (m.kind == 0) c != 0 and c != 20 and c != 21 and c != 22 else c != 1) return error.InvalidResidentComposite;
            const seen = if (m.kind == 0) g_seen else x_seen;
            if (m.source_logical_row >= seen.len or seen[m.source_logical_row]) return error.InvalidResidentComposite;
            seen[m.source_logical_row] = true;
            const key = (@as(u64, c) << 32) | m.destination_logical_row;
            if (destinations.contains(key)) return error.InvalidResidentComposite;
            try destinations.put(key, {});
            counts[c] += 1;
        }
        for (g_seen) |v| if (!v) return error.IncompleteResidentComposite;
        for (x_seen) |v| if (!v) return error.IncompleteResidentComposite;
        if (!std.mem.eql(usize, &counts, &row_counts)) return error.IncompleteResidentComposite;
        const write_done = try a.alloc(bool, writes.len);
        @memset(write_done, false);
        const frame_done = try a.alloc(bool, h.frames.len);
        @memset(frame_done, false);
        const graph_done = try a.alloc(bool, arithmetic.graphs.len);
        @memset(graph_done, false);
        const direct_done = try a.alloc(bool, r.groups.len);
        @memset(direct_done, false);
        const scatter_done = try a.alloc(bool, hash_rows.len);
        @memset(scatter_done, false);
        var readonly_done = false;
        var resolved: usize = 0;
        var expanded = false;
        var paths_done = false;
        var answer_destination: ?u32 = null;
        var answers_derived = false;
        if (answers) |ap| if (ap.graph_index >= arithmetic.graph_ids.len or !std.meta.eql(ap.graph_identity, arithmetic.graph_ids[ap.graph_index])) return error.InvalidResidentComposite;
        var child_replayed = false;
        var child_gathered: [3]bool = @splat(false);
        if (resolver) |rp| if (rp.main_words != main_words) return error.InvalidResidentComposite;
        if (r.bounds.readonly_words != (if (readonly) |ro| ro.view().argument_rows * 4 else @as(usize, 0))) return error.InvalidResidentComposite;
        var previous: u32 = 0;
        for (tasks) |task| {
            if (task.phase < previous) return error.InvalidResidentCompositeOrder;
            previous = task.phase;
            switch (task.operation) {
                .write => |range| {
                    try mark(write_done, range.first, range.count);
                    const batch = writes[range.first..][0..range.count];
                    try validateWriteBatch(a, batch);
                    // Check every read before publishing any concurrent write.
                    for (batch) |w| {
                        try Routes.validateSource(w.source, r.bounds, task.phase);
                        try requireSourceReady(w.source, &cohorts, &ready_rows, &main_staged, resident_ready, frame_done, h, graph_done, arithmetic, readonly_done);
                    }
                    for (writes[range.first..][0..range.count]) |w| {
                        if (w.phase != task.phase or w.source.ready_phase > task.phase or w.bytes == 0 or w.bytes > 4) return error.InvalidResidentCompositeOrder;
                        const limit = switch (w.destination) {
                            .hash_bytes => h.input_bytes,
                            .arithmetic_inputs => arithmetic.input_words * 4,
                            .resident_words => r.bounds.resident_words * 4,
                            .main_words => main_words * 4,
                        };
                        if (w.byte_offset > limit or w.bytes > limit - w.byte_offset) return error.InvalidResidentComposite;
                        try Routes.validateSource(w.source, r.bounds, task.phase);
                        switch (w.destination) {
                            .hash_bytes => try mark(hash_ready, w.byte_offset, w.bytes),
                            .arithmetic_inputs => try mark(arithmetic_ready, w.byte_offset, w.bytes),
                            .main_words => {
                                if (w.bytes != 4 or w.byte_offset % 4 != 0) return error.InvalidResidentComposite;
                                const word = w.byte_offset / 4;
                                if (main_staged.contains(word)) return error.InvalidResidentComposite;
                                // Only stage values that a later canonical row constructor
                                // necessarily overwrites; padding cannot acquire private data.
                                var owner: ?usize = null;
                                for (r.groups, 0..) |group, gi| {
                                    for (r.calls[group.first..][0..group.count]) |call| {
                                        const c = cohorts[call.cohort];
                                        const physical = @import("../../frontends/riscv/recursion/air/framework_interaction.zig").committedRow(call.logical_row, call.trace_log);
                                        if (word >= c.first_word and word < c.first_word + @as(usize, c.rows) * c.columns and (word - c.first_word) % c.rows == physical) owner = gi;
                                    }
                                }
                                const group_index = owner orelse return error.InvalidResidentComposite;
                                if (direct_done[group_index]) return error.InvalidResidentCompositeOrder;
                                try main_staged.put(word, task.phase);
                            },
                            .resident_words => try mark(resident_ready, w.byte_offset, w.bytes),
                        }
                    }
                },
                .hash_frame => |index| {
                    try mark(frame_done, index, 1);
                    const frame = h.frames[index];
                    try requireReady(hash_ready, frame.input_first, frame.input_bytes);
                },
                .arithmetic => |range| {
                    if (answers) |ap| if (ap.graph_index >= range.first and ap.graph_index < @as(usize, range.first) + range.count and !answers_derived) return error.InvalidResidentCompositeOrder;
                    try mark(graph_done, range.first, range.count);
                    for (arithmetic.graphs[range.first..][0..range.count]) |graph| try requireReady(arithmetic_ready, @as(usize, graph.input_first) * 16, @as(usize, graph.input_count) * 16);
                },
                .child_paths => |dest| {
                    const pp = paths orelse return error.InvalidResidentComposite;
                    const cp = child orelse return error.InvalidResidentComposite;
                    if (!expanded or !child_replayed or paths_done or pp.packet != cp.packet) return error.InvalidResidentCompositeOrder;
                    for (pp.layout.trees) |tree| if (tree.kind == 1) try requireReady(resident_ready, @as(usize, tree.values_first) * 4, @as(usize, cp.packet.query_count) * tree.leaf_count * tree.leaf_width * 4);
                    try mark(resident_ready, @as(usize, dest.destination_first) * 4, @as(usize, pp.layout.output_words) * 4);
                    paths_done = true;
                },
                .zero_answers => |dest| {
                    const ap = answers orelse return error.InvalidResidentComposite;
                    if (answer_destination != null) return error.InvalidResidentCompositeOrder;
                    try mark(resident_ready, @as(usize, dest.destination_first) * 4, @as(usize, ap.output_words) * 4);
                    answer_destination = dest.destination_first;
                },
                .derive_answers => {
                    const ap = answers orelse return error.InvalidResidentComposite;
                    if (answer_destination == null or answers_derived or graph_done[ap.graph_index]) return error.InvalidResidentCompositeOrder;
                    const graph = arithmetic.graphs[ap.graph_index];
                    try requireReady(arithmetic_ready, @as(usize, graph.input_first) * 16, @as(usize, graph.input_count) * 16);
                    answers_derived = true;
                },
                .fri_expand => |dest| {
                    const fp = fri_expand orelse return error.InvalidResidentComposite;
                    const cp = child orelse return error.InvalidResidentComposite;
                    if (!child_replayed or expanded or (answers != null and !answers_derived) or fp.query_count != cp.packet.query_count or fp.raw_words != cp.packet.words.len) return error.InvalidResidentCompositeOrder;
                    try requireReady(resident_ready, @as(usize, dest.deep_first) * 4, @as(usize, fp.query_count) * 16);
                    try requireReady(resident_ready, @as(usize, dest.alpha_first) * 4, fp.layers.len * 16);
                    try mark(resident_ready, @as(usize, dest.destination_first) * 4, @as(usize, fp.output_words) * 4);
                    expanded = true;
                },
                .child_replay => |dest| {
                    const cp = child orelse return error.InvalidResidentComposite;
                    if (child_replayed or dest.output_first > r.bounds.resident_words or cp.transcript.output_words > r.bounds.resident_words - dest.output_first or dest.trace_first > r.bounds.resident_words or cp.transcript.trace_words > r.bounds.resident_words - dest.trace_first) return error.InvalidResidentComposite;
                    if (dest.output_first < @as(usize, dest.trace_first) + cp.transcript.trace_words and dest.trace_first < @as(usize, dest.output_first) + cp.transcript.output_words) return error.InvalidResidentComposite;
                    try mark(resident_ready, @as(usize, dest.output_first) * 4, @as(usize, cp.transcript.output_words) * 4);
                    try mark(resident_ready, @as(usize, dest.trace_first) * 4, @as(usize, cp.transcript.trace_words) * 4);
                    child_replayed = true;
                },
                .child_gather => |graph| {
                    if (!child_replayed or child_gathered[@intFromEnum(graph)]) return error.InvalidResidentCompositeOrder;
                    const cp = child.?;
                    const descriptors = switch (graph) {
                        .composition => cp.routes.composition,
                        .deep => cp.routes.deep,
                        .fri => cp.routes.fri,
                    };
                    for (descriptors) |descriptor| {
                        if (descriptor.kind == @intFromEnum(@import("resident_parent_child_packet_v1.zig").Kind.resident_field)) try requireReady(resident_ready, @as(usize, descriptor.index) * 4, 4);
                        try mark(arithmetic_ready, @as(usize, descriptor.destination) * 4, 4);
                    }
                    child_gathered[@intFromEnum(graph)] = true;
                },
                .resolve => |request| {
                    const rp = resolver orelse return error.InvalidResidentComposite;
                    const count: usize = request.count;
                    if (count == 0 or resolved > rp.requests.len or count > rp.requests.len - resolved or request.resident_first > r.bounds.resident_words or count * 4 > r.bounds.resident_words - request.resident_first) return error.InvalidResidentComposite;
                    for (rp.requests[resolved..][0..count]) |rq| {
                        if (rq.phase != task.phase) return error.InvalidResidentCompositeOrder;
                        for (rp.instructions[rq.first..][0..rq.count]) |instruction| if (instruction.op == @intFromEnum(Resolve.Cold.Registry.Op.main)) {
                            const actual = try mainReadyPhase(instruction.value, &cohorts, &ready_rows, &main_staged);
                            if (actual >= task.phase) return error.InvalidResidentCompositeOrder;
                        };
                    }
                    try mark(resident_ready, @as(usize, request.resident_first) * 4, count * 16);
                    resolved += count;
                },
                .readonly => {
                    if (readonly == null or readonly_done) return error.InvalidResidentCompositeOrder;
                    for (r.groups, 0..) |group, i| if (group.cohort == 17 and !direct_done[i]) return error.InvalidResidentCompositeOrder;
                    readonly_done = true;
                },
                .direct_group => |index| {
                    try mark(direct_done, index, 1);
                    if (r.groups[index].cohort == 16 and !readonly_done) return error.InvalidResidentCompositeOrder;
                    const group = r.groups[index];
                    if (group.phase != task.phase) return error.InvalidResidentCompositeOrder;
                    for (r.calls[group.first..][0..group.count]) |call| for (r.sources[call.source_first..][0..call.source_count]) |source| try requireSourceReady(source, &cohorts, &ready_rows, &main_staged, resident_ready, frame_done, h, graph_done, arithmetic, readonly_done);
                    for (r.calls[group.first..][0..group.count]) |call| {
                        const physical = @import("../../frontends/riscv/recursion/air/framework_interaction.zig").committedRow(call.logical_row, call.trace_log);
                        try ready_rows.put((@as(u64, call.cohort) << 32) | physical, task.phase);
                    }
                },
                .scatter_hash => |range| {
                    try mark(scatter_done, range.first, range.count);
                    for (hash_rows[range.first..][0..range.count]) |m| {
                        const call = m.source_logical_row / @as(u32, if (m.kind == 0) 56 else 16);
                        var frame: usize = 0;
                        while (frame < h.frames.len and call >= h.frames[frame].first_call + h.frames[frame].calls) : (frame += 1) {}
                        if (frame == h.frames.len or !frame_done[frame]) return error.InvalidResidentCompositeOrder;
                        const physical = @import("../../frontends/riscv/recursion/air/framework_interaction.zig").committedRow(m.destination_logical_row, p.cohorts[m.destination_cohort].trace_log);
                        try ready_rows.put((@as(u64, m.destination_cohort) << 32) | physical, task.phase);
                    }
                },
            }
        }
        if (readonly != null and !readonly_done) return error.IncompleteResidentComposite;
        if (resolver) |rp| if (resolved != rp.requests.len) return error.IncompleteResidentComposite;
        if (paths != null and !paths_done) return error.IncompleteResidentComposite;
        if (answers != null and !answers_derived) return error.IncompleteResidentComposite;
        if (fri_expand != null and !expanded) return error.IncompleteResidentComposite;
        if (child != null and (!child_replayed or !std.mem.allEqual(bool, &child_gathered, true))) return error.IncompleteResidentComposite;
        for ([_][]const bool{ write_done, frame_done, graph_done, direct_done, scatter_done }) |done| for (done) |v| if (!v) return error.IncompleteResidentComposite;
        try requireReady(hash_ready, 0, hash_ready.len);
        try requireReady(arithmetic_ready, 0, arithmetic_ready.len);
        var framework = try Framework.Plan.init(backing, program, .{ .max_extra_bytes = limits.max_extra_bytes });
        errdefer framework.deinit();
        var requirements: std.ArrayList(cuda.runtime.arena.Requirement) = .empty;
        try requirements.appendSlice(a, framework.requirements);
        const readonly_requirements = if (readonly) |ro| try Readonly.Requirements.init(ro, limits.max_extra_bytes) else null;
        if (readonly_requirements) |rr| try requirements.appendSlice(a, &rr.slots);
        if (resolver) |rp| try requirements.appendSlice(a, try Resolve.requirements(a, rp));
        if (child) |cp| try requirements.appendSlice(a, try cp.requirements(a));
        if (paths) |pp| try requirements.appendSlice(a, try pp.requirements(a));
        if (fri_expand) |fp| try requirements.appendSlice(a, try fp.requirements(a));
        const ar = try Arithmetic.requirements(a, arithmetic);
        try requirements.appendSlice(a, ar);
        const sizes = [_]usize{ main_words, @max(1, r.bounds.resident_words), @max(1, writes.len * @sizeOf(Types.Write) / 4), @max(1, hash_rows.len * @sizeOf(Types.HashRow) / 4), 23 * @sizeOf(Types.Cohort) / 4, @max(1, r.calls.len * @sizeOf(Routes.Call) / 4), @max(1, r.sources.len * @sizeOf(Routes.Source) / 4), @max(1, r.fixed.len), @max(1, (h.input_bytes + 3) / 4), @max(1, h.sources.len * @sizeOf(Hash.Source) / 4), h.calls.len * @sizeOf(Hash.Call) / 4, h.level_calls.len, h.phase_calls.len, h.wire_count, @as(usize, 82) << @intCast(h.g_log), @as(usize, 12) << @intCast(h.xor_log) };
        var bytes: usize = 0;
        for (sizes, 0..) |n, i| {
            bytes = try std.math.add(usize, bytes, try std.math.mul(usize, n, 4));
            try requirements.append(a, .{ .id = id(@enumFromInt(i)), .words = n, .alignment_words = 64, .live_from = .ingress, .live_through = .trace_generation });
        }
        // The local cap includes all attached producer scratch and metadata,
        // not only this module's packed MAIN and routing storage.
        bytes = 0;
        for (requirements.items) |requirement| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, requirement.words, 4));
        if (bytes > limits.max_extra_bytes) return error.ResidentCompositeResourceLimit;
        const metadata = try std.math.add(usize, tasks.len * @sizeOf(Types.Task), writes.len * @sizeOf(Types.Write) + hash_rows.len * @sizeOf(Types.HashRow));
        if (metadata > limits.max_metadata_bytes) return error.ResidentCompositeResourceLimit;
        const owned_tasks = try a.dupe(Types.Task, tasks);
        const owned_writes = try a.dupe(Types.Write, writes);
        const owned_rows = try a.dupe(Types.HashRow, hash_rows);
        const owned_requirements = try requirements.toOwnedSlice(a);
        return .{ .arena = arena, .program = program, .routes = routes, .hash = hash, .arithmetic = arithmetic, .framework = framework, .readonly = readonly, .readonly_requirements = readonly_requirements, .resolver = resolver, .child = child, .fri_expand = fri_expand, .answers = answers, .paths = paths, .tasks = owned_tasks, .writes = owned_writes, .hash_rows = owned_rows, .cohorts = cohorts, .requirements = owned_requirements, .main_words = main_words };
    }
    pub fn deinit(self: *Plan) void {
        self.framework.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
fn mark(done: []bool, first: usize, count: usize) !void {
    if (count == 0 or first > done.len or count > done.len - first) return error.InvalidResidentComposite;
    for (done[first..][0..count]) |*v| {
        if (v.*) return error.InvalidResidentComposite;
        v.* = true;
    }
}

fn requireReady(done: []const bool, first: usize, count: usize) !void {
    if (first > done.len or count > done.len - first) return error.InvalidResidentComposite;
    for (done[first..][0..count]) |ready| if (!ready) return error.IncompleteResidentComposite;
}
test "resident composite producer inputs must precede consumption and cannot alias" {
    var ready: [8]bool = @splat(false);
    try std.testing.expectError(error.IncompleteResidentComposite, requireReady(&ready, 0, 8));
    try mark(&ready, 0, 4);
    try requireReady(&ready, 0, 4);
    try std.testing.expectError(error.InvalidResidentComposite, mark(&ready, 3, 2));
    try std.testing.expectError(error.IncompleteResidentComposite, requireReady(&ready, 4, 4));
    try mark(&ready, 4, 4);
    try requireReady(&ready, 0, 8);
}

fn mainReadyPhase(word: u32, cohorts: *const [23]Types.Cohort, rows: *const std.AutoHashMap(u64, u32), staged: *const std.AutoHashMap(u32, u32)) !u32 {
    for (cohorts, 0..) |cohort, i| {
        if (word >= cohort.first_word and word < cohort.first_word + @as(usize, cohort.rows) * cohort.columns) {
            const key = (@as(u64, @intCast(i)) << 32) | ((word - cohort.first_word) % cohort.rows);
            if (rows.get(key)) |phase| return phase;
            return staged.get(word) orelse error.UninitializedResidentCompositeSource;
        }
    }
    return error.InvalidResidentComposite;
}
fn requireSourceReady(source: Routes.Source, cohorts: *const [23]Types.Cohort, rows: *const std.AutoHashMap(u64, u32), staged: *const std.AutoHashMap(u32, u32), resident: []const bool, frames: []const bool, h: *const Hash.Data, graphs: []const bool, arithmetic: *const Arithmetic.Cold.Plan, readonly_done: bool) !void {
    switch (@as(Routes.Kind, @enumFromInt(source.kind))) {
        .constant, .raw_u32_le, .raw_byte => {},
        .resident_word, .extract_bit, .resident_byte => try requireReady(resident, @as(usize, source.index) * 4, 4),
        .packed_bytes4 => try requireReady(resident, @as(usize, source.index) * 4, 16),
        .main_word => if (try mainReadyPhase(source.index, cohorts, rows, staged) > source.ready_phase) return error.InvalidResidentCompositeOrder,
        .packed_main4 => for (0..4) |j| {
            const word = try std.math.add(u32, source.index, try std.math.mul(u32, @intCast(j), source.aux));
            if (try mainReadyPhase(word, cohorts, rows, staged) > source.ready_phase) return error.InvalidResidentCompositeOrder;
        },
        .readonly_word => if (!readonly_done) return error.InvalidResidentCompositeOrder,
        .arithmetic_word => {
            var found = false;
            for (arithmetic.graphs, graphs) |graph, ready| if (source.index >= graph.value_word_base and source.index < @as(usize, graph.value_word_base) + @as(usize, graph.node_count) * 4) {
                if (!ready) return error.InvalidResidentCompositeOrder;
                found = true;
                break;
            };
            if (!found) return error.InvalidResidentComposite;
        },
        .hash_word, .hash_byte => {
            var found = false;
            for (h.frames, frames, 0..) |frame, ready, i| {
                const end = if (i + 1 < h.frames.len) h.frames[i + 1].wire_first else h.wire_count;
                if (source.index >= frame.wire_first and source.index < end) {
                    if (!ready) return error.InvalidResidentCompositeOrder;
                    found = true;
                    break;
                }
            }
            if (!found) return error.InvalidResidentComposite;
        },
    }
}
fn validateWriteBatch(a: std.mem.Allocator, writes: []const Types.Write) !void {
    var destinations = std.AutoHashMap(u64, void).init(a);
    defer destinations.deinit();
    for (writes) |write| {
        if (write.bytes == 0 or write.bytes > 4) return error.InvalidResidentComposite;
        for (0..write.bytes) |j| {
            const byte = try std.math.add(u32, write.byte_offset, @intCast(j));
            const key = (@as(u64, @intFromEnum(write.destination)) << 32) | byte;
            if (destinations.contains(key)) return error.InvalidResidentComposite;
            try destinations.put(key, {});
        }
    }
    for (writes) |write| {
        const kind = std.meta.intToEnum(Routes.Kind, write.source.kind) catch return error.InvalidResidentComposite;
        const dest: Types.Destination = switch (kind) {
            .resident_word, .extract_bit, .packed_bytes4, .resident_byte => .resident_words,
            .main_word, .packed_main4 => .main_words,
            else => continue,
        };
        const count: usize = if (kind == .packed_bytes4 or kind == .packed_main4) 4 else 1;
        for (0..count) |j| {
            const stride: u32 = if (kind == .packed_main4) write.source.aux else 1;
            const word = try std.math.add(u32, write.source.index, try std.math.mul(u32, @intCast(j), stride));
            for (0..4) |byte| if (destinations.contains((@as(u64, @intFromEnum(dest)) << 32) | (@as(u64, word) * 4 + byte))) return error.InvalidResidentCompositeOrder;
        }
    }
}

test "resident composite concurrent writes reject aliases and same-launch reads" {
    const a = std.testing.allocator;
    const first = Types.Write{ .source = Routes.Source.constant(3), .destination = .resident_words, .byte_offset = 0, .bytes = 4, .phase = 1 };
    var second = Types.Write{ .source = Routes.Source.resident(0, 1), .destination = .main_words, .byte_offset = 0, .bytes = 4, .phase = 1 };
    try std.testing.expectError(error.InvalidResidentCompositeOrder, validateWriteBatch(a, &.{ first, second }));
    second.source = Routes.Source.constant(1);
    try validateWriteBatch(a, &.{ first, second });
    second.destination = .resident_words;
    try std.testing.expectError(error.InvalidResidentComposite, validateWriteBatch(a, &.{ first, second }));
}
