//! Cold exact bindings for the original parent framework. No challenge, claim,
//! MAIN value or proof-dependent polynomial is evaluated here.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const Program = @import("resident_parent_program_v1.zig");
const Code = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
const Interaction = @import("../../backends/cuda/framework_interaction_codegen_v1.zig");
const Relation = @import("../../frontends/riscv/air/lang/relation.zig");
const Geometry = core.poly.circle.quotient_geometry;
const Selectors = @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig").selectors;
const Wide = @import("resident_parent_counter_wide_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 4096;
pub const Slot = enum(u32) { metadata, relations, powers, source, coefficients, output, scan, normalized, aggregate, logs, wide_bitwise, wide_range };
pub fn id(slot: Slot) u32 {
    return FIRST_ID + @intFromEnum(slot);
}
pub const RelationRoute = extern struct { domain: u32, arity: u32, offset: u32 };
pub const Cohort = struct {
    offsets_trace: []u64,
    offsets_evaluation: []u64,
    routes: []RelationRoute,
    profile: []u32,
    denominators: [8]u32,
    relation_count: u32,
    denominator_count: u32,
    columns: u32,
    composition_id: [32]u8,
    interaction_id: [32]u8,
    composition_name: [:0]u8,
    interaction_name: [:0]u8,
    metadata_start: usize,
    trace_offsets_start: usize,
    evaluation_offsets_start: usize,
    routes_start: usize,
    profile_start: usize,
    denominators_start: usize,
    logs_start: usize,
    extension_logs_start: usize,
};
pub const Limits = struct { max_extra_bytes: usize = 16 << 30, max_log: u32 = 26, wide_counters: bool = false };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    program: *const Program.Owned,
    cohorts: [Program.COMPONENT_COUNT]Cohort,
    requirements: []cuda.runtime.arena.Requirement,
    metadata: []u32,
    scan_ids: [3][32]u8,
    scan_names: [3][:0]u8,
    extra_bytes: usize,
    wide_counters: bool,
    counter_requests: [2]u128,
    pub fn init(backing: std.mem.Allocator, program: *const Program.Owned, limits: Limits) !Plan {
        if (limits.max_extra_bytes == 0 or limits.max_log > 28) return error.InvalidResidentFrameworkPolicy;
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        const p = program.view();
        if (p.composition_log > limits.max_log or p.composition_split < 1 or p.composition_split > 2) return error.UnsupportedResidentFrameworkGeometry;
        const requests = Wide.requestBounds(p.programs[0..Program.AIR_COUNT], p.cohorts[0..Program.AIR_COUNT]);
        const use_wide = limits.wide_counters and Wide.admitted(requests);
        var result: Plan = .{ .allocator = backing, .arena = undefined, .program = program, .cohorts = undefined, .requirements = undefined, .metadata = undefined, .scan_ids = undefined, .scan_names = undefined, .extra_bytes = 0, .wide_counters = use_wide, .counter_requests = requests };
        var meta: std.ArrayList(u32) = .empty;
        var max_relations: usize = 1;
        var max_sources: usize = 1;
        var max_coefficients: usize = 1;
        var max_output: usize = 1;
        var max_scan: usize = 1;
        var max_columns: usize = 4;
        for (p.cohorts, &p.programs, &result.cohorts) |cohort, *pr, *out| {
            const counts: [3]usize = .{ cohort.columns[0], cohort.columns[1], cohort.columns[2] };
            const entry = Code.Entry{ .program = pr, .tree_column_counts = &counts };
            try Code.validate(entry);
            try Interaction.validate(entry);
            if (pr.layout == .independent_prefix_v1 and pr.batches.len != 1) return error.UnsupportedResidentFrameworkGeometry;
            if (pr.profile_parameter_count != 0 and pr.profile_parameter_count != Selectors.len) return error.UnsupportedResidentFrameworkProfile;
            const n = pr.inputs.len + pr.interaction_columns.len;
            const tr = try a.alloc(u64, n);
            const ev = try a.alloc(u64, n);
            var starts: [3]usize = .{ 0, counts[0], counts[0] + counts[1] };
            _ = &starts;
            for (pr.inputs, 0..) |input, i| switch (input) {
                .profile_parameter => {
                    tr[i] = 0;
                    ev[i] = 0;
                },
                .trace_column => |column| {
                    const k = starts[column.tree_index] + column.column_index;
                    tr[i] = k * pow(cohort.trace_log);
                    ev[i] = k * pow(cohort.evaluation_log);
                },
            };
            for (pr.interaction_columns, pr.inputs.len..) |column, i| {
                const k = starts[column.tree_index] + column.column_index;
                tr[i] = k * pow(cohort.trace_log);
                ev[i] = k * pow(cohort.evaluation_log);
            }
            const routes = try a.alloc(RelationRoute, pr.entries.len);
            var rc: u32 = 0;
            for (pr.entries, routes) |e, *r| {
                if (e.domain >= Relation.universal_descriptors.len or Relation.universal_descriptors[e.domain].arity != e.arity) return error.InvalidResidentFrameworkRelation;
                r.* = .{ .domain = e.domain, .arity = e.arity, .offset = rc };
                rc += 1 + e.arity;
            }
            const profile = try a.alloc(u32, pr.profile_parameter_count);
            for (profile, 0..) |*v, i| v.* = Selectors[i].toU32();
            const den = try Geometry.derive(cohort.trace_log, cohort.evaluation_log);
            while (meta.items.len % 2 != 0) try meta.append(a, 0);
            const start = meta.items.len;
            const ts = try append(a, &meta, std.mem.sliceAsBytes(tr));
            const es = try append(a, &meta, std.mem.sliceAsBytes(ev));
            const rs = try append(a, &meta, std.mem.sliceAsBytes(routes));
            const ps = try append(a, &meta, std.mem.sliceAsBytes(profile));
            const dw = Geometry.words(den);
            const ds = try append(a, &meta, std.mem.asBytes(&dw));
            const ls = meta.items.len;
            for (0..counts[0] + counts[1] + counts[2]) |_| try meta.append(a, cohort.trace_log);
            const els = meta.items.len;
            for (0..4) |_| try meta.append(a, cohort.evaluation_log);
            const ci = try Code.identity(a, entry);
            const ii = try Interaction.identity(a, entry);
            out.* = .{ .offsets_trace = tr, .offsets_evaluation = ev, .routes = routes, .profile = profile, .denominators = dw, .relation_count = rc, .denominator_count = den.count, .columns = @intCast(counts[0] + counts[1] + counts[2]), .composition_id = ci, .interaction_id = ii, .composition_name = try Code.kernelName(a, entry), .interaction_name = try Interaction.name(a, ii), .metadata_start = start, .trace_offsets_start = ts, .evaluation_offsets_start = es, .routes_start = rs, .profile_start = ps, .denominators_start = ds, .logs_start = ls, .extension_logs_start = els };
            max_columns = @max(max_columns, out.columns);
            max_sources = @max(max_sources, out.columns * pow(cohort.evaluation_log));
            max_coefficients = @max(max_coefficients, out.columns * pow(cohort.evaluation_log - 1));
            max_output = @max(max_output, @max(4 * pow(cohort.evaluation_log), cohort.columns[2] * pow(cohort.trace_log) + 4));
            max_scan = @max(max_scan, 4 * ((pow(cohort.trace_log) + 255) / 256));
            max_relations = @max(max_relations, 4 * (rc + 1));
        }
        result.metadata = try meta.toOwnedSlice(a);
        const sizes = [_]usize{ result.metadata.len, max_relations, 4 * p.total_constraints, max_sources, @max(max_coefficients, 4 * pow(p.composition_log - 1)), max_output, max_scan, 4 * pow(p.composition_log), 4 * pow(p.composition_log), max_columns, if (use_wide) 2 * pow(18) else 1, if (use_wide) 2 * pow(16) else 1 };
        result.requirements = try a.alloc(cuda.runtime.arena.Requirement, sizes.len);
        for (sizes, result.requirements, 0..) |words, *r, i| {
            const slot: Slot = @enumFromInt(i);
            const start: cuda.runtime.telemetry.Stage = if (slot == .metadata or slot == .logs) .ingress else if (slot == .source or slot == .relations or slot == .wide_bitwise or slot == .wide_range) .trace_generation else .trace_commit;
            r.* = .{ .id = id(slot), .words = words, .alignment_words = 64, .live_from = start, .live_through = if (slot == .wide_bitwise or slot == .wide_range) .trace_generation else .constraint_evaluation };
            result.extra_bytes = try std.math.add(usize, result.extra_bytes, try std.math.mul(usize, words, 4));
        }
        if (result.extra_bytes > limits.max_extra_bytes) return error.ResidentFrameworkResourceLimit;
        inline for (std.meta.tags(Interaction.Scan), 0..) |kind, i| {
            result.scan_ids[i] = try Interaction.scanIdentity(a, kind);
            result.scan_names[i] = try Interaction.scanName(a, kind, result.scan_ids[i]);
        }
        result.arena = arena;
        return result;
    }
    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
fn append(a: std.mem.Allocator, list: *std.ArrayList(u32), bytes: []const u8) !usize {
    const start = list.items.len;
    if (bytes.len % 4 != 0) return error.InvalidResidentFrameworkMetadata;
    for (0..bytes.len / 4) |i| try list.append(a, std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little));
    return start;
}
fn pow(log: u32) usize {
    return @as(usize, 1) << @intCast(log);
}
test "resident framework cold bindings preserve all physical cohorts and bounded scratch" {
    const p = try Program.Owned.derive(std.testing.allocator, try Program.fixtureAdmission(), .{});
    defer p.deinit();
    var plan = try Plan.init(std.testing.allocator, p, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 25), plan.cohorts.len);
    for (plan.cohorts, p.view().cohorts) |c, original| {
        try std.testing.expectEqual(original.columns[0] + original.columns[1] + original.columns[2], c.columns);
        try std.testing.expectEqual(@as(u32, 1) << @intCast(original.evaluation_log - original.trace_log), c.denominator_count);
    }
    try std.testing.expectError(error.ResidentFrameworkResourceLimit, Plan.init(std.testing.allocator, p, .{ .max_extra_bytes = 1 }));
}

test "resident framework wide counts are opt in bounded and preserve original metadata" {
    const a = std.testing.allocator;
    const p = try Program.Owned.derive(a, try Program.fixtureAdmission(), .{});
    defer p.deinit();
    var old = try Plan.init(a, p, .{});
    defer old.deinit();
    var wide = try Plan.init(a, p, .{ .wide_counters = true });
    defer wide.deinit();
    try std.testing.expect(!old.wide_counters);
    try std.testing.expect(wide.wide_counters);
    try std.testing.expectEqualSlices(u32, old.metadata, wide.metadata);
    try std.testing.expectEqualSlices(cuda.runtime.arena.Requirement, old.requirements[0..10], wide.requirements[0..10]);
    try std.testing.expectEqual(@as(usize, 2 * (pow(18) + pow(16)) * 4 - 8), wide.extra_bytes - old.extra_bytes);
    try std.testing.expectError(error.ResidentFrameworkResourceLimit, Plan.init(a, p, .{ .wide_counters = true, .max_extra_bytes = old.extra_bytes }));
    for (wide.counter_requests) |n| try std.testing.expect(n <= Wide.MAX_REQUESTS);
}
