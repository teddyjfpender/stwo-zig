//! Native PCS -> GPU request framing for the hybrid proving boundary.
//! This exports borrowed native coefficients and actual opening points; it
//! neither constructs a witness nor changes the native transcript.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Assembly = @import("pcs_assembly.zig");
const F = @import("fri.zig");
const C = @import("../rv64_pcs_fixture_main.zig");
const M = D.M;
const Point = D.Point;
const Shift = core.circle.CirclePointM31;
pub const Metadata = struct {
    shape: Assembly.Shape,
    sources: u32,
    terms: u32,
    groups: u32,
    source_groups: u32,
    sample_count: u32,
    degree_log: u32,
    eval_log: u32,
    /// Input coefficient cells across all four PCS trees, including composition.
    coefficient_cells: u64,
    pub fn deinit(self: *Metadata, a: std.mem.Allocator) void {
        for (self.shape.trees) |tree| {
            a.free(tree.coefficient_logs);
            a.free(tree.sorted_to_original);
            a.free(tree.sample_counts);
        }
        a.free(self.shape.trees);
        self.* = undefined;
    }
};
const Term = struct { source: u32, exponent: u32, original: ?u32 };
const Group = struct { shift: Shift, log: u32, terms: std.ArrayList(Term) = .empty };
fn appendGroup(a: std.mem.Allocator, groups: *std.ArrayList(Group), shift: Shift, log: u32, term: Term) !void {
    for (groups.items) |*g| if (g.log == log and g.shift.eql(shift)) {
        try g.terms.append(a, term);
        return;
    };
    if (groups.items.len >= 1024) return error.DevicePcsGroupCapacityExceeded;
    try groups.append(a, .{ .shift = shift, .log = log });
    try groups.items[groups.items.len - 1].terms.append(a, term);
}
fn relative(point: Point, base: Point) !Shift {
    const p = point.sub(base);
    const x = p.x.toM31Array();
    const y = p.y.toM31Array();
    for (x[1..]) |v| if (!v.isZero()) return error.UnsupportedDevicePcsPointOffset;
    for (y[1..]) |v| if (!v.isZero()) return error.UnsupportedDevicePcsPointOffset;
    return .{ .x = x[0], .y = y[0] };
}
fn count32(value: anytype) !u32 {
    return std.math.cast(u32, value) orelse return error.DevicePcsExportSizeExceeded;
}
fn pair(value: u64) [2]u32 {
    return .{ @truncate(value), @truncate(value >> 32) };
}
fn words(file: std.fs.File, values: []const u32) !void {
    if (comptime builtin.cpu.arch.endian() != .little) @compileError("PCS export currently requires a little-endian host");
    try file.writeAll(std.mem.sliceAsBytes(values));
}
fn fields(file: std.fs.File, values: []const M) !void {
    comptime if (@sizeOf(M) != 4) @compileError("M31 export ABI changed");
    try file.writeAll(std.mem.sliceAsBytes(values));
}
fn secure(file: std.fs.File, value: D.O) !void {
    const coordinates = value.toM31Array();
    try fields(file, &coordinates);
}
fn hash(file: std.fs.File, digest: [32]u8) !void {
    try file.writeAll(&digest);
}
pub fn exportRequest(a: std.mem.Allocator, request: D.Request, initial: D.Channel, path: []const u8) !Metadata {
    if (request.trees.len == 0 or request.trees.len > 4 or request.points.items.len != request.trees.len or request.lifting_log_size < request.config.fri_config.log_blowup_factor or request.lifting_log_size > 28) return error.InvalidDevicePcsRequest;
    const beta = request.config.fri_config.log_blowup_factor;
    const degree = request.lifting_log_size - beta;
    const plan = try F.Plan.init(degree, request.config.fri_config);
    const trees = try a.alloc(Assembly.Tree, request.trees.len);
    var made: usize = 0;
    errdefer {
        for (trees[0..made]) |tree| {
            a.free(tree.coefficient_logs);
            a.free(tree.sorted_to_original);
            a.free(tree.sample_counts);
        }
        a.free(trees);
    }
    var source_count: usize = 0;
    var sample_count: usize = 0;
    var maximum_source_log: u32 = 0;
    var base: ?Point = null;
    for (request.trees, request.points.items, trees) |tree, points, *meta| {
        if (tree.columns.len == 0 or tree.columns.len > 65536 or tree.columns.len != points.len) return error.InvalidDevicePcsTree;
        const logs = try a.alloc(u32, tree.columns.len);
        errdefer a.free(logs);
        const order = try a.alloc(u32, tree.columns.len);
        errdefer a.free(order);
        const counts = try a.alloc(u32, tree.columns.len);
        errdefer a.free(counts);
        for (tree.columns, points, logs, order, counts, 0..) |column, ps, *log, *index, *count, i| {
            if (column.log_size == 0 or column.log_size > 28 - beta or column.coefficients.len != @as(usize, 1) << @intCast(column.log_size) or ps.len > 5 or (ps.len != 0 and column.log_size > degree)) return error.InvalidDevicePcsColumn;
            log.* = column.log_size;
            index.* = @intCast(i);
            count.* = @intCast(ps.len);
            source_count = try std.math.add(usize, source_count, 1);
            sample_count = try std.math.add(usize, sample_count, ps.len);
            maximum_source_log = @max(maximum_source_log, column.log_size);
            if (base == null and ps.len != 0) base = ps[0];
        }
        std.mem.sort(u32, order, @as([]const u32, logs), struct {
            fn less(height: []const u32, lhs: u32, rhs: u32) bool {
                return height[lhs] < height[rhs] or (height[lhs] == height[rhs] and lhs < rhs);
            }
        }.less);
        meta.* = .{ .coefficient_logs = logs, .sorted_to_original = order, .sample_counts = counts };
        made += 1;
    }
    if (source_count > 65536 or sample_count == 0 or sample_count > 65536) return error.InvalidDevicePcsRequest;
    const base_point = base orelse return error.EmptyDevicePcsSamples;
    var sources: std.ArrayList(u32) = .empty;
    defer sources.deinit(a);
    var source_groups: std.ArrayList(u32) = .empty;
    defer source_groups.deinit(a);
    var tree_info: std.ArrayList(u32) = .empty;
    defer tree_info.deinit(a);
    var sample_counts: std.ArrayList(u32) = .empty;
    defer sample_counts.deinit(a);
    var groups: std.ArrayList(Group) = .empty;
    defer {
        for (groups.items) |*g| g.terms.deinit(a);
        groups.deinit(a);
    }
    var twiddles = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(maximum_source_log + beta).circleDomain().half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    var coefficient_words: u64 = 0;
    var evaluation_words: u64 = 0;
    var source_base: u32 = 0;
    var sample_index: u32 = 0;
    var exponent: u32 = 0;
    for (request.trees, request.points.items, trees) |tree, points, meta| {
        const original_to_source = try a.alloc(u32, tree.columns.len);
        defer a.free(original_to_source);
        const first_group = try count32(source_groups.items.len / 8);
        var sorted: usize = 0;
        while (sorted < tree.columns.len) {
            const log = meta.coefficient_logs[meta.sorted_to_original[sorted]];
            const first_sorted = sorted;
            const eval_start = evaluation_words;
            while (sorted < tree.columns.len and meta.coefficient_logs[meta.sorted_to_original[sorted]] == log) : (sorted += 1) {
                const original = meta.sorted_to_original[sorted];
                const offsets = pair(coefficient_words);
                try sources.appendSlice(a, &.{ offsets[0], offsets[1], 0, log });
                original_to_source[original] = source_base + try count32(sorted);
                coefficient_words += @as(u64, 1) << @intCast(log);
                evaluation_words += @as(u64, 1) << @intCast(log + beta);
            }
            const ev = pair(eval_start);
            const twiddle_count: u32 = @as(u32, 1) << @intCast(log + beta - 1);
            try source_groups.appendSlice(a, &.{ ev[0], ev[1], log, log + beta, source_base + try count32(first_sorted), try count32(sorted - first_sorted), try count32(twiddles.twiddles.len - twiddle_count), twiddle_count });
        }
        try tree_info.appendSlice(a, &.{ source_base, try count32(tree.columns.len), first_group, try count32(source_groups.items.len / 8) - first_group, std.mem.max(u32, meta.coefficient_logs) + beta, 0 });
        // Powers follow ORIGINAL tree/column/sample order, not height sorting.
        for (tree.columns, points, meta.sample_counts, 0..) |column, ps, count, original| {
            try sample_counts.append(a, count);
            if (ps.len == 2) {
                const periodic = core.poly.circle.canonic.CanonicCoset.new(request.lifting_log_size).step().repeatedDouble(column.log_size + beta);
                try appendGroup(a, &groups, (try relative(ps[1], base_point)).add(periodic), column.log_size, .{ .source = original_to_source[original], .exponent = exponent, .original = null });
                exponent += 1;
            }
            for (ps) |point| {
                try appendGroup(a, &groups, try relative(point, base_point), column.log_size, .{ .source = original_to_source[original], .exponent = exponent, .original = sample_index });
                exponent += 1;
                sample_index += 1;
            }
        }
        source_base += try count32(tree.columns.len);
    }
    if (exponent > 65536 or source_groups.items.len / 8 > 96) return error.DevicePcsGroupCapacityExceeded;
    var terms: std.ArrayList(u32) = .empty;
    defer terms.deinit(a);
    var deep_groups: std.ArrayList(u32) = .empty;
    defer deep_groups.deinit(a);
    var recipes: std.ArrayList(u32) = .empty;
    defer recipes.deinit(a);
    var deep_tw: std.ArrayList(u32) = .empty;
    defer deep_tw.deinit(a);
    const sample_map = try a.alloc(u32, sample_count);
    defer a.free(sample_map);
    @memset(sample_map, std.math.maxInt(u32));
    var combined_coefficients: u64 = 0;
    var combined_evaluations: u64 = 0;
    for (groups.items, 0..) |g, gi| {
        const first = try count32(terms.items.len / 4);
        for (g.terms.items) |term| {
            if (term.original) |index| sample_map[index] = try count32(terms.items.len / 4);
            try terms.appendSlice(a, &.{ term.source, try count32(gi), term.exponent, 0 });
        }
        const coeff = pair(combined_coefficients);
        const eval = pair(combined_evaluations);
        try deep_groups.appendSlice(a, &.{ first, try count32(terms.items.len / 4), g.log, g.log + beta, coeff[0], coeff[1], eval[0], eval[1] });
        try recipes.appendSlice(a, &.{ g.shift.x.v, g.shift.y.v, request.lifting_log_size - (g.log + beta), g.log });
        const count: u32 = @as(u32, 1) << @intCast(g.log + beta - 1);
        try deep_tw.appendSlice(a, &.{ try count32(twiddles.twiddles.len - count), count });
        combined_coefficients += @as(u64, 8) << @intCast(g.log);
        combined_evaluations += @as(u64, 8) << @intCast(g.log + beta);
    }
    for (sample_map) |index| if (index == std.math.maxInt(u32)) return error.DevicePcsMissingSample;
    // The shared fixture helper owns these ArrayLists through page_allocator.
    // Keep that allocator pairing explicit until the helper is generalized.
    var fri_desc: std.ArrayList(u32) = .empty;
    defer fri_desc.deinit(std.heap.page_allocator);
    var fri_tw: std.ArrayList(M) = .empty;
    defer fri_tw.deinit(std.heap.page_allocator);
    try C.friMetadata(plan, &fri_desc, &fri_tw);
    const h = [_]u32{ 0x52564d53, 2, 0, degree, request.lifting_log_size, beta, try count32(request.config.fri_config.n_queries), request.config.fri_config.fold_step, try count32(source_count), exponent, try count32(groups.items.len), try count32(source_groups.items.len / 8), try count32(trees.len), try count32(sample_count), try count32(plan.len), try count32(coefficient_words), try count32(evaluation_words), try count32(combined_coefficients), try count32(combined_evaluations), try count32(twiddles.twiddles.len), try count32(fri_tw.items.len), 1, request.config.pow_bits, 0 };
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    errdefer std.fs.cwd().deleteFile(path) catch {};
    try words(file, &h);
    try hash(file, initial.inner.digest);
    try words(file, &.{initial.inner.n_draws});
    try secure(file, base_point.x);
    try secure(file, base_point.y);
    for ([_][]const u32{ sources.items, terms.items, deep_groups.items, source_groups.items, tree_info.items, recipes.items, deep_tw.items, sample_map, sample_counts.items }) |section| try words(file, section);
    for (request.trees, trees) |tree, meta| for (meta.sorted_to_original) |original| try fields(file, tree.columns[original].coefficients);
    try fields(file, twiddles.twiddles);
    try words(file, fri_desc.items);
    try fields(file, fri_tw.items);
    const domain_words = try a.alloc(u32, @as(usize, 2) << @intCast(request.lifting_log_size));
    defer a.free(domain_words);
    var iterator = core.poly.circle.canonic.CanonicCoset.new(request.lifting_log_size).circleDomain().iter();
    var index: usize = 0;
    while (iterator.next()) |point| : (index += 1) {
        const physical = core.utils.bitReverseIndex(index, request.lifting_log_size);
        domain_words[2 * physical] = point.x.v;
        domain_words[2 * physical + 1] = point.y.v;
    }
    try words(file, domain_words);
    for (request.trees) |tree| try hash(file, tree.root);
    try words(file, &@as([17]u32, @splat(0)));
    return .{ .shape = .{ .config = request.config, .degree_log = degree, .trees = trees }, .sources = try count32(source_count), .terms = exponent, .groups = try count32(groups.items.len), .source_groups = try count32(source_groups.items.len / 8), .sample_count = try count32(sample_count), .degree_log = degree, .eval_log = request.lifting_log_size, .coefficient_cells = coefficient_words };
}
