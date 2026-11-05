//! Resident PCS request framing and borrowed, scoped coefficient spans.
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
pub const GeometryCache = @import("pcs_geometry_cache.zig").Cache;
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
pub fn prepareRequest(a: std.mem.Allocator, request: D.Request, initial: D.Channel) !Prepared {
    return prepareRequestWithCache(a, request, initial, null);
}
/// Native contexts supply a bounded immutable host cache. Debug exports keep
/// the uncached entry above; all transcript-derived sections stay fresh.
pub fn prepareRequestWithCache(a: std.mem.Allocator, request: D.Request, initial: D.Channel, cache: ?*GeometryCache) !Prepared {
    return prepareRequestWithFraming(a, request, initial, cache, false);
}
pub fn prepareRequestWithFraming(a: std.mem.Allocator, request: D.Request, initial: D.Channel, cache: ?*GeometryCache, wide_framing: bool) !Prepared {
    return prepareMode(a,request,initial,cache,wide_framing,false);
}
/// Source-owned class geometry needs logs and opening-offset recipes only;
/// coefficients may be empty and transcript/root values have no cost authority.
/// This path takes no geometry-cache lock and generates no FFT/FRI coordinates.
pub fn allocationPlan(a: std.mem.Allocator, request: D.Request, wide_framing: bool, options: @import("pcs_allocation_cost.zig").Options) !@import("pcs_allocation_cost.zig").Plan {
    var prepared=try prepareMode(a,request,D.Channel.init(),null,wide_framing,true);
    defer prepared.deinit(a);
    const descriptor=prepared.geometryDescriptor();
    return @import("pcs_allocation_cost.zig").initGeometry(a,&descriptor,options);
}
fn prepareMode(a: std.mem.Allocator, request: D.Request, initial: D.Channel, cache: ?*GeometryCache, wide_framing: bool, geometry_only: bool) !Prepared {
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
            if (column.log_size == 0 or column.log_size > 28 - beta or (!geometry_only and columnCount(column) != @as(usize, 1) << @intCast(column.log_size)) or ps.len > 5 or (ps.len != 0 and column.log_size > degree)) return error.InvalidDevicePcsColumn;
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
    const forward_count = @as(usize,1)<<@intCast(maximum_source_log+beta-1);
    const geometry = if (cache) |owner| try owner.acquire(maximum_source_log + beta, plan) else null;
    errdefer if (geometry) |borrow| borrow.release();
    var uncached_twiddles: ?engine.poly.twiddles.TwiddleTree([]M) = null;
    defer if (uncached_twiddles) |*tw| engine.poly.twiddles.deinitM31(a, tw);
    const forward: []const M = if (geometry_only) &.{} else if (geometry) |borrow| borrow.forward() else blk: {
        uncached_twiddles = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(maximum_source_log + beta).circleDomain().half_coset);
        break :blk uncached_twiddles.?.twiddles;
    };
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
            try source_groups.appendSlice(a, &.{ ev[0], ev[1], log, log + beta, source_base + try count32(first_sorted), try count32(sorted - first_sorted), try count32(forward_count - twiddle_count), twiddle_count });
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
        try deep_tw.appendSlice(a, &.{ try count32(forward_count - count), count });
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
    var coordinate_count: usize=0;
    if (geometry_only) {
        for(plan.layers[0..plan.len],0..) |layer,li| {
            var offsets: [4]u32=@splat(0);
            var count=layer.count;
            for(0..layer.fold_step) |step| {
                offsets[step]=try count32(coordinate_count);
                const half=count/2;
                coordinate_count+=if(li==0 and step==0) 2*((half+3)/4) else half;
                count/=2;
            }
            try fri_desc.appendSlice(std.heap.page_allocator,&.{layer.count,layer.fold_step,layer.leaf_log,layer.shift});
            try fri_desc.appendSlice(std.heap.page_allocator,&offsets);
        }
    } else if (geometry == null) try C.friMetadata(plan, &fri_desc, &fri_tw);
    const fri_descriptions: []const u32 = if (geometry) |borrow| borrow.descriptions() else fri_desc.items;
    const fri_coordinates: []const M = if (geometry) |borrow| borrow.coordinates() else fri_tw.items;
    var h = [_]u32{ 0x52564d53, 2, 0, degree, request.lifting_log_size, beta, try count32(request.config.fri_config.n_queries), request.config.fri_config.fold_step, try count32(source_count), exponent, try count32(groups.items.len), try count32(source_groups.items.len / 8), try count32(trees.len), try count32(sample_count), try count32(plan.len), 0, 0, 0, 0, try count32(forward_count), try count32(if(geometry_only)coordinate_count else fri_coordinates.len), 1, request.config.pow_bits, 0, 0, 0, 0, 0 };
    const header_len = try @import("pcs_framing.zig").encode(&h, .{ coefficient_words, evaluation_words, combined_coefficients, combined_evaluations }, wide_framing);
    var section_storage: [17][]const u32 = @splat(&.{});
    var section_owned: [17]bool = @splat(true);
    errdefer for (section_storage, section_owned) |section, owned| {
        if (owned) a.free(section);
    };
    var seed: [9]u32 = undefined;
    for (seed[0..8], 0..) |*v, i| v.* = std.mem.readInt(u32, initial.inner.digest[i * 4 ..][0..4], .little);
    seed[8] = initial.inner.n_draws;
    var point_words: [16]u32 = undefined;
    for (base_point.x.toM31Array(), point_words[0..8]) |v, *word| word.* = v.v;
    for (base_point.y.toM31Array(), point_words[8..]) |v, *word| word.* = v.v;
    const expected_roots = try a.alloc(u32, request.trees.len * 8);
    defer a.free(expected_roots);
    for (request.trees, 0..) |tree, t| for (0..8) |i| {
        expected_roots[t * 8 + i] = std.mem.readInt(u32, tree.root[i * 4 ..][0..4], .little);
    };
    const half = core.poly.circle.canonic.CanonicCoset.new(request.lifting_log_size).circleDomain().half_coset;
    const domain_parameters = [4]u32{ half.initial.x.v, half.initial.y.v, half.step.x.v, half.step.y.v };
    const sections = [_][]const u32{ h[0..header_len], &seed, &point_words, sources.items, terms.items, deep_groups.items, source_groups.items, tree_info.items, recipes.items, deep_tw.items, sample_map, sample_counts.items, mWords(forward), fri_descriptions, mWords(fri_coordinates), expected_roots, &domain_parameters };
    for (sections, &section_storage, &section_owned, 0..) |section, *storage, *owned, i| {
        if (geometry != null and i >= 12 and i <= 14) {
            storage.* = section;
            owned.* = false;
        } else storage.* = try a.dupe(u32, section);
    }
    const coefficients = try a.alloc(Native.Column, source_count);
    errdefer a.free(coefficients);
    var ci: usize = 0;
    for (request.trees, trees) |tree, meta| for (meta.sorted_to_original) |original| {
        coefficients[ci] = if(geometry_only) .{.kind=0,.coefficient_log=tree.columns[original].log_size,.count=@as(u64,1)<<@intCast(tree.columns[original].log_size),.words=null} else nativeColumn(tree.columns[original]);
        ci += 1;
    };
    return .{ .geometry_only=geometry_only, .forward_count=forward_count, .coordinate_count=if(geometry_only)coordinate_count else fri_coordinates.len, .metadata = .{ .shape = .{ .config = request.config, .degree_log = degree, .trees = trees }, .sources = try count32(source_count), .terms = exponent, .groups = try count32(groups.items.len), .source_groups = try count32(source_groups.items.len / 8), .sample_count = try count32(sample_count), .degree_log = degree, .eval_log = request.lifting_log_size, .coefficient_cells = coefficient_words }, .section_storage = section_storage, .section_owned = section_owned, .geometry = geometry, .coefficients = coefficients, .scope = requestScope(request) };
}

fn columnCount(column: D.Column) u64 {
    if (comptime @hasField(D.Column, "device")) {
        if (column.device) |device| return device.count;
    }
    return column.coefficients.len;
}
fn nativeColumn(column: D.Column) Native.Column {
    if (comptime @hasField(D.Column, "device")) {
        if (column.device) |device| return .{ .kind = 1, .coefficient_log = column.log_size, .words = device.words, .count = device.count, .context_token = device.context_token, .generation = device.generation };
    }
    const values = mWords(column.coefficients);
    return .{ .coefficient_log = column.log_size, .words = values.ptr, .count = values.len };
}
fn requestScope(request: D.Request) [8]u32 {
    if (comptime @hasField(D.Request, "scope")) {
        if (request.scope) |scope| return @import("pcs_scope.zig").identity(scope);
    }
    return @splat(0);
}
const Native = @import("pcs_native_abi.zig");
fn mWords(values: []const M) []const u32 {
    comptime if (@sizeOf(M) != @sizeOf(u32) or @alignOf(M) != @alignOf(u32)) @compileError("M31 word ABI changed");
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}
pub const Prepared = struct {
    geometry_only: bool=false,
    forward_count: usize=0,
    coordinate_count: usize=0,
    metadata: Metadata,
    section_storage: [17][]const u32,
    section_owned: [17]bool = @splat(true),
    geometry: ?GeometryCache.Borrow = null,
    coefficients: []Native.Column,
    owns_metadata: bool = true,
    scope: [8]u32 = @splat(0),
    pub fn descriptor(self: *const Prepared) Native.Request {
        if(self.geometry_only) @panic("geometry-only PCS descriptor cannot be proved");
        return self.geometryDescriptor();
    }
    fn geometryDescriptor(self: *const Prepared) Native.Request {
        var result = Native.Request{ .sections = undefined, .coefficients = self.coefficients.ptr, .coefficient_count = self.coefficients.len, .scope = self.scope };
        for (self.section_storage, &result.sections) |section, *span| span.* = .{ .words = section.ptr, .count = section.len };
        if(self.geometry_only) {
            result.sections[12]=.{.words=null,.count=self.forward_count};
            result.sections[14]=.{.words=null,.count=self.coordinate_count};
        }
        return result;
    }
    pub fn takeMetadata(self: *Prepared) Metadata {
        std.debug.assert(self.owns_metadata);
        self.owns_metadata = false;
        return self.metadata;
    }
    pub fn deinit(self: *Prepared, a: std.mem.Allocator) void {
        if (self.owns_metadata) self.metadata.deinit(a);
        for (self.section_storage, self.section_owned) |section, owned| if (owned) a.free(section);
        if (self.geometry) |borrow| borrow.release();
        a.free(self.coefficients);
        self.* = undefined;
    }
};

/// Debug file compatibility only. The native in-process lane uses prepareRequest
/// and borrows every coefficient span directly, without a materialized warehouse.
pub fn exportRequest(a: std.mem.Allocator, request: D.Request, initial: D.Channel, path: []const u8) !Metadata {
    var prepared = try prepareRequest(a, request, initial);
    defer prepared.deinit(a);
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    errdefer std.fs.cwd().deleteFile(path) catch {};
    for (prepared.section_storage[0..12]) |section| try words(file, section);
    for (prepared.coefficients) |column| {
        if (column.kind != 0) return error.DeviceColumnsRequireNativePcs;
        try words(file, column.words.?[0..@intCast(column.count)]);
    }
    for (prepared.section_storage[12..15]) |section| try words(file, section);
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
    try words(file, prepared.section_storage[15]);
    try words(file, &@as([17]u32, @splat(0)));
    return prepared.takeMetadata();
}
