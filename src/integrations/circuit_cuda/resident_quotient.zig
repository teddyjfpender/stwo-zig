//! Circuit DEEP quotient topology over the four compact resident trees.
//! Mirrors the CPU PCS mask/period ordering and reuses Cairo CUDA's
//! addressed, native-height quotient kernels without Cairo protocol fields.
const std = @import("std");
const core = @import("stwo_core");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const cairo = @import("stwo_cairo_frontend");
const cuda = @import("stwo_cuda_backend");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const quotient_abi = cuda.abi.stages.quotient;
const circle = core.circle;
const canonic = core.poly.circle.canonic;
const masks_module = cairo.witness.quotient_geometry;
const types = @import("stwo_cairo_cuda_integration").executor.quotient.types;
const buckets = @import("stwo_cairo_cuda_integration").executor.quotient.buckets;
const geometry_module = @import("geometry.zig");
const oods_module = @import("resident_oods.zig");
const commit_module = @import("resident_commit.zig");
const shared = @import("stwo_native_cuda_integration").common;
const common = cuda.runtime.stages.common;
const controller = @import("stwo_cairo_cuda_integration").executor.quotient.controller;

pub const Topology = types.Topology;

const Term = struct {
    descriptor: quotient_abi.PreparedTermDescriptor,
    source_index: u32,
    source_log: u32,
    shift: circle.CirclePointM31,
};

const Group = struct {
    shift: circle.CirclePointM31,
    log: u32,
    terms: std.ArrayList(u32) = .empty,

    fn deinit(self: *Group, allocator: std.mem.Allocator) void {
        self.terms.deinit(allocator);
    }
};

const Builder = struct {
    allocator: std.mem.Allocator,
    geometry: *const geometry_module.Geometry,
    blowup: u32,
    trace_step: circle.CirclePointM31,
    lifting_generator: circle.CirclePointM31,
    terms: std.ArrayList(Term) = .empty,
    groups: std.ArrayList(Group) = .empty,
    samples: std.ArrayList(u32) = .empty,

    fn deinit(self: *Builder) void {
        for (self.groups.items) |*group| group.deinit(self.allocator);
        self.groups.deinit(self.allocator);
        self.terms.deinit(self.allocator);
        self.samples.deinit(self.allocator);
    }

    fn appendColumn(self: *Builder, tree_index: usize, column: usize, offsets: []const i32) !void {
        const tree = self.geometry.trees[tree_index];
        if (column >= tree.column_logs.len or offsets.len == 0 or offsets.len > 2)
            return error.InvalidCircuitQuotientGeometry;
        const log = tree.column_logs[column];
        if (log == 0 or log >= self.geometry.fri_input_log)
            return error.InvalidCircuitQuotientGeometry;
        var source_index: usize = column;
        for (self.geometry.trees[0..tree_index]) |previous| source_index = try add(source_index, previous.column_logs.len);
        const source = std.math.cast(u32, source_index) orelse return error.CircuitQuotientSizeOverflow;
        const first_sample = self.samples.items.len;
        if (offsets.len == 2) {
            const period = self.lifting_generator.repeatedDouble(log + 1);
            try self.appendTerm(source, log, try u32Count(first_sample + 1), self.trace_step.mulSigned(offsets[1]).add(period), period);
        }
        for (offsets, 0..) |offset, ordinal| {
            try self.appendTerm(source, log, try u32Count(first_sample + ordinal), self.trace_step.mulSigned(offset), null);
            try self.samples.append(self.allocator, source);
        }
    }

    fn appendTerm(self: *Builder, source: u32, log: u32, sample_index: u32, shift: circle.CirclePointM31, period: ?circle.CirclePointM31) !void {
        const index = try u32Count(self.terms.items.len);
        try self.terms.append(self.allocator, .{
            .descriptor = .{
                .sample_index = sample_index,
                .exponent = index,
                .periodic = @intFromBool(period != null),
                .period_x = if (period) |point| point.x.v else 0,
                .period_y = if (period) |point| point.y.v else 0,
            },
            .source_index = source,
            .source_log = log,
            .shift = shift,
        });
        var group_index: usize = self.groups.items.len;
        for (self.groups.items, 0..) |group, i| {
            if (group.shift.eql(shift)) {
                group_index = i;
                break;
            }
        }
        if (group_index == self.groups.items.len)
            try self.groups.append(self.allocator, .{ .shift = shift, .log = 0 });
        const group = &self.groups.items[group_index];
        group.log = @max(group.log, log);
        try group.terms.append(self.allocator, index);
    }
};

pub fn derive(
    allocator: std.mem.Allocator,
    bound: *const circuit_cpu.air.Bundle,
    geometry: *const geometry_module.Geometry,
    oods: *const oods_module.Plan,
    blowup: u32,
) !Topology {
    if (blowup == 0 or blowup > 4 or geometry.fri_input_log <= blowup)
        return error.InvalidCircuitQuotientGeometry;
    var masks = try masks_module.deriveMasks(
        allocator,
        bound.*,
        geometry.trees[0].column_logs.len,
        geometry.trees[1].column_logs.len,
        geometry.trees[2].column_logs.len,
    );
    defer masks.deinit();
    var builder = Builder{
        .allocator = allocator,
        .geometry = geometry,
        .blowup = blowup,
        .trace_step = canonic.CanonicCoset.new(geometry.fri_input_log - 1).step(),
        .lifting_generator = canonic.CanonicCoset.new(geometry.fri_input_log).step(),
    };
    defer builder.deinit();
    for (geometry.trees[0].column_logs, 0..) |_, column| try builder.appendColumn(0, column, &.{0});
    for (masks.base_offsets, 0..) |offsets, column| try builder.appendColumn(1, column, offsets.items);
    for (masks.interaction_offsets, 0..) |offsets, column| try builder.appendColumn(2, column, offsets.items);
    for (geometry.trees[3].column_logs, 0..) |_, column| try builder.appendColumn(3, column, &.{0});
    if (builder.samples.items.len != oods.sources.len or builder.groups.items.len == 0)
        return error.InvalidCircuitQuotientGeometry;
    for (builder.samples.items, oods.sources) |expected, actual|
        if (expected != actual) return error.InvalidCircuitQuotientGeometry;

    const sources = try compileSources(allocator, geometry, blowup);
    errdefer allocator.free(sources.columns);
    errdefer allocator.free(sources.trees);
    const terms = try allocator.alloc(quotient_abi.PreparedTermDescriptor, builder.terms.items.len);
    errdefer allocator.free(terms);
    const group_offsets = try allocator.alloc(u32, builder.groups.items.len + 1);
    errdefer allocator.free(group_offsets);
    const group_term_indices = try allocator.alloc(u32, builder.terms.items.len);
    errdefer allocator.free(group_term_indices);
    const batch_terms = try allocator.alloc(quotient_abi.BatchTermDescriptor, builder.terms.items.len);
    errdefer allocator.free(batch_terms);
    const group_logs = try allocator.alloc(u32, builder.groups.items.len);
    errdefer allocator.free(group_logs);
    const partial_logs = try allocator.alloc(u32, builder.groups.items.len);
    errdefer allocator.free(partial_logs);
    const partial_offsets = try allocator.alloc(u64, builder.groups.items.len + 1);
    errdefer allocator.free(partial_offsets);
    for (builder.terms.items, terms) |term, *descriptor| descriptor.* = term.descriptor;
    group_offsets[0] = 0;
    partial_offsets[0] = 0;
    var cursor: usize = 0;
    var maximum_log: u32 = 0;
    for (builder.groups.items, 0..) |group, i| {
        if (group.log == 0 or group.terms.items.len == 0 or group.log >= 31)
            return error.InvalidCircuitQuotientGeometry;
        group_logs[i] = group.log;
        partial_logs[i] = group.log;
        maximum_log = @max(maximum_log, group.log);
        partial_offsets[i + 1] = std.math.add(u64, partial_offsets[i], @as(u64, 1) << @intCast(group.log)) catch
            return error.CircuitQuotientSizeOverflow;
        for (group.terms.items) |term_index| {
            const term = builder.terms.items[term_index];
            group_term_indices[cursor] = term_index;
            batch_terms[cursor] = .{
                .source_index = term.source_index,
                .term_index = term_index,
                .source_log_size = term.source_log,
            };
            cursor += 1;
        }
        group_offsets[i + 1] = try u32Count(cursor);
    }
    if (cursor != terms.len) return error.InvalidCircuitQuotientGeometry;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/circuit-cuda/quotient-topology/v1\x00");
    hash.update(&geometry.identity);
    hash.update(std.mem.sliceAsBytes(terms));
    hash.update(std.mem.sliceAsBytes(group_offsets));
    hash.update(std.mem.sliceAsBytes(group_term_indices));
    hash.update(std.mem.sliceAsBytes(batch_terms));
    hash.update(std.mem.sliceAsBytes(group_logs));
    hash.update(std.mem.sliceAsBytes(partial_offsets));
    return .{
        .allocator = allocator,
        .prepared_terms = terms,
        .group_offsets = group_offsets,
        .group_term_indices = group_term_indices,
        .batch_terms = batch_terms,
        .sources = sources.columns,
        .source_trees = sources.trees,
        .group_log_sizes = group_logs,
        .partial_log_sizes = partial_logs,
        .partial_offsets = partial_offsets,
        .sampled_value_count = try u32Count(builder.samples.items.len),
        .source_evaluation_word_count = sources.words,
        .maximum_partial_rows = try pow2u32(maximum_log),
        .identity = hash.finalResult(),
    };
}

/// Admit and execute the circuit's DEEP quotient with the shared Cairo CUDA
/// addressed-kernel controller. Every source remains in its committed tree.
pub fn prepareResident(
    allocator: std.mem.Allocator,
    session: anytype,
    bound: *const circuit_cpu.air.Bundle,
    geometry: *const geometry_module.Geometry,
    oods_plan: *const oods_module.Plan,
    blowup: u32,
    commits: [4]commit_module.Buffers,
    oods_view: shared.resident_views.Oods,
    quotient: controller.QuotientBindings,
    twiddles_forward: common.Words,
    twiddles_inverse: common.Words,
) !controller.Prepared {
    var topology = try derive(allocator, bound, geometry, oods_plan, blowup);
    var owns_topology = true;
    errdefer if (owns_topology) topology.deinit();
    var evaluations: [4]common.Words = undefined;
    for (commits, topology.source_trees, &evaluations) |tree, span, *output| {
        if (tree.evaluations.len != span.evaluation_words or
            tree.coefficients.len != span.evaluation_words >> @intCast(blowup))
            return error.InvalidCircuitQuotientBuffers;
        output.* = tree.evaluations;
    }
    var prepared = try controller.prepareFromTopology(
        allocator,
        session,
        &topology,
        &evaluations,
        oods_view.sample_points,
        oods_view.sampled_values,
        quotient,
        twiddles_forward,
        geometry.fri_input_log,
        geometry.identity,
    );
    owns_topology = false;
    errdefer prepared.deinit();
    try prepared.initializeTransform(session, twiddles_inverse);
    return prepared;
}

const SourceSet = struct {
    columns: []types.SourceDescriptor,
    trees: []types.TreeSpan,
    words: u64,
};

fn compileSources(allocator: std.mem.Allocator, geometry: *const geometry_module.Geometry, blowup: u32) !SourceSet {
    var count: usize = 0;
    for (geometry.trees) |tree| count = try add(count, tree.column_logs.len);
    const columns = try allocator.alloc(types.SourceDescriptor, count);
    errdefer allocator.free(columns);
    const trees = try allocator.alloc(types.TreeSpan, 4);
    errdefer allocator.free(trees);
    var source_index: usize = 0;
    var all_words: u64 = 0;
    for (geometry.trees, trees, 0..) |tree, *span, ordinal| {
        var offset: u64 = 0;
        const first = source_index;
        for (tree.column_logs, 0..) |log, local| {
            const physical_log = try addU32(log, blowup);
            const stride = try pow2u32(physical_log);
            columns[source_index] = .{
                .tree_ordinal = @intCast(ordinal),
                .local_column = @intCast(local),
                .global_column = @intCast(source_index),
                .compact = .{
                    .offset_words = offset,
                    .stride_words = stride,
                    .log_size = log,
                },
            };
            source_index += 1;
            offset = std.math.add(u64, offset, stride) catch return error.CircuitQuotientSizeOverflow;
        }
        span.* = .{
            .tree_ordinal = @intCast(ordinal),
            .role = @enumFromInt(ordinal),
            .first_source = @intCast(first),
            .source_count = @intCast(tree.column_logs.len),
            .evaluation_words = offset,
        };
        all_words = std.math.add(u64, all_words, offset) catch return error.CircuitQuotientSizeOverflow;
    }
    return .{ .columns = columns, .trees = trees, .words = all_words };
}

fn pow2u32(log: u32) !u32 {
    if (log >= 31) return error.CircuitQuotientSizeOverflow;
    return @as(u32, 1) << @intCast(log);
}
fn u32Count(value: usize) !u32 { return std.math.cast(u32, value) orelse error.CircuitQuotientSizeOverflow; }
fn add(a: usize, b: usize) !usize { return std.math.add(usize, a, b) catch error.CircuitQuotientSizeOverflow; }
fn addU32(a: u32, b: u32) !u32 { return std.math.add(u32, a, b) catch error.CircuitQuotientSizeOverflow; }

test "resident circuit quotient admits all sampled terms and native-height buckets" {
    const allocator = std.testing.allocator;
    const circuit = @import("stwo_circuit_frontend");
    const air = @import("air_aot.zig");
    const encoded = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try circuit_cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air.build(allocator, encoded);
    defer catalog.deinit();
    const layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(circuit_cpu.air.recorded_sizes);
    var bound = try circuit_cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&layout), &layout);
    defer bound.deinit();
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    var geometry = try geometry_module.Geometry.init(allocator, &layout, &bound, &catalog, core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, layout.traceLogSize()));
    defer geometry.deinit();
    var oods = try oods_module.Plan.init(allocator, &bound, &geometry, 1);
    defer oods.deinit();
    var topology = derive(allocator, &bound, &geometry, &oods, 1) catch |err| {
        std.debug.print("circuit quotient derive failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer topology.deinit();
    try std.testing.expectEqual(oods.offsets.len, topology.sampled_value_count);
    try std.testing.expect(topology.prepared_terms.len >= topology.sampled_value_count);
    try std.testing.expectEqual(@as(usize, 4), topology.source_trees.len);
    var bucket_plan = try buckets.build(allocator, topology);
    defer bucket_plan.deinit();
    try std.testing.expect(bucket_plan.descriptors.len != 0);
}

test "resident circuit quotient binds the shared native CUDA executor" {
    const Dispatch = struct {
        fn run(
            allocator: std.mem.Allocator,
            session: *cuda.runtime.NativeSession,
            bound: *const circuit_cpu.air.Bundle,
            geometry: *const geometry_module.Geometry,
            oods: *const oods_module.Plan,
            commits: [4]commit_module.Buffers,
            view: shared.resident_views.Oods,
            quotient: controller.QuotientBindings,
            forward: common.Words,
            inverse: common.Words,
        ) !controller.Prepared {
            return prepareResident(allocator, session, bound, geometry, oods, 1, commits, view, quotient, forward, inverse);
        }
    };
    const entry: *const fn (std.mem.Allocator, *cuda.runtime.NativeSession, *const circuit_cpu.air.Bundle, *const geometry_module.Geometry, *const oods_module.Plan, [4]commit_module.Buffers, shared.resident_views.Oods, controller.QuotientBindings, common.Words, common.Words) anyerror!controller.Prepared = &Dispatch.run;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
