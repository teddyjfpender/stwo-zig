//! Cold ownership boundary for authenticated framework composition jobs.
//! Exports are owned once. Dispatch preparation and trace-pointer reads consume
//! that admitted state without repeating upstream program/parameter audits.
const std = @import("std");
const core = @import("stwo_core");
const component_mod = @import("stwo_prover_engine").air.component_prover;
const runtime_mod = @import("../runtime.zig");
const codegen = @import("framework_polynomial_codegen.zig");
const Component = component_mod.ComponentProver;
const Capability = component_mod.FrameworkPolynomialCapabilityV1;
const Program = component_mod.OwnedFrameworkPolynomialProgramV1;
const Parameters = component_mod.OwnedFrameworkPolynomialParametersV1;
const Trace = component_mod.Trace;
const M31 = core.fields.m31.M31;

pub const Job = struct {
    allocator: std.mem.Allocator,
    component: Component,
    program: Program,
    parameters: Parameters,
    kernel_name: []u8,
    column_trees: []u32,
    profile_words: []u32,
    relation_words: []u32,
    trace_log_size: u32,
    eval_log_size: u32,
    row_count: usize,
    constraint_count: usize,
    power_start: usize,
    plan: ?runtime_mod.FrameworkPolynomialPlan = null,

    pub fn init(
        allocator: std.mem.Allocator,
        component: Component,
        capability: Capability,
        tree_counts: []const usize,
        power_start: usize,
    ) !Job {
        const active = component.backend_composition_capability orelse
            return error.InvalidFrameworkPolynomialCapability;
        switch (active) {
            .framework_polynomial_v1 => |expected| if (!std.meta.eql(expected, capability))
                return error.InvalidFrameworkPolynomialCapability,
            else => return error.InvalidFrameworkPolynomialCapability,
        }
        var program = try capability.export_program(component.ctx, allocator, tree_counts);
        errdefer program.deinit();
        var parameters = try capability.export_parameters(component.ctx, allocator);
        errdefer parameters.deinit();
        const eval_log_size = component.maxConstraintLogDegreeBound();
        const constraint_count = component.nConstraints();
        const geometry = try admit(
            &program,
            parameters.values,
            tree_counts,
            capability.trace_log_size,
            eval_log_size,
            constraint_count,
            power_start,
        );
        const kernel_name = try codegen.kernelName(allocator, .{ .program = &program, .tree_column_counts = tree_counts });
        errdefer allocator.free(kernel_name);
        const column_trees = try allocator.alloc(u32, geometry.column_count);
        errdefer allocator.free(column_trees);
        for (program.inputs, column_trees[0..program.inputs.len]) |input, *tree| {
            tree.* = switch (input) {
                .trace_column => |column| column.tree_index,
                .profile_parameter => std.math.maxInt(u32),
            };
        }
        for (program.interaction_columns, column_trees[program.inputs.len..]) |column, *tree|
            tree.* = column.tree_index;
        const profile_words = try allocator.alloc(u32, parameters.values.profile_values.len);
        errdefer allocator.free(profile_words);
        for (parameters.values.profile_values, profile_words) |value, *word|
            word.* = value.toU32();
        const relation_words = try allocator.alloc(u32, geometry.relation_word_count);
        errdefer allocator.free(relation_words);
        for (parameters.values.relation_values, 0..) |value, index|
            writeSecure(relation_words[index * 4 ..][0..4], value);
        for (0..parameters.values.claimPayloadCount(&program)) |index|
            writeSecure(relation_words[(parameters.values.relation_values.len + index) * 4 ..][0..4], try parameters.values.claimPayload(&program, index));
        return .{
            .allocator = allocator,
            .component = component,
            .program = program,
            .parameters = parameters,
            .kernel_name = kernel_name,
            .column_trees = column_trees,
            .profile_words = profile_words,
            .relation_words = relation_words,
            .trace_log_size = capability.trace_log_size,
            .eval_log_size = eval_log_size,
            .row_count = geometry.row_count,
            .constraint_count = constraint_count,
            .power_start = power_start,
        };
    }

    pub fn deinit(self: *Job) void {
        if (self.plan) |*plan| plan.deinit();
        self.allocator.free(self.relation_words);
        self.allocator.free(self.profile_words);
        self.allocator.free(self.column_trees);
        self.allocator.free(self.kernel_name);
        self.parameters.deinit();
        self.program.deinit();
        self.* = undefined;
    }

    pub fn prepare(self: *Job, runtime: *runtime_mod.Runtime) !void {
        if (self.plan != null) return error.FrameworkPolynomialAlreadyPrepared;
        self.plan = try runtime.prepareFrameworkPolynomialAot(
            self.kernel_name,
            self.column_trees,
            @intCast(self.profile_words.len),
            @intCast(self.relation_words.len),
            @intCast(self.constraint_count * 4),
        );
    }

    /// The returned pointer descriptors borrow exact evaluation columns; the
    /// caller frees only this descriptor slice. Residency is checked by the
    /// runtime against proof-owned buffers, never inferred from host pointers.
    pub fn columnPointers(self: *const Job, allocator: std.mem.Allocator, trace: *const Trace) ![]?[*]const u32 {
        return resolvePointers(allocator, &self.program, self.eval_log_size, self.row_count, trace);
    }
};

const Geometry = struct { row_count: usize, column_count: usize, relation_word_count: usize };

fn admit(program: *const Program, parameters: component_mod.FrameworkPolynomialParametersV1, tree_counts: []const usize, trace_log: u32, eval_log: u32, constraints: usize, power_start: usize) !Geometry {
    try codegen.validate(.{ .program = program, .tree_column_counts = tree_counts });
    try parameters.validate(program);
    if (trace_log == 0 or eval_log > 30 or eval_log <= trace_log or eval_log - trace_log > 3 or
        parameters.trace_log_size != trace_log or constraints == 0 or
        constraints != try std.math.add(usize, program.direct.roots.len, program.batches.len))
        return error.InvalidFrameworkPolynomialGeometry;
    const column_count = try std.math.add(usize, program.inputs.len, program.interaction_columns.len);
    const relation_word_count = try std.math.mul(usize, 4, try std.math.add(usize, parameters.relation_values.len, parameters.claimPayloadCount(program)));
    const power_end = try std.math.add(usize, power_start, constraints);
    const power_words = try std.math.mul(usize, power_end, 4);
    for ([_]usize{ column_count, parameters.profile_values.len, relation_word_count, power_words }) |count|
        if (count > std.math.maxInt(u32)) return error.FrameworkPolynomialGeometryOverflow;
    return .{
        .row_count = @as(usize, 1) << @intCast(eval_log),
        .column_count = column_count,
        .relation_word_count = relation_word_count,
    };
}

fn resolvePointers(allocator: std.mem.Allocator, program: *const Program, eval_log: u32, row_count: usize, trace: *const Trace) ![]?[*]const u32 {
    const columns = try allocator.alloc(?[*]const u32, program.inputs.len + program.interaction_columns.len);
    errdefer allocator.free(columns);
    for (program.inputs, columns[0..program.inputs.len]) |input, *pointer| pointer.* = switch (input) {
        .trace_column => |column| try columnPointer(trace, column, eval_log, row_count),
        .profile_parameter => null,
    };
    for (program.interaction_columns, columns[program.inputs.len..]) |column, *pointer|
        pointer.* = try columnPointer(trace, column, eval_log, row_count);
    return columns;
}

fn columnPointer(trace: *const Trace, coordinate: component_mod.TypedPolynomialColumnV1, eval_log: u32, rows: usize) ![*]const u32 {
    if (coordinate.tree_index >= trace.polys.items.len) return error.InvalidFrameworkPolynomialTrace;
    const tree = trace.polys.items[coordinate.tree_index];
    if (coordinate.column_index >= tree.len) return error.InvalidFrameworkPolynomialTrace;
    const column = tree[coordinate.column_index];
    if (column.log_size != eval_log or column.values.len != rows) return error.InvalidFrameworkPolynomialTrace;
    return @ptrCast(column.values.ptr);
}

fn writeSecure(words: []u32, value: core.fields.qm31.QM31) void {
    for (words, value.toM31Array()) |*word, coordinate| word.* = coordinate.toU32();
}

test "framework job cold admission binds canonical parameters geometry and constraint windows" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fixture = @import("framework_polynomial_codegen_test.zig");
    var program = try fixture.fixture(arena.allocator());
    var parameters = component_mod.FrameworkPolynomialParametersV1{
        .profile_values = &.{M31.fromU64(9)},
        .relation_values = &([_]core.fields.qm31.QM31{core.fields.qm31.QM31.one()} ** 6),
        .trace_log_size = 3,
        .claimed_sum = core.fields.qm31.QM31.fromU32Unchecked(8, 16, 24, 32),
    };
    const geometry = try admit(&program, parameters, &fixture.TREE_COUNTS, 3, 4, 3, 10);
    try std.testing.expectEqual(@as(usize, 16), geometry.row_count);
    try std.testing.expectEqual(@as(usize, 11), geometry.column_count);
    try std.testing.expectEqual(@as(usize, 28), geometry.relation_word_count);
    var shift: [4]u32 = undefined;
    writeSecure(&shift, try parameters.claimedSumShift());
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4 }, &shift);
    try std.testing.expectError(error.InvalidFrameworkPolynomialGeometry, admit(&program, parameters, &fixture.TREE_COUNTS, 2, 4, 3, 0));
    try std.testing.expectError(error.InvalidFrameworkPolynomialGeometry, admit(&program, parameters, &fixture.TREE_COUNTS, 3, 4, 2, 0));
    try std.testing.expectError(error.InvalidFrameworkPolynomialGeometry, admit(&program, parameters, &fixture.TREE_COUNTS, 3, 7, 3, 0));
    try std.testing.expectError(error.InvalidFrameworkPolynomialGeometry, admit(&program, parameters, &fixture.TREE_COUNTS, 3, 31, 3, 0));
    try std.testing.expectError(error.FrameworkPolynomialGeometryOverflow, admit(&program, parameters, &fixture.TREE_COUNTS, 3, 4, 3, std.math.maxInt(u32)));
    parameters.relation_values = parameters.relation_values[0..5];
    try std.testing.expectError(error.InvalidFrameworkPolynomialParameters, admit(&program, parameters, &fixture.TREE_COUNTS, 3, 4, 3, 0));
}

test "framework job pointer reads preserve exact columns and reject wrong evaluation domains" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fixture = @import("framework_polynomial_codegen_test.zig");
    var program = try fixture.fixture(arena.allocator());
    var words: [26][16]M31 = undefined;
    for (&words, 0..) |*column, index| @memset(column, M31.fromU64(index));
    var columns: [26]component_mod.Poly = undefined;
    for (&columns, &words) |*column, *values| column.* = .{ .log_size = 4, .values = values };
    var trees = [_][]const component_mod.Poly{ columns[0..3], columns[3..8], columns[8..26] };
    var trace = Trace{ .polys = .{ .items = &trees } };
    const pointers = try resolvePointers(std.testing.allocator, &program, 4, 16, &trace);
    defer std.testing.allocator.free(pointers);
    try std.testing.expectEqual(@intFromPtr(words[2][0..].ptr), @intFromPtr(pointers[0].?));
    try std.testing.expectEqual(@intFromPtr(words[7][0..].ptr), @intFromPtr(pointers[1].?));
    try std.testing.expect(pointers[2] == null);
    for (pointers[3..], 18..) |pointer, index|
        try std.testing.expectEqual(@intFromPtr(words[index][0..].ptr), @intFromPtr(pointer.?));
    columns[7].log_size = 5;
    try std.testing.expectError(error.InvalidFrameworkPolynomialTrace, resolvePointers(std.testing.allocator, &program, 4, 16, &trace));
    columns[7].log_size = 4;
    columns[7].values = words[7][0..8];
    try std.testing.expectError(error.InvalidFrameworkPolynomialTrace, resolvePointers(std.testing.allocator, &program, 4, 16, &trace));
}
