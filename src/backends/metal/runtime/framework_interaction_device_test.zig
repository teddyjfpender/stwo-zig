//! Device fraction/scan parity uses an independent CPU sum of individual
//! fractions in canonical coset order, including scan carries and padded rows.
const std = @import("std");
const core = @import("stwo_core");
const backend = @import("stwo_prover_engine").air.component_prover;
const generator = @import("framework_interaction_codegen.zig");
const runtime = @import("../runtime.zig");
const interaction = @import("framework_interaction.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const allocator = std.testing.allocator;
extern fn stwo_framework_interaction_test_prepare([*]const u8, usize, [*]const u8, usize, [*]const u32, u32, u32, u32, u32) ?*anyopaque;
extern fn stwo_framework_interaction_test_reject_metadata(*anyopaque) bool;
extern fn stwo_framework_interaction_test_upload(*anyopaque, [*]const u32, usize, *?*anyopaque) ?*anyopaque;
const counts = [_]usize{ 3, 4, 8 };

fn fixture(a: std.mem.Allocator) !backend.OwnedFrameworkPolynomialProgramV1 {
    const inputs = [_]backend.TypedPolynomialInputV1{
        .{ .trace_column = .{ .tree_index = 1, .column_index = 2 } },
        .{ .trace_column = .{ .tree_index = 1, .column_index = 0 } },
        .{ .trace_column = .{ .tree_index = 0, .column_index = 1 } },
    };
    const nodes = [_]backend.BasePolynomialNode{
        .{ .op = .column, .value = 0 }, .{ .op = .column, .value = 1 }, .{ .op = .constant, .value = 7 }, .{ .op = .neg, .lhs = 0 },
    };
    var entries = [_]backend.FrameworkLookupEntryV1{
        .{ .domain = 1, .schema_version = 1, .numerator = 0, .arity = 2 },
        .{ .domain = 2, .schema_version = 1, .numerator = 3, .arity = 1 },
        .{ .domain = 3, .schema_version = 1, .numerator = 0, .arity = 1 },
    };
    entries[0].values[0] = 1;
    entries[0].values[1] = 2;
    entries[1].values[0] = 1;
    entries[2].values[0] = 2;
    const batches = [_]backend.FrameworkLookupBatchV1{
        .{ .first_entry = 0, .entry_count = 2, .interaction_column_start = 0 },
        .{ .first_entry = 2, .entry_count = 1, .interaction_column_start = 4 },
    };
    var columns: [8]backend.TypedPolynomialColumnV1 = undefined;
    for (&columns, 0..) |*column, index| column.* = .{ .tree_index = 2, .column_index = @intCast(index) };
    var temporary = backend.OwnedFrameworkPolynomialProgramV1{
        .allocator = a,
        .semantic_digest = @splat(7),
        .registry_order_digest = @splat(9),
        .direct = .{ .allocator = a, .nodes = try a.alloc(backend.BasePolynomialNode, 0), .roots = try a.alloc(u32, 0), .column_count = inputs.len },
        .lookup_nodes = try a.dupe(backend.BasePolynomialNode, &nodes),
        .entries = try a.dupe(backend.FrameworkLookupEntryV1, &entries),
        .batches = try a.dupe(backend.FrameworkLookupBatchV1, &batches),
        .inputs = try a.dupe(backend.TypedPolynomialInputV1, &inputs),
        .interaction_columns = try a.dupe(backend.TypedPolynomialColumnV1, &columns),
        .profile_parameter_count = 0,
        .layout = .independent_prefix_v1,
        .is_first_input = 2,
        .identity = @splat(0),
    };
    temporary.identity = temporary.identityDigest();
    try temporary.validate(&counts);
    return temporary;
}

fn upload(plan: *const interaction.Plan, words: []const u32) !runtime.ResidentBuffer {
    var contents: ?*anyopaque = null;
    const handle = stwo_framework_interaction_test_upload(plan.handleForTesting(), words.ptr, words.len, &contents) orelse return error.MetalUnavailable;
    return .{ .handle = handle, .contents = contents.?, .byte_length = words.len * 4 };
}
fn rowIndex(index: usize, log: u32) usize {
    return core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(index, log), log);
}
fn readRow(result: *const interaction.Result, batch: usize, row: usize) QM31 {
    return QM31.fromM31Array(.{ result.column(batch * 4)[row], result.column(batch * 4 + 1)[row], result.column(batch * 4 + 2)[row], result.column(batch * 4 + 3)[row] });
}

test "framework interaction GPU independent fractions scans claims padding and rejection" {
    var fixture_arena = std.heap.ArenaAllocator.init(allocator);
    defer fixture_arena.deinit();
    var program = try fixture(fixture_arena.allocator());
    defer program.deinit();
    const entry = generator.Entry{ .program = &program, .tree_column_counts = &counts };
    var plan = try interaction.Plan.init(allocator, entry);
    defer plan.deinit();
    const source = try generator.generateLibrary(allocator, entry);
    defer allocator.free(source);
    // Admission owns its input coordinates, symbol and shape. Mutating even a
    // same-tree source coordinate before prepare must not reroute execution.
    program.inputs[0].trace_column.column_index = 1;
    program.inputs[1].trace_column.tree_index = 0;
    program.profile_parameter_count = 2;
    program.batches[0].entry_count = 1;
    program.identity = @splat(0);
    // Wrong/unadmitted profiles fail before dereferencing this dummy runtime.
    var old_core = runtime.Runtime{ .handle = @ptrFromInt(1), .admitted_profile = .core_v2 };
    try std.testing.expectError(error.FrameworkInteractionUnavailable, plan.prepare(&old_core));
    old_core.admitted_profile = null;
    try std.testing.expectError(error.FrameworkInteractionUnavailable, plan.prepare(&old_core));
    old_core.admitted_profile = .recursive_framework_v1;
    // This synthetic test program is deliberately outside production roster.
    try std.testing.expectError(error.FrameworkInteractionUnavailable, plan.prepare(&old_core));
    try plan.prepareForTesting(source, stwo_framework_interaction_test_prepare);
    try std.testing.expect(stwo_framework_interaction_test_reject_metadata(plan.handleForTesting()));

    const challenges = [_]QM31{
        QM31.fromU32Unchecked(11, 13, 17, 19), QM31.one(), QM31.fromU32Unchecked(3, 5, 7, 9),
        QM31.fromU32Unchecked(23, 29, 31, 37), QM31.one(), QM31.fromU32Unchecked(41, 43, 47, 53),
        QM31.fromU32Unchecked(59, 61, 67, 71),
    };
    var checked_rows: usize = 0;
    for ([_]u32{ 1, 7, 8, 9, 10 }) |log| {
        const rows = @as(usize, 1) << @intCast(log);
        const pp = try allocator.alloc(u32, 3 * rows + 11);
        defer allocator.free(pp);
        @memset(pp, 0);
        const main = try allocator.alloc(u32, 4 * rows + 17);
        defer allocator.free(main);
        @memset(main, 0);
        const pp_offsets = [_]u64{ 0, 5, 2 * rows };
        const main_offsets = [_]u64{ 7, rows + 7, 2 * rows + 7, 3 * rows + 7 };
        pp[5] = 1;
        const real = if (rows > 3) rows - 3 else 1;
        for (0..rows) |index| {
            const row = rowIndex(index, log);
            main[7 + row] = @intCast(index + 101);
            main[2 * rows + 7 + row] = if (index < real) @intCast(index % 17 + 1) else 0;
        }
        var pp_resident = try upload(&plan, pp);
        defer pp_resident.deinit();
        var main_resident = try upload(&plan, main);
        defer main_resident.deinit();
        const trees = [2]?interaction.Tree{ .{ .buffer = &pp_resident, .column_offsets = &pp_offsets }, .{ .buffer = &main_resident, .column_offsets = &main_offsets } };
        const invocation = interaction.Invocation{ .trace_log_size = log, .profile_values = &.{}, .relation_values = &challenges };
        var result = try plan.generate(trees, invocation);
        defer result.deinit();
        var totals = [_]QM31{ QM31.zero(), QM31.zero() };
        for (0..rows) |index| {
            const row = rowIndex(index, log);
            const value = QM31.fromBase(M31.fromCanonical(main[7 + row]));
            const numerator = QM31.fromBase(M31.fromCanonical(main[2 * rows + 7 + row]));
            const d0 = value.mul(challenges[1]).add(QM31.fromBase(M31.fromCanonical(7)).mul(challenges[2])).sub(challenges[0]);
            const d1 = value.mul(challenges[4]).sub(challenges[3]);
            const d2 = QM31.fromBase(M31.fromCanonical(7)).mul(challenges[6]).sub(challenges[5]);
            totals[0] = totals[0].add(numerator.mul(try d0.inv())).sub(numerator.mul(try d1.inv()));
            totals[1] = totals[1].add(numerator.mul(try d2.inv()));
            for (totals, 0..) |expected, batch| try std.testing.expect(readRow(&result, batch, row).eql(expected));
        }
        for (totals, 0..) |expected, batch| try std.testing.expect(result.claim(batch).eql(expected));
        try std.testing.expect(!result.claim(0).eql(result.claim(1)));
        checked_rows += rows;
        // A zero denominator in a padded row is still rejected, not silently
        // replaced by 0/1. This provider's AIR evaluates all rows.
        var zero_challenges = challenges;
        zero_challenges[0] = QM31.fromBase(M31.fromU64(rows - 1 + 101)).mul(challenges[1]).add(QM31.fromBase(M31.fromCanonical(7)).mul(challenges[2]));
        var invalid = invocation;
        invalid.relation_values = &zero_challenges;
        try std.testing.expectError(error.FrameworkInteractionZeroDenominator, plan.generate(trees, invalid));
        const mapped_pp: [*]u32 = @ptrCast(@alignCast(pp_resident.contents));
        const bad_row = rowIndex(rows - 1, log);
        mapped_pp[5 + bad_row] = 1;
        try std.testing.expectError(error.FrameworkInteractionInvalidSelector, plan.generate(trees, invocation));
        mapped_pp[5 + bad_row] = 0;
        const mapped_main: [*]u32 = @ptrCast(@alignCast(main_resident.contents));
        mapped_main[7 + bad_row] = core.fields.m31.Modulus;
        try std.testing.expectError(error.FrameworkInteractionNoncanonicalInput, plan.generate(trees, invocation));
        mapped_main[7 + bad_row] = main[7 + bad_row];
        var short = main_resident;
        short.byte_length = 4;
        var malformed_trees = trees;
        malformed_trees[1].?.buffer = &short;
        try std.testing.expectError(error.InvalidFrameworkInteraction, plan.generate(malformed_trees, invocation));
        var recovered = try plan.generate(trees, invocation);
        defer recovered.deinit();
        try std.testing.expect(recovered.claim(0).eql(totals[0]));
    }
    std.debug.print("FRAMEWORK_INTERACTION_GPU_V1 geometries=5 rows={} batches=2 dispatches=100 includes_failure_recovery=true\n", .{checked_rows});
}
