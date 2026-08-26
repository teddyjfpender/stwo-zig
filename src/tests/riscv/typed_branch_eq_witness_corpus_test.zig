//! Shared-corpus acceptance evidence for typed BRANCH_EQ production authority.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const frontend = @import("stwo_riscv_frontend");
const corpus_mod = @import("rigidity_corpus.zig");

const trace_mod = frontend.runner.trace;
const typed = frontend.testing.typed_branch_eq;
const witness = frontend.testing.typed_branch_eq_witness;
const legacy_oracle = frontend.testing.branch_eq_legacy_test_oracle;

test "witness rigidity: typed BRANCH_EQ authority and legacy oracle match every sampled row" {
    const allocator = std.testing.allocator;
    const corpus = try corpus_mod.shared();

    var trace = trace_mod.Trace.init(allocator);
    defer trace.deinit();
    for (corpus.samples) |sample| {
        if (sample.family != .branch_eq) continue;
        try std.testing.expect(
            sample.trace_row.opcode == .BEQ or sample.trace_row.opcode == .BNE,
        );
        try trace.append(sample.trace_row);
    }
    try std.testing.expect(trace.rows.items.len != 0);

    const log_size: u32 = @intCast(std.math.log2_int_ceil(
        usize,
        trace.rows.items.len,
    ));
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var production = try trace.columnsForFamily(allocator, .branch_eq, log_size);
    defer production.deinit(allocator);
    try std.testing.expectEqual(trace.rows.items.len, production.n_real_rows);
    try std.testing.expectEqual(witness.MAIN_COLUMN_COUNT, production.n_columns);

    var generated: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var legacy: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var initialized: usize = 0;
    defer {
        for (generated[0..initialized]) |column| allocator.free(column);
        for (legacy[0..initialized]) |column| allocator.free(column);
    }
    for (&generated, &legacy) |*generated_column, *legacy_column| {
        generated_column.* = try allocator.alloc(M31, domain_size);
        errdefer allocator.free(generated_column.*);
        legacy_column.* = try allocator.alloc(M31, domain_size);
        initialized += 1;
        @memset(legacy_column.*, M31.zero());
    }

    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try executor.generateMainInto(&generated, trace.rows.items, log_size);
    for (trace.rows.items, 0..) |row, logical_row|
        legacy_oracle.writeRow(&legacy, logical_row, row);

    for (generated, production.columns[0..witness.MAIN_COLUMN_COUNT], legacy) |
        generated_column,
        production_column,
        legacy_column,
    | {
        try std.testing.expectEqualSlices(M31, legacy_column, generated_column);
        try std.testing.expectEqualSlices(M31, legacy_column, production_column);
    }
}
