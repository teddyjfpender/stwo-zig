//! Shared-corpus acceptance evidence for the typed LUI production witness.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const frontend = @import("stwo_riscv_frontend");
const corpus_mod = @import("rigidity_corpus.zig");

const trace_mod = frontend.runner.trace;
const typed_lui = frontend.testing.typed_lui;
const witness = frontend.testing.typed_lui_witness;
const legacy_oracle = frontend.testing.lui_legacy_test_oracle;

test "witness rigidity: typed LUI authority and legacy oracle match every sampled row" {
    const allocator = std.testing.allocator;
    const corpus = try corpus_mod.shared();

    var trace = trace_mod.Trace.init(allocator);
    defer trace.deinit();
    for (corpus.samples) |sample| {
        if (sample.family != .lui) continue;
        try std.testing.expectEqual(frontend.isa.decode.Opcode.LUI, sample.trace_row.opcode);
        try trace.append(sample.trace_row);
    }
    try std.testing.expect(trace.rows.items.len != 0);

    const log_size: u32 = @intCast(std.math.log2_int_ceil(
        usize,
        trace.rows.items.len,
    ));
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var production = try trace.columnsForFamily(allocator, .lui, log_size);
    defer production.deinit(allocator);
    try std.testing.expectEqual(trace.rows.items.len, production.n_real_rows);
    try std.testing.expectEqual(witness.MAIN_COLUMN_COUNT, production.n_columns);

    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var legacy: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    var initialized: usize = 0;
    defer {
        for (columns[0..initialized]) |column| allocator.free(column);
        for (legacy[0..initialized]) |column| allocator.free(column);
    }
    for (&columns, &legacy) |*column, *legacy_column| {
        column.* = try allocator.alloc(M31, domain_size);
        errdefer allocator.free(column.*);
        legacy_column.* = try allocator.alloc(M31, domain_size);
        initialized += 1;
        @memset(legacy_column.*, M31.zero());
    }

    var definition = try typed_lui.build(allocator, .generated);
    defer definition.deinit();
    const binding = witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try executor.generateMainInto(&columns, trace.rows.items, log_size);
    for (trace.rows.items, 0..) |row, logical_row| {
        legacy_oracle.writeRow(&legacy, logical_row, row);
    }

    for (columns, production.columns[0..witness.MAIN_COLUMN_COUNT], legacy) |
        executor_column,
        production_column,
        legacy_column,
    | {
        try std.testing.expectEqualSlices(M31, legacy_column, executor_column);
        try std.testing.expectEqualSlices(M31, legacy_column, production_column);
    }
}
