//! Checked-in CUDA matrix fixture derived by the Zig SIMD witness interpreter.

const std = @import("std");
const bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const oracle_mod = @import("recorded_witness_oracle.zig");
const pedersen_rows = @import("pedersen_fixture_rows.zig");
const program_mod = @import("stwo_cairo_frontend").witness.program;
const product_aot = @import("../../backends/cuda/aot/product_registry.zig");

const golden_path =
    "tests/cuda/fixtures/recorded_witness_matrix_fixture.bin";
const row_count: u32 = 4;
const expected_admitted = 32;
const expected_blocked = 1;
const fixture_magic = "STWZRWM\x00";
const fixture_version: u32 = 2;

const BlockReason = enum(u32) {
    native_composite_writer = 1,
};

fn isNativeComposite(label: []const u8) bool {
    return std.mem.eql(u8, label, "partial_ec_mul_generic");
}

fn transposeAuxiliary(
    allocator: std.mem.Allocator,
    words: usize,
    row_major: []const u32,
) ![]u32 {
    const result = try allocator.alloc(u32, words * row_count);
    for (0..row_count) |row| {
        for (0..words) |word| {
            result[word * row_count + row] =
                row_major[row * words + word];
        }
    }
    return result;
}

fn writeString(writer: anytype, value: []const u8) !void {
    if (value.len > std.math.maxInt(u16)) return error.FixtureStringTooLong;
    try writer.writeInt(u16, @intCast(value.len), .little);
    try writer.writeAll(value);
}

fn writeWords(writer: anytype, values: []const u32) !void {
    for (values) |value| try writer.writeInt(u32, value, .little);
}

fn writeCase(
    allocator: std.mem.Allocator,
    writer: anytype,
    entry: bundle_mod.Entry,
    resolved: product_aot.RecordedWitness,
    oracle: *oracle_mod.Oracle,
) !void {
    const program = entry.program;
    if (program.n_mult_tables != 0) {
        return error.UnsupportedFixtureMultiplicity;
    }
    const input_words = try std.math.mul(
        usize,
        program.n_inputs,
        row_count,
    );
    const output_words = try std.math.mul(
        usize,
        program.n_cols,
        row_count,
    );
    const inputs = try allocator.alloc(u32, input_words);
    defer allocator.free(inputs);
    @memset(inputs, 0);
    const input_columns = try allocator.alloc([]const u32, program.n_inputs);
    defer allocator.free(input_columns);
    for (input_columns, 0..) |*column, index| {
        column.* = inputs[index * row_count ..][0..row_count];
    }

    const outputs = try allocator.alloc(u32, output_words);
    defer allocator.free(outputs);
    const output_columns = try allocator.alloc([]u32, program.n_cols);
    defer allocator.free(output_columns);
    for (output_columns, 0..) |*column, index| {
        column.* = outputs[index * row_count ..][0..row_count];
    }
    const lookup_row_major = try allocator.alloc(
        u32,
        program.n_lookup_words * row_count,
    );
    defer allocator.free(lookup_row_major);
    const sub_row_major = try allocator.alloc(
        u32,
        program.n_sub_words * row_count,
    );
    defer allocator.free(sub_row_major);
    const registers = try allocator.alloc(u32, program.n_regs);
    defer allocator.free(registers);
    const deduce_args = try allocator.alloc(u32, program.n_regs);
    defer allocator.free(deduce_args);
    try program_mod.executeAll(
        program,
        input_columns,
        output_columns,
        .{
            .lookup_words = lookup_row_major,
            .sub_words = sub_row_major,
            .multiplicity_tables = &.{},
        },
        registers,
        deduce_args,
        .zero(),
        oracle.context(),
    );
    const lookup_word_major = try transposeAuxiliary(
        allocator,
        program.n_lookup_words,
        lookup_row_major,
    );
    defer allocator.free(lookup_word_major);
    const sub_word_major = try transposeAuxiliary(
        allocator,
        program.n_sub_words,
        sub_row_major,
    );
    defer allocator.free(sub_word_major);

    try writeString(writer, entry.label);
    try writeString(writer, resolved.kernel_name);
    try writer.writeInt(u64, resolved.cache_key, .little);
    try writer.writeInt(u64, entry.semantic_hash, .little);
    try writer.writeAll(&resolved.program_identity);
    try writer.writeInt(
        u32,
        @intFromEnum(resolved.module_globals),
        .little,
    );
    try writer.writeInt(u32, program.n_inputs, .little);
    try writer.writeInt(u32, program.n_cols, .little);
    try writer.writeInt(u32, program.n_lookup_words, .little);
    try writer.writeInt(u32, program.n_sub_words, .little);
    try writer.writeInt(u32, program.n_mult_tables, .little);
    try writeWords(writer, inputs);
    try writeWords(writer, outputs);
    try writeWords(writer, lookup_word_major);
    try writeWords(writer, sub_word_major);
}

fn renderGolden(allocator: std.mem.Allocator) ![]u8 {
    var bundle = try bundle_mod.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer bundle.deinit();
    var registry = try product_aot.Registry.initProduct(allocator);
    defer registry.deinit();
    var oracle = try oracle_mod.Oracle.init();

    var admitted: usize = 0;
    var blocked: usize = 0;
    for (bundle.entries) |entry| {
        _ = registry.resolveRecordedWitness(.{
            .label = entry.label,
            .semantic_hash = entry.semantic_hash,
            .program_identity = entry.program.semanticIdentity(),
        }) orelse return error.MissingProductRecordedWitness;
        if (isNativeComposite(entry.label)) {
            blocked += 1;
        } else {
            admitted += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, expected_admitted), admitted);
    try std.testing.expectEqual(@as(usize, expected_blocked), blocked);

    var rendered: std.ArrayList(u8) = .{};
    errdefer rendered.deinit(allocator);
    const writer = rendered.writer(allocator);
    try writer.writeAll(fixture_magic);
    try writer.writeInt(u32, fixture_version, .little);
    try writer.writeInt(u32, row_count, .little);
    try writer.writeInt(u32, @intCast(admitted), .little);
    try writer.writeInt(u32, @intCast(blocked), .little);
    try writer.writeAll(&oracle_mod.pedersenFixtureIdentity());
    try writer.writeInt(u32, 28, .little);
    for (0..28) |round| {
        const row: u32 = @intCast(round * pedersen_rows.row_stride);
        try writer.writeInt(u32, row, .little);
        try writeWords(writer, pedersen_rows.find(row).?);
    }

    for (bundle.entries) |entry| {
        const resolved = registry.resolveRecordedWitness(.{
            .label = entry.label,
            .semantic_hash = entry.semantic_hash,
            .program_identity = entry.program.semanticIdentity(),
        }).?;
        if (isNativeComposite(entry.label)) continue;
        try writeCase(
            allocator,
            writer,
            entry,
            resolved,
            &oracle,
        );
    }
    for (bundle.entries) |entry| {
        const reason: BlockReason = if (isNativeComposite(entry.label))
            .native_composite_writer
        else
            continue;
        try writeString(writer, entry.label);
        try writer.writeInt(u32, @intFromEnum(reason), .little);
    }
    return rendered.toOwnedSlice(allocator);
}

test "recorded witness CUDA matrix matches Zig SIMD for every admitted writer" {
    const allocator = std.testing.allocator;
    const rendered = try renderGolden(allocator);
    defer allocator.free(rendered);

    const update = std.process.getEnvVarOwned(
        allocator,
        "STWO_UPDATE_CUDA_RECORDED_MATRIX_FIXTURE",
    ) catch null;
    defer if (update) |value| allocator.free(value);
    if (update != null) {
        try std.fs.cwd().writeFile(.{
            .sub_path = golden_path,
            .data = rendered,
        });
        return;
    }
    const golden = try std.fs.cwd().readFileAlloc(
        allocator,
        golden_path,
        8 * 1024 * 1024,
    );
    defer allocator.free(golden);
    try std.testing.expectEqualSlices(u8, golden, rendered);
}
