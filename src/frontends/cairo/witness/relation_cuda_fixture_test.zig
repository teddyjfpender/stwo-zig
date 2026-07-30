//! Deterministic Zig SIMD oracle for the first Cairo CUDA relation differential.

const std = @import("std");
const stwo_core = @import("stwo_core");
const QM31 = stwo_core.fields.qm31.QM31;
const relation_bundle = @import("relation_bundle.zig");
const interaction = @import("interaction_trace.zig");

const golden_path =
    "tests/cuda/fixtures/add_ap_relation_fixture.h";
const component_name = "add_ap_opcode";
const row_count: usize = 16;
const real_rows: usize = 11;

fn coordinates(value: QM31) [4]u32 {
    const words = value.toM31Array();
    return .{ words[0].v, words[1].v, words[2].v, words[3].v };
}

fn writeWords(
    writer: anytype,
    name: []const u8,
    values: []const u32,
) !void {
    try writer.print(
        "inline constexpr std::uint32_t {s}[{d}] = {{\n",
        .{ name, values.len },
    );
    for (values, 0..) |value, index| {
        if (index % 8 == 0) try writer.writeAll("    ");
        try writer.print("{d}u", .{value});
        if (index + 1 != values.len)
            try writer.writeAll(if (index % 8 == 7) "," else ", ");
        if (index % 8 == 7 or index + 1 == values.len)
            try writer.writeByte('\n');
    }
    try writer.writeAll("};\n\n");
}

fn renderGolden(allocator: std.mem.Allocator) ![]u8 {
    var bundle = try relation_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer bundle.deinit();
    if (bundle.graph_hash != relation_bundle.expected_graph_hash)
        return error.GraphHashMismatch;
    const component = bundle.find(component_name) orelse
        return error.MissingCanonicalRelation;
    if (component.traces.len != 1)
        return error.InvalidCanonicalRelation;
    const trace = &component.traces[0];
    if (trace.layout != .lookup_words or
        trace.part != .component or
        component.lookup_words != trace.layout_arg)
    {
        return error.InvalidCanonicalRelation;
    }

    const source_words = try allocator.alloc(
        u32,
        try std.math.mul(usize, trace.layout_arg, row_count),
    );
    defer allocator.free(source_words);
    for (0..trace.layout_arg) |column| {
        for (0..row_count) |row| {
            source_words[column * row_count + row] =
                @intCast(1 + (column * 17 + row * 13) % 1009);
        }
    }

    var max_alpha_powers: usize = 0;
    var descriptor_offset: usize = 0;
    while (descriptor_offset < trace.descriptors.len) : (descriptor_offset += 16) {
        const descriptor = trace.descriptors[descriptor_offset..][0..16];
        for (0..descriptor[0]) |use_index| {
            max_alpha_powers = @max(
                max_alpha_powers,
                descriptor[1 + use_index * 7 + 2],
            );
        }
    }
    if (max_alpha_powers == 0) return error.InvalidCanonicalRelation;

    const z = QM31.fromU32Unchecked(101, 103, 107, 109);
    const alpha = QM31.fromU32Unchecked(3, 5, 7, 11);
    const alpha_powers = try allocator.alloc(QM31, max_alpha_powers);
    defer allocator.free(alpha_powers);
    const alpha_words = try allocator.alloc(u32, max_alpha_powers * 4);
    defer allocator.free(alpha_words);
    var power = QM31.one();
    for (alpha_powers, 0..) |*slot, index| {
        slot.* = power;
        alpha_words[index * 4 ..][0..4].* = coordinates(power);
        power = power.mul(alpha);
    }

    const columns: usize = trace.output_columns;
    const expected_words = try allocator.alloc(
        u32,
        try std.math.mul(usize, columns * 4, row_count),
    );
    defer allocator.free(expected_words);
    const cumulative = try allocator.alloc(QM31, columns);
    defer allocator.free(cumulative);
    var reference = try interaction.Reference.init(
        allocator,
        trace.descriptors,
        try interaction.SourceView.lookupWords(
            try interaction.LookupColumns.init(source_words, row_count),
            real_rows,
        ),
        z,
        alpha_powers,
    );
    defer reference.deinit();

    var claimed_sum = QM31.zero();
    for (0..row_count) |row| {
        const total = try reference.evaluateRow(row, cumulative);
        claimed_sum = claimed_sum.add(total);
        for (cumulative, 0..) |value, column| {
            for (coordinates(value), 0..) |word, coordinate| {
                expected_words[
                    (column * 4 + coordinate) * row_count + row
                ] = word;
            }
        }
    }
    const last_values = try allocator.alloc(QM31, row_count);
    defer allocator.free(last_values);
    for (last_values, 0..) |*value, row| {
        const base = (columns - 1) * 4;
        value.* = QM31.fromU32Unchecked(
            expected_words[(base + 0) * row_count + row],
            expected_words[(base + 1) * row_count + row],
            expected_words[(base + 2) * row_count + row],
            expected_words[(base + 3) * row_count + row],
        );
    }
    const final = try interaction.scanLastColumnInPlace(
        last_values,
        claimed_sum,
    );
    if (!final.eql(QM31.zero())) return error.InvalidClaimedSum;
    for (last_values, 0..) |value, row| {
        const base = (columns - 1) * 4;
        for (coordinates(value), 0..) |word, coordinate|
            expected_words[(base + coordinate) * row_count + row] = word;
    }

    var rendered: std.ArrayList(u8) = .{};
    errdefer rendered.deinit(allocator);
    const writer = rendered.writer(allocator);
    try writer.writeAll(
        \\#ifndef STWO_ZIG_CUDA_ADD_AP_RELATION_FIXTURE_H
        \\#define STWO_ZIG_CUDA_ADD_AP_RELATION_FIXTURE_H
        \\
        \\#include <cstdint>
        \\
        \\namespace stwo::cuda::test::add_ap_relation {
        \\
    );
    try writer.print(
        "inline constexpr std::uint64_t kGraphHash = 0x{x:0>16}ull;\n",
        .{bundle.graph_hash},
    );
    try writer.print(
        \\inline constexpr std::uint32_t kRows = {d};
        \\inline constexpr std::uint32_t kRealRows = {d};
        \\inline constexpr std::uint32_t kSourceColumns = {d};
        \\inline constexpr std::uint32_t kOutputColumns = {d};
        \\inline constexpr std::uint32_t kAlphaPowers = {d};
        \\
        \\
    ,
        .{
            row_count,
            real_rows,
            trace.layout_arg,
            trace.output_columns,
            max_alpha_powers,
        },
    );
    try writeWords(writer, "kDrawnZAlpha", &(coordinates(z) ++ coordinates(alpha)));
    try writeWords(writer, "kExpectedAlphaPowers", alpha_words);
    try writeWords(writer, "kSourceWords", source_words);
    try writeWords(writer, "kDescriptors", trace.descriptors);
    try writeWords(writer, "kClaimedSum", &coordinates(claimed_sum));
    try writeWords(writer, "kExpectedCoordinates", expected_words);
    try writer.writeAll(
        \\}  // namespace stwo::cuda::test::add_ap_relation
        \\
        \\#endif
        \\
    );
    return rendered.toOwnedSlice(allocator);
}

test "add-ap relation golden is the cumulative Zig SIMD oracle" {
    const allocator = std.testing.allocator;
    const rendered = try renderGolden(allocator);
    defer allocator.free(rendered);

    const update = std.process.getEnvVarOwned(
        allocator,
        "STWO_UPDATE_CUDA_RELATION_FIXTURE",
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
        2 * 1024 * 1024,
    );
    defer allocator.free(golden);
    try std.testing.expectEqualStrings(golden, rendered);
}
