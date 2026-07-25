//! Checked-in CUDA device fixture derived by the Zig SIMD witness interpreter.

const std = @import("std");
const bundle_mod = @import("bundle.zig");
const program_mod = @import("program.zig");

const golden_path =
    "tests/cuda/fixtures/add_ap_opcode_recorded_witness_fixture.h";
const row_count = 4;
const input_count = 4;
const output_count = 17;
const lookup_count = 55;
const sub_count = 11;
const big_limb_count = 28;
const small_limb_count = 8;
const big_value_count = 2;
const small_value_count = 2;
const address_table_size = 256;

const AddressEntry = struct {
    address: u32,
    encoded_id: u32,
};

const address_entries = [_]AddressEntry{
    .{ .address = 1, .encoded_id = 0x4000_0001 },
    .{ .address = 2, .encoded_id = 0x4000_0000 },
    .{ .address = 16, .encoded_id = 1 },
    .{ .address = 32, .encoded_id = 0 },
    .{ .address = 100, .encoded_id = 0 },
    .{ .address = 101, .encoded_id = 1 },
    .{ .address = 102, .encoded_id = 0x4000_0000 },
    .{ .address = 103, .encoded_id = 0x4000_0001 },
};

const input_columns = [input_count][row_count]u32{
    .{ 100, 101, 102, 103 },
    .{ 32768, 32768, 32768, 32768 },
    .{ 5, 7, 11, 13 },
    .{ 17, 19, 23, 29 },
};

const Tables = struct {
    address_to_id: [address_table_size]u32 = @splat(0),
    big_limbs: [big_limb_count][big_value_count]u32 =
        @splat(@splat(0)),
    small_limbs: [small_limb_count][small_value_count]u32 =
        @splat(@splat(0)),

    fn init() Tables {
        var tables = Tables{};
        for (address_entries) |entry| {
            tables.address_to_id[entry.address] = entry.encoded_id;
        }

        // The first dereference produces addresses 1, 2, 16, and 32.
        tables.small_limbs[3] = .{ 32, 64 };
        tables.big_limbs[4] = .{ 1, 2 };

        // The second dereference covers both high-limb flag branches.
        tables.big_limbs[20][1] = 511;
        tables.big_limbs[27] = .{ 256, 256 };
        return tables;
    }

    fn context(self: *Tables) program_mod.TableContext {
        return .{ .context = self, .limb_fn = tableLimb };
    }

    fn tableLimb(
        erased: *anyopaque,
        table: u32,
        row: u32,
        limb_index: u32,
    ) u32 {
        const self: *Tables = @ptrCast(@alignCast(erased));
        return switch (table) {
            0 => if (row < self.address_to_id.len)
                self.address_to_id[row]
            else
                0,
            1 => self.valueLimb(row, limb_index),
            else => 0,
        };
    }

    fn valueLimb(self: *Tables, encoded_id: u32, limb_index: u32) u32 {
        const tag = encoded_id >> 30;
        const value_index = encoded_id & 0x3fff_ffff;
        if (tag == 1) {
            if (limb_index >= big_limb_count or
                value_index >= big_value_count)
                return 0;
            return self.big_limbs[limb_index][value_index];
        }
        if (limb_index >= small_limb_count or
            value_index >= small_value_count)
            return 0;
        return self.small_limbs[limb_index][value_index];
    }
};

fn flatten(
    comptime outer: usize,
    comptime inner: usize,
    source: *const [outer][inner]u32,
) [outer * inner]u32 {
    var result: [outer * inner]u32 = undefined;
    for (source, 0..) |values, column| {
        @memcpy(result[column * inner ..][0..inner], &values);
    }
    return result;
}

fn transposeAuxiliary(
    comptime words: usize,
    row_major: *const [row_count * words]u32,
) [row_count * words]u32 {
    var word_major: [row_count * words]u32 = undefined;
    for (0..row_count) |row| {
        for (0..words) |word| {
            word_major[word * row_count + row] =
                row_major[row * words + word];
        }
    }
    return word_major;
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
    var bundle = try bundle_mod.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer bundle.deinit();
    const entry = bundle.find("add_ap_opcode") orelse
        return error.MissingCanonicalWitness;
    try std.testing.expectEqual(
        @as(u64, 0xd94540f2fd219001),
        entry.semantic_hash,
    );
    try std.testing.expectEqual(@as(u32, output_count), entry.program.n_cols);
    try std.testing.expectEqual(
        @as(u32, lookup_count),
        entry.program.n_lookup_words,
    );
    try std.testing.expectEqual(
        @as(u32, sub_count),
        entry.program.n_sub_words,
    );
    try std.testing.expectEqual(@as(u32, 0), entry.program.n_mult_tables);
    var expected_identity: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_identity,
        "1c87a53a6c6ded98045fb88728f9cbd14f79ad8471cff7a16416139a64737da5",
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_identity,
        &entry.program.semanticIdentity(),
    );

    var tables = Tables.init();
    var outputs: [output_count][row_count]u32 = undefined;
    var output_slices: [output_count][]u32 = undefined;
    for (&outputs, 0..) |*column, index| {
        output_slices[index] = column;
    }
    var input_slices: [input_count][]const u32 = undefined;
    for (&input_columns, 0..) |*column, index| {
        input_slices[index] = column;
    }
    var lookup_row_major: [row_count * lookup_count]u32 = undefined;
    var sub_row_major: [row_count * sub_count]u32 = undefined;
    var registers: [128]u32 = undefined;
    var deduce_args: [128]u32 = undefined;
    try program_mod.executeAll(
        entry.program,
        &input_slices,
        &output_slices,
        .{
            .lookup_words = &lookup_row_major,
            .sub_words = &sub_row_major,
            .multiplicity_tables = &.{},
        },
        &registers,
        &deduce_args,
        tables.context(),
        program_mod.DeduceContext.unsupported(),
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 1, 2, 16, 32 },
        &outputs[3],
    );

    const flat_inputs = flatten(input_count, row_count, &input_columns);
    const flat_big = flatten(
        big_limb_count,
        big_value_count,
        &tables.big_limbs,
    );
    const flat_small = flatten(
        small_limb_count,
        small_value_count,
        &tables.small_limbs,
    );
    const flat_outputs = flatten(output_count, row_count, &outputs);
    const lookup_word_major = transposeAuxiliary(
        lookup_count,
        &lookup_row_major,
    );
    const sub_word_major = transposeAuxiliary(sub_count, &sub_row_major);

    var rendered: std.ArrayList(u8) = .{};
    errdefer rendered.deinit(allocator);
    const writer = rendered.writer(allocator);
    try writer.writeAll(
        \\#ifndef STWO_ZIG_CUDA_ADD_AP_RECORDED_WITNESS_FIXTURE_H
        \\#define STWO_ZIG_CUDA_ADD_AP_RECORDED_WITNESS_FIXTURE_H
        \\
        \\#include <cstdint>
        \\
        \\namespace stwo::cuda::test::add_ap {
        \\
        \\inline constexpr std::uint64_t kCacheKey = 0x735903777afd70d2ull;
        \\inline constexpr std::uint64_t kSemanticHash = 0xd94540f2fd219001ull;
        \\inline constexpr std::uint32_t kAbiSchema = 2;
        \\inline constexpr std::uint32_t kArgumentCount = 8;
        \\inline constexpr std::uint32_t kRowCount = 4;
        \\inline constexpr std::uint32_t kInputCount = 4;
        \\inline constexpr std::uint32_t kOutputCount = 17;
        \\inline constexpr std::uint32_t kLookupCount = 55;
        \\inline constexpr std::uint32_t kSubCount = 11;
        \\inline constexpr std::uint32_t kAddressTableSize = 256;
        \\inline constexpr std::uint32_t kBigLimbCount = 28;
        \\inline constexpr std::uint32_t kSmallLimbCount = 8;
        \\inline constexpr std::uint32_t kBigValueCount = 2;
        \\inline constexpr std::uint32_t kSmallValueCount = 2;
        \\inline constexpr const char *kKernelName =
        \\    "stwo_jit_witness_d94540f2fd219001";
        \\inline constexpr const char *kProgramIdentity =
        \\    "1c87a53a6c6ded98045fb88728f9cbd14f79ad8471cff7a16416139a64737da5";
        \\
        \\struct AddressEntry {
        \\    std::uint32_t address;
        \\    std::uint32_t encoded_id;
        \\};
        \\
        \\inline constexpr AddressEntry kAddressEntries[] = {
        \\
    );
    for (address_entries) |entry_value| {
        try writer.print(
            "    {{{d}u, {d}u}},\n",
            .{ entry_value.address, entry_value.encoded_id },
        );
    }
    try writer.writeAll("};\n\n");
    try writeWords(writer, "kInputs", &flat_inputs);
    try writeWords(writer, "kBigLimbs", &flat_big);
    try writeWords(writer, "kSmallLimbs", &flat_small);
    try writeWords(writer, "kExpectedOutputs", &flat_outputs);
    try writeWords(
        writer,
        "kExpectedLookupWordMajor",
        &lookup_word_major,
    );
    try writeWords(writer, "kExpectedSubWordMajor", &sub_word_major);
    try writer.writeAll(
        \\}  // namespace stwo::cuda::test::add_ap
        \\
        \\#endif
        \\
    );
    return rendered.toOwnedSlice(allocator);
}

test "add-ap recorded witness golden comes from Zig SIMD interpreter" {
    const allocator = std.testing.allocator;
    const rendered = try renderGolden(allocator);
    defer allocator.free(rendered);

    const update = std.process.getEnvVarOwned(
        allocator,
        "STWO_UPDATE_CUDA_RECORDED_FIXTURE",
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
        64 * 1024,
    );
    defer allocator.free(golden);
    try std.testing.expectEqualStrings(golden, rendered);
}
