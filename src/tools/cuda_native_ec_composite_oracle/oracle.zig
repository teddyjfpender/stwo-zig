//! Compact Zig SIMD oracle receipt for the native EC composite consumer.

const std = @import("std");
const bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const program_mod = @import("stwo_cairo_frontend").witness.program;
const oracle_mod = @import(
    "../../integrations/cairo_cuda/recorded_witness_oracle.zig",
);

const fixture_path = "vectors/cairo/ec_op_parity.bin";
const partial_columns = 127;
const partial_rounds = 256;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        fixture_path,
        16 * 1024 * 1024,
    );
    defer allocator.free(bytes);
    const partial = try parsePartial(bytes);

    var bundle = try bundle_mod.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer bundle.deinit();
    const entry = bundle.find("partial_ec_mul_generic") orelse
        return error.MissingCanonicalWitness;
    const program = entry.program;
    try program.validate();
    if (program.n_inputs + 1 != partial_columns)
        return error.InvalidCanonicalInputCount;
    if (program.n_mult_tables != 0)
        return error.UnsupportedCanonicalMultiplicity;
    if (program.deductionRequirements().pedersen_table)
        return error.UnexpectedPedersenRequirement;

    const row_count: u32 = @intCast(partial.len / partial_columns);
    const inputs = try allocator.alloc([]const u32, program.n_inputs);
    defer allocator.free(inputs);
    for (inputs, 0..) |*column, index| {
        column.* = partial[index * row_count ..][0..row_count];
    }

    const output_words = try std.math.mul(
        usize,
        program.n_cols,
        row_count,
    );
    const outputs = try allocator.alloc(u32, output_words);
    defer allocator.free(outputs);
    const output_columns = try allocator.alloc([]u32, program.n_cols);
    defer allocator.free(output_columns);
    for (output_columns, 0..) |*column, index| {
        column.* = outputs[index * row_count ..][0..row_count];
    }

    const lookup_words = try std.math.mul(
        usize,
        program.n_lookup_words,
        row_count,
    );
    const lookup = try allocator.alloc(u32, lookup_words);
    defer allocator.free(lookup);
    const sub_words = try std.math.mul(
        usize,
        program.n_sub_words,
        row_count,
    );
    const sub = try allocator.alloc(u32, sub_words);
    defer allocator.free(sub);
    const registers = try allocator.alloc(u32, program.n_regs);
    defer allocator.free(registers);
    const deduce_args = try allocator.alloc(u32, program.n_regs);
    defer allocator.free(deduce_args);
    var oracle = try oracle_mod.Oracle.init();
    try program_mod.executeAll(
        program,
        inputs,
        output_columns,
        .{
            .lookup_words = lookup,
            .sub_words = sub,
            .multiplicity_tables = &.{},
        },
        registers,
        deduce_args,
        .zero(),
        oracle.context(),
    );

    const output_digest = digestNativeWords(outputs);
    const lookup_digest = digestTransposed(
        lookup,
        program.n_lookup_words,
        row_count,
    );
    const sub_digest = digestTransposed(
        sub,
        program.n_sub_words,
        row_count,
    );
    const stdout = std.fs.File.stdout().deprecatedWriter();
    try stdout.print(
        "rows={d} inputs={d} outputs={d} lookup_words={d} sub_words={d}\n" ++
            "outputs_sha256={x}\nlookup_sha256={x}\nsub_sha256={x}\n",
        .{
            row_count,
            program.n_inputs,
            program.n_cols,
            program.n_lookup_words,
            program.n_sub_words,
            output_digest,
            lookup_digest,
            sub_digest,
        },
    );
}

fn parsePartial(bytes: []const u8) ![]const u32 {
    if (bytes.len < 32 or !std.mem.eql(u8, bytes[0..8], "STWZECO\x00"))
        return error.InvalidEcFixture;
    var cursor: usize = 8;
    const version = readWord(bytes, &cursor);
    const rows = readWord(bytes, &cursor);
    _ = readWord(bytes, &cursor);
    const n_addresses = readWord(bytes, &cursor);
    const n_big = readWord(bytes, &cursor);
    const n_small = readWord(bytes, &cursor);
    if (version != 1 or rows == 0) return error.InvalidEcFixture;
    cursor = try skipWords(cursor, n_addresses, bytes.len);
    cursor = try skipWords(cursor, @as(usize, n_big) * 8, bytes.len);
    cursor = try skipWords(cursor, @as(usize, n_small) * 4, bytes.len);
    cursor = try skipWords(cursor, @as(usize, rows) * 273, bytes.len);
    cursor = try skipWords(cursor, @as(usize, rows) * 488, bytes.len);
    const word_count = @as(usize, rows) * partial_rounds * partial_columns;
    const end = try skipWords(cursor, word_count, bytes.len);
    if (end != bytes.len) return error.InvalidEcFixture;
    const aligned: []align(@alignOf(u32)) const u8 =
        @alignCast(bytes[cursor..end]);
    return std.mem.bytesAsSlice(u32, aligned);
}

fn readWord(bytes: []const u8, cursor: *usize) u32 {
    const value = std.mem.readInt(u32, bytes[cursor.*..][0..4], .little);
    cursor.* += 4;
    return value;
}

fn skipWords(cursor: usize, words: usize, byte_len: usize) !usize {
    const bytes = try std.math.mul(usize, words, @sizeOf(u32));
    const end = try std.math.add(usize, cursor, bytes);
    if (end > byte_len) return error.InvalidEcFixture;
    return end;
}

fn digestNativeWords(words: []const u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(std.mem.sliceAsBytes(words));
    return hash.finalResult();
}

fn digestTransposed(
    words: []const u32,
    words_per_row: usize,
    rows: usize,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var encoded: [4]u8 = undefined;
    for (0..words_per_row) |word| {
        for (0..rows) |row| {
            std.mem.writeInt(
                u32,
                &encoded,
                words[row * words_per_row + word],
                .little,
            );
            hash.update(&encoded);
        }
    }
    return hash.finalResult();
}
