//! Deterministic unique-PC decoded program table construction.

const std = @import("std");
const opcode_manifest = @import("../../opcode_manifest.zig");
const profile = @import("../../isa/profile.zig");
const decode = @import("decode.zig");

pub const Fetch = struct {
    pc: u32,
    word: u32,
};

pub const Row = struct {
    pc: u32,
    values: decode.ProgramValues,
    multiplicity: u32,

    pub fn relationValues(self: Row) [5]u32 {
        return .{ self.pc, self.values[0], self.values[1], self.values[2], self.values[3] };
    }
};

pub const Table = struct {
    rows: []Row,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Table) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }
};

pub const Error = decode.Error || profile.ProgramAddressError || std.mem.Allocator.Error || error{
    ProgramWordChanged,
    MultiplicityOverflow,
};

/// Build one decoded row per PC in first-fetch order. Repeated fetches increase
/// the row multiplicity; a PC observed with a different word is rejected even
/// when both words would project to the same tuple.
pub fn generate(allocator: std.mem.Allocator, fetches: []const Fetch) Error!Table {
    const Entry = struct { index: usize, word: u32 };
    var index_by_pc = std.AutoHashMap(u32, Entry).init(allocator);
    defer index_by_pc.deinit();
    var rows: std.ArrayList(Row) = .{};
    defer rows.deinit(allocator);

    for (fetches) |fetch| {
        try profile.requireProgramWordAddress(fetch.pc);
        const gop = try index_by_pc.getOrPut(fetch.pc);
        if (gop.found_existing) {
            if (gop.value_ptr.word != fetch.word) return Error.ProgramWordChanged;
            const row = &rows.items[gop.value_ptr.index];
            if (row.multiplicity == std.math.maxInt(u32)) return Error.MultiplicityOverflow;
            row.multiplicity += 1;
            continue;
        }

        const values = decode.decodeProgramWord(fetch.word) catch |err| {
            _ = index_by_pc.remove(fetch.pc);
            return err;
        };
        const index = rows.items.len;
        try rows.append(allocator, .{ .pc = fetch.pc, .values = values, .multiplicity = 1 });
        gop.value_ptr.* = .{ .index = index, .word = fetch.word };
    }

    return .{ .rows = try rows.toOwnedSlice(allocator), .allocator = allocator };
}

test "decoded program table: unique PCs retain order and multiplicity" {
    const allocator = std.testing.allocator;
    const fetches = [_]Fetch{
        .{ .pc = 0x1000, .word = 0x00100093 },
        .{ .pc = 0x1004, .word = 0x002081b3 },
        .{ .pc = 0x1000, .word = 0x00100093 },
        .{ .pc = 0x1000, .word = 0x00100093 },
        .{ .pc = 0x1004, .word = 0x002081b3 },
    };
    var table = try generate(allocator, &fetches);
    defer table.deinit();

    try std.testing.expectEqual(@as(usize, 2), table.rows.len);
    try std.testing.expectEqual(@as(u32, 0x1000), table.rows[0].pc);
    try std.testing.expectEqual(@as(u32, 3), table.rows[0].multiplicity);
    try std.testing.expectEqual([5]u32{ 0x1000, 10, 1, 0, 1 }, table.rows[0].relationValues());
    try std.testing.expectEqual(@as(u32, 0x1004), table.rows[1].pc);
    try std.testing.expectEqual(@as(u32, 2), table.rows[1].multiplicity);
    try std.testing.expectEqual([5]u32{ 0x1004, 0, 3, 1, 2 }, table.rows[1].relationValues());
}

test "decoded program table: changing a word at one PC is rejected" {
    const first_word: u32 = 0x00100093;
    const changed_word: u32 = 0x00200093;
    const fetches = [_]Fetch{
        .{ .pc = 0x1000, .word = first_word },
        .{ .pc = 0x1000, .word = changed_word },
    };
    try std.testing.expectError(Error.ProgramWordChanged, generate(std.testing.allocator, &fetches));
}

test "decoded program table: instruction addresses are aligned and commitment-bounded" {
    try std.testing.expectError(
        error.MisalignedProgramWord,
        generate(std.testing.allocator, &.{.{
            .pc = 0x1002,
            .word = 0x00100093,
        }}),
    );
    try std.testing.expectError(
        error.ProgramAddressOutOfRange,
        generate(std.testing.allocator, &.{.{
            .pc = profile.program_commitment_size,
            .word = 0x00100093,
        }}),
    );
}

test "decoded program table: manifest rejection matrix fails before row construction" {
    for (opcode_manifest.proof_rejection_vectors) |vector| {
        const fetches = [_]Fetch{.{ .pc = 0x1000, .word = vector.word }};
        const expected: Error = switch (vector.kind) {
            .unsupported_instruction_class => Error.UnsupportedInstructionClass,
            .invalid_instruction => Error.InvalidInstruction,
        };
        try std.testing.expectError(expected, generate(std.testing.allocator, &fetches));
    }
}

test "decoded program table: empty fetch stream produces an empty table" {
    var table = try generate(std.testing.allocator, &.{});
    defer table.deinit();
    try std.testing.expectEqual(@as(usize, 0), table.rows.len);
}
