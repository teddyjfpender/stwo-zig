//! Independently pinned v5 initial-value sources. Program/ROM fetches have a
//! separate table; this plan covers registers, public input, and RW memory.
const std = @import("std");
const layout_mod = @import("../runner/memory_state.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");

pub const INPUT_RECORD_BYTES: usize = 8; // address LE4, nonzero value LE4
pub const RW_RECORD_BYTES: usize = 8;
pub const TOUCH_RECORD_BYTES: usize = 9; // space, address LE4, initial value LE4
pub const MAX_INPUT_WORDS: u64 = 1_000_000;
pub const MAX_RW_WORDS: u64 = 4_000_000;
pub const MAX_TOUCHES: u64 = 10_000_000;

pub const FilePin = struct {
    sha256: [32]u8,
    records: u64,
};

pub const Pins = struct {
    layout: layout_mod.MemoryLayout,
    initial_rw_root: [32]u8,
    initial_registers: [32]u32,
    public_input_sha256: [32]u8,
    public_input_len: u64,
    input_words: FilePin,
    rw_words: FilePin,
    first_touches: FilePin,

    pub fn validate(self: Pins) !void {
        try validateLayout(self.layout);
        if ((self.layout.input_base & 3) != 0 or self.initial_registers[0] != 0 or
            self.public_input_len > MAX_INPUT_WORDS * 4 or
            self.public_input_len > self.layout.input_end - self.layout.input_base or
            self.input_words.records > MAX_INPUT_WORDS or
            self.rw_words.records > MAX_RW_WORDS or
            self.first_touches.records > MAX_TOUCHES)
            return error.InvalidV5InitialSourcePlan;
    }

    /// This digest is included in the one v5 SourceSeal before relation
    /// challenges. The receiver recomputes it from independently trusted pins.
    pub fn digest(self: Pins) ![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/block-v5/initial-sources-plan/v1\x00");
        hash.update(&self.initial_rw_root);
        hash.update(&self.public_input_sha256);
        putWide(&hash, self.public_input_len);
        inline for (std.meta.fields(layout_mod.MemoryLayout)) |field| putWord(&hash, @field(self.layout, field.name));
        for (self.initial_registers) |value| putWord(&hash, value);
        for ([_]FilePin{ self.input_words, self.rw_words, self.first_touches }) |pin| {
            hash.update(&pin.sha256);
            putWide(&hash, pin.records);
        }
        return hash.finalResult();
    }
};

pub const Files = struct {
    input_words: std.fs.File,
    rw_words: std.fs.File,
    first_touches: std.fs.File,
};

pub fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

/// Shared structural layout checks; no provisional source-file pins are needed.
pub fn validateLayout(layout: layout_mod.MemoryLayout) !void {
    const program = Interval{ .start = layout.program_base, .end = layout.program_end };
    const data = Interval{ .start = layout.data_base, .end = layout.data_end };
    const stack = Interval{ .start = layout.stack_bottom, .end = layout.stack_top };
    const io = Interval{ .start = layout.io_base, .end = layout.io_end };
    const input = Interval{ .start = layout.input_base, .end = layout.input_end };
    for ([_]Interval{ program, data, stack, io, input }) |range| {
        if (range.end < range.start or range.end > tree.ADDRESS_LIMIT)
            return error.InvalidV5InitialSourceLayout;
    }
    // Data, stack and IO are the same RW-root source. The canonical ELF
    // loader can give IO an inclusive control byte at the stack boundary;
    // overlapping RW subranges therefore have no ambiguous authority.
    // Program must remain disjoint, and public input must be wholly
    // covered by the RW union before its explicit input classification.
    if (overlap(program, data) or overlap(program, stack) or overlap(program, io) or
        overlap(program, input) or !coveredByRw(input, .{ data, stack, io }))
        return error.InvalidV5InitialSourceLayout;
}

const Interval = struct { start: u32, end: u32 };
fn overlap(left: Interval, right: Interval) bool {
    return left.start < left.end and right.start < right.end and
        left.start < right.end and right.start < left.end;
}
fn coveredByRw(input: Interval, ranges: [3]Interval) bool {
    var cursor = input.start;
    // Each successful step consumes at least one range's right endpoint.
    // No sorting or allocation is needed for the three independently pinned
    // RW intervals, including containment and adjacent intervals.
    for (0..ranges.len) |_| {
        if (cursor == input.end) return true;
        var next = cursor;
        for (ranges) |range| if (range.start <= cursor and range.end > next) {
            next = range.end;
        };
        if (next >= input.end) return true;
        if (next == cursor) return false;
        cursor = next;
    }
    return cursor == input.end;
}

test "block-v5 initial layout admits canonical RW union and rejects source ambiguity" {
    var pins = Pins{
        .layout = .{ .program_base = 0x400, .program_end = 0x31fde4, .data_base = 0x2000000, .data_end = 0x10000000, .stack_bottom = 0x1000000, .stack_top = 0x2000000, .io_base = 0x800000, .io_end = 0x1000001, .input_base = 0x800000, .input_end = 0xc00000, .output_len_addr = 0xc00004, .output_data_addr = 0xc00008, .output_base = 0xc00004, .output_end = 0x1000000 },
        .initial_rw_root = @splat(1),
        .initial_registers = @splat(0),
        .public_input_sha256 = @splat(2),
        .public_input_len = 2700708,
        .input_words = .{ .sha256 = @splat(3), .records = 0 },
        .rw_words = .{ .sha256 = @splat(4), .records = 0 },
        .first_touches = .{ .sha256 = @splat(5), .records = 0 },
    };
    try pins.validate();
    const canonical = pins;
    // Input can cross an adjacent/overlapping RW boundary without changing
    // the source union. A single byte outside the union remains forbidden.
    pins.layout.input_end = 0x2000004;
    try pins.validate();
    pins.layout.stack_bottom += 2;
    try std.testing.expectError(error.InvalidV5InitialSourceLayout, pins.validate());
    pins = canonical;
    pins.layout.io_base = pins.layout.program_end - 1;
    try std.testing.expectError(error.InvalidV5InitialSourceLayout, pins.validate());
    pins = canonical;
    pins.layout.input_base = pins.layout.program_base;
    try std.testing.expectError(error.InvalidV5InitialSourceLayout, pins.validate());
    pins = canonical;
    pins.layout.data_end = pins.layout.data_base - 1;
    try std.testing.expectError(error.InvalidV5InitialSourceLayout, pins.validate());
    pins = canonical;
    pins.layout.stack_top = tree.ADDRESS_LIMIT + 1;
    try std.testing.expectError(error.InvalidV5InitialSourceLayout, pins.validate());
    // Empty subranges do not introduce program/RW overlap.
    pins = canonical;
    pins.layout.data_base = pins.layout.program_base;
    pins.layout.data_end = pins.layout.data_base;
    try pins.validate();
}

pub fn readPinned(a: std.mem.Allocator, file: std.fs.File, pin: FilePin, comptime width: usize) ![]u8 {
    const expected = try std.math.mul(u64, pin.records, @as(u64, width));
    if (expected > std.math.maxInt(usize) or try file.getEndPos() != expected)
        return error.InvalidV5InitialSourceLength;
    const bytes = try a.alloc(u8, @intCast(expected));
    errdefer a.free(bytes);
    if (try file.preadAll(bytes, 0) != bytes.len) return error.TruncatedV5InitialSource;
    if (!std.meta.eql(sha256(bytes), pin.sha256)) return error.UntrustedV5InitialSourceBytes;
    return bytes;
}

pub fn readWord(bytes: []const u8) u32 {
    var word: [4]u8 = undefined;
    @memcpy(&word, bytes[0..4]);
    return std.mem.readInt(u32, &word, .little);
}

pub fn inputWord(pins: Pins, public_input: []const u8, address: u32) !u32 {
    return inputWordAt(pins.layout, public_input, address);
}
/// One shared little-endian/partial/zero-word derivation for selection and
/// final independently pinned sources. Layout/input authority is checked by
/// their respective admission paths before this value helper is used.
pub fn inputWordAt(layout: layout_mod.MemoryLayout, public_input: []const u8, address: u32) !u32 {
    if (!layout.isInputAddr(address) or (address & 3) != 0)
        return error.InvalidV5InputAddress;
    const offset: usize = address - layout.input_base;
    var word: [4]u8 = @splat(0);
    if (offset < public_input.len) {
        const count = @min(4, public_input.len - offset);
        @memcpy(word[0..count], public_input[offset..][0..count]);
    }
    return std.mem.readInt(u32, &word, .little);
}

fn putWord(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, value, .little);
    hash.update(&word);
}

fn putWide(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var wide: [8]u8 = undefined;
    std.mem.writeInt(u64, &wide, value, .little);
    hash.update(&wide);
}
