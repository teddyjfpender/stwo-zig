//! Canonical postcard cursor and first-mismatch config/count admission.
const std = @import("std");
const schema = @import("proof_preflight.zig");
const Error = schema.Error;
const Config = schema.Config;
const Diagnostic = schema.Diagnostic;
const DiagnosticStage = schema.DiagnosticStage;
pub const M31_MODULUS: u32 = 0x7fff_ffff;

pub fn expectConfig(cursor: *Cursor, expected: Config) Error!void {
    if (try cursor.readU32() != expected.pow_bits or
        try cursor.readU32() != expected.log_blowup_factor or
        try cursor.readVarint() != expected.n_queries or
        try cursor.readU32() != expected.log_last_layer_degree_bound or
        try cursor.readU32() != expected.fold_step)
        return error.InvalidProofConfig;

    const lifting_tag = try cursor.readByte();
    const actual_lifting: ?u32 = switch (lifting_tag) {
        0 => null,
        1 => try cursor.readU32(),
        else => return error.InvalidOptionTag,
    };
    if (actual_lifting != expected.lifting_log_size)
        return error.InvalidProofConfig;
}

pub fn expectCount(cursor: *Cursor, expected: anytype) Error!void {
    return expectCountAt(
        cursor,
        expected,
        null,
        .commitment_tree_count,
        null,
        null,
    );
}

pub fn expectCountAt(
    cursor: *Cursor,
    expected: anytype,
    diagnostic: ?*?Diagnostic,
    stage: DiagnosticStage,
    tree: ?u32,
    index: ?u32,
) Error!void {
    const offset = cursor.position;
    const actual = try cursor.readUsize();
    const expected_usize = std.math.cast(usize, expected) orelse
        return error.InvalidPreflightShape;
    if (actual != expected_usize) {
        recordMismatch(
            diagnostic,
            stage,
            tree,
            index,
            offset,
            actual,
            expected_usize,
        );
        return error.InvalidProofShape;
    }
}

pub fn recordMismatch(
    diagnostic: ?*?Diagnostic,
    stage: DiagnosticStage,
    tree: ?u32,
    index: ?u32,
    offset: usize,
    actual: usize,
    expected: usize,
) void {
    const output = diagnostic orelse return;
    if (output.* != null) return;
    output.* = .{
        .stage = stage,
        .tree = tree,
        .index = index,
        .offset = offset,
        .actual = actual,
        .expected = expected,
    };
}

pub const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    pub fn readByte(self: *Cursor) Error!u8 {
        if (self.position == self.bytes.len) return error.EndOfStream;
        const byte = self.bytes[self.position];
        self.position += 1;
        return byte;
    }

    pub fn skip(self: *Cursor, count: usize) Error!void {
        const end = std.math.add(usize, self.position, count) catch
            return error.ProofResourceLimitExceeded;
        if (end > self.bytes.len) return error.EndOfStream;
        self.position = end;
    }

    pub fn readUsize(self: *Cursor) Error!usize {
        const value = try self.readVarint();
        return std.math.cast(usize, value) orelse error.VarintOverflow;
    }

    pub fn readU32(self: *Cursor) Error!u32 {
        const value = try self.readVarint();
        return std.math.cast(u32, value) orelse error.VarintOverflow;
    }

    pub fn readM31(self: *Cursor) Error!void {
        if (try self.readU32() >= M31_MODULUS) return error.NonCanonicalM31;
    }

    pub fn readQm31(self: *Cursor) Error!void {
        for (0..4) |_| try self.readM31();
    }

    pub fn readVarint(self: *Cursor) Error!u64 {
        var result: u64 = 0;
        var byte_count: usize = 0;
        while (byte_count < 10) : (byte_count += 1) {
            const byte = try self.readByte();
            const payload = byte & 0x7f;
            if (byte_count == 9 and payload > 1) return error.VarintOverflow;
            result |= @as(u64, payload) << @intCast(byte_count * 7);
            if ((byte & 0x80) == 0) {
                if (byte_count != 0 and payload == 0)
                    return error.NonCanonicalVarint;
                return result;
            }
        }
        return error.VarintOverflow;
    }
};
