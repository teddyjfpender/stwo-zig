//! Strict decoder for the code inventory in the retained stateless-input SSZ.

const std = @import("std");

pub const Classification = enum {
    empty,
    eip7702_delegation,
    legacy,

    pub fn wireName(self: Classification) []const u8 {
        return switch (self) {
            .empty => "empty-bytecode-new-raw",
            .eip7702_delegation => "eip7702-delegation-new-raw",
            .legacy => "legacy-analyze-legacy",
        };
    }
};

pub const Code = struct {
    bytes: []const u8,
    classification: Classification,
    sha256: [32]u8,
};

pub const Inventory = struct {
    codes: []Code,
    eip7702_delegation_count: u32,
    empty_count: u32,
    legacy_bytes: u64,
    legacy_count: u32,
    total_bytes: u64,

    pub fn deinit(self: *Inventory, allocator: std.mem.Allocator) void {
        allocator.free(self.codes);
        self.* = undefined;
    }

    pub fn findLegacyExact(self: Inventory, bytes: []const u8) !u32 {
        const wanted = digest(bytes);
        var found: ?u32 = null;
        for (self.codes, 0..) |code, index| {
            if (code.classification != .legacy or
                !std.mem.eql(u8, &code.sha256, &wanted) or
                !std.mem.eql(u8, code.bytes, bytes))
            {
                continue;
            }
            if (found != null) return error.AmbiguousWitnessCode;
            found = @intCast(index);
        }
        return found orelse error.SourceNotInWitnessCodes;
    }
};

/// Decode `u32le length || u16be schema || StatelessInputElectraFulu` just
/// deeply enough to recover the exact `ExecutionWitness.codes` byte slices.
pub fn parse(
    allocator: std.mem.Allocator,
    transport: []const u8,
) !Inventory {
    if (transport.len < 6) return error.InvalidStatelessInput;
    const canonical_length = try readU32(transport, 0);
    if (canonical_length != transport.len - 4 or
        transport[4] != 0x14 or transport[5] != 0x01)
    {
        return error.InvalidStatelessInput;
    }
    const body = transport[6..];
    if (body.len < 20) return error.InvalidStatelessInput;
    const payload_offset = try readU32(body, 0);
    const witness_offset = try readU32(body, 4);
    const public_keys_offset = try readU32(body, 16);
    if (payload_offset != 20 or witness_offset < payload_offset or
        public_keys_offset < witness_offset or public_keys_offset > body.len)
    {
        return error.InvalidStatelessInput;
    }
    const witness = body[witness_offset..public_keys_offset];
    if (witness.len < 12) return error.InvalidStatelessInput;
    const state_offset = try readU32(witness, 0);
    const codes_offset = try readU32(witness, 4);
    const headers_offset = try readU32(witness, 8);
    if (state_offset != 12 or codes_offset < state_offset or
        headers_offset < codes_offset or headers_offset > witness.len)
    {
        return error.InvalidStatelessInput;
    }
    const encoded_codes = witness[codes_offset..headers_offset];
    const count: usize = if (encoded_codes.len == 0) 0 else count: {
        const first_offset = try readU32(encoded_codes, 0);
        if (first_offset == 0 or first_offset % 4 != 0 or
            first_offset > encoded_codes.len)
        {
            return error.InvalidStatelessInput;
        }
        break :count first_offset / 4;
    };
    const codes = try allocator.alloc(Code, count);
    errdefer allocator.free(codes);
    var total_bytes: u64 = 0;
    var legacy_bytes: u64 = 0;
    var empty_count: u32 = 0;
    var eip7702_count: u32 = 0;
    var legacy_count: u32 = 0;
    for (codes, 0..) |*code, index| {
        const start = try readU32(encoded_codes, index * 4);
        const end = if (index + 1 < count)
            try readU32(encoded_codes, (index + 1) * 4)
        else
            encoded_codes.len;
        if (start < count * 4 or end < start or end > encoded_codes.len)
            return error.InvalidStatelessInput;
        const bytes = encoded_codes[start..end];
        const classification: Classification = if (bytes.len == 0)
            .empty
        else if (bytes.len >= 2 and bytes[0] == 0xef and bytes[1] == 0x01)
            .eip7702_delegation
        else
            .legacy;
        switch (classification) {
            .empty => empty_count += 1,
            .eip7702_delegation => eip7702_count += 1,
            .legacy => {
                legacy_count += 1;
                legacy_bytes = try add(legacy_bytes, bytes.len);
            },
        }
        total_bytes = try add(total_bytes, bytes.len);
        code.* = .{
            .bytes = bytes,
            .classification = classification,
            .sha256 = digest(bytes),
        };
    }
    return .{
        .codes = codes,
        .eip7702_delegation_count = eip7702_count,
        .empty_count = empty_count,
        .legacy_bytes = legacy_bytes,
        .legacy_count = legacy_count,
        .total_bytes = total_bytes,
    };
}

fn readU32(bytes: []const u8, offset: usize) !u32 {
    if (offset > bytes.len or bytes.len - offset < 4)
        return error.InvalidStatelessInput;
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn add(left: u64, right: anytype) !u64 {
    return std.math.add(u64, left, @intCast(right)) catch
        return error.InvalidStatelessInput;
}

fn digest(bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

test "strict SSZ code inventory classifies legacy, delegation, and empty" {
    // Container offsets: StatelessInput(20), witness(12), then list offsets.
    const canonical = [_]u8{
        0x14, 0x01,
        20,   0,
        0,    0,
        20,   0,
        0,    0,
        1,    0,
        0,    0,
        0,    0,
        0,    0,
        44,   0,
        0,    0,
        12,   0,
        0,    0,
        12,   0,
        0,    0,
        36,   0,
        0,    0,
        12,   0,
        0,    0,
        14,   0,
        0,    0,
        17,   0,
        0,    0,
        0x60, 0x00,
        0xef, 0x01,
        0x42,
    };
    var transport: [canonical.len + 4]u8 = undefined;
    std.mem.writeInt(u32, transport[0..4], canonical.len, .little);
    @memcpy(transport[4..], &canonical);
    var inventory = try parse(std.testing.allocator, &transport);
    defer inventory.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), inventory.codes.len);
    try std.testing.expectEqual(Classification.legacy, inventory.codes[0].classification);
    try std.testing.expectEqual(Classification.eip7702_delegation, inventory.codes[1].classification);
    try std.testing.expectEqual(Classification.empty, inventory.codes[2].classification);
}
