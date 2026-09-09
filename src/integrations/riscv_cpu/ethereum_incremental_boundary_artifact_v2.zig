//! Canonical transport for one changed-only Ethereum memory transition.
//!
//! The transport is deliberately not proof admission.  Cold decode rebuilds
//! and validates both sparse roots from the touched words and canonical
//! frontier.  A native leaf proof must still constrain the memory-access,
//! Merkle, Poseidon, bridge, and root relations before this transition can be
//! used by recursion.

const std = @import("std");
const authority_mod = @import("ethereum_incremental_boundary_authority_v1.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'M', 'T', '0', '2' };
pub const CONTENT_DOMAIN = "stwo.ethereum.incremental-boundary-artifact.v2\x00";
pub const PRODUCTION_ACTIVE = false;
pub const RECURSIVE_ADMISSIBLE = false;

const header_bytes: usize = 8 + 2 + 2 + 4 + 4 * 6 + 8 * 3 + 1 + 7 + 32 + 32;
const touched_bytes: usize = 4 * 4;
const frontier_bytes: usize = 1 + 3 + 4 + 4;
const seal_bytes: usize = 32;

pub const Limits = struct {
    max_bytes: usize,
    max_touched_words: usize,
    max_frontier_nodes: usize,

    pub fn validate(self: Limits) !void {
        if (self.max_bytes < header_bytes + seal_bytes or
            self.max_touched_words == 0 or
            self.max_frontier_nodes == 0)
        {
            return error.InvalidIncrementalBoundaryArtifactLimits;
        }
    }
};

pub const default_limits = Limits{
    .max_bytes = 512 * 1024 * 1024,
    .max_touched_words = 8 * 1024 * 1024,
    .max_frontier_nodes = 32 * 1024 * 1024,
};

pub const OwnedArtifactV2 = struct {
    authority: authority_mod.IncrementalBoundaryAuthorityV1,
    content_sha256: [32]u8,

    pub fn deinit(self: *OwnedArtifactV2) void {
        self.authority.deinit();
        self.* = undefined;
    }
};

/// Decoded ownership plus the process-local proof established by the same
/// mutation-sensitive decode. The token owns no memory; `artifact` remains the
/// sole allocation owner.
pub const DecodedValidatedArtifactV2 = struct {
    artifact: OwnedArtifactV2,
    validated: authority_mod.ValidatedIncrementalBoundaryAuthorityV1,
};

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    authority: *const authority_mod.IncrementalBoundaryAuthorityV1,
    limits: Limits,
) ![]u8 {
    const validated = try authority_mod.ValidatedIncrementalBoundaryAuthorityV1
        .init(authority);
    return encodeValidatedAlloc(allocator, &validated, limits);
}

/// Canonically encode an authority already validated in this process. The
/// token is transport-free and does not weaken the public raw-authority entry
/// point above.
pub fn encodeValidatedAlloc(
    allocator: std.mem.Allocator,
    validated: *const authority_mod.ValidatedIncrementalBoundaryAuthorityV1,
    limits: Limits,
) ![]u8 {
    try limits.validate();
    const authority = validated.authority();
    if (authority.touched_words.len > limits.max_touched_words or
        authority.frontier_nodes.len > limits.max_frontier_nodes)
    {
        return error.IncrementalBoundaryArtifactResourceLimitExceeded;
    }
    const encoded_len = try encodedSize(
        authority.touched_words.len,
        authority.frontier_nodes.len,
    );
    if (encoded_len > limits.max_bytes)
        return error.IncrementalBoundaryArtifactResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(bytes);
    var writer = Writer{ .bytes = bytes };
    writer.writeBytes(&MAGIC);
    writer.writeInt(u16, FORMAT_VERSION);
    writer.writeInt(u16, SCHEMA_VERSION);
    writer.writeInt(u32, 0);
    writer.writeInt(u32, authority.segment_index);
    writer.writeInt(u32, authority.entry_root);
    writer.writeInt(u32, authority.exit_root);
    writer.writeInt(u32, authority.changed_word_count);
    writer.writeInt(u32, try countU32(authority.touched_words.len));
    writer.writeInt(u32, try countU32(authority.frontier_nodes.len));
    writer.writeInt(u64, authority.work.entry_hash_calls);
    writer.writeInt(u64, authority.work.exit_hash_calls);
    writer.writeInt(u64, authority.work.total_hash_calls);
    writer.writeByte(authority.work.max_shard_log);
    writer.writeBytes(&([_]u8{0} ** 7));
    writer.writeBytes(&authority.prior_authority_id);
    writer.writeBytes(&authority.authority_id);
    for (authority.touched_words) |word| {
        writer.writeInt(u32, word.address);
        writer.writeInt(u32, word.old_word);
        writer.writeInt(u32, word.new_word);
        writer.writeInt(u32, word.final_clock);
    }
    for (authority.frontier_nodes) |node| {
        writer.writeByte(node.depth);
        writer.writeBytes(&([_]u8{0} ** 3));
        writer.writeInt(u32, node.index);
        writer.writeInt(u32, node.value);
    }
    if (writer.at + seal_bytes != bytes.len)
        return error.InvalidIncrementalBoundaryArtifactLength;
    const seal = contentIdentity(bytes[0..writer.at]);
    writer.writeBytes(&seal);
    if (writer.at != bytes.len)
        return error.InvalidIncrementalBoundaryArtifactLength;
    return bytes;
}

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !OwnedArtifactV2 {
    const decoded = try decodeValidatedAlloc(allocator, bytes, limits);
    return decoded.artifact;
}

pub fn decodeValidatedAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !DecodedValidatedArtifactV2 {
    try limits.validate();
    if (bytes.len < header_bytes + seal_bytes or bytes.len > limits.max_bytes)
        return error.InvalidIncrementalBoundaryArtifactLength;
    var reader = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, reader.readBytes(8), &MAGIC) or
        reader.readInt(u16) != FORMAT_VERSION or
        reader.readInt(u16) != SCHEMA_VERSION or
        reader.readInt(u32) != 0)
    {
        return error.InvalidIncrementalBoundaryArtifactHeader;
    }
    const segment_index = reader.readInt(u32);
    const entry_root = reader.readInt(u32);
    const exit_root = reader.readInt(u32);
    const changed_word_count = reader.readInt(u32);
    const touched_count: usize = reader.readInt(u32);
    const frontier_count: usize = reader.readInt(u32);
    const work = authority_mod.HashWorkV1{
        .entry_hash_calls = reader.readInt(u64),
        .exit_hash_calls = reader.readInt(u64),
        .total_hash_calls = reader.readInt(u64),
        .max_shard_log = reader.readByte(),
    };
    if (!allZero(reader.readBytes(7)))
        return error.InvalidIncrementalBoundaryArtifactHeader;
    const prior_authority_id = reader.readArray(32);
    const authority_id = reader.readArray(32);
    if (reader.failed or
        touched_count > limits.max_touched_words or
        frontier_count > limits.max_frontier_nodes or
        (try encodedSize(touched_count, frontier_count)) != bytes.len)
    {
        return error.IncrementalBoundaryArtifactResourceLimitExceeded;
    }

    const touched = try allocator.alloc(
        authority_mod.TouchedWordV1,
        touched_count,
    );
    errdefer allocator.free(touched);
    for (touched) |*word| word.* = .{
        .address = reader.readInt(u32),
        .old_word = reader.readInt(u32),
        .new_word = reader.readInt(u32),
        .final_clock = reader.readInt(u32),
    };
    const frontier = try allocator.alloc(
        authority_mod.FrontierNodeV1,
        frontier_count,
    );
    errdefer allocator.free(frontier);
    for (frontier) |*node| {
        node.depth = reader.readByte();
        if (!allZero(reader.readBytes(3)))
            return error.InvalidIncrementalBoundaryArtifactHeader;
        node.index = reader.readInt(u32);
        node.value = reader.readInt(u32);
    }
    if (reader.failed or reader.at + seal_bytes != bytes.len)
        return error.InvalidIncrementalBoundaryArtifactLength;
    const expected_content = contentIdentity(bytes[0..reader.at]);
    const retained_content = reader.readArray(32);
    if (reader.failed or reader.at != bytes.len or
        !std.mem.eql(u8, &expected_content, &retained_content))
    {
        return error.IncrementalBoundaryArtifactContentMismatch;
    }

    var authority = authority_mod.IncrementalBoundaryAuthorityV1{
        .allocator = allocator,
        .segment_index = segment_index,
        .entry_root = entry_root,
        .exit_root = exit_root,
        .touched_words = touched,
        .frontier_nodes = frontier,
        .changed_word_count = changed_word_count,
        .work = work,
        .prior_authority_id = prior_authority_id,
        .authority_id = authority_id,
    };
    errdefer authority.deinit();
    const validated = try authority_mod.ValidatedIncrementalBoundaryAuthorityV1
        .init(&authority);
    return .{
        .artifact = .{
            .authority = authority,
            .content_sha256 = retained_content,
        },
        .validated = validated,
    };
}

pub fn validateAgainst(
    artifact: *const OwnedArtifactV2,
    segment_index: u32,
    entry_root: u32,
    exit_root: u32,
    prior_authority_id: [32]u8,
) !void {
    try artifact.authority.validateAgainst(
        segment_index,
        entry_root,
        exit_root,
        prior_authority_id,
    );
}

fn encodedSize(touched_count: usize, frontier_count: usize) !usize {
    const touched_total = std.math.mul(usize, touched_count, touched_bytes) catch
        return error.IncrementalBoundaryArtifactSizeOverflow;
    const frontier_total = std.math.mul(usize, frontier_count, frontier_bytes) catch
        return error.IncrementalBoundaryArtifactSizeOverflow;
    const payload = std.math.add(usize, touched_total, frontier_total) catch
        return error.IncrementalBoundaryArtifactSizeOverflow;
    return std.math.add(
        usize,
        header_bytes + seal_bytes,
        payload,
    ) catch error.IncrementalBoundaryArtifactSizeOverflow;
}

fn countU32(value: usize) !u32 {
    return std.math.cast(u32, value) orelse
        error.IncrementalBoundaryArtifactSizeOverflow;
}

fn contentIdentity(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTENT_DOMAIN);
    hash.update(bytes);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn allZero(bytes: []const u8) bool {
    var merged: u8 = 0;
    for (bytes) |value| merged |= value;
    return merged == 0;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn writeByte(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    fn writeBytes(self: *Writer, values: []const u8) void {
        @memcpy(self.bytes[self.at..][0..values.len], values);
        self.at += values.len;
    }

    fn writeInt(self: *Writer, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.bytes[self.at..][0..@sizeOf(T)], value, .little);
        self.at += @sizeOf(T);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    failed: bool = false,

    fn take(self: *Reader, count: usize) []const u8 {
        const end = std.math.add(usize, self.at, count) catch {
            self.failed = true;
            return &.{};
        };
        if (end > self.bytes.len) {
            self.failed = true;
            return &.{};
        }
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }

    fn readByte(self: *Reader) u8 {
        const value = self.take(1);
        return if (value.len == 1) value[0] else 0;
    }

    fn readBytes(self: *Reader, count: usize) []const u8 {
        return self.take(count);
    }

    fn readArray(self: *Reader, comptime count: usize) [count]u8 {
        var result = [_]u8{0} ** count;
        const value = self.take(count);
        if (value.len == count) @memcpy(&result, value);
        return result;
    }

    fn readInt(self: *Reader, comptime T: type) T {
        const value = self.take(@sizeOf(T));
        return if (value.len == @sizeOf(T))
            std.mem.readInt(T, value[0..@sizeOf(T)], .little)
        else
            0;
    }
};

test "incremental boundary artifact cold reconstructs canonical transition" {
    const allocator = std.testing.allocator;
    const state = [_]authority_mod.SparseWordV1{
        .{ .address = 0x1000, .value = 0x1122_3344 },
        .{ .address = 0x2000, .value = 0xa1a2_a3a4 },
    };
    var session = try authority_mod.SessionTree.init(
        allocator,
        [_]u8{0x44} ** 32,
        9,
        &state,
        try testing.fullRoot(allocator, &state),
    );
    defer session.deinit();
    const prior = session.priorAuthorityId();
    var authority = try session.apply(9, &.{.{
        .address = 0x1000,
        .old_word = state[0].value,
        .new_word = 0x5566_7788,
        .final_clock = 17,
    }});
    defer authority.deinit();
    const encoded = try encodeAlloc(allocator, &authority, default_limits);
    defer allocator.free(encoded);
    var decoded = try decodeAlloc(allocator, encoded, default_limits);
    defer decoded.deinit();
    try validateAgainst(
        &decoded,
        9,
        authority.entry_root,
        authority.exit_root,
        prior,
    );
    const reencoded = try encodeAlloc(
        allocator,
        &decoded.authority,
        default_limits,
    );
    defer allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
}

test "incremental boundary artifact rejects payload and reserved mutations" {
    try std.testing.expect(!PRODUCTION_ACTIVE);
    try std.testing.expect(!RECURSIVE_ADMISSIBLE);
    const allocator = std.testing.allocator;
    const state = [_]authority_mod.SparseWordV1{
        .{ .address = 0x1000, .value = 0x0102_0304 },
    };
    var session = try authority_mod.SessionTree.init(
        allocator,
        [_]u8{0x55} ** 32,
        0,
        &state,
        try testing.fullRoot(allocator, &state),
    );
    defer session.deinit();
    var authority = try session.apply(0, &.{.{
        .address = 0x1000,
        .old_word = state[0].value,
        .new_word = state[0].value,
        .final_clock = 3,
    }});
    defer authority.deinit();
    const encoded = try encodeAlloc(allocator, &authority, default_limits);
    defer allocator.free(encoded);

    encoded[12] = 1;
    try std.testing.expectError(
        error.InvalidIncrementalBoundaryArtifactHeader,
        decodeAlloc(allocator, encoded, default_limits),
    );
    encoded[12] = 0;
    encoded[header_bytes] ^= 1;
    try std.testing.expectError(
        error.IncrementalBoundaryArtifactContentMismatch,
        decodeAlloc(allocator, encoded, default_limits),
    );
}

pub const testing = struct {
    pub fn fullRoot(
        allocator: std.mem.Allocator,
        words: []const authority_mod.SparseWordV1,
    ) !u32 {
        const sparse_merkle = @import("stwo_riscv_frontend").air
            .memory_commitment.sparse_merkle;
        var leaves: std.ArrayList(sparse_merkle.Leaf) = .empty;
        defer leaves.deinit(allocator);
        try leaves.ensureTotalCapacity(allocator, words.len * 4);
        for (words) |word| for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const value: u8 = @truncate(word.value >> shift);
            if (value != 0) leaves.appendAssumeCapacity(.{
                .index = word.address + @as(u32, @intCast(limb)),
                .value = value,
            });
        };
        var tree = try sparse_merkle.build(allocator, leaves.items);
        defer tree.deinit(allocator);
        return tree.root;
    }
};
