//! Canonical durable wire for one compact Ethereum replay leaf.
//!
//! The artifact owns the leaf authority, its sparse touched-word replay
//! boundary, and the exact memory layout used by native calls. Program bytes
//! remain separately authenticated by `leaf.source.program`. The trailing
//! SHA-256 is a corruption seal, not a signature; product custody must also
//! bind the complete file bytes in its create-only manifest.

const std = @import("std");
const recovery_abi = @import("../../isa/ethereum_signer_recovery.zig");
const Cpu = @import("../cpu.zig").Cpu;
const base_replay = @import("replay.zig");
const base_types = @import("types.zig");
const types = @import("ethereum_types.zig");

pub const MAGIC = "STWEMT01";
pub const MAX_ENCODED_BYTES: usize = 256 << 20;
const CHECKSUM_DOMAIN = "stwo.riscv.ethereum-minimal-artifact.v1\x00";

pub const ArtifactV1 = struct {
    leaf: types.LeafV1,
    boundary_words: []base_replay.BoundaryWord,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ArtifactV1) void {
        self.leaf.deinit();
        self.allocator.free(self.boundary_words);
        self.* = undefined;
    }

    pub fn validate(self: *const ArtifactV1) !void {
        try self.leaf.validate();
        var boundary = try base_replay.SliceBoundary.init(self.boundary_words);
        if (!std.mem.eql(
            u8,
            &self.leaf.entry_boundary,
            &boundary.entry_identity,
        ) or !std.mem.eql(
            u8,
            &self.leaf.exit_boundary,
            &boundary.exit_identity,
        )) return error.MemoryBoundaryIdentityMismatch;
    }
};

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    artifact: *const ArtifactV1,
) ![]u8 {
    try artifact.validate();
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.appendSlice(allocator, MAGIC);
    try putInt(&output, allocator, u16, types.FORMAT_VERSION);
    try putInt(&output, allocator, u16, types.SCHEMA_VERSION);
    try putInt(&output, allocator, u32, 0);

    const leaf = &artifact.leaf;
    try output.appendSlice(allocator, &leaf.source.program);
    try output.appendSlice(allocator, &leaf.source.input);
    try output.appendSlice(allocator, &leaf.source.session);
    try output.appendSlice(allocator, &leaf.source.entry_memory);
    try output.appendSlice(allocator, &leaf.source.exit_memory);
    try output.appendSlice(allocator, &leaf.entry_boundary);
    try output.appendSlice(allocator, &leaf.exit_boundary);
    try putInt(&output, allocator, u32, leaf.segment_index);
    try putInt(&output, allocator, u64, leaf.global_first_cycle);
    try putInt(&output, allocator, u32, leaf.cycle_count);
    try putInt(&output, allocator, u32, leaf.core_cycle_count);
    try putCpu(&output, allocator, leaf.entry_cpu);
    try putCpu(&output, allocator, leaf.exit_cpu);
    try putCompletion(&output, allocator, leaf.completion);
    try putCount(&output, allocator, leaf.ordinary_memory_read_words.len);
    for (leaf.ordinary_memory_read_words) |word|
        try putInt(&output, allocator, u32, word);
    try putCount(&output, allocator, leaf.keccak_records.len);
    for (leaf.keccak_records) |record|
        try putKeccak(&output, allocator, record);
    try putCount(&output, allocator, leaf.recovery_records.len);
    for (leaf.recovery_records) |record|
        try putRecovery(&output, allocator, record);
    try output.appendSlice(allocator, &leaf.seal);
    try putCount(&output, allocator, artifact.boundary_words.len);
    for (artifact.boundary_words) |word| {
        try putInt(&output, allocator, u32, word.address);
        try putInt(&output, allocator, u32, word.entry);
        try putInt(&output, allocator, u32, word.exit);
    }
    if (output.items.len + @sizeOf(types.Digest) > MAX_ENCODED_BYTES)
        return error.ArtifactResourceLimitExceeded;
    const digest = checksum(output.items);
    try output.appendSlice(allocator, &digest);
    return output.toOwnedSlice(allocator);
}

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) !ArtifactV1 {
    if (encoded.len > MAX_ENCODED_BYTES or
        encoded.len < MAGIC.len + 8 + @sizeOf(types.Digest))
    {
        return error.ArtifactResourceLimitExceeded;
    }
    const body = encoded[0 .. encoded.len - @sizeOf(types.Digest)];
    const retained_checksum = encoded[encoded.len - @sizeOf(types.Digest) ..];
    const expected_checksum = checksum(body);
    if (!std.mem.eql(u8, retained_checksum, &expected_checksum))
        return error.ArtifactChecksumMismatch;

    var cursor = Cursor{ .bytes = body };
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), MAGIC))
        return error.InvalidArtifactMagic;
    if (try cursor.int(u16) != types.FORMAT_VERSION or
        try cursor.int(u16) != types.SCHEMA_VERSION)
    {
        return error.UnsupportedTapeVersion;
    }
    if (try cursor.int(u32) != 0) return error.NonCanonicalArtifact;

    const source = types.SourceIdentityV1{
        .program = try cursor.digest(),
        .input = try cursor.digest(),
        .session = try cursor.digest(),
        .entry_memory = try cursor.digest(),
        .exit_memory = try cursor.digest(),
    };
    const entry_boundary = try cursor.digest();
    const exit_boundary = try cursor.digest();
    const segment_index = try cursor.int(u32);
    const global_first_cycle = try cursor.int(u64);
    const cycle_count = try cursor.int(u32);
    const core_cycle_count = try cursor.int(u32);
    const entry_cpu = try cursor.cpu();
    const exit_cpu = try cursor.cpu();
    const completion = try cursor.completion();
    if (cycle_count == 0 or cycle_count > base_types.MAX_LEAF_CYCLES or
        core_cycle_count > cycle_count)
    {
        return error.LeafCycleLimitExceeded;
    }

    const ordinary_count = try cursor.count(cycle_count);
    var leaf_owns_payload = false;
    const ordinary = try allocator.alloc(u32, ordinary_count);
    errdefer if (!leaf_owns_payload) allocator.free(ordinary);
    for (ordinary) |*word| word.* = try cursor.int(u32);
    const keccak_count = try cursor.count(cycle_count);
    const keccak = try allocator.alloc(types.KeccakRecord, keccak_count);
    errdefer if (!leaf_owns_payload) allocator.free(keccak);
    for (keccak) |*record| record.* = try cursor.keccak();
    const recovery_count = try cursor.count(cycle_count);
    const recovery = try allocator.alloc(types.RecoveryRecord, recovery_count);
    errdefer if (!leaf_owns_payload) allocator.free(recovery);
    for (recovery) |*record| record.* = try cursor.recovery();
    const retained_leaf_seal = try cursor.digest();

    const maximum_boundary_words = @min(
        @as(usize, base_types.MAX_LEAF_CYCLES),
        cursor.remaining() / @sizeOf(base_replay.BoundaryWord),
    );
    const boundary_count = try cursor.count(maximum_boundary_words);
    const boundary_words = try allocator.alloc(
        base_replay.BoundaryWord,
        boundary_count,
    );
    errdefer allocator.free(boundary_words);
    for (boundary_words) |*word| {
        word.* = .{
            .address = try cursor.int(u32),
            .entry = try cursor.int(u32),
            .exit = try cursor.int(u32),
        };
    }
    if (cursor.remaining() != 0) return error.NonCanonicalArtifact;

    var leaf = try types.LeafV1.initOwned(
        allocator,
        source,
        entry_boundary,
        exit_boundary,
        segment_index,
        global_first_cycle,
        cycle_count,
        core_cycle_count,
        entry_cpu,
        exit_cpu,
        completion,
        ordinary,
        keccak,
        recovery,
    );
    leaf_owns_payload = true;
    errdefer leaf.deinit();
    if (!std.mem.eql(u8, &retained_leaf_seal, &leaf.seal))
        return error.TapeSealMismatch;
    var result = ArtifactV1{
        .leaf = leaf,
        .boundary_words = boundary_words,
        .allocator = allocator,
    };
    try result.validate();
    return result;
}

fn putCompletion(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    completion: ?types.CompletionV1,
) !void {
    if (completion) |value| {
        try output.append(allocator, 1);
        try output.append(allocator, value.kind);
        try putInt(output, allocator, u32, value.address);
        try putInt(output, allocator, u32, value.value);
        try putInt(output, allocator, u32, value.clock);
        if (value.exit_code) |exit_code| {
            try output.append(allocator, 1);
            try putInt(output, allocator, u32, exit_code);
        } else {
            try output.append(allocator, 0);
        }
    } else {
        try output.append(allocator, 0);
    }
}

fn putCpu(output: *std.ArrayList(u8), allocator: std.mem.Allocator, cpu: Cpu) !void {
    try putInt(output, allocator, u32, cpu.pc);
    for (cpu.regs) |value| try putInt(output, allocator, u32, value);
}

fn putKeccak(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    record: types.KeccakRecord,
) !void {
    try putInt(output, allocator, u32, record.execution_clock);
    try putInt(output, allocator, u32, record.pc);
    try putInt(output, allocator, u32, record.state_ptr);
    try output.append(allocator, record.pointer_register);
    try putInt(output, allocator, u32, record.pointer_previous_clock);
    for (record.input) |word| try putInt(output, allocator, u32, word);
    for (record.output) |word| try putInt(output, allocator, u32, word);
    for (record.memory_previous_clocks) |clock|
        try putInt(output, allocator, u32, clock);
}

fn putRecovery(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    record: types.RecoveryRecord,
) !void {
    try putInt(output, allocator, u32, record.execution_clock);
    try putInt(output, allocator, u32, record.pc);
    try putInt(output, allocator, u32, record.io_ptr);
    try output.append(allocator, record.pointer_register);
    try putInt(output, allocator, u32, record.pointer_previous_clock);
    try output.appendSlice(allocator, &record.digest_big_endian);
    try output.appendSlice(allocator, &record.r_big_endian);
    try output.appendSlice(allocator, &record.s_big_endian);
    try putInt(output, allocator, u32, record.recovery_id);
    try output.appendSlice(allocator, &record.public_key_xy_big_endian);
    try putInt(output, allocator, u32, record.status);
    for (record.input_previous_clocks) |clock|
        try putInt(output, allocator, u32, clock);
    for (record.output_previous_words) |word|
        try putInt(output, allocator, u32, word);
    for (record.output_previous_clocks) |clock|
        try putInt(output, allocator, u32, clock);
}

fn putCount(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: usize,
) !void {
    try putInt(
        output,
        allocator,
        u32,
        std.math.cast(u32, value) orelse return error.ArtifactResourceLimitExceeded,
    );
}

fn putInt(
    output: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try output.appendSlice(allocator, &encoded);
}

fn checksum(body: []const u8) types.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CHECKSUM_DOMAIN);
    hash.update(body);
    return hash.finalResult();
}

const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    fn remaining(self: Cursor) usize {
        return self.bytes.len - self.position;
    }

    fn take(self: *Cursor, length: usize) ![]const u8 {
        if (length > self.remaining()) return error.TruncatedArtifact;
        const result = self.bytes[self.position..][0..length];
        self.position += length;
        return result;
    }

    fn int(self: *Cursor, comptime T: type) !T {
        var encoded: [@sizeOf(T)]u8 = undefined;
        @memcpy(&encoded, try self.take(encoded.len));
        return std.mem.readInt(T, &encoded, .little);
    }

    fn count(self: *Cursor, maximum: anytype) !usize {
        const value = try self.int(u32);
        if (value > maximum) return error.ArtifactResourceLimitExceeded;
        return value;
    }

    fn digest(self: *Cursor) !types.Digest {
        var result: types.Digest = undefined;
        @memcpy(&result, try self.take(result.len));
        return result;
    }

    fn cpu(self: *Cursor) !Cpu {
        var result = Cpu{
            .pc = try self.int(u32),
            .regs = undefined,
        };
        for (&result.regs) |*value| value.* = try self.int(u32);
        return result;
    }

    fn completion(self: *Cursor) !?types.CompletionV1 {
        return switch (try self.int(u8)) {
            0 => null,
            1 => .{
                .kind = try self.int(u8),
                .address = try self.int(u32),
                .value = try self.int(u32),
                .clock = try self.int(u32),
                .exit_code = switch (try self.int(u8)) {
                    0 => null,
                    1 => try self.int(u32),
                    else => return error.NonCanonicalArtifact,
                },
            },
            else => error.NonCanonicalArtifact,
        };
    }

    fn keccak(self: *Cursor) !types.KeccakRecord {
        var result: types.KeccakRecord = undefined;
        result.execution_clock = try self.int(u32);
        result.pc = try self.int(u32);
        result.state_ptr = try self.int(u32);
        const pointer_register = try self.int(u8);
        if (pointer_register > std.math.maxInt(u5))
            return error.NonCanonicalArtifact;
        result.pointer_register = @intCast(pointer_register);
        result.pointer_previous_clock = try self.int(u32);
        for (&result.input) |*word| word.* = try self.int(u32);
        for (&result.output) |*word| word.* = try self.int(u32);
        for (&result.memory_previous_clocks) |*clock| clock.* = try self.int(u32);
        return result;
    }

    fn recovery(self: *Cursor) !types.RecoveryRecord {
        var result: types.RecoveryRecord = undefined;
        result.execution_clock = try self.int(u32);
        result.pc = try self.int(u32);
        result.io_ptr = try self.int(u32);
        const pointer_register = try self.int(u8);
        if (pointer_register > std.math.maxInt(u5))
            return error.NonCanonicalArtifact;
        result.pointer_register = @intCast(pointer_register);
        result.pointer_previous_clock = try self.int(u32);
        @memcpy(&result.digest_big_endian, try self.take(recovery_abi.digest_size));
        @memcpy(&result.r_big_endian, try self.take(recovery_abi.scalar_size));
        @memcpy(&result.s_big_endian, try self.take(recovery_abi.scalar_size));
        result.recovery_id = try self.int(u32);
        @memcpy(
            &result.public_key_xy_big_endian,
            try self.take(recovery_abi.public_key_size),
        );
        result.status = try self.int(u32);
        for (&result.input_previous_clocks) |*clock| clock.* = try self.int(u32);
        for (&result.output_previous_words) |*word| word.* = try self.int(u32);
        for (&result.output_previous_clocks) |*clock| clock.* = try self.int(u32);
        return result;
    }
};
