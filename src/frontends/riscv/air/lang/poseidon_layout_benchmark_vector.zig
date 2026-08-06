//! Canonical deterministic vectors for the isolated H-010 benchmark.
//!
//! Logs 10 and 14 are decoded from checked `STWAIRB-v1` bytes. Log 18 is an
//! explicitly generated opt-in stress vector and is not receipt-eligible.
//! Expected outputs come from the unchanged static Poseidon implementation,
//! independently of the candidate layout executor and direct interpreter.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const production = @import("../memory_commitment/poseidon2_air.zig");
const protocol = @import("poseidon_layout_benchmark_protocol.zig");

const semantic_digest = decodePinnedDigest(protocol.semantic_digest_hex);
const m31_modulus: u32 = 0x7fff_ffff;

pub const StorageClass = enum {
    checked_repository_artifact,
    generated_correctness_fixture,
    generated_opt_in_uncommitted_non_receiptable,

    pub fn id(self: StorageClass) []const u8 {
        return switch (self) {
            .checked_repository_artifact => "checked_repository_artifact",
            .generated_correctness_fixture => "generated_correctness_fixture",
            .generated_opt_in_uncommitted_non_receiptable => "generated_opt_in_uncommitted_non_receiptable",
        };
    }
};

pub const Error = std.mem.Allocator.Error || protocol.VectorAuthenticationError || error{
    ArtifactLengthMismatch,
    BadMagic,
    CorruptVectorSeal,
    InputOutOfRange,
    InvalidExpectedOutput,
    InvalidFixedRole,
    NonCanonicalVector,
    SemanticOutputMismatch,
    TruncatedVector,
    UnsupportedFormat,
};

pub const Owned = struct {
    allocator: std.mem.Allocator,
    calls: []production.Call,
    identity: protocol.VectorIdentity,
    storage_class: StorageClass,

    pub fn generate(
        allocator: std.mem.Allocator,
        log_size: u8,
        authenticate: bool,
    ) Error!Owned {
        const rows = try rowCount(log_size);
        const calls = try allocator.alloc(production.Call, rows);
        errdefer allocator.free(calls);
        for (calls, 0..) |*call, row| call.* = generatedCall(log_size, row);
        const identity = computeIdentity(calls, log_size);
        if (authenticate) try protocol.authenticateVector(identity);
        return .{
            .allocator = allocator,
            .calls = calls,
            .identity = identity,
            .storage_class = if (protocol.isMeasurementLog(log_size))
                .generated_opt_in_uncommitted_non_receiptable
            else
                .generated_correctness_fixture,
        };
    }

    pub fn decodeChecked(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        expected_log_size: u8,
    ) Error!Owned {
        const pin = protocol.vectorPin(expected_log_size) orelse
            return error.UnsupportedVectorLog;
        if (bytes.len != pin.artifact_bytes) return error.ArtifactLengthMismatch;
        const preimage_len: usize = @intCast(pin.preimage_bytes);
        const preimage = bytes[0..preimage_len];
        const encoded_seal = bytes[preimage_len..][0..32];
        var actual_seal: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(preimage, &actual_seal, .{});
        if (!std.mem.eql(u8, &actual_seal, encoded_seal))
            return error.CorruptVectorSeal;
        var artifact_sha256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &artifact_sha256, .{});

        var cursor = Cursor{ .bytes = preimage };
        try cursor.expect(protocol.vector_magic);
        if (try cursor.int(u16) != protocol.vector_format_version)
            return error.UnsupportedFormat;
        if (try cursor.int(u16) != protocol.vector_generator_id.len)
            return error.NonCanonicalVector;
        try cursor.expect(protocol.vector_generator_id);
        try cursor.expect(&semantic_digest);
        if (try cursor.int(u32) != expected_log_size)
            return error.NonCanonicalVector;
        const encoded_rows = try cursor.int(u64);
        if (encoded_rows != pin.rows) return error.NonCanonicalVector;
        const calls = try allocator.alloc(production.Call, @intCast(encoded_rows));
        errdefer allocator.free(calls);

        var output_hash = beginOutputHash(expected_log_size, calls.len);
        for (calls, 0..) |*call, row| {
            call.* = .{ .input = undefined };
            for (&call.input) |*input| {
                input.* = try cursor.int(u32);
                if (input.* >= m31_modulus) return error.InputOutOfRange;
            }
            if (try cursor.int(u32) != 1) return error.InvalidFixedRole;
            const wide = try cursor.int(u32);
            const io = try cursor.int(u32);
            if (wide > 1 or io > 1 or wide + io != 1 or
                wide != @intFromBool((row & 1) == 1))
            {
                return error.InvalidFixedRole;
            }
            call.wide = wide == 1;
            call.io = io == 1;
            const expected = production.output(production.fill(call.*));
            for (expected) |value| {
                const encoded = try cursor.int(u32);
                if (encoded >= m31_modulus) return error.InvalidExpectedOutput;
                if (encoded != value.toU32()) return error.SemanticOutputMismatch;
                hashInt(&output_hash, u32, encoded);
            }
        }
        if (cursor.position != preimage.len) return error.NonCanonicalVector;
        const identity = protocol.VectorIdentity{
            .log_size = expected_log_size,
            .rows = encoded_rows,
            .preimage_bytes = preimage.len,
            .artifact_bytes = bytes.len,
            .vector_seal = actual_seal,
            .vector_artifact_sha256 = artifact_sha256,
            .call_digest = callsDigest(calls, expected_log_size),
            .output_digest = output_hash.finalResult(),
        };
        try protocol.authenticateVector(identity);
        return .{
            .allocator = allocator,
            .calls = calls,
            .identity = identity,
            .storage_class = .checked_repository_artifact,
        };
    }

    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.calls);
        self.* = undefined;
    }
};

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    log_size: u8,
) Error![]u8 {
    var vector = try Owned.generate(allocator, log_size, true);
    defer vector.deinit();
    const byte_len: usize = @intCast(vector.identity.artifact_bytes);
    const bytes = try allocator.alloc(u8, byte_len);
    errdefer allocator.free(bytes);
    var cursor = WriteCursor{ .bytes = bytes };
    try cursor.put(protocol.vector_magic);
    try cursor.int(u16, protocol.vector_format_version);
    try cursor.int(u16, protocol.vector_generator_id.len);
    try cursor.put(protocol.vector_generator_id);
    try cursor.put(&semantic_digest);
    try cursor.int(u32, log_size);
    try cursor.int(u64, vector.calls.len);
    for (vector.calls) |call| {
        for (call.input) |value| try cursor.int(u32, value);
        try cursor.int(u32, 1);
        try cursor.int(u32, @intFromBool(call.wide));
        try cursor.int(u32, @intFromBool(call.io));
        for (production.output(production.fill(call))) |value| {
            try cursor.int(u32, value.toU32());
        }
    }
    if (cursor.position != vector.identity.preimage_bytes)
        return error.ArtifactLengthMismatch;
    try cursor.put(&vector.identity.vector_seal);
    if (cursor.position != bytes.len) return error.ArtifactLengthMismatch;
    return bytes;
}

pub fn generatedIdentity(
    allocator: std.mem.Allocator,
    log_size: u8,
) Error!protocol.VectorIdentity {
    var vector = try Owned.generate(allocator, log_size, false);
    defer vector.deinit();
    return vector.identity;
}

fn computeIdentity(
    calls: []const production.Call,
    log_size: u8,
) protocol.VectorIdentity {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var preimage_bytes: u64 = 0;
    hashCountedBytes(&hash, &preimage_bytes, protocol.vector_magic);
    hashCountedInt(&hash, &preimage_bytes, u16, protocol.vector_format_version);
    hashCountedInt(
        &hash,
        &preimage_bytes,
        u16,
        protocol.vector_generator_id.len,
    );
    hashCountedBytes(&hash, &preimage_bytes, protocol.vector_generator_id);
    hashCountedBytes(&hash, &preimage_bytes, &semantic_digest);
    hashCountedInt(&hash, &preimage_bytes, u32, log_size);
    hashCountedInt(&hash, &preimage_bytes, u64, calls.len);
    var output_hash = beginOutputHash(log_size, calls.len);
    for (calls) |call| {
        for (call.input) |value| hashCountedInt(
            &hash,
            &preimage_bytes,
            u32,
            value,
        );
        hashCountedInt(&hash, &preimage_bytes, u32, 1);
        hashCountedInt(&hash, &preimage_bytes, u32, @intFromBool(call.wide));
        hashCountedInt(&hash, &preimage_bytes, u32, @intFromBool(call.io));
        for (production.output(production.fill(call))) |value| {
            hashCountedInt(&hash, &preimage_bytes, u32, value.toU32());
            hashInt(&output_hash, u32, value.toU32());
        }
    }
    var artifact_hash = hash;
    const vector_seal = hash.finalResult();
    artifact_hash.update(&vector_seal);
    return .{
        .log_size = log_size,
        .rows = calls.len,
        .preimage_bytes = preimage_bytes,
        .artifact_bytes = preimage_bytes + 32,
        .vector_seal = vector_seal,
        .vector_artifact_sha256 = artifact_hash.finalResult(),
        .call_digest = callsDigest(calls, log_size),
        .output_digest = output_hash.finalResult(),
    };
}

fn generatedCall(log_size: u8, row: usize) production.Call {
    var call = production.Call{ .input = undefined };
    for (&call.input, 0..) |*value, lane| {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(protocol.vector_value_domain);
        hash.update(&semantic_digest);
        hashInt(&hash, u32, log_size);
        hashInt(&hash, u64, row);
        hashInt(&hash, u16, @as(u16, @intCast(lane)));
        const digest = hash.finalResult();
        value.* = std.mem.readInt(u32, digest[0..4], .little) % m31_modulus;
    }
    call.wide = (row & 1) == 1;
    call.io = !call.wide;
    return call;
}

pub fn callsDigest(calls: []const production.Call, log_size: u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(protocol.call_digest_domain);
    hashInt(&hash, u8, log_size);
    hashInt(&hash, u64, calls.len);
    for (calls) |call| {
        for (call.input) |value| hashInt(&hash, u32, value);
        hashInt(&hash, u8, @intFromBool(call.wide));
        hashInt(&hash, u8, @intFromBool(call.io));
    }
    return hash.finalResult();
}

fn beginOutputHash(log_size: u8, rows: usize) std.crypto.hash.sha2.Sha256 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(protocol.output_digest_domain);
    hashInt(&hash, u8, log_size);
    hashInt(&hash, u64, rows);
    return hash;
}

fn rowCount(log_size: u8) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.VectorGeometryMismatch;
    return @as(usize, 1) << @intCast(log_size);
}

const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    fn take(self: *Cursor, count: usize) Error![]const u8 {
        const end = std.math.add(usize, self.position, count) catch
            return error.TruncatedVector;
        if (end > self.bytes.len) return error.TruncatedVector;
        defer self.position = end;
        return self.bytes[self.position..end];
    }

    fn expect(self: *Cursor, expected: []const u8) Error!void {
        if (!std.mem.eql(u8, try self.take(expected.len), expected))
            return error.BadMagic;
    }

    fn int(self: *Cursor, comptime T: type) Error!T {
        const bytes = try self.take(@sizeOf(T));
        const fixed: *const [@sizeOf(T)]u8 = @ptrCast(bytes.ptr);
        return std.mem.readInt(T, fixed, .little);
    }
};

const WriteCursor = struct {
    bytes: []u8,
    position: usize = 0,

    fn put(self: *WriteCursor, value: []const u8) Error!void {
        const end = std.math.add(usize, self.position, value.len) catch
            return error.ArtifactLengthMismatch;
        if (end > self.bytes.len) return error.ArtifactLengthMismatch;
        @memcpy(self.bytes[self.position..end], value);
        self.position = end;
    }

    fn int(self: *WriteCursor, comptime T: type, value: anytype) Error!void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, @intCast(value), .little);
        try self.put(&encoded);
    }
};

fn decodePinnedDigest(comptime encoded: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hashCountedBytes(hash: anytype, count: *u64, bytes: []const u8) void {
    hash.update(bytes);
    count.* += bytes.len;
}

fn hashCountedInt(
    hash: anytype,
    count: *u64,
    comptime T: type,
    value: anytype,
) void {
    hashInt(hash, T, value);
    count.* += @sizeOf(T);
}
