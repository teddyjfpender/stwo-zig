//! One-time loader for authenticated Cairo preprocessed coefficients.
//!
//! STWZPPC stores Rust SIMD coefficient blocks. This boundary validates every
//! column identity and shape, canonicalizes blocked coefficient order, and
//! uploads directly into the immutable process arena.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const trace_commit = @import("trace_commit.zig");
const cuda = @import("stwo_cuda_backend");

const NativeContext = @TypeOf(@as(cuda.runtime.NativeSession, undefined).context);

/// Opt-in process snapshot of validated fixed coefficients. The first proof
/// copies the exact uploaded words into this allocation; subsequent proofs
/// restore them device-to-device after matching the source/layout identity.
/// A receipt becomes reusable only after the first Cairo proof verifies.
pub const DeviceImage = struct {
    buffer: NativeContext.Buffer,
    key: [32]u8,
    receipt: ?Receipt = null,
    pending: ?Receipt = null,

    pub fn init(runtime: *cuda.runtime.NativeRuntime, words: usize, key: [32]u8) !DeviceImage {
        return .{
            .buffer = try runtime.inner.session.context.allocatePersistent(words),
            .key = key,
        };
    }

    pub fn deinit(self: *DeviceImage, runtime: *cuda.runtime.NativeRuntime) !void {
        try runtime.inner.session.context.freePersistent(&self.buffer);
        self.* = undefined;
    }

    pub fn slice(self: *const DeviceImage) cuda.runtime.column.DeviceSlice(u32) {
        return .{
            .address = @intFromPtr(self.buffer.pointer),
            .len = self.buffer.words,
            .owner = self.buffer.owner,
            .generation = self.buffer.generation,
        };
    }

    pub fn restore(
        self: *const DeviceImage,
        session: anytype,
        destination: anytype,
        expected: ?proof_ir.Digest,
        commitment_identity: proof_ir.Digest,
    ) !Receipt {
        var receipt = self.receipt orelse return error.InvalidPreprocessedDeviceImage;
        try receipt.validate();
        if (destination.len != self.buffer.words or
            (expected != null and !std.mem.eql(u8, &expected.?, &receipt.artifact_identity)))
            return error.InvalidPreprocessedDeviceImage;
        // The coefficient image is independent of arena slots. Bind its
        // validated artifact to this request's commitment plan before the
        // controller admits the receipt.
        receipt.commitment_identity = commitment_identity;
        receipt.identity = receiptIdentity(receipt);
        try receipt.validate();
        try session.context.copyDeviceSlice(u32, destination, self.slice());
        return receipt;
    }

    pub fn capture(self: *DeviceImage, session: anytype, source: anytype, receipt: Receipt) !void {
        if (self.receipt != null or self.pending != null or source.len != self.buffer.words)
            return error.InvalidPreprocessedDeviceImage;
        try receipt.validate();
        try session.context.copyDeviceSlice(u32, self.slice(), source);
        self.pending = receipt;
    }

    pub fn admit(self: *DeviceImage) !void {
        const receipt = self.pending orelse return error.InvalidPreprocessedDeviceImage;
        if (self.receipt != null) return error.InvalidPreprocessedDeviceImage;
        self.receipt = receipt;
        self.pending = null;
    }
};

pub fn deviceImageKey(path: []const u8, identities: []const []const u8, prepared: *const trace_commit.Prepared) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/preprocessed-device-image/v2\x00");
    var path_size: [8]u8 = undefined;
    std.mem.writeInt(u64, &path_size, @intCast(path.len), .little);
    hash.update(&path_size);
    hash.update(path);
    hashInt(&hash, u32, prepared.tree_ordinal);
    hashInt(&hash, u8, @intFromEnum(prepared.input_form));
    hashInt(&hash, u32, prepared.tree_size);
    hashInt(&hash, u64, prepared.column_logs.len);
    for (prepared.column_logs) |log| hashInt(&hash, u32, log);
    hashInt(&hash, u64, prepared.column_offsets.len);
    for (prepared.column_offsets) |offset| hashInt(&hash, u32, offset);
    var coefficient_words: [8]u8 = undefined;
    std.mem.writeInt(u64, &coefficient_words, prepared.column_offsets[prepared.column_offsets.len - 1], .little);
    hash.update(&coefficient_words);
    for (identities) |identity| {
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, identity.len, .little);
        hash.update(&size);
        hash.update(identity);
    }
    return hash.finalResult();
}

pub const format_magic = "STWZPPC\x00";
pub const format_version: u32 = 1;

pub const Receipt = struct {
    artifact_identity: proof_ir.Digest,
    commitment_identity: proof_ir.Digest,
    column_count: u32,
    coefficient_words: u64,
    identity: proof_ir.Digest,

    pub fn validate(self: Receipt) !void {
        if (digestEmpty(self.artifact_identity) or
            digestEmpty(self.commitment_identity) or
            self.column_count == 0 or
            self.coefficient_words == 0 or
            digestEmpty(self.identity) or
            !std.mem.eql(u8, &self.identity, &receiptIdentity(self)))
        {
            return error.InvalidPreprocessedCacheReceipt;
        }
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    session: anytype,
    path: []const u8,
    expected_artifact_identity: ?proof_ir.Digest,
    expected_identities: anytype,
    prepared: *const trace_commit.Prepared,
    bound: *const trace_commit.Bound,
) !Receipt {
    if (prepared.tree_ordinal != 0 or
        prepared.input_form != .coefficients or
        prepared.column_logs.len != expected_identities.len or
        prepared.column_offsets.len != expected_identities.len + 1 or
        bound.prepared != prepared)
    {
        return error.InvalidPreprocessedCacheBinding;
    }
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var reader_buffer: [1 << 20]u8 = undefined;
    var reader = file.readerStreaming(&reader_buffer);
    var artifact_hash = std.crypto.hash.sha2.Sha256.init(.{});
    var hashing_buffer: [4096]u8 = undefined;
    var hashing_reader = reader.interface.hashed(&artifact_hash, &hashing_buffer);
    const stream = &hashing_reader.reader;
    const profile_setting = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_PROFILE_PREPROCESSED") catch null;
    defer if (profile_setting) |value| allocator.free(value);
    const profile = profile_setting != null and std.mem.eql(u8, profile_setting.?, "1");
    var phase_timer = try std.time.Timer.start();
    var read_ns: u64 = 0;
    var validate_ns: u64 = 0;
    var transpose_ns: u64 = 0;
    var upload_ns: u64 = 0;
    if (!std.mem.eql(u8, try stream.takeArray(8), format_magic))
        return error.InvalidPreprocessedArtifact;
    if (try stream.takeInt(u32, .little) != format_version or
        try stream.takeInt(u32, .little) != expected_identities.len)
    {
        return error.InvalidPreprocessedArtifact;
    }

    var maximum_words: usize = 0;
    for (prepared.column_logs) |log_rows|
        maximum_words = @max(maximum_words, try pow2(log_rows));
    const staging = try allocator.alloc(u32, maximum_words);
    defer allocator.free(staging);

    var coefficient_words: u64 = 0;
    for (
        expected_identities,
        prepared.column_logs,
        0..,
    ) |expected_identity, expected_log, ordinal| {
        const identity_len = try stream.takeInt(u16, .little);
        if (try stream.takeInt(u16, .little) != 0 or
            identity_len != expected_identity.len)
        {
            return error.InvalidPreprocessedArtifact;
        }
        const log_rows = try stream.takeInt(u32, .little);
        const value_count = try stream.takeInt(u64, .little);
        const words = try pow2(log_rows);
        if (log_rows != expected_log or value_count != words)
            return error.InvalidPreprocessedArtifact;
        const identity = try allocator.alloc(u8, identity_len);
        defer allocator.free(identity);
        try stream.readSliceAll(identity);
        if (!std.mem.eql(u8, identity, expected_identity))
            return error.InvalidPreprocessedArtifact;

        const values = staging[0..words];
        try stream.readSliceAll(std.mem.sliceAsBytes(values));
        if (profile) read_ns += phase_timer.lap();
        for (values) |value| {
            if (value >= 0x7fff_ffff)
                return error.NonCanonicalPreprocessedCoefficient;
        }
        if (profile) validate_ns += phase_timer.lap();
        if (log_rows > 16)
            canonicalizeSimdCoefficientBlocks(values, log_rows);
        if (profile) transpose_ns += phase_timer.lap();
        const begin: usize = prepared.column_offsets[ordinal];
        const end: usize = prepared.column_offsets[ordinal + 1];
        if (end < begin or end - begin != words)
            return error.InvalidPreprocessedCacheBinding;
        try session.context.uploadSlice(
            u32,
            try bound.coefficients.sub(begin, words),
            values,
        );
        if (profile) upload_ns += phase_timer.lap();
        coefficient_words = std.math.add(
            u64,
            coefficient_words,
            words,
        ) catch return error.PreprocessedArtifactOverflow;
    }
    var trailing: [1]u8 = undefined;
    if (try stream.readSliceShort(&trailing) != 0)
        return error.InvalidPreprocessedArtifact;
    // Hash the same raw bytes that were parsed and uploaded, before SIMD
    // canonicalization. This avoids a separate whole-artifact read and binds
    // the receipt to consumed content rather than an earlier file snapshot.
    const artifact_identity = artifact_hash.finalResult();
    if (profile) std.debug.print("cairo-cuda preprocessed-profile read_ns={} validate_ns={} transpose_ns={} upload_ns={} words={}\n", .{
        read_ns, validate_ns, transpose_ns, upload_ns, coefficient_words,
    });
    if (expected_artifact_identity) |expected| {
        if (!std.mem.eql(u8, &expected, &artifact_identity))
            return error.PreprocessedArtifactIdentityMismatch;
    }

    var receipt = Receipt{
        .artifact_identity = artifact_identity,
        .commitment_identity = prepared.identity,
        .column_count = @intCast(expected_identities.len),
        .coefficient_words = coefficient_words,
        .identity = undefined,
    };
    receipt.identity = receiptIdentity(receipt);
    try receipt.validate();
    return receipt;
}

const canonicalizeSimdCoefficientBlocks = @import("stwo_cairo_frontend").preprocessed.coefficient_order.transposeSimdBlocks;

fn receiptIdentity(value: Receipt) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/preprocessed-cache/v1\x00");
    hash.update(&value.artifact_identity);
    hash.update(&value.commitment_identity);
    hashInt(&hash, u32, value.column_count);
    hashInt(&hash, u64, value.coefficient_words);
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn pow2(log_rows: u32) !usize {
    if (log_rows >= @bitSizeOf(usize))
        return error.PreprocessedArtifactOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

fn digestEmpty(value: proof_ir.Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

test "SIMD coefficient canonicalization is an involution" {
    const log_rows: u32 = 17;
    const values = try std.testing.allocator.alloc(
        u32,
        @as(usize, 1) << log_rows,
    );
    defer std.testing.allocator.free(values);
    for (values, 0..) |*value, index| value.* = @intCast(index);
    canonicalizeSimdCoefficientBlocks(values, log_rows);
    try std.testing.expectEqual(@as(u32, 128 * 16), values[16]);
    try std.testing.expectEqual(@as(u32, 16), values[128 * 16]);
    canonicalizeSimdCoefficientBlocks(values, log_rows);
    for (values, 0..) |value, index|
        try std.testing.expectEqual(@as(u32, @intCast(index)), value);
}

test "device image key follows fixed coefficient layout, not arena plan identity" {
    var logs = [_]u32{2};
    var offsets = [_]u32{ 0, 4 };
    var prepared: trace_commit.Prepared = undefined;
    prepared.tree_ordinal = 0;
    prepared.tree_size = 8;
    prepared.input_form = .coefficients;
    prepared.column_logs = &logs;
    prepared.column_offsets = &offsets;
    prepared.identity = [_]u8{1} ** 32;
    const first = deviceImageKey("/canonical", &.{"fixed"}, &prepared);
    prepared.identity = [_]u8{2} ** 32;
    const new_plan = deviceImageKey("/canonical", &.{"fixed"}, &prepared);
    try std.testing.expectEqualSlices(u8, &first, &new_plan);
    logs[0] = 3;
    offsets[1] = 8;
    const new_layout = deviceImageKey("/canonical", &.{"fixed"}, &prepared);
    try std.testing.expect(!std.mem.eql(u8, &first, &new_layout));
}

test "device image admits only verified snapshots and restores exact words" {
    const FakeSession = struct {
        context: struct {
            pub fn copyDeviceSlice(_: *@This(), comptime F: type, destination: anytype, source: anytype) !void {
                if (F != u32 or destination.len != source.len) return error.InvalidCopy;
                const dst: [*]u32 = @ptrFromInt(destination.address);
                const src: [*]const u32 = @ptrFromInt(source.address);
                @memcpy(dst[0..destination.len], src[0..source.len]);
            }
        } = .{},
    };
    var source = [_]u32{ 1, 2, 3, 4 };
    var storage = [_]u32{0} ** 4;
    var destination = [_]u32{0} ** 4;
    var session = FakeSession{};
    var receipt = Receipt{
        .artifact_identity = [_]u8{1} ** 32,
        .commitment_identity = [_]u8{2} ** 32,
        .column_count = 1,
        .coefficient_words = 4,
        .identity = undefined,
    };
    receipt.identity = receiptIdentity(receipt);
    var image = DeviceImage{
        .buffer = .{ .pointer = &storage, .words = 4, .owner = 1, .generation = 1 },
        .key = [_]u8{3} ** 32,
    };
    const source_slice: cuda.runtime.column.DeviceSlice(u32) = .{
        .address = @intFromPtr(&source),
        .len = 4,
        .owner = 1,
        .generation = 2,
    };
    const destination_slice: cuda.runtime.column.DeviceSlice(u32) = .{
        .address = @intFromPtr(&destination),
        .len = 4,
        .owner = 1,
        .generation = 3,
    };
    try image.capture(&session, source_slice, receipt);
    try std.testing.expectError(error.InvalidPreprocessedDeviceImage, image.restore(&session, destination_slice, null, receipt.commitment_identity));
    try image.admit();
    try std.testing.expectError(error.InvalidPreprocessedDeviceImage, image.admit());
    try std.testing.expectError(error.InvalidPreprocessedDeviceImage, image.restore(&session, destination_slice, [_]u8{4} ** 32, receipt.commitment_identity));
    const rebound = try image.restore(&session, destination_slice, receipt.artifact_identity, [_]u8{5} ** 32);
    try std.testing.expectEqualSlices(u8, &rebound.commitment_identity, &([_]u8{5} ** 32));
    try rebound.validate();
    try std.testing.expectEqualSlices(u32, &source, &destination);
}
