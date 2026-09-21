//! Allocation-free structural preflight for the postcard `StarkProof` wire.
//!
//! The ordinary decoder allocates each length-prefixed sequence as it is read.
//! External proof bytes must pass this exact-shape walk first so an attacker
//! cannot turn a small payload into a large allocation request.

const std = @import("std");

const M31_MODULUS: u32 = 0x7fff_ffff;
const TREE_COUNT: usize = 4;
// These are allocation-safety limits, not an AIR mask declaration. Exact mask
// widths are reconstructed from the production components by the verifier.
pub const DEFAULT_SAMPLE_WIDTH_LIMITS = [TREE_COUNT]u32{ 2, 2, 2, 1 };
const TEST_SAMPLE_WIDTHS = [TREE_COUNT]u32{ 1, 1, 2, 1 };

pub const Config = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    n_queries: u64,
    log_last_layer_degree_bound: u32,
    fold_step: u32,
    lifting_log_size: ?u32,
};

/// Postcard representation of one Merkle hash.
///
/// Blake-family hashes are fixed byte arrays and therefore occupy exactly
/// `hash_size` bytes.  Poseidon hashes are arrays of M31 words; postcard
/// serializes each word as a canonical varint, so their encoded size is not
/// fixed and every word must be parsed rather than skipped.
pub const HashEncoding = enum {
    raw_bytes,
    canonical_m31_words,
};

/// Shape known before proof decoding from an independently validated statement.
pub const Shape = struct {
    config: Config,
    /// Preprocessed, main, interaction, and composition column counts.
    tree_columns: [TREE_COUNT]u32,
    /// Maximum column log size after composition splitting and before FRI.
    max_column_log_size: u32,
    /// Allocation-safety bounds for sampled values per column in each tree.
    ///
    /// The default preserves the released V1 proof-artifact admission policy.
    /// Profiles whose statically authenticated AIR masks are wider must opt in
    /// through their statement-derived shape rather than artifact bytes.
    sample_width_limits: [TREE_COUNT]u32 = DEFAULT_SAMPLE_WIDTH_LIMITS,
    /// In-memory hash width.  For `canonical_m31_words` this must be a
    /// non-zero multiple of four and determines the number of M31 words.
    hash_size: u32,
    hash_encoding: HashEncoding = .raw_bytes,
    max_wire_bytes: usize,
};

pub const Error = error{
    EndOfStream,
    InvalidOptionTag,
    InvalidProofConfig,
    InvalidProofShape,
    InvalidPreflightShape,
    NonCanonicalM31,
    NonCanonicalVarint,
    ProofResourceLimitExceeded,
    TrailingProofBytes,
    VarintOverflow,
};

/// Typed, allocation-free localization for the first proof-shape mismatch.
///
/// This is diagnostic telemetry only.  `validateWithDiagnostic` executes the
/// same admission parser and returns the same error set as `validate`.
pub const DiagnosticStage = enum {
    commitment_tree_count,
    sampled_tree_count,
    sampled_column_count,
    sampled_width,
    decommitment_tree_count,
    queried_tree_count,
    queried_column_count,
    fri_inner_layer_count,
    fri_last_coefficient_count,
};

pub const Diagnostic = struct {
    stage: DiagnosticStage,
    tree: ?u32,
    index: ?u32,
    offset: usize,
    actual: usize,
    expected: usize,
};

/// Validate every length prefix and scalar without allocating.
pub fn validate(raw: []const u8, shape: Shape) Error!void {
    return validateInternal(raw, shape, null);
}

/// Run the canonical preflight while retaining only its first exact mismatch.
pub fn validateWithDiagnostic(
    raw: []const u8,
    shape: Shape,
    diagnostic: *?Diagnostic,
) Error!void {
    diagnostic.* = null;
    return validateInternal(raw, shape, diagnostic);
}

fn validateInternal(
    raw: []const u8,
    shape: Shape,
    diagnostic: ?*?Diagnostic,
) Error!void {
    const bounds = try Bounds.init(shape);
    if (raw.len > shape.max_wire_bytes) return error.ProofResourceLimitExceeded;

    var cursor = Cursor{ .bytes = raw };
    try expectConfig(&cursor, shape.config);

    try expectCountAt(
        &cursor,
        TREE_COUNT,
        diagnostic,
        .commitment_tree_count,
        null,
        null,
    );
    for (0..TREE_COUNT) |_| try skipHash(&cursor, bounds);

    try expectCountAt(
        &cursor,
        TREE_COUNT,
        diagnostic,
        .sampled_tree_count,
        null,
        null,
    );
    for (shape.tree_columns, shape.sample_width_limits, 0..) |
        column_count,
        sample_width_limit,
        tree_index,
    | {
        try expectCountAt(
            &cursor,
            column_count,
            diagnostic,
            .sampled_column_count,
            @intCast(tree_index),
            null,
        );
        for (0..column_count) |column_index| {
            const sample_width_offset = cursor.position;
            const sample_width = try cursor.readUsize();
            if (sample_width == 0) {
                recordMismatch(
                    diagnostic,
                    .sampled_width,
                    @intCast(tree_index),
                    @intCast(column_index),
                    sample_width_offset,
                    sample_width,
                    1,
                );
                return error.InvalidProofShape;
            }
            if (sample_width > sample_width_limit)
                return error.ProofResourceLimitExceeded;
            for (0..sample_width) |_| try cursor.readQm31();
        }
    }

    try expectCountAt(
        &cursor,
        TREE_COUNT,
        diagnostic,
        .decommitment_tree_count,
        null,
        null,
    );
    for (0..TREE_COUNT) |_| try skipHashWitness(&cursor, bounds);

    try expectCountAt(
        &cursor,
        TREE_COUNT,
        diagnostic,
        .queried_tree_count,
        null,
        null,
    );
    for (shape.tree_columns, 0..) |column_count, tree_index| {
        try expectCountAt(
            &cursor,
            column_count,
            diagnostic,
            .queried_column_count,
            @intCast(tree_index),
            null,
        );
        for (0..column_count) |_| {
            const value_count = try cursor.readUsize();
            if (value_count > bounds.n_queries) return error.ProofResourceLimitExceeded;
            for (0..value_count) |_| try cursor.readM31();
        }
    }

    _ = try cursor.readVarint(); // proof of work
    try readFriLayer(&cursor, bounds);

    try expectCountAt(
        &cursor,
        bounds.inner_layer_count,
        diagnostic,
        .fri_inner_layer_count,
        null,
        null,
    );
    for (0..bounds.inner_layer_count) |_| try readFriLayer(&cursor, bounds);

    try expectCountAt(
        &cursor,
        bounds.last_layer_coefficients,
        diagnostic,
        .fri_last_coefficient_count,
        null,
        null,
    );
    for (0..bounds.last_layer_coefficients) |_| try cursor.readQm31();

    if (cursor.position != raw.len) return error.TrailingProofBytes;
}

const Bounds = struct {
    n_queries: usize,
    hash_size: usize,
    max_hash_witnesses: usize,
    max_fri_witnesses: usize,
    inner_layer_count: usize,
    last_layer_coefficients: usize,
    hash_encoding: HashEncoding,
    hash_word_count: usize,

    fn init(shape: Shape) Error!Bounds {
        const config = shape.config;
        if (shape.max_wire_bytes == 0 or shape.hash_size == 0 or
            config.n_queries == 0 or config.n_queries > std.math.maxInt(usize) or
            config.fold_step == 0 or config.fold_step > 16 or
            config.log_blowup_factor > 16 or
            config.log_last_layer_degree_bound > 30 or
            shape.max_column_log_size > 30 or
            shape.max_column_log_size < config.log_last_layer_degree_bound)
            return error.InvalidPreflightShape;
        for (shape.tree_columns) |count| {
            if (count == 0) return error.InvalidPreflightShape;
        }
        for (shape.sample_width_limits) |limit| {
            if (limit == 0) return error.InvalidPreflightShape;
        }
        const hash_word_count: usize = switch (shape.hash_encoding) {
            .raw_bytes => 0,
            .canonical_m31_words => blk: {
                if (shape.hash_size % @sizeOf(u32) != 0)
                    return error.InvalidPreflightShape;
                break :blk @intCast(shape.hash_size / @sizeOf(u32));
            },
        };

        const n_queries: usize = @intCast(config.n_queries);
        const merkle_depth_u32 = std.math.add(
            u32,
            shape.max_column_log_size,
            config.log_blowup_factor + 1,
        ) catch return error.InvalidPreflightShape;
        const merkle_depth: usize = @intCast(merkle_depth_u32);
        const max_hash_witnesses = multiply(n_queries, merkle_depth) catch
            return error.InvalidPreflightShape;

        const subset_size = @as(usize, 1) << @intCast(config.fold_step);
        const max_fri_witnesses = multiply(n_queries, subset_size - 1) catch
            return error.InvalidPreflightShape;
        const inner_layer_count = try expectedInnerLayers(
            shape.max_column_log_size,
            config.log_last_layer_degree_bound,
            config.fold_step,
        );
        const last_layer_coefficients = @as(usize, 1) <<
            @intCast(config.log_last_layer_degree_bound);

        return .{
            .n_queries = n_queries,
            .hash_size = shape.hash_size,
            .max_hash_witnesses = max_hash_witnesses,
            .max_fri_witnesses = max_fri_witnesses,
            .inner_layer_count = inner_layer_count,
            .last_layer_coefficients = last_layer_coefficients,
            .hash_encoding = shape.hash_encoding,
            .hash_word_count = hash_word_count,
        };
    }
};

fn expectedInnerLayers(max_log: u32, last_log: u32, fold_step: u32) Error!usize {
    if (max_log < fold_step) return error.InvalidPreflightShape;
    const after_first = max_log - fold_step;
    if (after_first < last_log) return error.InvalidPreflightShape;
    const remaining = after_first - last_log;
    const rounds = std.math.divCeil(u32, remaining, fold_step) catch
        return error.InvalidPreflightShape;
    return @intCast(rounds);
}

fn expectConfig(cursor: *Cursor, expected: Config) Error!void {
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

fn readFriLayer(cursor: *Cursor, bounds: Bounds) Error!void {
    const witness_count = try cursor.readUsize();
    if (witness_count > bounds.max_fri_witnesses)
        return error.ProofResourceLimitExceeded;
    for (0..witness_count) |_| try cursor.readQm31();
    try skipHashWitness(cursor, bounds);
    try skipHash(cursor, bounds);
}

fn skipHashWitness(cursor: *Cursor, bounds: Bounds) Error!void {
    const hash_count = try cursor.readUsize();
    if (hash_count > bounds.max_hash_witnesses)
        return error.ProofResourceLimitExceeded;
    switch (bounds.hash_encoding) {
        .raw_bytes => try cursor.skip(try multiply(hash_count, bounds.hash_size)),
        .canonical_m31_words => {
            for (0..hash_count) |_| try skipHash(cursor, bounds);
        },
    }
}

fn skipHash(cursor: *Cursor, bounds: Bounds) Error!void {
    switch (bounds.hash_encoding) {
        .raw_bytes => try cursor.skip(bounds.hash_size),
        .canonical_m31_words => {
            for (0..bounds.hash_word_count) |_| try cursor.readM31();
        },
    }
}

fn expectCount(cursor: *Cursor, expected: anytype) Error!void {
    return expectCountAt(
        cursor,
        expected,
        null,
        .commitment_tree_count,
        null,
        null,
    );
}

fn expectCountAt(
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

fn recordMismatch(
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

fn multiply(left: usize, right: usize) Error!usize {
    return std.math.mul(usize, left, right) catch
        return error.ProofResourceLimitExceeded;
}

const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    fn readByte(self: *Cursor) Error!u8 {
        if (self.position == self.bytes.len) return error.EndOfStream;
        const byte = self.bytes[self.position];
        self.position += 1;
        return byte;
    }

    fn skip(self: *Cursor, count: usize) Error!void {
        const end = std.math.add(usize, self.position, count) catch
            return error.ProofResourceLimitExceeded;
        if (end > self.bytes.len) return error.EndOfStream;
        self.position = end;
    }

    fn readUsize(self: *Cursor) Error!usize {
        const value = try self.readVarint();
        return std.math.cast(usize, value) orelse error.VarintOverflow;
    }

    fn readU32(self: *Cursor) Error!u32 {
        const value = try self.readVarint();
        return std.math.cast(u32, value) orelse error.VarintOverflow;
    }

    fn readM31(self: *Cursor) Error!void {
        if (try self.readU32() >= M31_MODULUS) return error.NonCanonicalM31;
    }

    fn readQm31(self: *Cursor) Error!void {
        for (0..4) |_| try self.readM31();
    }

    fn readVarint(self: *Cursor) Error!u64 {
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

fn testShape() Shape {
    return .{
        .config = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .n_queries = 3,
            .log_last_layer_degree_bound = 0,
            .fold_step = 1,
            .lifting_log_size = null,
        },
        .tree_columns = .{ 1, 1, 1, 8 },
        .max_column_log_size = 1,
        .hash_size = 32,
        .max_wire_bytes = 1 << 20,
    };
}

fn appendVarint(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), value: u64) !void {
    var remaining = value;
    while (remaining >= 0x80) {
        try bytes.append(allocator, @intCast((remaining & 0x7f) | 0x80));
        remaining >>= 7;
    }
    try bytes.append(allocator, @intCast(remaining));
}

fn appendZeroQm31(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8)) !void {
    try bytes.appendNTimes(allocator, 0, 4);
}

fn appendConfig(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), shape: Shape) !void {
    try appendVarint(allocator, bytes, shape.config.pow_bits);
    try appendVarint(allocator, bytes, shape.config.log_blowup_factor);
    try appendVarint(allocator, bytes, shape.config.n_queries);
    try appendVarint(allocator, bytes, shape.config.log_last_layer_degree_bound);
    try appendVarint(allocator, bytes, shape.config.fold_step);
    try bytes.append(allocator, 0);
}

fn appendZeroHash(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    shape: Shape,
) !void {
    switch (shape.hash_encoding) {
        .raw_bytes => try bytes.appendNTimes(allocator, 0, shape.hash_size),
        .canonical_m31_words => {
            if (shape.hash_size == 0 or shape.hash_size % @sizeOf(u32) != 0)
                return error.InvalidPreflightShape;
            try bytes.appendNTimes(
                allocator,
                0,
                shape.hash_size / @sizeOf(u32),
            );
        },
    }
}

fn validWire(allocator: std.mem.Allocator, shape: Shape) ![]u8 {
    var bytes: std.ArrayList(u8) = .{};
    errdefer bytes.deinit(allocator);
    try appendConfig(allocator, &bytes, shape);

    try appendVarint(allocator, &bytes, TREE_COUNT);
    for (0..TREE_COUNT) |_| try appendZeroHash(allocator, &bytes, shape);

    try appendSamples(allocator, &bytes, shape);

    try appendVarint(allocator, &bytes, TREE_COUNT);
    for (0..TREE_COUNT) |_| try appendVarint(allocator, &bytes, 0);

    try appendVarint(allocator, &bytes, TREE_COUNT);
    for (shape.tree_columns) |column_count| {
        try appendVarint(allocator, &bytes, column_count);
        for (0..column_count) |_| {
            try appendVarint(allocator, &bytes, 0);
        }
    }

    try appendVarint(allocator, &bytes, 0); // proof of work
    try appendVarint(allocator, &bytes, 0); // first FRI witness
    try appendVarint(allocator, &bytes, 0); // first FRI Merkle witness
    try appendZeroHash(allocator, &bytes, shape);
    try appendVarint(allocator, &bytes, 0); // no inner layers for max log 1
    try appendVarint(allocator, &bytes, 1);
    try appendZeroQm31(allocator, &bytes);
    return bytes.toOwnedSlice(allocator);
}

fn appendSamples(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    shape: Shape,
) !void {
    return appendSamplesWithWidths(allocator, bytes, shape, TEST_SAMPLE_WIDTHS);
}

fn appendSamplesWithWidths(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    shape: Shape,
    widths: [TREE_COUNT]u32,
) !void {
    try appendVarint(allocator, bytes, TREE_COUNT);
    for (shape.tree_columns, widths) |column_count, width| {
        try appendVarint(allocator, bytes, column_count);
        for (0..column_count) |_| {
            try appendVarint(allocator, bytes, width);
            for (0..width) |_| try appendZeroQm31(allocator, bytes);
        }
    }
}

test "proof preflight accepts a complete bounded wire without allocation" {
    const shape = testShape();
    const raw = try validWire(std.testing.allocator, shape);
    defer std.testing.allocator.free(raw);
    try validate(raw, shape);
}

test "proof preflight diagnoses the first exact shape mismatch" {
    const allocator = std.testing.allocator;
    const shape = testShape();
    var raw: std.ArrayList(u8) = .{};
    defer raw.deinit(allocator);
    try appendConfig(allocator, &raw, shape);
    try appendVarint(allocator, &raw, TREE_COUNT);
    try raw.appendNTimes(allocator, 0, TREE_COUNT * shape.hash_size);
    try appendVarint(allocator, &raw, TREE_COUNT);
    const mismatch_offset = raw.items.len;
    const actual = shape.tree_columns[0] + 1;
    try appendVarint(allocator, &raw, actual);

    var diagnostic: ?Diagnostic = null;
    try std.testing.expectError(
        error.InvalidProofShape,
        validateWithDiagnostic(raw.items, shape, &diagnostic),
    );
    const mismatch = diagnostic orelse return error.MissingDiagnostic;
    try std.testing.expectEqual(
        DiagnosticStage.sampled_column_count,
        mismatch.stage,
    );
    try std.testing.expectEqual(@as(?u32, 0), mismatch.tree);
    try std.testing.expectEqual(@as(?u32, null), mismatch.index);
    try std.testing.expectEqual(mismatch_offset, mismatch.offset);
    try std.testing.expectEqual(@as(usize, actual), mismatch.actual);
    try std.testing.expectEqual(
        @as(usize, shape.tree_columns[0]),
        mismatch.expected,
    );
    try std.testing.expectError(error.InvalidProofShape, validate(raw.items, shape));
}

test "proof preflight parses canonical M31-word hashes without allocation" {
    var shape = testShape();
    shape.hash_encoding = .canonical_m31_words;
    const raw = try validWire(std.testing.allocator, shape);
    defer std.testing.allocator.free(raw);
    try validate(raw, shape);

    var noncanonical: std.ArrayList(u8) = .{};
    defer noncanonical.deinit(std.testing.allocator);
    try appendConfig(std.testing.allocator, &noncanonical, shape);
    try appendVarint(std.testing.allocator, &noncanonical, TREE_COUNT);
    try appendVarint(std.testing.allocator, &noncanonical, M31_MODULUS);
    try std.testing.expectError(
        error.NonCanonicalM31,
        validate(noncanonical.items, shape),
    );

    shape.hash_size -= 1;
    try std.testing.expectError(
        error.InvalidPreflightShape,
        validate(raw, shape),
    );
}

test "proof preflight bounds sample widths without assuming exact AIR masks" {
    const allocator = std.testing.allocator;
    const shape = testShape();

    var accepted: std.ArrayList(u8) = .{};
    defer accepted.deinit(allocator);
    try appendConfig(allocator, &accepted, shape);
    try appendVarint(allocator, &accepted, TREE_COUNT);
    try accepted.appendNTimes(allocator, 0, TREE_COUNT * shape.hash_size);
    try appendSamplesWithWidths(allocator, &accepted, shape, .{ 2, 2, 1, 1 });
    const valid_tail = try validWire(allocator, shape);
    defer allocator.free(valid_tail);

    var prefix_cursor = Cursor{ .bytes = valid_tail };
    try expectConfig(&prefix_cursor, shape.config);
    try expectCount(&prefix_cursor, TREE_COUNT);
    try prefix_cursor.skip(TREE_COUNT * shape.hash_size);
    try expectCount(&prefix_cursor, TREE_COUNT);
    for (shape.tree_columns, TEST_SAMPLE_WIDTHS) |column_count, width| {
        try expectCount(&prefix_cursor, column_count);
        for (0..column_count) |_| {
            try expectCount(&prefix_cursor, width);
            try prefix_cursor.skip(width * 4);
        }
    }
    try accepted.appendSlice(allocator, valid_tail[prefix_cursor.position..]);
    try validate(accepted.items, shape);

    var excessive: std.ArrayList(u8) = .{};
    defer excessive.deinit(allocator);
    try appendConfig(allocator, &excessive, shape);
    try appendVarint(allocator, &excessive, TREE_COUNT);
    try excessive.appendNTimes(allocator, 0, TREE_COUNT * shape.hash_size);
    try appendVarint(allocator, &excessive, TREE_COUNT);
    try appendVarint(allocator, &excessive, shape.tree_columns[0]);
    try appendVarint(allocator, &excessive, shape.sample_width_limits[0] + 1);
    try std.testing.expectError(
        error.ProofResourceLimitExceeded,
        validate(excessive.items, shape),
    );
}

test "proof preflight admits an authenticated six-point main mask and rejects seven" {
    const allocator = std.testing.allocator;
    var shape = testShape();
    shape.sample_width_limits = .{ 2, 6, 2, 1 };

    var accepted: std.ArrayList(u8) = .{};
    defer accepted.deinit(allocator);
    try appendConfig(allocator, &accepted, shape);
    try appendVarint(allocator, &accepted, TREE_COUNT);
    try accepted.appendNTimes(allocator, 0, TREE_COUNT * shape.hash_size);
    try appendSamplesWithWidths(allocator, &accepted, shape, .{ 1, 6, 2, 1 });
    const valid_tail = try validWire(allocator, shape);
    defer allocator.free(valid_tail);

    var prefix_cursor = Cursor{ .bytes = valid_tail };
    try expectConfig(&prefix_cursor, shape.config);
    try expectCount(&prefix_cursor, TREE_COUNT);
    try prefix_cursor.skip(TREE_COUNT * shape.hash_size);
    try expectCount(&prefix_cursor, TREE_COUNT);
    for (shape.tree_columns, TEST_SAMPLE_WIDTHS) |column_count, width| {
        try expectCount(&prefix_cursor, column_count);
        for (0..column_count) |_| {
            try expectCount(&prefix_cursor, width);
            try prefix_cursor.skip(width * 4);
        }
    }
    try accepted.appendSlice(allocator, valid_tail[prefix_cursor.position..]);
    try validate(accepted.items, shape);

    var excessive: std.ArrayList(u8) = .{};
    defer excessive.deinit(allocator);
    try appendConfig(allocator, &excessive, shape);
    try appendVarint(allocator, &excessive, TREE_COUNT);
    try excessive.appendNTimes(allocator, 0, TREE_COUNT * shape.hash_size);
    try appendVarint(allocator, &excessive, TREE_COUNT);
    try appendVarint(allocator, &excessive, shape.tree_columns[0]);
    try appendVarint(allocator, &excessive, 1);
    try appendZeroQm31(allocator, &excessive);
    try appendVarint(allocator, &excessive, shape.tree_columns[1]);
    try appendVarint(allocator, &excessive, shape.sample_width_limits[1] + 1);
    try std.testing.expectError(
        error.ProofResourceLimitExceeded,
        validate(excessive.items, shape),
    );

    shape.sample_width_limits[1] = 0;
    try std.testing.expectError(
        error.InvalidPreflightShape,
        validate(accepted.items, shape),
    );
}

test "proof preflight V1 sample-width defaults remain unchanged" {
    try std.testing.expectEqual(
        DEFAULT_SAMPLE_WIDTH_LIMITS,
        testShape().sample_width_limits,
    );
}

test "proof preflight rejects shallow and nested length bombs" {
    const allocator = std.testing.allocator;
    const shape = testShape();

    var commitments: std.ArrayList(u8) = .{};
    defer commitments.deinit(allocator);
    try appendConfig(allocator, &commitments, shape);
    try appendVarint(allocator, &commitments, 1 << 32);
    try std.testing.expectError(
        error.InvalidProofShape,
        validate(commitments.items, shape),
    );

    var sampled: std.ArrayList(u8) = .{};
    defer sampled.deinit(allocator);
    try appendConfig(allocator, &sampled, shape);
    try appendVarint(allocator, &sampled, TREE_COUNT);
    try sampled.appendNTimes(allocator, 0, TREE_COUNT * shape.hash_size);
    try appendVarint(allocator, &sampled, TREE_COUNT);
    try appendVarint(allocator, &sampled, 1 << 32);
    try std.testing.expectError(error.InvalidProofShape, validate(sampled.items, shape));

    var decommitment: std.ArrayList(u8) = .{};
    defer decommitment.deinit(allocator);
    try appendConfig(allocator, &decommitment, shape);
    try appendVarint(allocator, &decommitment, TREE_COUNT);
    try decommitment.appendNTimes(allocator, 0, TREE_COUNT * shape.hash_size);
    try appendSamples(allocator, &decommitment, shape);
    try appendVarint(allocator, &decommitment, TREE_COUNT);
    try appendVarint(allocator, &decommitment, 1 << 32);
    try std.testing.expectError(
        error.ProofResourceLimitExceeded,
        validate(decommitment.items, shape),
    );
}

test "proof preflight rejects every truncation and trailing bytes" {
    const allocator = std.testing.allocator;
    const shape = testShape();
    const raw = try validWire(allocator, shape);
    defer allocator.free(raw);

    for (0..raw.len) |end| {
        if (validate(raw[0..end], shape)) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    const extended = try allocator.alloc(u8, raw.len + 1);
    defer allocator.free(extended);
    @memcpy(extended[0..raw.len], raw);
    extended[raw.len] = 0;
    try std.testing.expectError(error.TrailingProofBytes, validate(extended, shape));
}

test "proof preflight rejects deep layer bombs and noncanonical varints" {
    const allocator = std.testing.allocator;
    const shape = testShape();
    const raw = try validWire(allocator, shape);
    defer allocator.free(raw);

    var cursor = Cursor{ .bytes = &.{ 0x80, 0x00 } };
    try std.testing.expectError(error.NonCanonicalVarint, cursor.readVarint());

    var bomb = try allocator.dupe(u8, raw);
    defer allocator.free(bomb);
    // The inner-layer and last-coefficient counts are adjacent to the final
    // four one-byte zero coefficients in this fixture.
    const inner_count_index = bomb.len - 6;
    bomb[inner_count_index] = 2;
    try std.testing.expectError(error.InvalidProofShape, validate(bomb, shape));

    @memcpy(bomb, raw);
    const count_index = bomb.len - 5;
    bomb[count_index] = 2;
    try std.testing.expectError(error.InvalidProofShape, validate(bomb, shape));
}
