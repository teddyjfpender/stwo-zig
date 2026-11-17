//! Exact wire fixtures and adversarial bounded proof-preflight cases.
const std = @import("std");
const schema = @import("proof_preflight.zig");
const cursor_owner = @import("proof_preflight_cursor.zig");
const DEFAULT_SAMPLE_WIDTH_LIMITS = schema.DEFAULT_SAMPLE_WIDTH_LIMITS;
const Shape = schema.Shape;
const ShapeFor = schema.ShapeFor;
const validateFor = schema.validateFor;
const DiagnosticStage = schema.DiagnosticStage;
const Diagnostic = schema.Diagnostic;
const validate = schema.validate;
const validateWithDiagnostic = schema.validateWithDiagnostic;
const Cursor = cursor_owner.Cursor;
const expectConfig = cursor_owner.expectConfig;
const expectCount = cursor_owner.expectCount;
const M31_MODULUS = cursor_owner.M31_MODULUS;
const TREE_COUNT: usize = schema.DEFAULT_SAMPLE_WIDTH_LIMITS.len;
const TEST_SAMPLE_WIDTHS = [TREE_COUNT]u32{ 1, 1, 2, 1 };

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

fn typedWire(comptime N: usize, allocator: std.mem.Allocator, shape: ShapeFor(N)) ![]u8 {
    var raw: std.ArrayList(u8) = .empty;
    errdefer raw.deinit(allocator);
    // Test framing has one first-layer fold, no inner layers and one last
    // coefficient. Typed production admission derives its real FRI count.
    for ([_]u64{ shape.config.pow_bits, shape.config.log_blowup_factor, shape.config.n_queries, shape.config.log_last_layer_degree_bound, shape.config.fold_step }) |value| try appendVarint(allocator, &raw, value);
    try raw.append(allocator, 0); // lifting log absent
    try appendVarint(allocator, &raw, N);
    try raw.appendNTimes(allocator, 0, N * shape.hash_size);
    try appendVarint(allocator, &raw, N);
    for (shape.tree_columns) |count| {
        try appendVarint(allocator, &raw, count);
        for (0..count) |_| {
            try appendVarint(allocator, &raw, 1);
            try appendZeroQm31(allocator, &raw);
        }
    }
    try appendVarint(allocator, &raw, N);
    for (0..N) |_| try appendVarint(allocator, &raw, 0);
    try appendVarint(allocator, &raw, N);
    for (shape.tree_columns) |count| {
        try appendVarint(allocator, &raw, count);
        for (0..count) |_| try appendVarint(allocator, &raw, 0);
    }
    for (0..3) |_| try appendVarint(allocator, &raw, 0); // PoW, first FRI witness, Merkle
    try raw.appendNTimes(allocator, 0, shape.hash_size);
    try appendVarint(allocator, &raw, 0); // inner layers
    try appendVarint(allocator, &raw, 1);
    try appendZeroQm31(allocator, &raw);
    return raw.toOwnedSlice(allocator);
}
fn typedTestShape() ShapeFor(8) {
    return .{ .config = testShape().config, .tree_columns = .{ 15, 1728, 8, 5, 174, 256, 128, 16 }, .sample_width_limits = .{ 1, 1, 1, 1, 1, 1, 2, 1 }, .max_column_log_size = 1, .hash_size = 32, .max_wire_bytes = 1 << 20 };
}
test "proof preflight typed eight-tree framing retains exact config lengths and allocation-free parser" {
    const shape = typedTestShape();
    const raw = try typedWire(8, std.testing.allocator, shape);
    defer std.testing.allocator.free(raw);
    // No allocator enters validateFor: the same accepted framing can be checked
    // while a deny-all allocator proves that a caller has no allocation budget.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, failing.allocator().alloc(u8, 1));
    try validateFor(8, raw, shape);
    var wrong = shape;
    wrong.tree_columns[5] += 1;
    try std.testing.expectError(error.InvalidProofShape, validateFor(8, raw, wrong));
    wrong = shape;
    wrong.config.n_queries += 1;
    try std.testing.expectError(error.InvalidProofConfig, validateFor(8, raw, wrong));
    wrong = shape;
    wrong.sample_width_limits[3] = 17;
    try std.testing.expectError(error.InvalidPreflightShape, validateFor(8, raw, wrong));
    try std.testing.expectError(error.EndOfStream, validateFor(8, raw[0 .. raw.len - 1], shape));
}
test "proof preflight typed eight-tree bombs and noncanonical varints reject before any decode allocation" {
    const shape = typedTestShape();
    var prefix: std.ArrayList(u8) = .empty;
    defer prefix.deinit(std.testing.allocator);
    try appendConfig(std.testing.allocator, &prefix, testShape());
    const count_at = prefix.items.len;
    try appendVarint(std.testing.allocator, &prefix, 7);
    try std.testing.expectError(error.InvalidProofShape, validateFor(8, prefix.items, shape));
    prefix.shrinkRetainingCapacity(count_at);
    try prefix.appendSlice(std.testing.allocator, &.{ 0x88, 0x00 }); // overlong 8
    try std.testing.expectError(error.NonCanonicalVarint, validateFor(8, prefix.items, shape));
    prefix.shrinkRetainingCapacity(count_at);
    try appendVarint(std.testing.allocator, &prefix, 8);
    try prefix.appendNTimes(std.testing.allocator, 0, 8 * 32);
    try appendVarint(std.testing.allocator, &prefix, 8);
    try appendVarint(std.testing.allocator, &prefix, shape.tree_columns[0]);
    try appendVarint(std.testing.allocator, &prefix, std.math.maxInt(u64)); // nested sample bomb
    try std.testing.expectError(error.ProofResourceLimitExceeded, validateFor(8, prefix.items, shape));
}
