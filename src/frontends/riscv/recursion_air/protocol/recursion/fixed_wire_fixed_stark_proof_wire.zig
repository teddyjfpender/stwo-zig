//! Internal fixed wire authority shard; use fixed_wire.zig publicly.

const dependency_0 = @import("fixed_wire_fri_layer_wire.zig");

const ByteReader = dependency_0.ByteReader;
const ByteWriter = dependency_0.ByteWriter;
const DIGEST_BYTES = dependency_0.DIGEST_BYTES;
const Error = dependency_0.Error;
const FriLayerWire = dependency_0.FriLayerWire;
const M31_MODULUS = dependency_0.M31_MODULUS;
const M31_WORD_BYTES = dependency_0.M31_WORD_BYTES;
const MerklePathWire = dependency_0.MerklePathWire;
const QM31_BYTES = dependency_0.QM31_BYTES;
const Qm31Wire = dependency_0.Qm31Wire;
const U64_BYTES = dependency_0.U64_BYTES;
const channel = dependency_0.channel;
const checkedAdd = dependency_0.checkedAdd;
const checkedMul = dependency_0.checkedMul;
const fixed_profile = dependency_0.fixed_profile;
const friLayerBytes = dependency_0.friLayerBytes;
const isZeroQm31 = dependency_0.isZeroQm31;
const merklePathBytes = dependency_0.merklePathBytes;
const preflightPath = dependency_0.preflightPath;
const protocol = dependency_0.protocol;
const readPath = dependency_0.readPath;
const slicesOverlap = dependency_0.slicesOverlap;
const std = dependency_0.std;
const validateDigest = dependency_0.validateDigest;
const validateM31 = dependency_0.validateM31;
const validateQm31 = dependency_0.validateQm31;
const writePath = dependency_0.writePath;

/// All dimensions of one fixed proof representation.  These values are
/// comptime parameters of `FixedStarkProofWire`; they never appear as
/// proof-selected length prefixes.
pub const Dimensions = struct {
    commitment_count: usize,
    claimed_sum_count: usize,
    sampled_value_count: usize,
    queried_value_count: usize,
    trace_path_count: usize,
    fri_layer_count: usize,
    query_count: usize,
    maximum_fold_width: usize,
    last_layer_coefficient_count: usize,
    maximum_merkle_depth: usize,

    pub fn validate(comptime self: Dimensions) void {
        if (self.commitment_count == 0 or
            self.claimed_sum_count == 0 or
            self.sampled_value_count == 0 or
            self.queried_value_count == 0 or
            self.trace_path_count == 0 or
            self.fri_layer_count == 0 or
            self.query_count == 0 or
            self.maximum_fold_width == 0 or
            self.last_layer_coefficient_count == 0 or
            self.maximum_merkle_depth == 0)
        {
            @compileError("fixed recursion wire dimensions must be nonzero");
        }
        if ((self.maximum_fold_width & (self.maximum_fold_width - 1)) != 0)
            @compileError("maximum FRI fold width must be a power of two");
        if (self.maximum_fold_width > (@as(usize, 1) << 4))
            @compileError("fixed recursion wire exceeds the V1 FRI fold bound");
        if (self.maximum_merkle_depth > fixed_profile.MAX_DOMAIN_LOG)
            @compileError("fixed recursion wire exceeds the V1 Merkle-depth bound");
    }
};

/// Produces the exact fixed proof type selected by `dimensions`.
///
/// Large arrays are intentionally inline.  Production callers allocate the
/// value in an arena or dedicated owned buffer; the type itself contains no
/// pointers, slices, optionals, allocator state, or host-sized wire integers.
pub fn FixedStarkProofWire(comptime dimensions: Dimensions) type {
    dimensions.validate();
    return struct {
        commitments: [dimensions.commitment_count]channel.Digest,
        claimed_sums: [dimensions.claimed_sum_count]Qm31Wire,
        sampled_values: [dimensions.sampled_value_count]Qm31Wire,
        queried_values: [dimensions.queried_value_count]u32,
        trace_paths: [dimensions.trace_path_count]MerklePathWire(
            dimensions.maximum_merkle_depth,
        ),
        fri_layers: [dimensions.fri_layer_count]FriLayerWire(
            dimensions.query_count,
            dimensions.maximum_fold_width,
            dimensions.maximum_merkle_depth,
        ),
        last_layer_coefficients: [dimensions.last_layer_coefficient_count]Qm31Wire,
        interaction_pow: u64,
        pcs_pow: u64,

        const Self = @This();
        pub const wire_dimensions = dimensions;
        pub const serialized_byte_count = serializedByteCount(dimensions);

        /// Checks the comptime wire dimensions and every active/padded slot
        /// against one already authenticated profile shape.
        pub fn validateAgainstShape(
            self: *const Self,
            shape: fixed_profile.ProofShapeV1,
        ) Error!void {
            try shape.validate();
            try validateDimensionsAgainstShape(dimensions, shape);
            if (shape.proof_wire_bytes != serialized_byte_count)
                return error.WireByteCountMismatch;

            for (self.commitments) |commitment| try validateDigest(commitment);
            for (self.claimed_sums) |value| try validateQm31(value);
            for (self.sampled_values) |value| try validateQm31(value);
            for (self.queried_values) |value| try validateM31(value);
            for (self.last_layer_coefficients) |value| try validateQm31(value);

            for (shape.tree_heights, 0..) |tree_height, tree| {
                const start = tree * dimensions.query_count;
                for (self.trace_paths[start..][0..dimensions.query_count]) |*path| {
                    try path.validate(tree_height);
                }
            }
            for (&self.fri_layers, shape.fri.active()) |*layer, round| {
                try layer.validate(round);
            }
        }

        /// Writes the canonical little-endian payload after completing every
        /// fallible check.  An error therefore leaves `destination` untouched.
        pub fn encodeInto(
            self: *const Self,
            destination: []u8,
            shape: fixed_profile.ProofShapeV1,
        ) Error!void {
            try validateShapeAndLength(dimensions, shape, destination.len);
            if (slicesOverlap(std.mem.asBytes(self), destination))
                return error.AliasedBuffer;
            try self.validateAgainstShape(shape);

            var writer = ByteWriter.init(destination);
            for (self.commitments) |value| writer.writeDigest(value);
            for (self.claimed_sums) |value| writer.writeQm31(value);
            for (self.sampled_values) |value| writer.writeQm31(value);
            for (self.queried_values) |value| writer.writeU32(value);
            for (self.trace_paths) |path| writePath(
                dimensions.maximum_merkle_depth,
                &writer,
                path,
            );
            for (self.fri_layers) |layer| {
                writer.writeU32(layer.active_width);
                writer.writeDigest(layer.commitment);
                for (layer.queries) |query| {
                    for (query.values) |value| writer.writeQm31(value);
                    writePath(
                        dimensions.maximum_merkle_depth,
                        &writer,
                        query.path,
                    );
                }
            }
            for (self.last_layer_coefficients) |value| writer.writeQm31(value);
            writer.writeU64(self.interaction_pow);
            writer.writeU64(self.pcs_pow);
            std.debug.assert(writer.done());
        }

        /// Decodes only after a complete read-only preflight of the source.
        /// The destination is published in one infallible second pass.
        pub fn decodeInto(
            destination: *Self,
            encoded: []const u8,
            shape: fixed_profile.ProofShapeV1,
        ) Error!void {
            try validateShapeAndLength(dimensions, shape, encoded.len);
            if (slicesOverlap(std.mem.asBytes(destination), encoded))
                return error.AliasedBuffer;
            try preflightEncoded(dimensions, encoded, shape);

            @memset(std.mem.asBytes(destination), 0);
            var reader = ByteReader.init(encoded);
            for (&destination.commitments) |*value| value.* = reader.readDigest();
            for (&destination.claimed_sums) |*value| value.* = reader.readQm31();
            for (&destination.sampled_values) |*value| value.* = reader.readQm31();
            for (&destination.queried_values) |*value| value.* = reader.readU32();
            for (&destination.trace_paths) |*path| readPath(
                dimensions.maximum_merkle_depth,
                &reader,
                path,
            );
            for (&destination.fri_layers) |*layer| {
                layer.active_width = reader.readU32();
                layer.commitment = reader.readDigest();
                for (&layer.queries) |*query| {
                    for (&query.values) |*value| value.* = reader.readQm31();
                    readPath(
                        dimensions.maximum_merkle_depth,
                        &reader,
                        &query.path,
                    );
                }
            }
            for (&destination.last_layer_coefficients) |*value| {
                value.* = reader.readQm31();
            }
            destination.interaction_pow = reader.readU64();
            destination.pcs_pow = reader.readU64();
            std.debug.assert(reader.done());
            destination.validateAgainstShape(shape) catch unreachable;
        }
    };
}

pub fn validateShapeAndLength(
    dimensions: Dimensions,
    shape: fixed_profile.ProofShapeV1,
    byte_count: usize,
) Error!void {
    try shape.validate();
    try validateDimensionsAgainstShape(dimensions, shape);
    const expected = serializedByteCountRuntime(dimensions) catch
        return error.ArithmeticOverflow;
    if (shape.proof_wire_bytes != expected)
        return error.WireByteCountMismatch;
    if (byte_count != expected) return error.ByteLengthMismatch;
}

pub fn preflightEncoded(
    dimensions: Dimensions,
    encoded: []const u8,
    shape: fixed_profile.ProofShapeV1,
) Error!void {
    var reader = ByteReader.init(encoded);
    var index: usize = 0;
    while (index < dimensions.commitment_count) : (index += 1)
        try validateDigest(reader.readDigest());
    index = 0;
    while (index < dimensions.claimed_sum_count) : (index += 1)
        try validateQm31(reader.readQm31());
    index = 0;
    while (index < dimensions.sampled_value_count) : (index += 1)
        try validateQm31(reader.readQm31());
    index = 0;
    while (index < dimensions.queried_value_count) : (index += 1)
        try validateM31(reader.readU32());

    for (shape.tree_heights) |expected_depth| {
        var query: usize = 0;
        while (query < dimensions.query_count) : (query += 1) {
            try preflightPath(
                dimensions.maximum_merkle_depth,
                &reader,
                expected_depth,
                false,
            );
        }
    }
    for (shape.fri.active()) |round| {
        const active_width = reader.readU32();
        if (active_width != round.fold_width or
            active_width > dimensions.maximum_fold_width)
        {
            return error.FriLayerWidthMismatch;
        }
        try validateDigest(reader.readDigest());
        var query: usize = 0;
        while (query < dimensions.query_count) : (query += 1) {
            var value_index: usize = 0;
            while (value_index < dimensions.maximum_fold_width) : (value_index += 1) {
                const value = reader.readQm31();
                try validateQm31(value);
                if (value_index >= active_width and !isZeroQm31(value))
                    return error.NonZeroFriValuePadding;
            }
            try preflightPath(
                dimensions.maximum_merkle_depth,
                &reader,
                round.authentication_path_depth,
                true,
            );
        }
    }
    index = 0;
    while (index < dimensions.last_layer_coefficient_count) : (index += 1)
        try validateQm31(reader.readQm31());
    _ = reader.readU64();
    _ = reader.readU64();
    std.debug.assert(reader.done());
}

pub fn validateDimensionsAgainstShape(
    dimensions: Dimensions,
    shape: fixed_profile.ProofShapeV1,
) Error!void {
    if (dimensions.commitment_count != fixed_profile.TREE_COUNT or
        dimensions.claimed_sum_count != shape.claimed_sum_count or
        dimensions.sampled_value_count != shape.sampled_value_count or
        dimensions.fri_layer_count != shape.fri.count or
        dimensions.query_count != protocol.FRI_QUERY_COUNT or
        dimensions.last_layer_coefficient_count !=
            shape.fri.last_layer_coefficient_count)
    {
        return error.WireCountMismatch;
    }
    const expected_query_values = try shape.queriedValueCount();
    const expected_trace_paths = try shape.tracePathCount();
    if (dimensions.queried_value_count != expected_query_values or
        dimensions.trace_path_count != expected_trace_paths)
    {
        return error.WireCountMismatch;
    }

    var maximum_fold_width: u32 = 0;
    var maximum_merkle_depth: u32 = 0;
    for (shape.tree_heights) |height| {
        maximum_merkle_depth = @max(maximum_merkle_depth, height);
    }
    for (shape.fri.active()) |round| {
        maximum_fold_width = @max(maximum_fold_width, round.fold_width);
        maximum_merkle_depth = @max(
            maximum_merkle_depth,
            round.authentication_path_depth,
        );
    }
    if (dimensions.maximum_fold_width != maximum_fold_width or
        dimensions.maximum_merkle_depth != maximum_merkle_depth)
    {
        return error.WireCountMismatch;
    }
}

pub fn serializedByteCount(comptime dimensions: Dimensions) usize {
    dimensions.validate();
    return serializedByteCountRuntime(dimensions) catch
        @panic("fixed recursion wire byte count overflows usize");
}

/// Returns the exact fixed-width encoding size for runtime-selected design
/// dimensions.  This does not confer protocol authority: production wire
/// types still require comptime dimensions and an authenticated shape.
pub fn serializedByteCountRuntime(dimensions: Dimensions) Error!usize {
    try validateRuntimeDimensions(dimensions);
    var bytes: usize = 0;
    bytes = try checkedAdd(
        bytes,
        try checkedMul(dimensions.commitment_count, DIGEST_BYTES),
    );
    bytes = try checkedAdd(
        bytes,
        try checkedMul(dimensions.claimed_sum_count, QM31_BYTES),
    );
    bytes = try checkedAdd(
        bytes,
        try checkedMul(dimensions.sampled_value_count, QM31_BYTES),
    );
    bytes = try checkedAdd(
        bytes,
        try checkedMul(dimensions.queried_value_count, M31_WORD_BYTES),
    );
    const path_bytes = try merklePathBytes(dimensions.maximum_merkle_depth);
    bytes = try checkedAdd(
        bytes,
        try checkedMul(dimensions.trace_path_count, path_bytes),
    );
    const layer_bytes = try friLayerBytes(
        dimensions.query_count,
        dimensions.maximum_fold_width,
        dimensions.maximum_merkle_depth,
    );
    bytes = try checkedAdd(
        bytes,
        try checkedMul(dimensions.fri_layer_count, layer_bytes),
    );
    bytes = try checkedAdd(
        bytes,
        try checkedMul(dimensions.last_layer_coefficient_count, QM31_BYTES),
    );
    bytes = try checkedAdd(bytes, 2 * U64_BYTES);
    return bytes;
}

pub fn validateRuntimeDimensions(dimensions: Dimensions) Error!void {
    if (dimensions.commitment_count == 0 or
        dimensions.claimed_sum_count == 0 or
        dimensions.sampled_value_count == 0 or
        dimensions.queried_value_count == 0 or
        dimensions.trace_path_count == 0 or
        dimensions.fri_layer_count == 0 or
        dimensions.query_count == 0 or
        dimensions.maximum_fold_width == 0 or
        dimensions.last_layer_coefficient_count == 0 or
        dimensions.maximum_merkle_depth == 0)
    {
        return error.InvalidDimensions;
    }
    if (!std.math.isPowerOfTwo(dimensions.maximum_fold_width) or
        dimensions.maximum_fold_width > (@as(usize, 1) << 4) or
        dimensions.maximum_merkle_depth > fixed_profile.MAX_DOMAIN_LOG)
    {
        return error.InvalidDimensions;
    }
}

pub const TEST_DIMENSIONS = Dimensions{
    .commitment_count = fixed_profile.TREE_COUNT,
    .claimed_sum_count = 36,
    .sampled_value_count = 2_100,
    .queried_value_count = 2_000 * protocol.FRI_QUERY_COUNT,
    .trace_path_count = fixed_profile.TREE_COUNT * protocol.FRI_QUERY_COUNT,
    .fri_layer_count = 6,
    .query_count = protocol.FRI_QUERY_COUNT,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 25,
};
pub const TestWire = FixedStarkProofWire(TEST_DIMENSIONS);

pub fn testDigest(label: []const u8) channel.Digest {
    return channel.hashBytes(label, 0x4657); // "FW"
}

pub fn testShape() fixed_profile.ProofShapeV1 {
    return .{
        .air_program_id = testDigest("air-program"),
        .preprocessing_id = testDigest("preprocessing"),
        .table_layout_id = testDigest("ordered-table-layout"),
        .table_count = 2_000,
        .claimed_sum_count = 36,
        .sampled_value_count = 2_100,
        .preprocessed_column_count = 128,
        .tree_column_counts = .{ 128, 1_500, 364, 8 },
        .tree_heights = .{ 25, 25, 25, 25 },
        .column_log_degree = 24,
        .proof_wire_bytes = serializedByteCount(TEST_DIMENSIONS),
        .fri = fixed_profile.FriSchedule.init(
            24,
            protocol.PCS_CONFIG.fri_config,
        ) catch unreachable,
    };
}

pub fn initializeTestWire(wire: *TestWire, shape: fixed_profile.ProofShapeV1) void {
    @memset(std.mem.asBytes(wire), 0);
    wire.commitments[0] = testDigest("tree-zero");
    wire.claimed_sums[0] = .{ 1, 2, 3, 4 };
    wire.sampled_values[0] = .{ 5, 6, 7, 8 };
    wire.queried_values[0] = 9;
    wire.last_layer_coefficients[0] = .{ 10, 11, 12, 13 };
    wire.interaction_pow = 0x0102_0304_0506_0708;
    wire.pcs_pow = 0x1112_1314_1516_1718;
    for (shape.tree_heights, 0..) |height, tree| {
        const start = tree * TEST_DIMENSIONS.query_count;
        for (wire.trace_paths[start..][0..TEST_DIMENSIONS.query_count]) |*path| {
            path.active_depth = height;
        }
    }
    for (&wire.fri_layers, shape.fri.active()) |*layer, round| {
        layer.active_width = round.fold_width;
        for (&layer.queries) |*query| {
            query.path.active_depth = round.authentication_path_depth;
        }
    }
    wire.fri_layers[0].queries[0].values[0] = .{ 14, 15, 16, 17 };
}

test "recursion fixed wire: exact byte count is independent of host struct padding" {
    const bytes = serializedByteCount(TEST_DIMENSIONS);
    try std.testing.expectEqual(@as(usize, 3_426_720), bytes);
    try std.testing.expect(@sizeOf(FixedStarkProofWire(TEST_DIMENSIONS)) >= bytes);
}

test "recursion fixed wire: authenticated shape admits exactly one active geometry" {
    const wire = try std.testing.allocator.create(TestWire);
    defer std.testing.allocator.destroy(wire);

    const shape = testShape();
    initializeTestWire(wire, shape);
    try wire.validateAgainstShape(shape);

    wire.fri_layers[0].active_width = 8;
    try std.testing.expectError(
        error.FriLayerWidthMismatch,
        wire.validateAgainstShape(shape),
    );
    wire.fri_layers[0].active_width = shape.fri.rounds[0].fold_width;

    const first_padding = shape.fri.rounds[0].authentication_path_depth;
    wire.fri_layers[0].queries[0].path.siblings[first_padding][0] = 1;
    try std.testing.expectError(
        error.NonZeroMerklePadding,
        wire.validateAgainstShape(shape),
    );
    wire.fri_layers[0].queries[0].path.siblings[first_padding][0] = 0;

    wire.queried_values[0] = M31_MODULUS;
    try std.testing.expectError(
        error.NonCanonicalM31,
        wire.validateAgainstShape(shape),
    );
}

test "recursion fixed wire: dimension and byte substitutions reject" {
    const shape = testShape();
    var wrong = TEST_DIMENSIONS;
    wrong.sampled_value_count -= 1;
    try std.testing.expectError(
        error.WireCountMismatch,
        validateDimensionsAgainstShape(wrong, shape),
    );

    wrong = TEST_DIMENSIONS;
    wrong.maximum_merkle_depth -= 1;
    try std.testing.expectError(
        error.WireCountMismatch,
        validateDimensionsAgainstShape(wrong, shape),
    );

    var changed_shape = shape;
    changed_shape.proof_wire_bytes += 1;
    const wire = try std.testing.allocator.create(TestWire);
    defer std.testing.allocator.destroy(wire);
    @memset(std.mem.asBytes(wire), 0);
    try std.testing.expectError(
        error.WireByteCountMismatch,
        wire.validateAgainstShape(changed_shape),
    );
}

test "recursion fixed wire: canonical codec round trips without struct ABI" {
    const allocator = std.testing.allocator;
    const shape = testShape();
    const wire = try allocator.create(TestWire);
    defer allocator.destroy(wire);
    initializeTestWire(wire, shape);

    const encoded = try allocator.alloc(u8, TestWire.serialized_byte_count);
    defer allocator.free(encoded);
    @memset(encoded, 0xa5);
    try wire.encodeInto(encoded, shape);

    const decoded = try allocator.create(TestWire);
    defer allocator.destroy(decoded);
    @memset(std.mem.asBytes(decoded), 0xcd);
    try TestWire.decodeInto(decoded, encoded, shape);
    try std.testing.expectEqualSlices(u8, std.mem.asBytes(wire), std.mem.asBytes(decoded));

    const reencoded = try allocator.alloc(u8, TestWire.serialized_byte_count);
    defer allocator.free(reencoded);
    try decoded.encodeInto(reencoded, shape);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
}

test "recursion fixed wire: decode is failure atomic and rejects aliases" {
    const allocator = std.testing.allocator;
    const shape = testShape();
    const wire = try allocator.create(TestWire);
    defer allocator.destroy(wire);
    initializeTestWire(wire, shape);
    const encoded = try allocator.alloc(u8, TestWire.serialized_byte_count);
    defer allocator.free(encoded);
    try wire.encodeInto(encoded, shape);

    const destination = try allocator.create(TestWire);
    defer allocator.destroy(destination);
    const destination_bytes = std.mem.asBytes(destination);

    const trace_path_offset = TEST_DIMENSIONS.commitment_count * DIGEST_BYTES +
        TEST_DIMENSIONS.claimed_sum_count * QM31_BYTES +
        TEST_DIMENSIONS.sampled_value_count * QM31_BYTES +
        TEST_DIMENSIONS.queried_value_count * M31_WORD_BYTES;
    const fri_layers_offset = trace_path_offset +
        TEST_DIMENSIONS.trace_path_count *
            (M31_WORD_BYTES + TEST_DIMENSIONS.maximum_merkle_depth * DIGEST_BYTES);
    const inactive_sibling_offset = fri_layers_offset +
        M31_WORD_BYTES + DIGEST_BYTES +
        TEST_DIMENSIONS.maximum_fold_width * QM31_BYTES +
        M31_WORD_BYTES + shape.fri.rounds[0].authentication_path_depth * DIGEST_BYTES;
    encoded[inactive_sibling_offset] = 1;
    @memset(destination_bytes, 0x7b);
    try std.testing.expectError(
        error.NonZeroMerklePadding,
        TestWire.decodeInto(destination, encoded, shape),
    );
    try std.testing.expect(std.mem.allEqual(u8, destination_bytes, 0x7b));
    encoded[inactive_sibling_offset] = 0;

    const queried_values_offset = TEST_DIMENSIONS.commitment_count * DIGEST_BYTES +
        TEST_DIMENSIONS.claimed_sum_count * QM31_BYTES +
        TEST_DIMENSIONS.sampled_value_count * QM31_BYTES;
    std.mem.writeInt(
        u32,
        encoded[queried_values_offset..][0..M31_WORD_BYTES],
        M31_MODULUS,
        .little,
    );
    try std.testing.expectError(
        error.NonCanonicalM31,
        TestWire.decodeInto(destination, encoded, shape),
    );
    try std.testing.expect(std.mem.allEqual(u8, destination_bytes, 0x7b));
    std.mem.writeInt(
        u32,
        encoded[queried_values_offset..][0..M31_WORD_BYTES],
        wire.queried_values[0],
        .little,
    );

    try std.testing.expectError(
        error.ByteLengthMismatch,
        TestWire.decodeInto(destination, encoded[0 .. encoded.len - 1], shape),
    );
    try std.testing.expect(std.mem.allEqual(u8, destination_bytes, 0x7b));

    try std.testing.expectError(
        error.AliasedBuffer,
        TestWire.decodeInto(
            destination,
            destination_bytes[0..TestWire.serialized_byte_count],
            shape,
        ),
    );
    try std.testing.expectError(
        error.AliasedBuffer,
        wire.encodeInto(
            std.mem.asBytes(wire)[0..TestWire.serialized_byte_count],
            shape,
        ),
    );
}
