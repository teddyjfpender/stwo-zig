const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const quotient_abi = @import("stwo_cuda_backend").abi.stages.quotient;
const column = @import("stwo_cuda_backend").runtime.column;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const pcs_types = @import("../pcs_hooks_types.zig");
const binding = @import("resident_sources.zig");
const types = @import("types.zig");

test "tree-relative sources lower to exact multi-arena addresses" {
    var topology = try testTopology();
    defer topology.deinit();
    var trees = testTrees();
    var bound = try binding.Bound.init(
        std.testing.allocator,
        topology,
        trees,
    );
    defer bound.deinit();
    try std.testing.expectEqual(@as(usize, 3), bound.columns.len);
    try std.testing.expectEqual(
        @as(u64, 0x1_0000),
        bound.descriptors[0].address,
    );
    try std.testing.expectEqual(
        @as(u64, 0x2_0000),
        bound.descriptors[1].address,
    );
    try std.testing.expectEqual(
        @as(u64, 0x2_0040),
        bound.descriptors[2].address,
    );
    try std.testing.expect(!std.mem.allEqual(u8, &bound.identity, 0));
    var session = FakeSession.init();
    const quotient = testQuotient();
    const prepared = try bound.prepareNumerator(
        &session,
        topology,
        quotient,
    );
    try std.testing.expectEqual(@as(u32, 2), prepared.group_count);
    try std.testing.expectEqual(@as(usize, 48), prepared.output_word_count);

    trees.storage[1].evaluations.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        binding.Bound.init(std.testing.allocator, topology, trees),
    );
}

fn testTopology() !types.Topology {
    const allocator = std.testing.allocator;
    const sources = try allocator.dupe(types.SourceDescriptor, &.{
        .{
            .tree_ordinal = 0,
            .local_column = 0,
            .global_column = 0,
            .compact = .{
                .offset_words = 0,
                .stride_words = 16,
                .log_size = 4,
            },
        },
        .{
            .tree_ordinal = 1,
            .local_column = 0,
            .global_column = 1,
            .compact = .{
                .offset_words = 0,
                .stride_words = 16,
                .log_size = 4,
            },
        },
        .{
            .tree_ordinal = 1,
            .local_column = 1,
            .global_column = 2,
            .compact = .{
                .offset_words = 16,
                .stride_words = 32,
                .log_size = 5,
            },
        },
    });
    errdefer allocator.free(sources);
    const spans = try allocator.dupe(types.TreeSpan, &.{
        .{
            .tree_ordinal = 0,
            .role = .preprocessed,
            .first_source = 0,
            .source_count = 1,
            .evaluation_words = 16,
        },
        .{
            .tree_ordinal = 1,
            .role = .main,
            .first_source = 1,
            .source_count = 2,
            .evaluation_words = 48,
        },
    });
    return .{
        .allocator = allocator,
        .prepared_terms = try allocator.dupe(
            quotient_abi.PreparedTermDescriptor,
            &.{
                .{ .sample_index = 0, .exponent = 0, .periodic = 0, .period_x = 0, .period_y = 0 },
                .{ .sample_index = 1, .exponent = 1, .periodic = 0, .period_x = 0, .period_y = 0 },
            },
        ),
        .group_offsets = try allocator.dupe(u32, &.{ 0, 1, 2 }),
        .group_term_indices = try allocator.dupe(u32, &.{ 0, 1 }),
        .batch_terms = try allocator.dupe(
            quotient_abi.BatchTermDescriptor,
            &.{
                .{ .source_index = 0, .term_index = 0, .source_log_size = 4 },
                .{ .source_index = 2, .term_index = 1, .source_log_size = 5 },
            },
        ),
        .sources = sources,
        .source_trees = spans,
        .group_log_sizes = try allocator.dupe(u32, &.{ 4, 5 }),
        .partial_log_sizes = try allocator.dupe(u32, &.{ 4, 5 }),
        .partial_offsets = try allocator.dupe(u64, &.{ 0, 16, 48 }),
        .sampled_value_count = 2,
        .source_evaluation_word_count = 64,
        .maximum_partial_rows = 32,
        .identity = [_]u8{9} ** 32,
    };
}

fn testQuotient() pcs_types.Quotient {
    return .{
        .challenge = slice(
            @import("stwo_cuda_backend").abi.field.SecureField,
            0x4_0000,
            1,
        ),
        .prepared_terms = slice(
            quotient_abi.PreparedTermDescriptor,
            0x4_1000,
            2,
        ),
        .group_offsets = words(0x4_2000, 3, 13),
        .group_term_indices = words(0x4_3000, 2, 13),
        .batch_terms = slice(
            quotient_abi.BatchTermDescriptor,
            0x4_4000,
            2,
        ),
        .source_descriptors = slice(
            quotient_abi.AddressedSourceDescriptor,
            0x4_5000,
            3,
        ),
        .group_log_sizes = words(0x4_6000, 2, 13),
        .partial_log_sizes = words(0x4_7000, 2, 13),
        .partial_offsets = slice(u64, 0x4_8000, 3),
        .term_points = undefined,
        .line_coefficients = undefined,
        .group_points = undefined,
        .first_linear_terms = undefined,
        .partial_coordinates = undefined,
        .result_coordinates = undefined,
    };
}

fn testTrees() pcs_types.TraceTrees {
    var storage: [pcs_types.max_trace_trees]pcs_types.CompactTree = undefined;
    storage[0] = tree(0, .preprocessed, 0, 1, words(0x1_0000, 16, 7));
    storage[1] = tree(1, .main, 1, 2, words(0x2_0000, 48, 11));
    return .{ .storage = storage, .len = 2 };
}

fn tree(
    ordinal: u32,
    role: proof_ir.CommitmentRole,
    first_column: u32,
    column_count: u32,
    evaluations: common.Words,
) pcs_types.CompactTree {
    const base = 0x3_0000 + ordinal * 0x1000;
    const metadata = words(base, 1, 5);
    const hashes = words(base + 0x100, 8, 5);
    const layers = words(base + 0x200, 4, 5);
    const root = words(base + 0x300, 8, 5);
    return .{
        .ordinal = ordinal,
        .role = role,
        .first_column = first_column,
        .column_count = column_count,
        .evaluation_log_rows = 5,
        .coefficients = metadata,
        .evaluations = evaluations,
        .column_log_sizes = metadata,
        .column_offsets = metadata,
        .merkle_hashes = hashes.cast(
            @import("stwo_cuda_backend").abi.field.Blake2sHash,
        ) catch unreachable,
        .merkle_layers = layers.cast(
            @import("stwo_cuda_backend").abi.field.MerkleLayerDescriptor,
        ) catch unreachable,
        .root = root.cast(
            @import("stwo_cuda_backend").abi.field.Blake2sHash,
        ) catch unreachable,
    };
}

fn words(address: usize, len: usize, generation: u64) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 19,
        .generation = generation,
    };
}

fn slice(
    comptime T: type,
    address: usize,
    len: usize,
) column.DeviceSlice(T) {
    return .{
        .address = address,
        .len = len,
        .owner = 19,
        .generation = 13,
    };
}

const FakeContext = struct {
    stream_storage: u8 = 0,
    stream: *anyopaque = undefined,
    active_stage: ?telemetry.Stage = .ingress,

    fn init() FakeContext {
        var result = FakeContext{};
        result.stream = &result.stream_storage;
        return result;
    }

    pub fn requireStage(self: *@This(), expected: telemetry.Stage) !void {
        if (self.active_stage != expected)
            return error.StageOrderViolation;
    }

    pub fn uploadSlice(
        self: *@This(),
        comptime T: type,
        destination: anytype,
        source: []const T,
    ) !void {
        try self.requireStage(.ingress);
        if (destination.owner != 19 or destination.len < source.len)
            return error.InvalidDeviceAddress;
    }
};

const FakeSession = struct {
    context: FakeContext,

    fn init() FakeSession {
        return .{ .context = FakeContext.init() };
    }
};
