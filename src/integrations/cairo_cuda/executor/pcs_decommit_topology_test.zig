const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("../../../backends/cuda/abi/field.zig");
const column = @import("../../../backends/cuda/runtime/column.zig");
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const compact = @import(
    "../../../frontends/cairo/compact_verifier_interchange.zig",
);
const composition = @import(
    "../../../frontends/cairo/witness/composition_bundle.zig",
);
const fixed_table = @import(
    "../../../frontends/cairo/witness/fixed_table_bundle.zig",
);
const semantic_authority = @import(
    "../../../frontends/cairo/proof_plan/semantic_authority.zig",
);
const shared_views = @import(
    "../../native_cuda/common/resident_views.zig",
);
const pcs_types = @import("pcs_hooks_types.zig");
const fixture = @import("resident_plan_test.zig");
const subject = @import("pcs_decommit_topology.zig");

test "SN2 decommit topology opens compact trace cohorts and all FRI trees" {
    const allocator = std.testing.allocator;
    var input = try sn2Inputs(allocator);
    defer input.deinit();
    var topology = try subject.derive(
        allocator,
        input.program,
        input.protocol,
    );
    defer topology.deinit();

    try std.testing.expectEqual(@as(usize, 4), topology.trace_openings.len);
    try std.testing.expectEqual(@as(usize, 5886), topology.column_log_sizes.len);
    try std.testing.expectEqual(@as(usize, 8), topology.fri_openings.len);
    try std.testing.expectEqual(@as(u32, 12), topology.tree_count);
    try std.testing.expectEqual(@as(usize, 70), topology.query_count);
    try std.testing.expectEqual(
        @as(usize, 2_077_800),
        topology.assembly_capacity_words,
    );
    try std.testing.expectEqual(@as(usize, 139), topology.trace_groups.len);
    try std.testing.expectEqual(@as(u32, 26), topology.query_log_size);
    try std.testing.expect(!std.mem.allEqual(u8, &topology.identity, 0));
    var expected_identity: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_identity,
        "73cd5e5e9b5a4d95f3060d7122e1ecb94f099c08169769c1a066f06ffd376e09",
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_identity,
        &topology.identity,
    );

    var column_cursor: usize = 0;
    for (topology.trace_openings, 0..) |opening, ordinal| {
        try std.testing.expectEqual(@as(u32, @intCast(ordinal)), opening.tree_index);
        const first_group: usize = opening.first_group;
        const end = first_group + opening.group_count;
        var first_column: u32 = 0;
        var evaluation_words: u64 = 0;
        for (topology.trace_groups[first_group..end]) |group| {
            try std.testing.expectEqual(opening.tree_index, group.tree_ordinal);
            try std.testing.expectEqual(first_column, group.first_column);
            first_column += group.column_count;
            evaluation_words += group.evaluation_words;
        }
        try std.testing.expectEqual(opening.column_count, first_column);
        const tree = input.program.commitments[ordinal];
        var expected_words: u64 = 0;
        for (input.program.trace_columns[tree.first_column .. tree.first_column + tree.column_count]) |trace_column| {
            expected_words += @as(u64, 1) << @intCast(
                trace_column.log_rows + input.protocol.log_blowup_factor,
            );
        }
        try std.testing.expectEqual(expected_words, evaluation_words);
        column_cursor += opening.column_count;
    }
    try std.testing.expectEqual(topology.column_log_sizes.len, column_cursor);
    for (topology.fri_openings, 0..) |opening, ordinal| {
        try std.testing.expectEqual(
            @as(u32, @intCast(4 + ordinal)),
            opening.tree_index,
        );
    }

    const runtime = testRuntime(topology, input.program);
    var upload_session = UploadSession{};
    try topology.uploadColumnLogs(
        &upload_session,
        runtime.decommit,
    );
    try std.testing.expectEqual(
        topology.trace_openings.len,
        upload_session.context.uploads,
    );
    Recorder.reset();
    try subject.normalizeWith(
        FakeDecommit,
        {},
        topology,
        runtime.decommit,
        runtime.assembly,
    );
    try subject.openAllWith(
        FakeDecommit,
        {},
        topology,
        runtime.trees,
        runtime.fri,
        runtime.decommit,
        runtime.assembly,
    );
    try std.testing.expectEqual(@as(usize, 1), Recorder.normalizes);
    try std.testing.expectEqual(topology.trace_openings.len, Recorder.trace_prepares);
    try std.testing.expectEqual(topology.trace_groups.len, Recorder.trace_packs);
    try std.testing.expectEqual(topology.trace_openings.len, Recorder.trace_assemblies);
    try std.testing.expectEqual(topology.fri_openings.len, Recorder.fri_prepares);
    try std.testing.expectEqual(topology.fri_openings.len, Recorder.fri_assemblies);

    std.debug.print(
        "SN2 decommit topology: trace_trees={} groups={} fri_trees={} " ++
            "query_log={} assembly_words={} identity={s}\n",
        .{
            topology.trace_openings.len,
            topology.trace_groups.len,
            topology.fri_openings.len,
            topology.query_log_size,
            topology.assembly_capacity_words,
            std.fmt.bytesToHex(topology.identity, .lower),
        },
    );
}

const UploadSession = struct {
    context: struct {
        uploads: usize = 0,

        pub fn uploadSlice(
            self: *@This(),
            comptime T: type,
            destination: column.DeviceSlice(T),
            source: []const T,
        ) !void {
            if (destination.len != source.len)
                return error.InvalidKernelDescriptor;
            self.uploads += 1;
        }
    } = .{},
};

const Recorder = struct {
    var normalizes: usize = 0;
    var trace_prepares: usize = 0;
    var trace_packs: usize = 0;
    var trace_assemblies: usize = 0;
    var fri_prepares: usize = 0;
    var fri_assemblies: usize = 0;

    fn reset() void {
        normalizes = 0;
        trace_prepares = 0;
        trace_packs = 0;
        trace_assemblies = 0;
        fri_prepares = 0;
        fri_assemblies = 0;
    }
};

const FakeDecommit = struct {
    pub fn normalizeQueries(
        _: anytype,
        _: common.Words,
        _: u32,
        _: u32,
        _: common.Words,
        _: common.Words,
        _: common.Words,
    ) !void {
        Recorder.normalizes += 1;
    }

    pub fn prepareTraceQueries(
        _: anytype,
        _: common.Words,
        _: common.Words,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: anytype,
    ) !void {
        Recorder.trace_prepares += 1;
    }

    pub fn packTraceGroup(
        _: anytype,
        _: u32,
        _: u32,
        _: u32,
        _: common.WordMatrix,
        _: common.Words,
        _: u32,
        _: common.Words,
        _: common.Words,
        _: common.Words,
    ) !void {
        Recorder.trace_packs += 1;
    }

    pub fn assembleTrace(
        _: anytype,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: anytype,
    ) !void {
        Recorder.trace_assemblies += 1;
    }

    pub fn prepareFriQueries(
        _: anytype,
        _: common.Words,
        _: common.Words,
        _: u32,
        _: u32,
        _: u32,
        _: anytype,
    ) !void {
        Recorder.fri_prepares += 1;
    }

    pub fn assembleFri(
        _: anytype,
        _: u32,
        _: u32,
        _: anytype,
    ) !void {
        Recorder.fri_assemblies += 1;
    }
};

const Inputs = struct {
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
    fixed: fixed_table.Bundle,
    logs: []u32,
    protocol: compact.CompactProtocolV1,
    program: proof_ir.ProofProgram,

    fn deinit(self: *Inputs) void {
        self.program.deinit(self.allocator);
        self.allocator.free(self.logs);
        self.fixed.deinit();
        self.bundle.deinit();
        self.* = undefined;
    }
};

fn sn2Inputs(allocator: std.mem.Allocator) !Inputs {
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    errdefer bundle.deinit();
    var fixed = try fixed_table.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    errdefer fixed.deinit();
    const logs = try semantic_authority.preprocessedLogs(allocator, fixed);
    errdefer allocator.free(logs);
    const protocol = try fixture.sn2Protocol(bundle, logs.len);
    const program = try fixture.sn2Program(
        allocator,
        bundle,
        protocol,
        logs,
    );
    return .{
        .allocator = allocator,
        .bundle = bundle,
        .fixed = fixed,
        .logs = logs,
        .protocol = protocol,
        .program = program,
    };
}

const Runtime = struct {
    trees: pcs_types.TraceTrees,
    fri: shared_views.Fri,
    decommit: shared_views.Decommit,
    assembly: common.Words,
};

fn testRuntime(
    topology: subject.Topology,
    program: proof_ir.ProofProgram,
) Runtime {
    var trees = pcs_types.TraceTrees{
        .storage = undefined,
        .len = topology.trace_openings.len,
    };
    var evaluation_cursor: usize = 0x1000_0000;
    for (topology.trace_openings, 0..) |opening, ordinal| {
        const groups = topology.trace_groups[opening.first_group .. opening.first_group + opening.group_count];
        var evaluation_words: usize = 0;
        for (groups) |group| evaluation_words += @intCast(group.evaluation_words);
        const tree = program.commitments[ordinal];
        trees.storage[ordinal] = compactTree(
            tree,
            @intCast(ordinal),
            evaluation_cursor,
            evaluation_words,
        );
        evaluation_cursor += evaluation_words * 4 + 0x1000;
    }
    var fri_layers: [shared_views.max_fri_layers]shared_views.FriLayer =
        undefined;
    for (program.fri_layers, 0..) |layer, ordinal| {
        const rows = @as(usize, 1) << @intCast(layer.evaluation_log_rows);
        fri_layers[ordinal] = .{
            .coordinates = .{
                .storage = words(
                    0x4000_0000 + ordinal * 0x100_0000,
                    rows * 4,
                ),
                .column_stride_words = rows,
            },
            .merkle_hashes = hashes(
                0x5000_0000 + ordinal * 0x100_0000,
                rows * 2 - 1,
            ),
            .merkle_layers = layers(
                0x6000_0000 + ordinal * 0x100_0000,
                layer.evaluation_log_rows + 1,
            ),
        };
    }
    const queries = topology.query_count;
    const max_expanded = queries * 8;
    return .{
        .trees = trees,
        .fri = .{
            .alpha = slice(field.SecureField, 0x7000, 1),
            .layers = fri_layers,
            .layer_count = topology.fri_openings.len,
            .last_evaluation = slice(field.SecureField, 0x7100, 1),
            .last_coefficients = slice(field.SecureField, 0x7200, 1),
            .last_degree_error = words(0x7300, 1),
            .last_transcript = slice(field.SecureField, 0x7400, 1),
        },
        .decommit = .{
            .raw_queries = words(0x8000, queries),
            .unique_queries = words(0x9000, queries),
            .mapped_queries = words(0xa000, queries),
            .walk_queries = words(0xb000, max_expanded),
            .walk_scratch = words(0xc000, max_expanded),
            .leaf_indices = words(0xd000, 1),
            .expanded_positions = words(0xe000, max_expanded),
            .sparse_indices = words(0xf000, 1),
            .sparse_hashes = hashes(0x1_0000, 1),
            .counts = .{
                .unique = words(0x1_1000, 1),
                .mapped_or_tree = words(0x1_2000, 1),
                .walk = words(0x1_3000, 1),
                .expanded = words(0x1_4000, 1),
                .leaf_or_sparse = words(0x1_5000, 1),
            },
            .sparse_level_offsets = words(0x1_6000, topology.query_log_size + 1),
            .sparse_level_counts = words(0x1_7000, topology.query_log_size + 1),
            .preprocessed_column_log_sizes = words(
                0x1_8000,
                topology.trace_openings[0].column_count,
            ),
            .main_column_log_sizes = words(
                0x1_9000,
                topology.trace_openings[1].column_count,
            ),
            .interaction_column_log_sizes = words(
                0x1_a000,
                topology.trace_openings[2].column_count,
            ),
            .composition_column_log_sizes = words(
                0x1_b000,
                topology.trace_openings[3].column_count,
            ),
        },
        .assembly = words(
            0x8000_0000,
            topology.assembly_capacity_words,
        ),
    };
}

fn compactTree(
    tree: proof_ir.CommitmentTree,
    ordinal: u32,
    evaluation_address: usize,
    evaluation_words: usize,
) pcs_types.CompactTree {
    const metadata = words(0x200_0000 + ordinal * 0x10000, tree.column_count);
    return .{
        .ordinal = ordinal,
        .role = tree.role,
        .first_column = tree.first_column,
        .column_count = tree.column_count,
        .evaluation_log_rows = tree.evaluation_log_rows,
        .coefficients = metadata,
        .evaluations = words(evaluation_address, evaluation_words),
        .column_log_sizes = metadata,
        .column_offsets = words(metadata.address + 0x1000, tree.column_count + 1),
        .merkle_hashes = hashes(
            metadata.address + 0x2000,
            (@as(usize, 1) << @intCast(tree.evaluation_log_rows)) * 2 - 1,
        ),
        .merkle_layers = layers(
            metadata.address + 0x3000,
            tree.evaluation_log_rows + 1,
        ),
        .root = hashes(metadata.address + 0x4000, 1),
    };
}

fn words(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 97,
        .generation = 19,
    };
}

fn hashes(address: usize, len: usize) common.Hashes {
    return slice(field.Blake2sHash, address, len);
}

fn layers(address: usize, len: usize) common.MerkleLayers {
    return slice(field.MerkleLayerDescriptor, address, len);
}

fn slice(
    comptime T: type,
    address: usize,
    len: usize,
) column.DeviceSlice(T) {
    return .{
        .address = address,
        .len = len,
        .owner = 97,
        .generation = 19,
    };
}
