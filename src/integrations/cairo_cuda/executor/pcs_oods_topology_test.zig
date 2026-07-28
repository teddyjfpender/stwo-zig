const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("../../../backends/cuda/abi/field.zig");
const column = @import("../../../backends/cuda/runtime/column.zig");
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const fixed_table = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const semantic_authority = @import("stwo_cairo_frontend").proof_plan.semantic_authority;
const shared_views = @import(
    "../../native_cuda/common/resident_views.zig",
);
const pcs_types = @import("pcs_hooks_types.zig");
const fixture = @import("resident_plan_test.zig");
const quotient_topology = @import("quotient/topology.zig");
const subject = @import("pcs_oods_topology.zig");

test "SN2 OODS topology binds every canonical sample to compact trees" {
    const allocator = std.testing.allocator;
    var input = try sn2Inputs(allocator);
    defer input.deinit();
    var quotient = try quotient_topology.derive(
        allocator,
        input.bundle,
        input.program,
        input.protocol,
    );
    defer quotient.deinit();
    var topology = try subject.derive(
        allocator,
        input.bundle,
        input.program,
        input.protocol,
        quotient,
    );
    defer topology.deinit();

    try std.testing.expectEqual(@as(usize, 6110), topology.source_indices.len);
    try std.testing.expectEqual(topology.source_indices.len, topology.offset_points.len);
    try std.testing.expectEqual(topology.source_indices.len, topology.fold_counts.len);
    try std.testing.expectEqual(@as(usize, 365), topology.cohorts.len);
    try std.testing.expectEqual(@as(usize, 102_455), topology.factor_count);
    try std.testing.expectEqual(@as(usize, 932_480), topology.scratch_count);
    try std.testing.expect(!std.mem.allEqual(u8, &topology.identity, 0));
    var expected_identity: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_identity,
        "5d75debc5eab9935362e6126fc0cbabcf06b2c7f19949d135ecad1a17b66b278",
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected_identity,
        &topology.identity,
    );
    try std.testing.expectEqualSlices(
        u32,
        topology.output_indices,
        &identityIndices(topology.output_indices.len),
    );

    var trees = try testTrees(allocator, quotient, input.program, input.protocol);
    defer trees.deinit();
    const oods = testOods(topology);
    var session = UploadSession{};
    try topology.upload(&session, oods);
    try std.testing.expectEqual(@as(usize, 3), session.context.uploads);
    var bound = try subject.Bound.init(
        allocator,
        topology,
        quotient,
        trees.views,
        oods,
    );
    defer bound.deinit();
    try std.testing.expectEqual(topology.cohorts.len, bound.batches.len);
    try std.testing.expectEqual(topology.factor_count, bound.oods.folding_factors.len);
    try std.testing.expectEqual(topology.scratch_count, bound.oods.reduce_a.len);
    for (topology.cohorts, bound.batches) |cohort, batch| {
        try std.testing.expectEqual(cohort.first_sample, batch.first_sample);
        try std.testing.expectEqual(cohort.sample_count, batch.sample_count);
        try std.testing.expectEqual(
            cohort.source_stride_words,
            batch.coefficients.column_stride_words,
        );
    }

    std.debug.print(
        "SN2 OODS topology: samples={} cohorts={} factors={} scratch={} identity={s}\n",
        .{
            topology.source_indices.len,
            topology.cohorts.len,
            topology.factor_count,
            topology.scratch_count,
            std.fmt.bytesToHex(topology.identity, .lower),
        },
    );

    quotient.batch_terms[0].source_index +%= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        subject.derive(
            allocator,
            input.bundle,
            input.program,
            input.protocol,
            quotient,
        ),
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

const OwnedTrees = struct {
    allocator: std.mem.Allocator,
    storage: []common.Words,
    views: pcs_types.TraceTrees,

    fn deinit(self: *OwnedTrees) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

fn testTrees(
    allocator: std.mem.Allocator,
    quotient: quotient_topology.Topology,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !OwnedTrees {
    const storage = try allocator.alloc(
        common.Words,
        quotient.source_trees.len,
    );
    var views = pcs_types.TraceTrees{
        .storage = undefined,
        .len = quotient.source_trees.len,
    };
    for (quotient.source_trees, 0..) |span, ordinal| {
        const tree = program.commitments[ordinal];
        const coefficient_words = span.evaluation_words >>
            @intCast(protocol.log_blowup_factor);
        storage[ordinal] = words(
            0x10_0000 + ordinal * 0x100_0000,
            @intCast(coefficient_words),
        );
        const logs = words(0x80_0000 + ordinal * 0x1000, tree.column_count);
        const hashes = words(0x90_0000 + ordinal * 0x1000, 8);
        const layers = words(
            0xa0_0000 + ordinal * 0x1000,
            (@as(usize, tree.evaluation_log_rows) + 1) * 4,
        );
        views.storage[ordinal] = .{
            .ordinal = @intCast(ordinal),
            .role = tree.role,
            .first_column = tree.first_column,
            .column_count = tree.column_count,
            .evaluation_log_rows = tree.evaluation_log_rows,
            .coefficients = storage[ordinal],
            .evaluations = words(
                0x1000_0000 + ordinal * 0x1_0000_0000,
                @intCast(span.evaluation_words),
            ),
            .column_log_sizes = logs,
            .column_offsets = words(logs.address + 0x400, tree.column_count + 1),
            .merkle_hashes = try hashes.cast(field.Blake2sHash),
            .merkle_layers = try layers.cast(field.MerkleLayerDescriptor),
            .root = try hashes.cast(field.Blake2sHash),
        };
    }
    return .{
        .allocator = allocator,
        .storage = storage,
        .views = views,
    };
}

fn testOods(topology: subject.Topology) shared_views.Oods {
    const samples = topology.source_indices.len;
    return .{
        .parameter = slice(field.SecureField, 0x2000, 1),
        .offset_points = slice(field.CirclePointBaseField, 0x3000, samples),
        .fold_counts = words(0x4000, samples),
        .output_indices = words(0x5000, samples),
        .sample_points = slice(field.SecureCirclePoint, 0x6000, samples),
        .evaluation_points = slice(field.SecureCirclePoint, 0x7000, samples),
        .folding_factors = slice(
            field.SecureField,
            0x8000,
            topology.factor_count + 17,
        ),
        .reduce_a = slice(
            field.SecureField,
            0x9000,
            topology.scratch_count + 17,
        ),
        .reduce_b = slice(
            field.SecureField,
            0xa000,
            topology.scratch_count + 17,
        ),
        .sampled_values = slice(field.SecureField, 0xb000, samples),
    };
}

fn identityIndices(count: usize) [6110]u32 {
    std.debug.assert(count == 6110);
    var output: [6110]u32 = undefined;
    for (&output, 0..) |*value, index| value.* = @intCast(index);
    return output;
}

fn words(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 91,
        .generation = 17,
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
        .owner = 91,
        .generation = 17,
    };
}
