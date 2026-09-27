const std = @import("std");
const stwo_core = @import("stwo_core");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");

const m31 = stwo_core.fields.m31;
const Digest = pair_node.Digest;

const GOLDEN_WIRE_SHA256 = hexDigest(
    "548dfc7e9d531f424c2ee2c22f7c50ef9c0c2192b33b8a1c9c60d92f7910916c",
);
const GOLDEN_RECORD_ID = Digest{
    2_039_660_602, 115_237_135,   1_331_741_423, 1_294_625_639,
    1_449_265_885, 1_690_024_629, 188_314_213,   1_988_757_495,
};
const GOLDEN_STATEMENT_ID = Digest{
    1_668_581_139, 1_656_416_802, 50_065_182,  2_125_230_098,
    410_337_995,   170_031_781,   255_905_502, 1_004_825_127,
};
const GOLDEN_PROOF_ID = Digest{
    2_090_435_214, 1_960_971_288, 245_807_019, 1_845_949_681,
    885_842_594,   425_023_899,   425_575_428, 2_080_706_910,
};
const GOLDEN_TRANSCRIPT_ID = Digest{
    2_060_483_450, 924_184_605,   949_267_678, 1_412_135_031,
    323_620_981,   1_611_917_707, 215_859_777, 1_824_587_802,
};
const GOLDEN_SUMMARY_ID = Digest{
    992_521_607,   547_623_542, 743_238_183,   1_184_546_926,
    1_925_167_659, 358_932_843, 1_946_952_417, 716_933_793,
};
const GOLDEN_NODE_ID = Digest{
    1_121_897_635, 1_933_104_947, 1_194_423_304, 1_229_304_646,
    314_473_721,   245_804_358,   601_591_189,   264_131_684,
};

const test_support = @import("pair_node_test_support.zig");
const Fixture = test_support.Fixture;
const makeChild = test_support.makeChild;
const verifiedChild = test_support.verifiedChild;
const id = test_support.id;
const hexDigest = test_support.hexDigest;

test "R-009 pair node codec is allocation-free alias-safe and failure-atomic" {
    const fixture = try Fixture.init();
    const sentinel: u8 = 0xa5;
    var encoded = [_]u8{sentinel} ** pair_node.ENCODED_LEN;
    var invalid = fixture.record;
    invalid.flags = 1;
    try std.testing.expectError(
        error.UnknownFlags,
        pair_node.encodeInto(&invalid, &encoded),
    );
    for (encoded) |byte| try std.testing.expectEqual(sentinel, byte);

    try pair_node.encodeInto(&fixture.record, &encoded);
    var bad_bytes = encoded;
    bad_bytes[0] ^= 1;
    var destination = fixture.record;
    destination.pair_index = 0;
    const before = destination;
    try std.testing.expectError(
        error.InvalidMagic,
        pair_node.decodeInto(&destination, &bad_bytes),
    );
    try std.testing.expectEqualDeep(before, destination);

    var storage: [
        @max(
            @sizeOf(pair_node.PairNodeRecordV1),
            pair_node.ENCODED_LEN,
        )
    ]u8 align(@alignOf(pair_node.PairNodeRecordV1)) = undefined;
    const alias_record: *pair_node.PairNodeRecordV1 = @ptrCast(&storage);
    alias_record.* = fixture.record;
    const alias_bytes: *[pair_node.ENCODED_LEN]u8 = @ptrCast(&storage);
    try std.testing.expectError(
        error.AliasedBuffer,
        pair_node.encodeInto(alias_record, alias_bytes),
    );
    try std.testing.expectError(
        error.AliasedBuffer,
        pair_node.decodeInto(alias_record, alias_bytes),
    );
}

test "R-009 pair node prepared-root wall-time measurement" {
    const allocator = std.testing.allocator;
    const raw_iterations = std.process.getEnvVarOwned(
        allocator,
        "STWO_PAIR_NODE_BENCH_ITERATIONS",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(raw_iterations);
    const iterations = try std.fmt.parseUnsigned(usize, raw_iterations, 10);
    if (iterations == 0 or iterations > 1_000_000)
        return error.InvalidBenchmarkIterations;

    const fixture = try Fixture.init();
    const suite = try pair_node.prepareProtocolSuite();
    const prepared_context = try pair_node.prepareRootContext(
        &suite,
        &fixture.authority,
        &fixture.root_pin,
    );
    const expected = try pair_node.authenticateRootPrepared(
        &suite,
        &fixture.authority,
        &fixture.record,
        &fixture.root_pin,
    );
    for (0..16) |_| {
        _ = try pair_node.authenticateRoot(
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
        _ = try pair_node.authenticateRootPrepared(
            &suite,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
        _ = try pair_node.authenticateRootWithPreparedContext(
            &prepared_context,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
    }

    // ABCCBA ordering reduces one-way thermal/order bias without claiming this
    // focused microbenchmark is a whole-recursion throughput result.
    var checksum: u32 = 0;
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        const result = try pair_node.authenticateRoot(
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[0];
    }
    const convenience_first_ns = timer.read();
    timer.reset();
    for (0..iterations) |_| {
        const result = try pair_node.authenticateRootPrepared(
            &suite,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[1];
    }
    const prepared_first_ns = timer.read();
    timer.reset();
    for (0..iterations) |_| {
        const result = try pair_node.authenticateRootWithPreparedContext(
            &prepared_context,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[2];
    }
    const context_first_ns = timer.read();
    timer.reset();
    for (0..iterations) |_| {
        const result = try pair_node.authenticateRootWithPreparedContext(
            &prepared_context,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[3];
    }
    const context_second_ns = timer.read();
    timer.reset();
    for (0..iterations) |_| {
        const result = try pair_node.authenticateRootPrepared(
            &suite,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[4];
    }
    const prepared_second_ns = timer.read();
    timer.reset();
    for (0..iterations) |_| {
        const result = try pair_node.authenticateRoot(
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        );
        std.mem.doNotOptimizeAway(&result);
        checksum ^= result.pair.node_id[5];
    }
    const convenience_second_ns = timer.read();
    std.mem.doNotOptimizeAway(&checksum);

    const samples: u64 = @intCast(2 * iterations);
    const convenience_ns = try std.math.add(
        u64,
        convenience_first_ns,
        convenience_second_ns,
    );
    const prepared_ns = try std.math.add(
        u64,
        prepared_first_ns,
        prepared_second_ns,
    );
    const context_ns = try std.math.add(
        u64,
        context_first_ns,
        context_second_ns,
    );
    const convenience_per_op = convenience_ns / samples;
    const prepared_per_op = prepared_ns / samples;
    const context_per_op = context_ns / samples;
    const speedup_basis_points = if (prepared_per_op == 0)
        @as(u64, 0)
    else
        convenience_per_op * 10_000 / prepared_per_op;
    const context_vs_prepared_basis_points = if (context_per_op == 0)
        @as(u64, 0)
    else
        prepared_per_op * 10_000 / context_per_op;
    const context_vs_convenience_basis_points = if (context_per_op == 0)
        @as(u64, 0)
    else
        convenience_per_op * 10_000 / context_per_op;
    try std.testing.expectEqualDeep(
        expected,
        try pair_node.authenticateRootPrepared(
            &suite,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        ),
    );
    try std.testing.expectEqualDeep(
        expected,
        try pair_node.authenticateRootWithPreparedContext(
            &prepared_context,
            &fixture.authority,
            &fixture.record,
            &fixture.root_pin,
        ),
    );
    std.debug.print(
        "\n  R009_WALL iterations={d} convenience_ns_per_op={d} " ++
            "prepared_ns_per_op={d} context_prepared_ns_per_op={d} " ++
            "speedup_basis_points={d} context_vs_prepared_basis_points={d} " ++
            "context_vs_convenience_basis_points={d} static_old={d} " ++
            "static_convenience={d} static_prepared={d} " ++
            "static_context_cold={d} static_context_hot={d}\n",
        .{
            samples,
            convenience_per_op,
            prepared_per_op,
            context_per_op,
            speedup_basis_points,
            context_vs_prepared_basis_points,
            context_vs_convenience_basis_points,
            pair_node.AuthenticationPermutationCostV1.prior_audit_static_estimate,
            pair_node.AuthenticationPermutationCostV1.successful_convenience_root,
            pair_node.AuthenticationPermutationCostV1.successful_prepared_root,
            pair_node.AuthenticationPermutationCostV1.context_preparation,
            pair_node.AuthenticationPermutationCostV1.successful_context_prepared_root,
        },
    );
}
