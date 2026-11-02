//! Lane parity for every batch component: native QM31 vtable evaluation,
//! QM31 evaluation through the flat scalar layouts, and an external trace lane
//! must all agree at random points over a roster that enables every service.
const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const Key = @import("../rv64_execution_verifier_key.zig");
const Point = @import("../rv64_point_evaluation.zig");
const Layout = @import("../rv64_point_layout.zig");
const Fixture = @import("rv64_ethereum_fixture.zig");
const Trace = @import("rv64_trace_lane.zig");
const core = A.core;
const Q = A.Q;
const M = core.fields.m31.M31;
const T = A.T;
const a = std.testing.allocator;

fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.uintLessThan(u32, core.fields.m31.Modulus), rng.uintLessThan(u32, core.fields.m31.Modulus), rng.uintLessThan(u32, core.fields.m31.Modulus), rng.uintLessThan(u32, core.fields.m31.Modulus));
}
fn randomClaims(rng: std.Random) A.Claims {
    var ram = A.RAM.Claims{ .callers = .{}, .provider = .{ randomQ(rng), randomQ(rng) }, .policy = randomQ(rng), .bytes = Q.zero() };
    for (T.TABLES) |table| for (ram.callers.tables[@intFromEnum(table)][0..T.sumCount(table)]) |*claim| {
        claim.* = randomQ(rng);
    };
    return .{ .cpu = .{ .secp_header = randomQ(rng), .secp_add = .{ .product = randomQ(rng), .linear = randomQ(rng), .bridge = randomQ(rng) }, .secp_double = .{ .product = randomQ(rng), .linear = randomQ(rng), .bridge = randomQ(rng) }, .multiplication = randomQ(rng), .multiplication_provider = randomQ(rng), .cpu = .{ .state = randomQ(rng), .rom = randomQ(rng), .bytes = randomQ(rng), .bitwise = randomQ(rng), .shifts = randomQ(rng) }, .division = randomQ(rng), .header = randomQ(rng), .permutation = randomQ(rng), .chi = randomQ(rng), .xor5 = randomQ(rng), .bridge = randomQ(rng), .bytes = randomQ(rng) }, .ram = ram };
}
fn randomValues(rng: std.Random, points: *const core.air.components.MaskPoints) !core.air.components.MaskValues {
    const trees = try a.alloc([][]Q, points.items.len);
    var built: usize = 0;
    errdefer {
        for (trees[0..built]) |tree| {
            for (tree) |column| a.free(column);
            a.free(tree);
        }
        a.free(trees);
    }
    for (points.items, trees) |tree, *out| {
        out.* = try a.alloc([]Q, tree.len);
        built += 1;
        var columns: usize = 0;
        errdefer for (out.*[0..columns]) |column| a.free(column);
        for (tree, out.*) |column, *values| {
            values.* = try a.alloc(Q, column.len);
            columns += 1;
            for (values.*) |*value| value.* = randomQ(rng);
        }
    }
    return core.air.components.MaskValues.initOwned(trees);
}
const Harness = struct {
    fixture: *Fixture.Fixture,
    policy: A.R.policy.Policy,
    public: A.Public,
    prepared: A.Prepared,
    key: Key.ReceiverKey,
    fn init() !Harness {
        var self: Harness = undefined;
        self.fixture = try Fixture.Fixture.create(a, .ethereum_services_v2);
        errdefer self.fixture.deinit();
        self.policy = try A.R.policy.Policy.init(a, &.{ .{ .first = Fixture.pc, .last = Fixture.pc + Fixture.program.len * 4 - 1, .flags = 5 }, .{ .first = Fixture.pointer, .last = Fixture.pointer + 511, .flags = 3 } });
        errdefer self.policy.deinit();
        var cpu = self.fixture.public;
        cpu.statement.cells = &.{};
        cpu.statement.memory_clocks = &.{};
        self.public = .{ .cpu = cpu, .geometry = .chunk512, .before = @splat(1), .after = @splat(2), .policy_identity = self.policy.identity, .ram = .{ .hashes = 1, .common_chunks = 1, .edge_chunks = 0, .nodes = 55, .sides = 0, .edge_permits = 0 } };
        self.prepared = try A.Prepared.initForLayout(a, self.public.layout(), &self.policy, null);
        errdefer self.prepared.deinit();
        self.key = try Key.ReceiverKey.fromPrepared(a, &self.prepared, self.public, null);
        return self;
    }
    fn deinit(self: *Harness) void {
        self.key.deinit();
        self.prepared.deinit();
        self.policy.deinit();
        self.fixture.deinit();
    }
};

test "every batch component agrees across native, flat QM31 and trace-lane evaluation" {
    var harness = try Harness.init();
    defer harness.deinit();
    const key = &harness.key;
    var prng = std.Random.DefaultPrng.init(0x504f494e54);
    const rng = prng.random();
    var channel = A.P.Channel{};
    channel.mixU32s(&.{ 0x4c414e45, 7 });
    var challenges = try A.drawView(a, &channel, key.view());
    const claims = randomClaims(rng);
    var components: Key.Components = undefined;
    try key.buildComponents(harness.public, claims, &challenges, &components);
    try std.testing.expect(components.ram != null);
    try std.testing.expect(components.cpu.permutation != null and components.cpu.division != null and components.cpu.multiplication != null and components.cpu.secp[0] != null and components.cpu.secp[1] != null);
    const roster = try Point.Roster.init(key, &components);
    const native = core.air.components.Components{ .components = components.verifiers(), .n_preprocessed_columns = key.fixed_logs.len };
    const flat_challenges = try Layout.flattenChallenges(a, roster.layouts.challenges, challenges);
    defer a.free(flat_challenges);
    const flat_claims = try Layout.flattenClaims(a, roster.layouts.claims, claims);
    defer a.free(flat_claims);
    const flat_publics = try Layout.flattenPublics(a, roster.layouts.publics, harness.public);
    defer a.free(flat_publics);
    const lane_challenges = try Trace.liftSlice(a, flat_challenges);
    defer a.free(lane_challenges);
    const lane_claims = try Trace.liftSlice(a, flat_claims);
    defer a.free(lane_claims);
    const lane_publics = try Trace.liftSlice(a, flat_publics);
    defer a.free(lane_publics);
    for (0..3) |round| {
        const point = core.circle.secureFieldPointFromRandomSeed(randomQ(rng));
        var points = try native.maskPoints(a, point, roster.global_log, false);
        defer points.deinitDeep(a);
        var values = try randomValues(rng, &points);
        defer values.deinitDeep(a);
        const alpha = randomQ(rng);
        if (round == 0) for (0..roster.count()) |ordinal| {
            var accumulator = core.air.accumulation.PointEvaluationAccumulator.init(alpha);
            try components.verifiers()[ordinal].evaluateConstraintQuotientsAtPoint(point, &values, &accumulator, roster.global_log);
            const vtable = accumulator.finalize();
            const flat = try Point.evalComponentAtPointFor(Q, &roster, ordinal, point, Point.NativeMasks{ .values = &values }, alpha, flat_challenges, flat_claims, flat_publics);
            const lane = try Point.evalComponentAtPointFor(Trace.TraceLane, &roster, ordinal, Trace.liftPoint(point), Trace.LaneMasks{ .values = &values }, Trace.TraceLane.fromQm31(alpha), lane_challenges, lane_claims, lane_publics);
            if (!vtable.eql(flat) or !vtable.eql(lane.value)) {
                std.debug.print("component ordinal {d} diverges (flat={any} lane={any})\n", .{ ordinal, vtable.eql(flat), vtable.eql(lane.value) });
                return error.ComponentLaneMismatch;
            }
        };
        const expected = try native.evalCompositionPolynomialAtPoint(point, &values, alpha, roster.global_log);
        const through_flat = try Point.evalCompositionAtPointFor(Q, &roster, point, Point.NativeMasks{ .values = &values }, alpha, flat_challenges, flat_claims, flat_publics);
        try std.testing.expect(expected.eql(through_flat));
        Trace.ops = .{};
        const over_lane = try Point.evalCompositionAtPointFor(Trace.TraceLane, &roster, Trace.liftPoint(point), Trace.LaneMasks{ .values = &values }, Trace.TraceLane.fromQm31(alpha), lane_challenges, lane_claims, lane_publics);
        try std.testing.expect(expected.eql(over_lane.value));
        try std.testing.expect(Trace.ops.mul > 0 and Trace.ops.inv == roster.count() and Trace.ops.square > 0);
    }
    // cpu, program, bytes, division, multiplication, four Keccak, two secp
    // groups of three, ten RAM components; the fixture plan needs no AND/shift
    // tables (the retained probe proof covers those two component types).
    try std.testing.expectEqual(@as(usize, 25), roster.count());
}

test "batch shape lists committed column logs and mask offsets per tree" {
    var harness = try Harness.init();
    defer harness.deinit();
    const key = &harness.key;
    var challenges: A.Challenges = undefined;
    var components: Key.Components = undefined;
    try key.shapeComponents(a, harness.public, &challenges, &components);
    const roster = try Point.Roster.init(key, &components);
    var shape = try Point.describeShape(a, &roster);
    defer shape.deinit();
    try std.testing.expectEqual(@as(usize, 3), shape.tree_column_log_sizes.len);
    try std.testing.expectEqualSlices(u32, key.fixed_logs, shape.tree_column_log_sizes[0]);
    try std.testing.expectEqualSlices(u32, key.main_logs, shape.tree_column_log_sizes[1]);
    try std.testing.expectEqualSlices(u32, key.interaction_logs, shape.tree_column_log_sizes[2]);
    try std.testing.expectEqual(roster.global_log, shape.global_log);
    try std.testing.expectEqual(@as(u32, 2), shape.composition_log_split);
    var wide: usize = 0;
    for (shape.mask_offsets, 0..) |tree, t| {
        try std.testing.expectEqual(shape.tree_column_log_sizes[t].len, tree.len);
        for (tree) |column| {
            try std.testing.expect(column.len >= 1 and column[0] == 0);
            if (column.len == 5) wide += 1;
            for (column) |offset| try std.testing.expect(offset >= -2 and offset <= 2);
        }
    }
    try std.testing.expectEqual(@as(usize, A.rv.crypto.keccak.layout.STATE), wide);
    const flat = try Layout.flattenChallenges(a, roster.layouts.challenges, challenges);
    defer a.free(flat);
    try std.testing.expectEqual(roster.layouts.challenges.len, flat.len);
}
