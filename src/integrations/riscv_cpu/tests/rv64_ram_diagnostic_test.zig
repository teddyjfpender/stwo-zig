const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const D = @import("../rv64_ram_diagnostic.zig");
const R = A.R;
const M = A.core.fields.m31.M31;

test "RAM native diagnostic localizes actual extension-field interaction failures after wide source release" {
    const a = std.testing.allocator;
    var cache = try R.values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    var policy = try R.policy.Policy.init(a, &.{.{ .first = 0x1000, .last = 0x11ff, .flags = 3 }});
    defer policy.deinit();
    const before: [64]u64 = @splat(0);
    var after = before;
    after[0] = 17;
    var clocks: [64]u32 = @splat(0);
    clocks[0] = 4;
    const rights: [64]u2 = @splat(3);
    const opening = [_]R.batch.Opening{.{ .index = 8, .before = &before, .after = &after, .terminal_clocks = &clocks, .rights = &rights }};
    var trace = try R.private_trace.Trace.init(a, &cache, &policy, &opening);
    defer trace.deinit();
    const original_provider = try a.dupe(M, trace.provider);
    defer a.free(original_provider);
    var source = A.RAM.Source.fromTrace(&trace);
    var policy_trace = try R.policy_provider.Trace.init(a, &policy, source.policy_counts);
    defer policy_trace.deinit();
    var owner = try source.takeMainForCommit(a, &policy_trace);
    owner.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), trace.main_backing.len);
    var channel = A.P.Channel{};
    const ch = try A.I.Challenges.draw(a, &channel);
    const coordinates = ch.bytes.toM31Array();
    try std.testing.expect(coordinates[1].v != 0 or coordinates[2].v != 0 or coordinates[3].v != 0);
    var inter = try source.generateInteractions(a, &ch);
    defer inter.deinit();
    _ = try policy_trace.generateInteraction(.{ .policy = ch.policy });
    try std.testing.expect((try D.audit(&source, &ch, &inter)) == null);
    try std.testing.expect((try D.auditProviders(&source, &ch, &inter, original_provider, &policy_trace)) == null);
    // This checks stored main, rather than replaying the retained IO ledger.
    const saved_active = original_provider[0];
    original_provider[0] = saved_active.add(M.one());
    const provider_main_failure = (try D.auditProviders(&source, &ch, &inter, original_provider, &policy_trace)) orelse return error.MissedProviderMainResidual;
    try std.testing.expectEqual(@as(usize, 0), provider_main_failure.row);
    try std.testing.expectEqual(@as(usize, 0), provider_main_failure.residual);
    original_provider[0] = saved_active;
    const saved_sum = inter.provider.columns[0];
    inter.provider.columns[0] = saved_sum.add(M.one());
    const provider_lookup_failure = (try D.auditProviders(&source, &ch, &inter, original_provider, &policy_trace)) orelse return error.MissedProviderLookupResidual;
    try std.testing.expectEqual(@as(usize, 0), provider_lookup_failure.row);
    try std.testing.expectEqual(A.frontend.air.memory_commitment.poseidon2_universal_degree3_v1.N_CONSTRAINTS, provider_lookup_failure.residual);
    inter.provider.columns[0] = saved_sum;
    const last = A.rv.witness.physical(policy_trace.shape.size() - 1, policy_trace.shape.log_size);
    policy_trace.main[last] = M.one();
    const policy_failure = (try D.auditProviders(&source, &ch, &inter, original_provider, &policy_trace)) orelse return error.MissedPolicyPaddingResidual;
    try std.testing.expect(policy_failure.component == .policy);
    try std.testing.expectEqual(policy_trace.shape.size() - 1, policy_failure.row);
    policy_trace.main[last] = M.zero();
    try std.testing.expect((try D.auditProviders(&source, &ch, &inter, original_provider, &policy_trace)) == null);
    const common = inter.tables[@intFromEnum(A.T.Table.common_cells)];
    const old = common[0];
    common[0] = old.add(M.one());
    const bad = (try D.audit(&source, &ch, &inter)) orelse return error.MissedNativeRamResidual;
    try std.testing.expectEqual(A.T.Table.common_cells, bad.table);
    try std.testing.expectEqual(@as(usize, 0), bad.row);
    try std.testing.expect(!bad.value.isZero());
    common[0] = old;
    // The absent edge-cell family is entirely padding, but its range lookup
    // inverses and recurrences remain real physical polynomial obligations.
    const edge = inter.tables[@intFromEnum(A.T.Table.edge_cells)];
    const old_padding = edge[0];
    edge[0] = old_padding.add(M.one());
    const padding = (try D.audit(&source, &ch, &inter)) orelse return error.MissedPaddingRamResidual;
    try std.testing.expectEqual(A.T.Table.edge_cells, padding.table);
    try std.testing.expectEqual(@as(usize, 0), padding.row);
    edge[0] = old_padding;
    try std.testing.expect((try D.audit(&source, &ch, &inter)) == null);
    try source.retireMetadata();
    try std.testing.expectError(error.InvalidPrivateRamTracePhase, D.audit(&source, &ch, &inter));
}

fn randomQ(random: std.Random) A.Q {
    const modulus = A.core.fields.m31.Modulus;
    return A.Q.fromU32Unchecked(random.int(u32) % modulus, random.int(u32) % modulus, random.int(u32) % modulus, random.int(u32) % modulus);
}
test "RAM Poseidon provider all residuals including full IO LogUp are cubic on independent arbitrary QM31 lines" {
    const P = A.frontend.air.memory_commitment.poseidon2_universal_degree3_v1;
    for (0..4) |seed| {
        var rng = std.Random.DefaultPrng.init(0x612bda7e + seed);
        const random = rng.random();
        var channel = A.P.Channel{};
        channel.mixU32s(&.{@intCast(seed)});
        const challenges = try A.I.Challenges.draw(std.testing.allocator, &channel);
        var origins: [P.N_MAIN_COLUMNS]A.Q = undefined;
        var directions: [P.N_MAIN_COLUMNS]A.Q = undefined;
        for (&origins, &directions) |*origin, *direction| {
            origin.* = randomQ(random);
            direction.* = randomQ(random);
        }
        const first = [2]A.Q{ randomQ(random), randomQ(random) };
        var prefix: [P.N_SUMS][4]A.Q = undefined;
        var claims: [P.N_SUMS]A.Q = undefined;
        for (&prefix, &claims) |*coordinates, *claim| {
            for (coordinates) |*coordinate| coordinate.* = randomQ(random);
            claim.* = randomQ(random);
        }
        var samples: [5][P.N_CONSTRAINTS + P.N_SUMS]A.Q = undefined;
        for (0..5) |step| {
            const t = A.Q.fromBase(M.fromCanonical(@intCast(step)));
            var main: [P.N_MAIN_COLUMNS]A.Q = undefined;
            for (&main, origins, directions) |*field, origin, direction| field.* = origin.add(t.mul(direction));
            var current: [P.N_SUMS]A.Q = undefined;
            var previous: [P.N_SUMS]A.Q = undefined;
            for (&current, &previous, prefix) |*value, *old, coordinates| {
                value.* = coordinates[0].add(t.mul(coordinates[1]));
                old.* = coordinates[2].add(t.mul(coordinates[3]));
            }
            @memcpy(samples[step][0..P.N_CONSTRAINTS], &P.evaluateGeneric(A.Q, main));
            @memcpy(samples[step][P.N_CONSTRAINTS..], &P.interactionConstraintsGeneric(A.Q, main, first[0].add(t.mul(first[1])), current, previous, claims, &challenges.permutations));
        }
        for (0..4) |level| for (0..4 - level) |row| for (0..P.N_CONSTRAINTS + P.N_SUMS) |constraint| {
            samples[row][constraint] = samples[row + 1][constraint].sub(samples[row][constraint]);
        };
        for (samples[0], 0..) |value, constraint| if (!value.isZero()) {
            std.debug.print("Poseidon degree audit seed={d} residual={d}\n", .{ seed, constraint });
            return error.UnderdeclaredRamPoseidonDegree;
        };
    }
}
