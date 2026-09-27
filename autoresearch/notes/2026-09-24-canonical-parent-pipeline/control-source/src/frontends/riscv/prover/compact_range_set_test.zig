const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const counters_mod = @import("../air/lookups/tables/counter.zig");
const compact = @import("compact_range_set.zig");
test "compact range provider set merges byte demand once after complete admission" {
    const a = std.testing.allocator;
    var counters = try counters_mod.Set.init(a);
    defer counters.deinit(a);
    const geometry = @import("../recursion/air/compact_range_geometry.zig");
    for (geometry.kinds) |kind| counters.get(kind).values[1] = M.one();
    const plan = try compact.derivePlan(&counters);
    const id = try plan.identity();
    const owner = try compact.Owner.init(a, &counters, plan, id);
    defer owner.deinit();
    try std.testing.expectEqual(@as(usize, 23), owner.columns.len);
    const bytes = counters.get(.range_check_8_8);
    const expected = try a.dupe(M, bytes.values);
    defer a.free(expected);
    inline for (0..3) |i| {
        for (expected, owner.witnesses[i].byte_counts) |*value, term| value.* = value.add(term);
    }
    var malformed = bytes.*;
    malformed.values = malformed.values[0..1];
    try std.testing.expectError(error.InvalidTraceShape, owner.mergeByteCounts(&malformed));
    var aliased = counters_mod.Counter{ .kind = .range_check_8_8, .values = owner.witnesses[0].byte_counts };
    try std.testing.expectError(error.AliasedInput, owner.mergeByteCounts(&aliased));
    try std.testing.expect(!owner.merged);
    for (bytes.values) |value| try std.testing.expect(value.isZero());
    try owner.mergeByteCounts(bytes);
    try std.testing.expectEqualSlices(M, expected, bytes.values);
    try std.testing.expectError(error.CompactRangeByteCountsAlreadyMerged, owner.mergeByteCounts(bytes));
    try std.testing.expectEqualSlices(M, expected, bytes.values);
    // A later provider mismatch must unwind earlier owners without census mutation.
    counters.get(.range_check_8_8_4).values[2] = M.one();
    try std.testing.expectError(error.CompactRangeWitnessGeometryMismatch, compact.Owner.init(a, &counters, plan, id));
    try std.testing.expectEqualSlices(M, expected, bytes.values);
}

test "compact range provider codec canonical framing rejects mutations before admission" {
    const geometry = @import("../recursion/air/compact_range_geometry.zig");
    const codec = @import("compact_range_codec.zig");
    const plan = try geometry.Plan.canonical(.{ 557, 27, 13 });
    const id = try plan.identity();
    const bytes = try codec.encode(plan);
    try std.testing.expectEqualDeep(plan, try codec.decode(&bytes, id));
    try std.testing.expectEqualSlices(u8, &bytes, &(try codec.encode(try codec.decode(&bytes, id))));
    try std.testing.expectError(error.InvalidCompactRangeEncodingLength, codec.decode(bytes[0 .. bytes.len - 1], id));
    try std.testing.expectError(error.InvalidCompactRangeEncodingLength, codec.decode(&(bytes ++ [_]u8{0}), id));
    try std.testing.expectError(error.UntrustedCompactRangeGeometry, codec.decode(&bytes, @splat(0)));
    // Every byte is structural or authenticated; no unused wire slack.
    for (0..bytes.len) |i| {
        var bad = bytes;
        bad[i] ^= 1;
        if (codec.decode(&bad, id)) |_| return error.AcceptedGeometryMutation else |_| {}
    }
    var legacy = bytes;
    std.mem.writeInt(u32, legacy[8..12], 0, .little);
    try std.testing.expectError(error.InvalidCompactRangeEncodingVersion, codec.decode(&legacy, id));
    var oversized = bytes;
    std.mem.writeInt(u32, oversized[12..16], (1 << 20) + 1, .little);
    try std.testing.expectError(error.InvalidCompactRangeGeometry, codec.decode(&oversized, id));
    var first = core.channel.blake3.Channel{};
    var second = core.channel.blake3.Channel{};
    try codec.mixAdmitted(&first, plan, id);
    try codec.mixAdmitted(&second, try codec.decode(&bytes, id), id);
    try std.testing.expectEqual(first.digestBytes(), second.digestBytes());
    const saved = second.digestBytes();
    try std.testing.expectError(error.UntrustedCompactRangeGeometry, codec.mixAdmitted(&second, plan, @splat(0)));
    try std.testing.expectEqual(saved, second.digestBytes());
    var changed = plan;
    changed.shapes[0].n_rows += 1;
    var third = core.channel.blake3.Channel{};
    try codec.mixAdmitted(&third, changed, try changed.identity());
    try std.testing.expect(!std.mem.eql(u8, &first.digestBytes(), &third.digestBytes()));
}

test "compact range provider assembly reuses preparation and separates verifier ownership" {
    const a = std.testing.allocator;
    const geometry = @import("../recursion/air/compact_range_geometry.zig");
    const assembly = @import("compact_range_assembly.zig");
    const plan = try geometry.Plan.canonical(.{ 3, 3, 3 });
    const id = try plan.identity();
    const prover = try assembly.Owner.init(a, plan, id, .{}, true);
    defer prover.deinit();
    const verifier = try assembly.Owner.init(a, plan, id, .{}, false);
    defer verifier.deinit();
    try std.testing.expectError(error.CompactRangeComponentsNotBound, prover.provers());
    try std.testing.expectError(error.CompactRangeComponentsNotBound, verifier.verifiers());
    var channel = core.channel.blake3.Channel{};
    const Universal = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
    const retained = prover.prepared[0];
    for (0..2) |iteration| {
        channel.mixU32s(&.{@intCast(iteration)});
        const relations = try Universal.draw(a, &channel);
        const claims: [3]core.fields.qm31.QM31 = @splat(core.fields.qm31.QM31.fromBase(M.fromCanonical(@intCast(iteration))));
        try prover.bind(relations, claims);
        try verifier.bind(relations, claims);
        const proving = try prover.provers();
        const verifying = try verifier.verifiers();
        for (proving, verifying) |p, v| try std.testing.expectEqual(p.maxConstraintLogDegreeBound(), v.maxConstraintLogDegreeBound());
        try std.testing.expect(retained == prover.prepared[0]);
        inline for (0..3) |i| {
            try std.testing.expect(prover.prepared[i].workspace != null);
            try std.testing.expect(verifier.prepared[i].workspace == null);
        }
        try std.testing.expectError(error.VerifierOnlyCompactRangePreparation, verifier.provers());
    }
    prover.manifest.log_sizes[0] += 1;
    try std.testing.expectError(error.InvalidProofShape, prover.bind(Universal.dummy(), @splat(core.fields.qm31.QM31.zero())));
    try std.testing.expectError(error.CompactRangeComponentsNotBound, prover.provers());
}

test "compact range provider append checks order capacity and final group offsets" {
    const a = std.testing.allocator;
    const geometry = @import("../recursion/air/compact_range_geometry.zig");
    const assembly = @import("compact_range_assembly.zig");
    const plan = try geometry.Plan.canonical(.{ 1, 1, 1 });
    const owner = try assembly.Owner.init(a, plan, try plan.identity(), .{ .columns = .{ 2, 10, 8, 20 } }, true);
    defer owner.deinit();
    const origin = try owner.endOrigin();
    try std.testing.expectEqualSlices(u32, &.{ 2, 33, 20, 37 }, &origin.columns);
    try std.testing.expectEqual(@as(u8, 3), origin.claimed_sum_index);
    const V = struct {
        handles: [3]core.air.components.Component = undefined,
        n_handles: usize = 0,
        pub fn push(self: *@This(), value: core.air.components.Component) void {
            self.handles[self.n_handles] = value;
            self.n_handles += 1;
        }
    };
    var table = V{};
    try std.testing.expectError(error.CompactRangeComponentsNotBound, owner.appendVerifiers(&table));
    try std.testing.expectEqual(@as(usize, 0), table.n_handles);
    try owner.bind(@import("../recursion/air/universal_challenges.zig").UniversalRelations.dummy(), @splat(core.fields.qm31.QM31.zero()));
    try owner.appendVerifiers(&table);
    try std.testing.expectEqual(@as(usize, 3), table.n_handles);
    try std.testing.expectError(error.CompactRangeComponentOrderMismatch, owner.appendVerifiers(&table));
    try std.testing.expectEqual(@as(usize, 3), table.n_handles);
    const Small = struct {
        handles: [2]core.air.components.Component = undefined,
        n_handles: usize = 0,
        pub fn push(_: *@This(), _: core.air.components.Component) void {
            unreachable;
        }
    };
    var small = Small{};
    try std.testing.expectError(error.CompactRangeComponentCapacityExceeded, owner.appendVerifiers(&small));
    try std.testing.expectEqual(@as(usize, 0), small.n_handles);
}
