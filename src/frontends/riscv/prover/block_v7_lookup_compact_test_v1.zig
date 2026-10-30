const std = @import("std");
const R = @import("block_v7_memory_relations_v1.zig");
const A = @import("block_v7_lookup_compact_algebra_v1.zig");
const L = @import("block_v7_lookup_compact_layout_v1.zig");
const S = A.Schema;
fn lift(comptime n: usize, v: [n]R.M) [n]R.Q {
    var out: [n]R.Q = undefined;
    for (&out, v) |*d, x| d.* = R.Q.fromBase(x);
    return out;
}
test "v7 compact tuple languages match all dense native rows exactly" {
    inline for (0..6) |i| {
        const kind: S.Kind = @enumFromInt(i);
        const C = A.For(kind, .sparse);
        for (0..S.size(kind)) |row| {
            const expected = try S.tupleAt(kind, row);
            const witness = try C.witness(expected, R.M.one());
            const tuple = C.tuple(R.Q, .{R.Q.one()}, lift(C.MAIN_COUNT, witness));
            for (tuple, expected.slice()) |got, want| try std.testing.expectEqualDeep(R.Q.fromBase(want), got);
            for (C.direct(R.Q, .{R.Q.one()}, lift(C.MAIN_COUNT, witness))) |v| try std.testing.expect(v.isZero());
        }
    }
}
test "v7 compact modes account for dense floor quotient and recursive overhead" {
    var raw: u64 = 0;
    inline for (0..6) |i| {
        const k: S.Kind = @enumFromInt(i);
        const d = try L.Cost.forPart(try L.part(k, .dense, S.logSize(k), @splat(0)), 1, 70);
        raw += d.raw_cells;
        try std.testing.expectEqual(A.Mode.sparse, try L.choose(k, 8, 1, 70));
        try std.testing.expectEqual(A.Mode.dense, try L.choose(k, S.size(k), 1, 70));
    }
    try std.testing.expectEqual(@as(u64, 24379392), raw);
}
test "v7 compact malformed bits op selectors and excluded M31 tuple fail constraints" {
    inline for (0..6) |i| {
        const C = A.For(@enumFromInt(i), .sparse);
        var row = try C.witness(try S.tupleAt(@enumFromInt(i), 0), R.M.one());
        row[1] = R.M.fromCanonical(2);
        var rejected = false;
        for (C.direct(R.Q, .{R.Q.one()}, lift(C.MAIN_COUNT, row))) |v| if (!v.isZero()) {
            rejected = true;
        };
        try std.testing.expect(rejected);
    }
    const C = A.For(.range_check_m31, .sparse);
    var row: [C.MAIN_COUNT]R.M = @splat(R.M.one());
    row[C.MAIN_COUNT - 1] = R.M.zero();
    var rejected = false;
    for (C.direct(R.Q, .{R.Q.one()}, lift(C.MAIN_COUNT, row))) |v| if (!v.isZero()) {
        rejected = true;
    };
    try std.testing.expect(rejected);
}

test "v7 compact six-table original proof matches dense original signed claims and fresh verification" {
    try proofDifferential(null);
}
test "v7 mixed compact and dense domains retain exact original claims and fresh verification" {
    try proofDifferential(.{ .sparse, .sparse, .sparse, .sparse, .sparse, .dense });
}
fn proofDifferential(modes: ?[6]A.Mode) !void {
    const core = @import("stwo_core");
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const P = @import("block_v7_lookup_compact_proof_v1.zig");
    const CP = P.For(Cpu);
    const Dense = @import("block_v7_lookup_provider_v1.zig");
    const DP = Dense.ForBackend(Cpu);
    const E = @import("block_v7_execution_epoch_v1.zig");
    const Tables = @import("../air/lookups/tables/mod.zig");
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    var counters = try Tables.counter.Set.init(a);
    defer counters.deinit(a);
    for (&counters.counters) |*counter| {
        counter.values[0] = R.M.fromCanonical(3);
        counter.values[counter.values.len - 1] = R.M.one().neg();
    }
    const plan = @import("block_v5_native_lookup_plan_v1.zig").Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(4) };
    var stage = try CP.Stage.init(a, &counters, plan, config, modes, .{});
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    for (stage.layout.parts, 0..) |p, i| try std.testing.expectEqual(if (modes) |m| m[i] else A.Mode.sparse, p.mode);
    var oldplan = plan;
    oldplan.index = 1;
    var dense = try DP.commit(a, &counters, oldplan, config);
    defer dense.deinit(a);
    const entries = [_]E.Entry{ try E.Entry.init(.native, 0, @splat(7), &.{ @splat(1), @splat(2) }), try stage.entry(), try Dense.firstEntry(oldplan, dense.roots) };
    var counts: E.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, entries.len);
    const admitted = stage.policy(epoch, &entries);
    const Fixed = @import("../recursion/block_v7_lookup_compact_fixed_shape_v1.zig");
    const drawn = try epoch.draw(a);
    const relations = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&drawn.word.universal_prefix);
    var shape_config = config;
    shape_config.fri_config.n_queries = 70; // Independent geometry only; originals below remain q8.
    var compact_shape = try Fixed.compact(a, stage.layout, shape_config, relations, .{});
    defer compact_shape.deinit();
    var dense_shape = try Fixed.originalDense(a, shape_config, relations, .{});
    defer dense_shape.deinit();
    const compact_census = try Fixed.Census.derive(&compact_shape);
    const dense_census = try Fixed.Census.derive(&dense_shape);
    if (modes == null) {
        try std.testing.expectEqual(@as(u32, 5), compact_census.lifting_log);
        try std.testing.expectEqual(@as(u32, 21), dense_census.lifting_log);
        try std.testing.expect(compact_census.fri_rounds < dense_census.fri_rounds);
    }
    std.debug.print("compact_lookup_geometry mixed={any} config_q=70 original_proofs_q=8 compact={any} dense={any} recursive_key=false\n", .{ modes != null, compact_census, dense_census });

    var compact = try stage.prove(epoch, &entries);
    defer compact.deinit(a);
    stage.deinit();
    stage_live = false;
    const dp = Dense.Policy{ .plan = oldplan, .roots = dense.roots, .epoch = epoch, .entries = &entries };
    var original = try DP.prove(a, &dense, &counters, dp);
    defer original.deinit(a);
    try std.testing.expectEqualDeep(original.claims, compact.claims);
    _ = try DP.verifyBorrowed(a, &original, dp);
    const compact_bytes = try roundTrip(a, &compact.stark);
    const dense_bytes = try roundTrip(a, &original.stark);
    std.debug.print("compact_lookup_wire mixed={any} compact_bytes={d} dense_bytes={d} exact_claims=true\n", .{ modes != null, compact_bytes, dense_bytes });
    _ = try CP.verify(a, &compact, admitted, .{});
    const saved = compact.claims;
    compact.claims[0] = saved[0].add(R.Q.one());
    compact.claims[1] = saved[1].sub(R.Q.one());
    try std.testing.expectError(error.OodsNotMatching, CP.verify(a, &compact, admitted, .{}));
    compact.claims = saved;
    var wrong = admitted;
    wrong.layout.parts[0].mode = .dense;
    try std.testing.expectError(error.InvalidCompactLookupGeometry, CP.verify(a, &compact, wrong, .{}));
    try std.testing.expectError(error.CompactLookupResourceLimit, CP.verify(a, &compact, admitted, .{ .max_total_cells = 1 }));
}
fn roundTrip(a: std.mem.Allocator, proof: *@import("stwo_core").proof_suites.Blake3.Proof) !usize {
    const core = @import("stwo_core");
    const wire = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.*);
    var reader = std.io.fixedBufferStream(writer.written());
    const rebuilt = try wire.deserializeProof(core.proof_suites.Blake3.Hasher, a, reader.reader());
    proof.deinit(a);
    proof.* = rebuilt;
    try std.testing.expectEqual(writer.written().len, reader.pos);
    return writer.written().len;
}
