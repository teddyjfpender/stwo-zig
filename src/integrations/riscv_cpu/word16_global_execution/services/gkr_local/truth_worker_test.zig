const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../roster.zig");
const W = @import("truth_worker.zig");
const P = @import("worker_protocol.zig");
const Manifest = @import("manifest.zig");
const a = std.testing.allocator;
const O = P.O;
fn run(truth: R.Truth, source: R.TruthSource) !void {
    const config = P.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
    const expected = Manifest.ExpectedWorker{ .kind = switch (truth) {
        .keccak => .keccak,
        .secp => |t| if (t.setup.kind == .add) .secp_add else .secp_double,
    }, .global_relations = .{ .ram = false, .kio = truth == .keccak, .wire = truth == .secp }, .mass = try W.truthMass(truth), .ordinal = 0, .statement = W.truthStatement(truth, config, @splat(17)), .fixed = truth.key().root, .local_instances = null };
    var worker = W.TruthWorker.init(a, truth, source, expected, config, 64 * 1024 * 1024) catch |err| {
        var s = source;
        s.deinit();
        return err;
    };
    defer worker.deinit(a);
    const stage = try worker.seal(a);
    try std.testing.expect(stage.local == null);
    var channel = P.Channel.init();
    var shared: Manifest.Shared = undefined;
    shared.ram.offset = channel.drawSecureFelt();
    for (&shared.ram.coefficients) |*v| v.* = channel.drawSecureFelt();
    shared.kio = A.crypto.keccak.equations.IoFor(O).draw(&channel);
    shared.wire = A.crypto.secp256k1.equations.WireFor(O).draw(&channel);
    var entries = [_]Manifest.Entry{.{ .kind = expected.kind, .global_relations = expected.global_relations, .mass = expected.mass, .scope = .{ .ordinal = 0, .statement = expected.statement, .fixed = expected.fixed, .main = stage.main }, .local = null }};
    const pending = Manifest.PendingManifest{ .entries = &entries, .digest = @splat(29), .shared = shared };
    var encoded = try worker.complete(a, &pending, 0, 64 * 1024 * 1024);
    defer encoded.deinit(a);
    var rejecting = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var bad = config;
    bad.pow_bits = 33;
    try std.testing.expectError(error.UnsupportedWideServicesConfig, W.verifyTruth(rejecting.allocator(), truth, expected, &pending, 0, bad, &encoded));
    try std.testing.expectEqual(@as(usize, 0), rejecting.alloc_index);
    const claims = try W.verifyTruth(a, truth, expected, &pending, 0, config, &encoded);
    try std.testing.expect(claims.ram.isZero());
    if (truth == .keccak) {
        try std.testing.expect(claims.kio.eql(encoded.claims[3]));
        try std.testing.expect(claims.wire.isZero());
    } else {
        try std.testing.expect(claims.wire.eql(encoded.claims[3].add(encoded.claims[4])));
        try std.testing.expect(claims.kio.isZero());
    }
    const global = encoded.claims[3];
    var coordinates = global.toM31Array();
    coordinates[7] = coordinates[7].add(core.fields.m31.M31.one());
    encoded.claims[3] = O.fromM31Array(coordinates);
    if (W.verifyTruth(a, truth, expected, &pending, 0, config, &encoded)) |_| return error.MutatedPureGlobalDebtAccepted else |_| {}
    encoded.claims[3] = global;
    const old = encoded.claims[0];
    encoded.claims[0] = old.add(O.one());
    try std.testing.expectError(error.UnclosedWideTruthLocalClaims, W.verifyTruth(a, truth, expected, &pending, 0, config, &encoded));
    encoded.claims[0] = old;
    const wrong = entries[0].scope.main;
    entries[0].scope.main[0] ^= 1;
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, W.verifyTruth(a, truth, expected, &pending, 0, config, &encoded));
    entries[0].scope.main = wrong;
    try std.testing.expectError(error.InvalidWideTruthPhase, worker.complete(a, &pending, 0, 64 * 1024 * 1024));
}
test "actual classic OM Keccak truth proof separately closes local claims and freshly authenticates pure KIO" {
    var setup = try @import("../../keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer setup.deinit();
    try run(.{ .keccak = .{ .setup = &setup, .first_id = 3, .calls = 2 } }, try @import("truth_test.zig").keccakSource());
}
test "actual classic OM secp truth proof separately closes BYTE and freshly authenticates pure Wire" {
    const source = try @import("truth_test.zig").secpSource(.canonical_inputs);
    var setup = @import("../../secp/roster.zig").TruthSetup.init(a, .add, .{ source.secp.batch.product.log_size, source.secp.batch.linear.log_size }) catch |err| {
        var s = source;
        s.deinit();
        return err;
    };
    defer setup.deinit();
    try run(.{ .secp = .{ .setup = &setup, .first_id = 5, .calls = 1 } }, source);
}

test "truth local characteristic admission and init budget precede ownership transfer" {
    var setup = try @import("../../keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer setup.deinit();
    try std.testing.expectError(error.KeccakLookupMassExceeded, W.truthMass(.{ .keccak = .{ .setup = &setup, .first_id = 1, .calls = 200000 } }));
    var source = try @import("truth_test.zig").keccakSource();
    defer source.deinit();
    const truth = R.Truth{ .keccak = .{ .setup = &setup, .first_id = 3, .calls = 2 } };
    const config = P.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
    const expected = Manifest.ExpectedWorker{ .kind = .keccak, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .mass = try W.truthMass(truth), .ordinal = 0, .statement = W.truthStatement(truth, config, @splat(17)), .fixed = truth.key().root, .local_instances = null };
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var bad = config;
    bad.pow_bits = 33;
    try std.testing.expectError(error.UnsupportedWideServicesConfig, W.TruthWorker.init(fail.allocator(), truth, source, expected, bad, 1));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    bad = config;
    bad.fri_config.log_blowup_factor = 2;
    try std.testing.expectError(error.UnsupportedWideServicesConfig, W.TruthWorker.init(fail.allocator(), truth, source, expected, bad, 1));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    try std.testing.expectError(error.WideTruthBudgetExceeded, W.TruthWorker.init(fail.allocator(), truth, source, expected, config, 1));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    try std.testing.expect(source.keccak.permutation.main.len != 0);
}

test "parked truth spill OOM is retryable and sealed abort releases unmapped coefficient files" {
    var setup = try @import("../../keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer setup.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const path = try temp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try @import("../../retained_main_store.zig").Store.initParked(path, 8 << 20);
    defer store.deinit();
    var fail = std.testing.FailingAllocator.init(a, .{});
    const allocator = fail.allocator();
    const truth = R.Truth{ .keccak = .{ .setup = &setup, .first_id = 3, .calls = 2 } };
    const config = P.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
    const expected = Manifest.ExpectedWorker{ .kind = .keccak, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .mass = try W.truthMass(truth), .ordinal = 0, .statement = W.truthStatement(truth, config, @splat(17)), .fixed = truth.key().root, .local_instances = null };
    {
        const source = try @import("truth_test.zig").keccakSourceWithAllocator(allocator);
        var worker = W.TruthWorker.init(allocator, truth, source, expected, config, 64 << 20) catch |err| {
            var owns = source;
            owns.deinit();
            return err;
        };
        defer worker.deinit(allocator);
        const stage = try worker.seal(allocator);
        fail.fail_index = fail.alloc_index;
        try std.testing.expectError(error.OutOfMemory, worker.spillMain(&store));
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
        try std.testing.expectEqualSlices(u8, &stage.main, &worker.scheme.trees.items[1].root());
        fail.fail_index = std.math.maxInt(usize);
        try std.testing.expect(try worker.spillMain(&store) > 0);
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    }
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
}
