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
    return runProfile(truth, source, false);
}
fn runProfile(truth: R.Truth, source: R.TruthSource, comptime beta2: bool) !void {
    const Fixed = @import("fixed_authority.zig");
    const config = P.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, if (beta2) 2 else 1, 12) };
    var cache: ?Fixed.Fixed.Cache = if (beta2) try Fixed.Fixed.Cache.init(a, 1 << 30) else null;
    defer if (cache) |*owner| owner.deinit();
    var fixed: ?Fixed.Binding = if (cache) |*owner| try Fixed.Binding.acquire(owner, truth.key(), config) else null;
    defer if (fixed) |*binding| binding.deinit();
    const fixed_ptr: ?*const Fixed.Binding = if (fixed) |*binding| binding else null;
    const expected = Manifest.ExpectedWorker{ .kind = switch (truth) {
        .keccak => .keccak,
        .secp => |t| if (t.setup.kind == .add) .secp_add else .secp_double,
        else => unreachable, // test helper: v2 truths only
    }, .global_relations = .{ .ram = false, .kio = truth == .keccak, .wire = truth == .secp }, .mass = try W.truthMass(truth), .ordinal = 0, .statement = try W.truthStatementWithAuthority(truth, config, @splat(17), fixed_ptr), .fixed = if (fixed_ptr) |binding| binding.root() else truth.key().root, .local_instances = null };
    var worker = W.TruthWorker.initWithAuthority(a, truth, source, expected, config, 64 * 1024 * 1024, fixed_ptr) catch |err| {
        var s = source;
        s.deinit();
        return err;
    };
    defer worker.deinit(a);
    var native_profile = @import("stwo_prover_api").stage_profile.Recorder.init(a, "rv64", "truth-worker-stage-scope");
    defer native_profile.deinit();
    worker.native_recorder = &native_profile;
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
    {
        const Authority = @import("mass_authority.zig");
        var counts = @import("mass_authority_test_support.zig").Counter{};
        var metadata = try @import("truth_global_metadata.zig").Provider.init(a, &worker.source, 64 << 20);
        defer metadata.deinit();
        const shapes = try @import("truth_components.zig").shapesForDeclaration(@import("../wire.zig").TruthDeclaration.from(truth));
        for (shapes) |shape| {
            if (shape.kind != .keccak and shape.kind != .product and shape.kind != .linear) continue;
            for (0..@as(usize, 1) << @intCast(shape.log_size)) |row| try metadata.emit(shape.kind, row, &counts);
        }
        try std.testing.expectEqualDeep(try Authority.truth(@import("../wire.zig").TruthDeclaration.from(truth)), counts.totals);
    }
    var local_channel = worker.channel;
    const local_challenges = @import("truth_fractions.zig").ChallengesFor(O).draw(&local_channel);
    var encoded = try worker.complete(a, &pending, 0, 64 * 1024 * 1024);
    defer encoded.deinit(a);
    var profile = try native_profile.snapshot(a);
    defer profile.deinit(a);
    var found: usize = 0;
    for (profile.stages) |stage_node| if (std.mem.eql(u8, stage_node.id, "interaction_generation")) {
        found += 1;
        try std.testing.expect(stage_node.children == null);
    };
    try std.testing.expectEqual(@as(usize, 1), found);
    try std.testing.expectEqual(@as(usize, 0), native_profile.stack.items.len);
    var rejecting = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var bad = config;
    bad.pow_bits = 33;
    try std.testing.expectError(error.UnsupportedWideServicesConfig, W.verifyTruthWithAuthority(rejecting.allocator(), truth, expected, &pending, 0, bad, &encoded, fixed_ptr));
    try std.testing.expectEqual(@as(usize, 0), rejecting.alloc_index);
    {
        const Components = @import("truth_components.zig");
        const descriptors = try Components.shapesForDeclaration(@import("../wire.zig").TruthDeclaration.from(truth));
        const physical = try Components.Components.init(truth, local_challenges, pending.shared, encoded.claims);
        var global_log: u32 = 0;
        for (descriptors) |shape| global_log = @max(global_log, shape.log_size);
        var channel_for_point = P.Channel.init();
        const point = try core.circle.randomSecureFieldPointFor(O, &channel_for_point);
        for (physical.items, descriptors) |component, descriptor| {
            try std.testing.expectEqualDeep(descriptor.widths(), component.widths());
            try std.testing.expectEqual(descriptor.nConstraints(), component.nConstraints());
            var masks = try component.maskPoints(a, point, global_log);
            defer masks.deinitDeep(a);
            for (masks.items) |tree| for (tree) |column| try std.testing.expect(column.len <= descriptor.maxSamples());
            for (0..component.nConstraints()) |i| try std.testing.expect(try component.constraintDegreeBound(i) <= descriptor.maxDegree());
        }
    }
    var decoded = try P.decodePhysical(a, encoded.bytes);
    defer decoded.deinit(a);
    decoded.commitment_scheme_proof.config.fri_config.n_queries += 1;
    const changed_config_bytes = try P.encodePhysical(a, decoded);
    defer a.free(changed_config_bytes);
    var changed_config = encoded;
    changed_config.bytes = changed_config_bytes;
    try std.testing.expectError(error.WideTruthProofConfig, W.verifyTruthWithAuthority(a, truth, expected, &pending, 0, config, &changed_config, fixed_ptr));
    decoded.commitment_scheme_proof.config = config;
    // Revision metadata is not representable in the current wide wire codec;
    // directly qualify the same structured guard used after decoding.
    const Revision = core.pcs.config_v2;
    decoded.commitment_scheme_proof.revision_config = Revision.PcsConfigV2.fromFriAndTraceSize(try Revision.FriConfigV2.init(config.pow_bits, 0, config.fri_config.log_blowup_factor, @intCast(config.fri_config.n_queries), config.fri_config.fold_step), 5);
    try std.testing.expectError(error.WideTruthProofConfig, W.validateProofConfig(&decoded, config));
    decoded.commitment_scheme_proof.revision_config = null;
    const claims = try W.verifyTruthWithAuthority(a, truth, expected, &pending, 0, config, &encoded, fixed_ptr);
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
    if (W.verifyTruthWithAuthority(a, truth, expected, &pending, 0, config, &encoded, fixed_ptr)) |_| return error.MutatedPureGlobalDebtAccepted else |_| {}
    encoded.claims[3] = global;
    const old = encoded.claims[0];
    encoded.claims[0] = old.add(O.one());
    try std.testing.expectError(error.UnclosedWideTruthLocalClaims, W.verifyTruthWithAuthority(a, truth, expected, &pending, 0, config, &encoded, fixed_ptr));
    encoded.claims[0] = old;
    const wrong = entries[0].scope.main;
    entries[0].scope.main[0] ^= 1;
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, W.verifyTruthWithAuthority(a, truth, expected, &pending, 0, config, &encoded, fixed_ptr));
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
    const expected = Manifest.ExpectedWorker{ .kind = .keccak, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .mass = try W.truthMass(truth), .ordinal = 0, .statement = try W.truthStatement(truth, config, @splat(17)), .fixed = truth.key().root, .local_instances = null };
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
    const expected = Manifest.ExpectedWorker{ .kind = .keccak, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .mass = try W.truthMass(truth), .ordinal = 0, .statement = try W.truthStatement(truth, config, @splat(17)), .fixed = truth.key().root, .local_instances = null };
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

test "beta2 K and ADD truth physical proofs separately close local claims and authenticate globals" {
    var ksetup = try @import("../../keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer ksetup.deinit();
    try runProfile(.{ .keccak = .{ .setup = &ksetup, .first_id = 3, .calls = 2 } }, try @import("truth_test.zig").keccakSource(), true);
    const source = try @import("truth_test.zig").secpSource(.canonical_inputs);
    var ssetup = @import("../../secp/roster.zig").TruthSetup.init(a, .add, .{ source.secp.batch.product.log_size, source.secp.batch.linear.log_size }) catch |err| {
        var owner = source;
        owner.deinit();
        return err;
    };
    defer ssetup.deinit();
    try runProfile(.{ .secp = .{ .setup = &ssetup, .first_id = 5, .calls = 1 } }, source, true);
}
