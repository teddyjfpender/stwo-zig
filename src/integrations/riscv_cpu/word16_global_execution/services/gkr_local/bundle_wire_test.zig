const std = @import("std");
const core = @import("stwo_core");
const Wire = @import("bundle_wire.zig");
const F = @import("coordinator_fixture.zig");
const Original = @import("../fixture.zig");
const R = @import("../roster.zig");
const a = std.testing.allocator;
fn readCase(allocator: std.mem.Allocator, dir: std.fs.Dir) !void {
    var loaded = try Wire.read(allocator, dir, .{});
    defer loaded.deinit(allocator);
}
test "complete wide proof files roundtrip into independent fresh keys and reject rekeyed geometry" {
    var fixture = try F.Case.init(a);
    defer fixture.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try Wire.write(a, tmp.dir, &fixture.keys.pointers(), &fixture.keys.truths(), &fixture.bundle);
    var loaded = try Wire.read(a, tmp.dir, .{});
    defer loaded.deinit(a);
    var fresh = try F.Keys.init(a);
    defer fresh.deinit();
    const expected = Original.expectedFor(fresh.cpus[0].materials.program.identity);
    const accepted = try loaded.bundle.verify(a, &fresh.pointers(), &fresh.truths(), expected, try F.config());
    try std.testing.expect(accepted.completed and accepted.total_steps == 7 and accepted.physical_proofs == 5);
    try std.testing.expectEqualSlices(u8, fixture.bundle.stage_one_bytes, loaded.bundle.stage_one_bytes);
    for (fixture.bundle.cpus, loaded.bundle.cpus) |before, after| {
        try std.testing.expectEqualSlices(u8, before.bytes, after.bytes);
        try std.testing.expectEqualSlices(@import("worker_protocol.zig").O, before.claims, after.claims);
    }
    // This is an admitted geometry with sufficient capacity, rebuilt into a
    // real different key. A proof cannot silently migrate with the declaration.
    var declaration = loaded.cpu_declarations[0];
    declaration.geometry.cpu_log = 6;
    var replacement = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Original.WORDS }, declaration.geometry, declaration.bridges);
    defer replacement.deinit();
    var pointers = fresh.pointers();
    pointers[0] = &replacement;
    if (loaded.bundle.verify(a, &pointers, &fresh.truths(), expected, try F.config())) |_| return error.AcceptedRekeyedGeometry else |_| {}
    try std.testing.checkAllAllocationFailures(a, readCase, .{tmp.dir});
    // File hashes are checked, but they are never cryptographic acceptance.
    var stage = try tmp.dir.openFile("stage-one.bin", .{ .mode = .read_write });
    defer stage.close();
    var first: [1]u8 = undefined;
    _ = try stage.preadAll(&first, 0);
    first[0] ^= 1;
    try stage.pwriteAll(&first, 0);
    try std.testing.expectError(error.WideBundleFileChanged, Wire.read(a, tmp.dir, .{}));
}

test "wide bundle metadata preflight rejects field alias claim width and budgets without keys" {
    // Transport-only fixture, deliberately no valid STARK or acceptance call.
    const Cpu = @typeInfo(@FieldType(Wire.Metadata, "cpus")).pointer.child;
    var claims = [_][8]u32{@splat(0)} ** 3;
    var cpus = [_]Cpu{.{ .declaration = .{ .geometry = .{ .cpu_log = 5 }, .bridges = .{} }, .request = .{ .cpu = .{ .steps = 1, .initial_pc = 4, .final_pc = 8, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) }, .epoch = 1, .memory_epoch = 1, .division_requests = 0, .multiplication_requests = 0, .ls_count = 0, .calls = @splat(0) }, .claims = &claims, .proof = .{ .bytes = 1, .sha256 = @splat(0) } }};
    var metadata = Wire.Metadata{ .cpus = &cpus, .truths = &.{}, .stage_one = .{ .bytes = 1, .sha256 = @splat(0) }, .memory_words = 0, .cells_sha256 = @splat(0) };
    try Wire.validate(metadata, .{});
    metadata.field_degree = 4;
    try std.testing.expectError(error.WideBundleProfile, Wire.validate(metadata, .{}));
    metadata.field_degree = 8;
    claims[0][7] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NoncanonicalWideBundleClaim, Wire.validate(metadata, .{}));
    claims[0][7] = 0;
    cpus[0].claims = claims[0..2];
    try std.testing.expectError(error.InvalidWideGlobalClaimShape, Wire.validate(metadata, .{}));
    cpus[0].claims = &claims;
    try std.testing.expectError(error.ServicesWireBudget, Wire.validate(metadata, .{ .max_total_proof_bytes = 1 }));
    try std.testing.expectError(error.ServicesProofLimit, Wire.validate(metadata, .{ .max_proof_bytes = 0 }));
    metadata.stage_one.bytes = @import("manifest_wire.zig").MAX_BYTES + 1;
    try std.testing.expectError(error.WideBundleStageLimit, Wire.validate(metadata, .{}));
}

test "wide route fails closed on every v3 bridge, call, bulk/sponge row and truth family" {
    // The OM GKR/wide services route is qualified for the v2 roster only. A v3
    // declaration must be rejected explicitly, never ignored or typed as secp.
    const Scope = @import("v2_scope.zig");
    const T = @import("../types.zig");
    try Scope.bridges(.{ .keccak = 5, .add = 5, .double = 5 });
    try Scope.calls(.{ 1, 1, 1 } ++ @as([T.FAMILIES - 3]u32, @splat(0)), .{}, .{});
    for (T.V3) |f| {
        var logs = T.Logs{};
        logs.set(f, 5);
        try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(logs));
        try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.family(f));
        var calls: [T.FAMILIES]u32 = @splat(0);
        calls[@intFromEnum(f)] = 1;
        try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.calls(calls, .{}, .{}));
    }
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(.{ .bulk = .{ .copy = 5 } }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(.{ .sponge = .{ .perm = 5 } }));
    // Unaligned memcpy / memcmp extension kinds are v3 bulk too.
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(.{ .bulk = .{ .ucopy = 5 } }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(.{ .bulk = .{ .cdesc = 5 } }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(.{ .bulk = .{ .cmp = 5 } }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.calls(@splat(0), .{ .ucopy_rows = 1 }, .{}));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.calls(@splat(0), .{ .cmp_calls = 1 }, .{}));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.calls(@splat(0), .{ .cmp_words = 1 }, .{}));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.calls(@splat(0), .{ .calls = 1 }, .{}));
    // JUMPDEST analysis kinds (jdesc/jscan/jtab) are v3 bulk too.
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(.{ .bulk = .{ .jdesc = 5 } }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(.{ .bulk = .{ .jscan = 5 } }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.bridges(.{ .bulk = .{ .jtab = 5 } }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.calls(@splat(0), .{ .jump_calls = 1 }, .{}));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.calls(@splat(0), .{ .jump_rows = 1 }, .{}));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.calls(@splat(0), .{}, .{ .perms = 1 }));

    // Transport preflight: an otherwise admissible v2 metadata turned v3.
    const Cpu = @typeInfo(@FieldType(Wire.Metadata, "cpus")).pointer.child;
    var claims = [_][8]u32{@splat(0)} ** 3;
    var cpus = [_]Cpu{.{ .declaration = .{ .geometry = .{ .cpu_log = 5 }, .bridges = .{} }, .request = .{ .cpu = .{ .steps = 1, .initial_pc = 4, .final_pc = 8, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) }, .epoch = 1, .memory_epoch = 1, .division_requests = 0, .multiplication_requests = 0, .ls_count = 0, .calls = @splat(0) }, .claims = &claims, .proof = .{ .bytes = 1, .sha256 = @splat(0) } }};
    var metadata = Wire.Metadata{ .cpus = &cpus, .truths = &.{}, .stage_one = .{ .bytes = 1, .sha256 = @splat(0) }, .memory_words = 0, .cells_sha256 = @splat(0) };
    try Wire.validate(metadata, .{});
    cpus[0].declaration.bridges.sha256 = 5;
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Wire.validate(metadata, .{}));
    cpus[0].declaration.bridges.sha256 = null;
    cpus[0].request.arith256_mod_calls = 1;
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Wire.validate(metadata, .{}));
    cpus[0].request.arith256_mod_calls = 0;
    cpus[0].request.bulk.calls = 1;
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Wire.validate(metadata, .{}));
    cpus[0].request.bulk.calls = 0;
    cpus[0].request.bulk.jump_calls = 1;
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Wire.validate(metadata, .{}));
    cpus[0].request.bulk.jump_calls = 0;
    cpus[0].declaration.bridges.bulk.jscan = 5;
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Wire.validate(metadata, .{}));
    cpus[0].declaration.bridges.bulk.jscan = null;
    try Wire.validate(metadata, .{});
    const Truth = @typeInfo(@FieldType(Wire.Metadata, "truths")).pointer.child;
    var truth_claims = [_][8]u32{@splat(0)} ** 5;
    const truths = [_]Truth{.{ .declaration = .{ .family = .sha256, .first_id = 1, .calls = 1, .logs = .{ 5, 0 } }, .claims = &truth_claims, .proof = .{ .bytes = 1, .sha256 = @splat(0) } }};
    metadata.truths = &truths;
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Wire.validate(metadata, .{}));

    // Throughput Keccak-f truth (wire logs[1] == 21) is v3-only: the GKR
    // roles, masses and statements describe the compact 2^13/2^10 tables.
    try Scope.truthDeclaration(.{ .family = .keccak, .first_id = 1, .calls = 1, .logs = .{ 5, 0 } });
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.truthDeclaration(.{ .family = .keccak, .first_id = 1, .calls = 1, .logs = .{ 5, 21 } }));
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.truthDeclaration(.{ .family = .keccak, .first_id = 1, .calls = 1, .logs = .{ 5, 13 } }));
    const KR = @import("../../keccak/shared/roster.zig");
    var compact: KR.TruthSetup = undefined;
    compact.log = 5;
    compact.policy = .triple_v2;
    try Scope.truth(.{ .keccak = .{ .setup = &compact, .first_id = 1, .calls = 1 } });
    var throughput = compact;
    throughput.policy = .throughput_v1;
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Scope.truth(.{ .keccak = .{ .setup = &throughput, .first_id = 1, .calls = 1 } }));
    const keccak_truths = [_]Truth{.{ .declaration = .{ .family = .keccak, .first_id = 1, .calls = 1, .logs = .{ 5, 21 } }, .claims = &truth_claims, .proof = .{ .bytes = 1, .sha256 = @splat(0) } }};
    metadata.truths = &keccak_truths;
    try std.testing.expectError(error.GkrV3ServiceUnsupported, Wire.validate(metadata, .{}));
}
