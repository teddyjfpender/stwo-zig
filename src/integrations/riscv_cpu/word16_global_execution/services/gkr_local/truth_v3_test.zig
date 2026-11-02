const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = @import("truth_v3_catalog.zig");
const R = @import("../roster.zig");
const Role = @import("truth_v3_role.zig");
test "V3 secure readers instantiate all eight coordinates and original equations" {
    const O = core.fields.om31.OM31;
    const cases = .{ C.Sha(), C.Arith(), C.Curve(@as(A.crypto.curves.spec.Op, .bn254_g1_add)), C.Curve(@as(A.crypto.curves.spec.SecpKind, .add)) };
    inline for (cases) |T| {
        const View = struct {
            pub fn fixed(_: *@This(), _: usize) O {
                return O.zero();
            }
            pub fn main(_: *@This(), _: usize) O {
                return O.zero();
            }
            pub fn previousActive(_: *@This()) O {
                return O.zero();
            }
            pub fn interaction(_: *@This(), _: usize) O {
                return O.zero();
            }
            pub fn previousInteraction(_: *@This(), _: usize) O {
                return O.zero();
            }
        };
        var v = View{};
        var acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator.init(O.one());
        var sink = A.evaluation.SinkFor(O){ .accumulator = &acc };
        const wire = A.crypto.sha256.equations.WireFor(O){ .offset = O.one(), .coefficients = @splat(O.one()) };
        if (T.bytes == 0) T.Eq.emit(O, &v, .{ .calls = 0, .first_id = 1 }, O.zero(), wire, &sink) else T.Eq.emit(O, &v, .{ .calls = 0, .first_id = 1 }, O.zero(), .{ .bytes = O.one(), .wire = wire }, &sink);
        try std.testing.expectEqual(T.main_constraints + T.byte_batches + T.wire_batches, sink.count);
    }
}

fn runV3(truth: R.Truth, source: R.TruthSource) !void {
    const W = @import("truth_v3_worker.zig");
    const P = @import("worker_protocol.zig");
    const Manifest = @import("manifest.zig");
    const a = std.testing.allocator;
    const O = P.O;
    const cfg = P.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 4) };
    const declaration = @import("../wire.zig").TruthDeclaration.from(truth);
    const descriptor = try C.descriptorForDeclaration(declaration);
    const counts = try C.lookupCountsForDeclaration(declaration);
    try std.testing.expectEqual((try C.shape(truth)).main, descriptor.shape.main);
    try std.testing.expect(counts.wire_denominator_slots >= (try W.truthMass(truth)).wire);
    _ = try @import("truth_v3_retention.zig").forTruth(a, truth, cfg, 256 << 20);
    const expected = Manifest.ExpectedWorker{ .kind = .delegation, .global_relations = .{ .ram = false, .kio = false, .wire = true }, .mass = try W.truthMass(truth), .ordinal = 0, .statement = try W.truthStatement(truth, cfg, @splat(17)), .fixed = truth.key().root, .local_instances = null };
    var worker = W.TruthWorker.init(a, truth, source, expected, cfg, 256 << 20) catch |err| {
        var owned = source;
        owned.deinit();
        return err;
    };
    defer worker.deinit(a);
    const stage = try worker.seal(a);
    var ch = P.Channel.init();
    var shared: Manifest.Shared = undefined;
    shared.ram.offset = ch.drawSecureFelt();
    for (&shared.ram.coefficients) |*x| x.* = ch.drawSecureFelt();
    shared.kio = A.crypto.keccak.equations.IoFor(O).draw(&ch);
    shared.wire = A.crypto.secp256k1.equations.WireFor(O).draw(&ch);
    var entries = [_]Manifest.Entry{.{ .kind = .delegation, .global_relations = expected.global_relations, .mass = expected.mass, .scope = .{ .ordinal = 0, .statement = expected.statement, .fixed = expected.fixed, .main = stage.main }, .local = null }};
    const pending = Manifest.PendingManifest{ .entries = &entries, .digest = @splat(29), .shared = shared };
    var encoded = try worker.complete(a, &pending, 0, 256 << 20);
    defer encoded.deinit(a);
    const claims = try W.verifyTruth(a, truth, expected, &pending, 0, cfg, &encoded);
    try std.testing.expect(claims.ram.isZero() and claims.kio.isZero());
    try std.testing.expect(claims.wire.eql(encoded.claims[0]));
    encoded.claims[0] = encoded.claims[0].add(O.one());
    if (W.verifyTruth(a, truth, expected, &pending, 0, cfg, &encoded)) |_| return error.ExpectedV3TamperRejection else |_| {}
}
test "V3 SHA physical OM proof fresh receiver and claim mutation" {
    const a = std.testing.allocator;
    const HR = @import("../../sha256/roster.zig");
    var setup = try HR.TruthSetup.init(a, 5);
    defer setup.deinit();
    var source = try A.crypto.sha256.trace.Source.init(a, &.{A.crypto.sha256.native.PADDING}, 1, 5);
    a.free(source.fixed);
    source.fixed = setup.fixed;
    source.owns_fixed = false;
    try runV3(.{ .sha256 = .{ .setup = &setup, .first_id = 1, .calls = 1 } }, .{ .sha256 = .{ .source = source } });
}
test "V3 arith256 physical OM proof byte closure and fresh receiver" {
    const a = std.testing.allocator;
    const HR = @import("../../arith256/roster.zig");
    var setup = try HR.TruthSetup.init(a, 8);
    defer setup.deinit();
    var source = try A.crypto.arith256.trace.Source.init(a, &.{.{ .a = 2, .b = 3, .c = 1, .m = 97, .r_before = 0 }}, 1, 8);
    a.free(source.fixed);
    source.fixed = setup.fixed;
    source.owns_fixed = false;
    try runV3(.{ .arith256_mod = .{ .setup = &setup, .first_id = 1, .calls = 1 } }, .{ .arith256_mod = .{ .source = source } });
}
test "V3 curve physical OM proof byte closure and fresh receiver" {
    const a = std.testing.allocator;
    const HR = @import("../../curves/roster.zig");
    const op = A.crypto.curves.Op.bn254_fp2_mul;
    var setup = try HR.TruthSetup.init(a, op, 8);
    defer setup.deinit();
    const N = A.crypto.curves.Native(op);
    var source = try A.crypto.curves.Trace(op).Source.init(a, &.{@as(N.Packet, @splat(0))}, 1, 8);
    a.free(source.fixed);
    source.fixed = setup.fixed;
    source.owns_fixed = false;
    try runV3(.{ .curve = .{ .setup = &setup, .first_id = 1, .calls = 1 } }, .{ .curve = @unionInit(HR.TruthSource, @tagName(op), source) });
}
test "V3 secp ADD DOUBLE physical OM 4n proofs and fresh receivers" {
    const a = std.testing.allocator;
    const HR = @import("../../secp/row_roster.zig");
    inline for (.{ A.crypto.curves.spec.SecpKind.add, A.crypto.curves.spec.SecpKind.double }) |op| {
        var setup = try HR.TruthSetup.init(a, op, 8);
        defer setup.deinit();
        const N = A.crypto.curves.Native(op);
        var source = try A.crypto.curves.Trace(op).Source.init(a, &.{@as(N.Packet, @splat(0))}, 1, 8);
        a.free(source.fixed);
        source.fixed = setup.fixed;
        source.owns_fixed = false;
        try runV3(.{ .secp_row = .{ .setup = &setup, .first_id = 1, .calls = 1 } }, .{ .secp_row = @unionInit(HR.TruthSource, @tagName(op), source) });
    }
}
