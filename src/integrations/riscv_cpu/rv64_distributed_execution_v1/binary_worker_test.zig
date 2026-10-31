const std = @import("std");
const Worker = @import("binary_worker.zig");
const D = @import("../rv64_distributed_v1/manifest.zig");
const MetadataFixture = @import("../rv64_distributed_v1/manifest_test.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const a = std.testing.allocator;

test "shared BINARY actual proof returns an open debt only after local AND closes" {
    // This is a provider-only qualification. The metadata CPU below has an
    // actual PCS commitment, but deliberately no CPU proof/acceptance API.
    var other = try MetadataFixture.Fixture.init();
    defer other.deinit();
    var material = try Worker.Materials.init(a, 5);
    defer material.deinit();
    const facts = [_]Worker.Fact{
        .{ .op = .and_, .a = 0xffff800012345678, .b = 0xff8033ff55558888, .c = 0xffff800012345678 & 0xff8033ff55558888 },
        .{ .op = .xor, .a = 0x8000ffff123400ff, .b = 0x83ff7fff66558844, .c = 0x8000ffff123400ff ^ 0x83ff7fff66558844 },
    };
    const spec = material.descriptor(1, facts.len, @splat(33), @splat(34));
    var stage = try Worker.Stage1.init(a, &material, MetadataFixture.context(), spec, &facts);
    defer stage.deinit();
    const inventory = [_]D.T.Spec{ other.specs[0], spec };
    var manifest = try D.Manifest.init(a, .{ .context = MetadataFixture.context(), .specs = &inventory }, &.{ other.receipts[0], stage.receipt });
    defer manifest.deinit();
    stage.source.releaseMain(); // committed coefficients, narrow advice survive.
    var encoded = try stage.complete(&manifest, 1);
    defer encoded.deinit(a);
    try std.testing.expectError(error.InvalidDistributedBinaryPhase, stage.complete(&manifest, 1));
    const debt = try Worker.verifyOpen(a, &material, &manifest, 1, encoded);
    const ch = (try manifest.derive()).binary;
    var expected = Q.zero();
    for (facts) |fact| {
        var tuple: [13]Q = undefined;
        tuple[0] = E.q(switch (fact.op) {
            .and_ => 16,
            .or_ => 17,
            .xor => 18,
        });
        for ([_]u64{ fact.a, fact.b, fact.c }, 0..) |word, i| for (0..4) |j| {
            tuple[1 + 4 * i + j] = E.q(@intCast((word >> @intCast(16 * j)) & 65535));
        };
        expected = expected.sub(try ch.denominatorFor(Q, tuple).inv());
    }
    try std.testing.expect(debt.eql(expected));
    encoded.claims.function = encoded.claims.function.add(Q.one());
    if (Worker.verifyOpen(a, &material, &manifest, 1, encoded)) |_| return error.AcceptedAlteredOpenDebt else |_| {}
}
