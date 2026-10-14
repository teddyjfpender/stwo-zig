//! Full Gate-shaped source geometry for experimental CAS09. These columns are
//! low-degree x+constant examples, not the actual Gate AIR/witness.
const std = @import("std");
const core = @import("stwo_core");
const host = @import("stwo_prover_engine").pcs.paired_independent_heights_experimental;
const cascade = core.pcs.paired_independent_heights_experimental;
const wire = core.pcs.paired_independent_heights_wire;
const M31 = core.fields.m31.M31;
const Channel = core.channel.blake2s.Blake2sChannel;

test "CAS09 full Gate-shaped roster verifies both degree tracks" {
    var input_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer input_arena.deinit();
    const a = input_arena.allocator();
    const counts = [_]usize{ 51, 0, 8, 0, 15, 0, 8, 0, 0, 0, 0, 28, 8, 0, 0, 0, 193 };
    var heights: [17][]const []const M31 = undefined;
    for (counts, 0..) |count, i| {
        const columns = try a.alloc([]const M31, count);
        if (count > 0) {
            const log_size: u32 = @intCast(20 - i);
            const values = try a.alloc(M31, @as(usize, 1) << @intCast(log_size));
            const domain = core.poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
            for (values, 0..) |*value, row| {
                const point = domain.at(core.utils.bitReverseIndex(row, log_size));
                value.* = point.x.add(M31.fromCanonical(@intCast(i + 1)));
            }
            for (columns) |*column| column.* = values;
        }
        heights[i] = columns;
    }
    const input = host.Input{ .source_columns = &heights, .log_blowup = 2, .n_queries = 232 };
    var prover_channel = Channel{};
    var timer = try std.time.Timer.start();
    var owned = try host.prove(std.testing.allocator, input, &prover_channel);
    defer owned.deinit();
    const proving_ns = timer.read();
    const encoded = try wire.encode(std.testing.allocator, owned.proof);
    defer std.testing.allocator.free(encoded);
    const statement = cascade.ExpectedStatement{
        .profile = owned.proof.profile,
        .source_root = owned.proof.source_root,
        .claims = owned.proof.claims,
    };
    var verifier_channel = Channel{};
    const start = timer.read();
    try wire.verifyAgainstStatement(std.testing.allocator, encoded, &verifier_channel, statement);
    const verifying_ns = timer.read() - start;
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqual(@as(usize, 16), owned.proof.line_openings.len);
    try std.testing.expectEqual(@as(usize, 2), owned.proof.terminals[0].len);
    try std.testing.expectEqual(@as(usize, 2), owned.proof.terminals[1].len);
    std.debug.print("CAS09_GATE_PILOT proving_ns={d} verifying_ns={d} proof_bytes={d}\n", .{ proving_ns, verifying_ns, encoded.len });
}
