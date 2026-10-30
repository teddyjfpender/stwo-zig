//! Genuine mixed original: producer destruction, bounded bytes and fresh keys.
//! Its endpoint-global plane remains OPEN, so this is not a block/root proof.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const Fixture = @import("block_v8_endpoint_mixed_fixture.zig");
const Proof = @import("../block_v8_endpoint_mixed_proof_v1.zig");
const Codec = @import("../block_v8_endpoint_mixed_codec_v1.zig");
const Statement = @import("../block_v8_endpoint_mixed_statement_v1.zig");
test "mixed original native SHA Keccak closes all local buses and freshly receives bytes" {
    _ = try run(.sha_keccak, false);
}
test "mixed original native recovery closes all local buses and freshly receives bytes" {
    _ = try run(.recovery, false);
}
fn run(kind: Fixture.Kind, batch: bool) ![32]u8 {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 12 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const fixture = try Fixture.Owned.init(a, kind, config);
    var fixture_live = true;
    defer if (fixture_live) fixture.deinit();
    var timing: Proof.Timings = .{};
    const original = try Proof.produceWithOptions(a, fixture.trusted, fixture.input(), fixture.current.?.owner.preprocessed.items, fixture.stages(), .{}, .{ .program = &fixture.image.?, .timings = &timing, .batch_native_projections = batch });
    var original_live = true;
    defer if (original_live) original.deinit();
    try std.testing.expectEqual(@as(usize, 15), original.stark.commitment_scheme_proof.commitments.items.len);
    try std.testing.expect(original.summary.external_retirements > 0);
    try std.testing.expectEqual(.mixed_execution_global_ram_open, original.summary.scope);
    var input = fixture.input();
    input.native_roots = original.native_roots;
    input.caller_roots = original.caller_roots;
    const public = try Statement.Owned.init(a, fixture.trusted, input);
    defer public.deinit();
    const bytes = try Codec.encode(a, original, fixture.trusted, input, .{});
    defer a.free(bytes);
    const expected = original.summary;
    original.deinit();
    original_live = false;
    fixture.deinit();
    fixture_live = false;
    const received = try Codec.verifyBytes(a, bytes, public.trusted, public.input, .{});
    try std.testing.expectEqualDeep(expected, received);
    // A separately nominated caller main root is not admitted by a host receipt.
    var wrong = public.input;
    wrong.caller_roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedEndpointEnvelope, Codec.verifyBytes(a, bytes, public.trusted, wrong, .{}));
    var decoded = try Codec.decode(a, bytes, public.trusted, public.input, .{});
    defer decoded.deinit();
    try std.testing.expect(decoded.claims.caller_ram.len >= 2);
    const claims = @constCast(decoded.claims.caller_ram);
    const delta = core.fields.qm31.QM31.fromBase(core.fields.m31.M31.one());
    const aggregate = claims[0].add(claims[1]);
    claims[0] = claims[0].add(delta);
    claims[1] = claims[1].sub(delta);
    try std.testing.expectEqualDeep(aggregate, claims[0].add(claims[1]));
    try std.testing.expectError(error.OodsNotMatching, Proof.verify(a, public.trusted, public.input, &decoded.stark, decoded.claims, .{}));
    std.debug.print("B8_MIXED_ORIGINAL kind={s} queries=70 pow=26 cycles={d} external={d} endpoint_count={d} bytes={d} whole_ns={d} global_ram_open=true\n", .{ @tagName(kind), received.cycles, received.external_retirements, received.source.endpoint_count, bytes.len, timing.whole_ns });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

test "mixed native domain batches preserve complete SHA Keccak original bytes" {
    try std.testing.expectEqualDeep(try run(.sha_keccak, false), try run(.sha_keccak, true));
}
test "mixed native domain batches preserve complete recovery original bytes" {
    try std.testing.expectEqualDeep(try run(.recovery, false), try run(.recovery, true));
}
