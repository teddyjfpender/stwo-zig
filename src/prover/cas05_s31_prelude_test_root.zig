//! Focused experimental CAS05/S31 transcript custody test.
const std = @import("std");
const core = @import("stwo_core");
const host = @import("stwo_prover_engine").pcs.paired_sparse_cascade_experimental;
const cascade = core.pcs.paired_sparse_cascade_experimental;
const wire = core.pcs.paired_sparse_cascade_wire;
const prelude = core.pcs.s31_cas05_prelude_experimental;
const M31 = core.fields.m31.M31;
const Channel = core.channel.blake2s.Blake2sChannel;

test {
    _ = prelude;
}

test "S31 CAS05 candidate transcript binds trusted key public words and AIR roster" {
    const allocator = std.testing.allocator;
    const top = [_]M31{M31.fromCanonical(7)} ** 32;
    const low = [_]M31{M31.fromCanonical(11)} ** 16;
    const h0 = [_][]const M31{&top};
    const h1 = [_][]const M31{&low};
    const heights = [_][]const []const M31{ &h0, &h1 };
    const input = host.Input{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 3,
    };
    const binding = prelude.Binding{
        .installed_key_sha256 = [_]u8{0x11} ** 32,
        .public_words = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .source_air_roster_sha256 = [_]u8{0x22} ** 32,
    };
    var prover_channel = Channel{};
    var owned = try host.proveForS31Statement(allocator, input, &prover_channel, binding);
    defer owned.deinit();
    const encoded = try wire.encode(allocator, owned.proof);
    defer allocator.free(encoded);
    const statement = cascade.ExpectedStatement{
        .profile = owned.proof.profile,
        .source_root = owned.proof.source_root,
        .claims = owned.proof.claims,
    };
    var verifier_channel = Channel{};
    try wire.verifyAgainstS31Statement(allocator, encoded, &verifier_channel, binding, statement);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);

    var changed = binding;
    changed.installed_key_sha256[0] ^= 1;
    var rejected = Channel{};
    const initial = Channel{};
    try std.testing.expectError(error.UnsampledOodPoint, wire.verifyAgainstS31Statement(
        allocator,
        encoded,
        &rejected,
        changed,
        statement,
    ));
    try std.testing.expectEqualSlices(u8, &initial.digest, &rejected.digest);
    changed = binding;
    changed.public_words[0] ^= 1;
    try std.testing.expectError(error.UnsampledOodPoint, wire.verifyAgainstS31Statement(
        allocator,
        encoded,
        &rejected,
        changed,
        statement,
    ));
    try std.testing.expectEqualSlices(u8, &initial.digest, &rejected.digest);
    changed = binding;
    changed.source_air_roster_sha256[0] ^= 1;
    try std.testing.expectError(error.UnsampledOodPoint, wire.verifyAgainstS31Statement(
        allocator,
        encoded,
        &rejected,
        changed,
        statement,
    ));
    try std.testing.expectEqualSlices(u8, &initial.digest, &rejected.digest);

    var unbound = Channel{};
    try std.testing.expectError(error.UnsampledOodPoint, wire.verifyAgainstStatement(
        allocator,
        encoded,
        &unbound,
        statement,
    ));
    try std.testing.expectEqualSlices(u8, &initial.digest, &unbound.digest);
    var old_prover_channel = Channel{};
    var old_proof = try host.prove(allocator, input, &old_prover_channel);
    defer old_proof.deinit();
    const old_encoded = try wire.encode(allocator, old_proof.proof);
    defer allocator.free(old_encoded);
    try std.testing.expectError(error.UnsampledOodPoint, wire.verifyAgainstS31Statement(
        allocator,
        old_encoded,
        &rejected,
        binding,
        .{
            .profile = old_proof.proof.profile,
            .source_root = old_proof.proof.source_root,
            .claims = old_proof.proof.claims,
        },
    ));
    try std.testing.expectEqualSlices(u8, &initial.digest, &rejected.digest);
}
