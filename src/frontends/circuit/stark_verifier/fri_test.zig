//! `crates/stark_verifier/src/fri_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): `fri_commit`'s regression
//! values. `fold_coset` and `validate_query_position_in_coset` are private
//! to `fri.zig`, whose own tests port their cases.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const fri = @import("fri.zig");
const proof_mod = @import("proof.zig");
const Channel = @import("channel.zig").Channel;

const QM31 = core.fields.qm31.QM31;
const Context = builder.Context(QM31);
const Var = builder.Var;
const HashValue = builder.blake.HashValue;
const qm31 = builder.ivalue.qm31FromU32s;

test "fri: fri_commit regression" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel: Channel = .{ .digest = .{
        .low = try ctx.constant(qm31(375224163, 1270824854, 44060607, 991529112)),
        .high = try ctx.constant(qm31(1068130924, 1630210318, 1632828025, 1983481471)),
    }, .n_draws = 0 };

    const roots = [_][8]u32{
        .{ 370372302, 356302922, 2040089875, 232934191, 1279830905, 1240360672, 1788604172, 465814885 },
        .{ 1558212721, 609186473, 1554074721, 1956195301, 1243917617, 135256448, 1193318416, 1792104990 },
        .{ 1017503040, 1411053946, 1805475392, 1906875756, 2035075097, 617472393, 571220918, 1577790110 },
        .{ 1290083578, 670256590, 203247471, 492011214, 353269841, 1619070080, 770215254, 1663098736 },
    };
    // `FriCommitProof::guess`: the layer commitments, then the last layer.
    var commitments: [roots.len]HashValue(Var) = undefined;
    for (&commitments, roots) |*commitment, root| commitment.* = try builder.blake.guessHash(QM31, &ctx, builder.blake.hashValue(QM31, root));
    var last_layer = [_]Var{try ctx.guess(qm31(1802004671, 1018373769, 131996621, 1575090881))};
    const proof: proof_mod.FriProof(Var) = .{
        .layer_commitments = &commitments,
        .last_layer_coefs = &last_layer,
        .auth_paths = .{ .n_queries = 0, .trees = &.{} },
        .witness = &.{},
    };

    const alphas = try fri.friCommit(QM31, &ctx, &channel, &proof);
    const expected = [_]QM31{
        qm31(2047550788, 23895068, 1676134944, 263598239),
        qm31(1988032363, 1739489633, 826507892, 1797301629),
        qm31(1957504342, 848565442, 1129943791, 1937962621),
        qm31(1748651123, 2133979933, 232524784, 85583628),
    };
    try std.testing.expectEqual(expected.len, alphas.len);
    for (alphas, expected) |alpha, want| try std.testing.expect(ctx.get(alpha).eql(want));
    try std.testing.expect(ctx.get(channel.digest.low).eql(qm31(968886948, 725376924, 836084817, 484428276)));
    try std.testing.expect(ctx.get(channel.digest.high).eql(qm31(1805658819, 300032261, 172116750, 994058243)));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
