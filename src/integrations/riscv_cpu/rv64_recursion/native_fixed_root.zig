//! The native verifier's fixed commitment is receiver authority, not a guess.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const builder = circuit.builder;
const Context = builder.Context(Q);
pub fn enforce(ctx: *Context, guessed: builder.blake.HashValue(builder.Var), expected_root: [32]u8) !void {
    const expected = try builder.blake.constantHash(Q, ctx, builder.blake.hashValueFromDigest(Q, expected_root));
    for (guessed.words, expected.words) |actual, wanted| try ctx.eq(actual.get(), wanted.get());
}
test "native fixed commitment is constrained in circuit including full u32 high bits" {
    var expected: [32]u8 = undefined;
    for (&expected, 0..) |*byte, i| byte.* = @truncate(251 * i + 193);
    for (0..9) |mutation| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var actual = builder.blake.hashValueFromDigest(Q, expected);
        if (mutation < 8) {
            var words = @import("stwo_core").vcs.blake2_hash.digestToU32s(expected);
            words[mutation] ^= 0x80000000;
            actual = builder.blake.hashValue(Q, words);
        }
        const guessed = try builder.blake.guessHash(Q, &ctx, actual);
        try enforce(&ctx, guessed, expected);
        try std.testing.expectEqual(@as(usize, 8), ctx.circuit.eq.items.len);
        try ctx.finalize(false);
        try std.testing.expectEqual(mutation == 8, try ctx.isCircuitValid());
    }
}
