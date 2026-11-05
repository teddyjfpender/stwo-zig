//! Explicit AST candidate framing: source labels, length and all typed payload.
//! Native counterpart is NOT implemented/qualified; no compatibility claim.
const B = @import("stwo_circuit_frontend").builder;
const C = @import("full_p2_common.zig");
const S = @import("sponge.zig").ForContext(@import("context.zig").Context);
pub fn rawWords(ctx: *C.Context, words: []const B.wrappers.U32Wrapper(C.Var)) !C.Hash {
    var sponge = try S.init(try C.sidecar(ctx), .words);
    try sponge.absorbConstU32(0x50324632);
    try sponge.absorbConstU64(words.len);
    for (words) |word| {
        const lanes = B.simd.Simd.fromPacked(&[1]C.Var{word.get()}, 4);
        for (0..4) |i| {
            const part = try B.simd.unpackIdx(C.Q, ctx, lanes, i);
            if (i < 2) {
                const checked = try ctx.guessU16(if (ctx.trace_only) B.ivalue.placeholder(C.Q) else ctx.get(part));
                try ctx.eq(part, checked);
                try sponge.absorb(checked);
            } else try ctx.eq(part, ctx.zero());
        }
    }
    return sponge.finish();
}
pub fn bytes(ctx: *C.Context, values: []const C.Var) !C.Hash {
    var sponge = try S.init(try C.sidecar(ctx), .bytes);
    try sponge.absorbConstU32(0x50325232);
    try sponge.absorbConstU64(values.len);
    // Receipt writer already constrains each dynamic byte to[0,255].
    try sponge.absorbMany(values);
    return sponge.finish();
}
