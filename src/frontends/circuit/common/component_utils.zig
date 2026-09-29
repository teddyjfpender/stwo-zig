//! Port of `crates/circuit_common/src/component_utils.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).

const std = @import("std");
const constraint_eval = @import("../stark_verifier/constraint_eval.zig");

/// `seq_of_component_size`: the evaluation of `seq_k` for the component's
/// log-height `k`, as `sum_k bit_k * seq_k` over the `seq_k` columns present,
/// followed by `eq(sum_k bit_k, one)`. Missing `seq_k` columns are skipped
/// without reading their bit. It re-emits its gates on every call; the
/// generated evaluators call it once per function body that reads `Seq`.
pub fn seqOfComponentSize(
    comptime Ctx: type,
    ctx: *Ctx,
    data: anytype,
    preprocessed_columns: *const constraint_eval.ColumnMap(Ctx.Var),
) !Ctx.Var {
    var sum_bits = ctx.zero();
    var result = ctx.zero();
    var name_buffer: [16]u8 = undefined;
    for (0..data.maxComponentSizeBits()) |log_size| {
        const name = std.fmt.bufPrint(&name_buffer, "seq_{d}", .{log_size}) catch unreachable;
        const seq_value = preprocessed_columns.get(name) orelse continue;
        const bit = try data.getNInstancesBit(ctx, log_size);
        sum_bits = try ctx.add(sum_bits, bit);
        result = try ctx.add(result, try ctx.mul(bit, seq_value));
    }
    try ctx.eq(sum_bits, ctx.one());
    return result;
}
