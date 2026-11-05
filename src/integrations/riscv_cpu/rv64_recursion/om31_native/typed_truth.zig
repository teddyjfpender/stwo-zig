//! Truth counter/state transitions. The numerical verifier must use these same
//! compact metadata handles for its AIR public values and native transcript.
const C = @import("common.zig");
const Public = @import("frame.zig");
const Summary = @import("node_summary_v3.zig");
const Counter = @import("typed_root.zig").Counter;
const Integer = @import("typed_integer.zig");
const Table = @import("../vk_table.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Canon = @import("../../word16_global_execution/ethereum/canon_native.zig");
const Declaration = @import("../../word16_global_execution/services/wire.zig").TruthDeclaration;
pub fn constrainTransitions(ctx: *C.Context, node: Summary.Wires, metadata: anytype, declaration: Declaration) !void {
    const family = @intFromEnum(declaration.family);
    const zero = try Table.constWord(ctx, 0);
    const one = try Table.constWord(ctx, 1);
    try ctx.eq(metadata.ordinal.get(), node.raw[Summary.Index.lo].get());
    try ctx.eq(metadata.family.get(), (try Table.constWord(ctx, @intFromEnum(Canon.Family.truth(declaration.family)))).get());
    for (metadata.logs, declaration.logs) |word, log| try ctx.eq(word.get(), (try Table.constWord(ctx, log)).get());
    try Integer.atMost(ctx, one, metadata.calls, 1, declaration.calls);
    try ctx.eq(metadata.first_id.get(), node.raw[Summary.Index.ctr_in + Counter.truth_next + family].get());
    for (0..T.FAMILIES) |f| {
        const index = Counter.truth_next + f;
        if (f == family) {
            try Integer.addTo(ctx, node.raw[Summary.Index.ctr_in + index], metadata.calls,
                node.raw[Summary.Index.ctr_out + index], node.assignment.ctr_in[index], declaration.calls);
        } else try ctx.eq(node.raw[Summary.Index.ctr_in + index].get(), node.raw[Summary.Index.ctr_out + index].get());
        try ctx.eq(node.raw[Summary.Index.ctr_in + Counter.cpu_calls + f].get(), node.raw[Summary.Index.ctr_out + Counter.cpu_calls + f].get());
    }
    for ([_]usize{Counter.sponge_next, Counter.cpu_next, Counter.boundary_lo, Counter.boundary_hi}) |index|
        try ctx.eq(node.raw[Summary.Index.ctr_in + index].get(), node.raw[Summary.Index.ctr_out + index].get());
    try ctx.eq(node.raw[Summary.Index.steps_in].get(), node.raw[Summary.Index.steps_out].get());
    for (node.raw[Summary.Index.s_in..][0..8], node.raw[Summary.Index.s_out..][0..8]) |before, after| try ctx.eq(before.get(), after.get());
    try ctx.eq(node.raw[Summary.Index.output_seen].get(), zero.get());
    try C.lane.check();
}
test "typed truth transitions bind one family span and stutter CPU state" {
    const std = @import("std");
    const declaration = Declaration{ .family = .add, .calls = 2, .first_id = 1, .logs = .{5,5} };
    var raw: [Summary.N_WORDS]u32 = @splat(0);
    raw[0] = Summary.VERSION;
    raw[1] = Summary.N_WORDS;
    raw[Summary.Index.count] = 1;
    for (0..T.FAMILIES) |f| {
        raw[Summary.Index.ctr_in + Counter.truth_next + f] = 1;
        raw[Summary.Index.ctr_out + Counter.truth_next + f] = 1;
    }
    raw[Summary.Index.ctr_out + Counter.truth_next + 1] = 3;
    const Metadata = struct { ordinal: Public.Word, family: Public.Word, first_id: Public.Word, calls: Public.Word, logs: [2]Public.Word };
    for (0..6) |mutation| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        var changed = raw;
        if (mutation == 1) changed[Summary.Index.ctr_out + Counter.truth_next + 1] += 1;
        if (mutation == 2) changed[Summary.Index.s_out] ^= 1;
        if (mutation == 5) changed[Summary.Index.output_seen] = 1;
        const node = try Summary.Wires.guess(&ctx, try Summary.Native.fromWords(&changed));
        const metadata = Metadata{ .ordinal = try Table.guessWord(&ctx, 0),
            .family = try Table.guessWord(&ctx, @intFromEnum(Canon.Family.truth(.add)) + @as(u32,@intFromBool(mutation == 3))),
            .first_id = try Table.guessWord(&ctx, if (mutation == 4) 2 else 1), .calls = try Table.guessWord(&ctx, 2),
            .logs = .{try Table.guessWord(&ctx, 5),try Table.guessWord(&ctx, 5)} };
        try constrainTransitions(&ctx, node, metadata, declaration);
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
