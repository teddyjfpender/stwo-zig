//! Fold-v3: authenticate every child, admit the exact verifier identity/FIXED
//! wires in T_rec, then combine its actual 180 public outputs. Callers derive
//! all child authorities and table geometry from source, never from the wire.
const std = @import("std");
const C = @import("common.zig");
const Bridge = @import("../om31_outer.zig");
const Summary = @import("node_summary_v3.zig");
const Table = @import("../vk_table.zig");
pub const Child = struct { proof: Bridge.Child, entry: Table.RecEntry, index: usize };
pub const Graph = struct {
    ctx: C.Context,
    summary: Summary.Native,
    pub fn deinit(self: *Graph) void {
        self.ctx.deinit();
        self.* = undefined;
    }
};

/// Bind the table header to the public summary. The header carries source
/// depth/count, so a path under a different-sized table cannot be substituted.
pub fn bindTable(ctx: *C.Context, table: *const Table.Table, parent: Summary.Wires) !C.Hash {
    const root = try Table.guessHash(ctx, table.root());
    var words: [11]Table.Word = undefined;
    words[0] = try Table.constWord(ctx, 1);
    words[1] = try Table.constWord(ctx, table.depth);
    words[2] = try Table.constWord(ctx, @intCast(table.count));
    words[3..11].* = root.words;
    const header = try Table.taggedCircuit(ctx, Table.TAG_REC_HEADER, &words);
    for (header.words, parent.raw[Summary.Index.trec..][0..8]) |got, want| try ctx.eq(got.get(), want.get());
    return root;
}

/// Authentication and membership share identity/FIXED handles. Metadata is
/// witnessed for stable fold topology; the membership authenticates it too.
pub fn admit(ctx: *C.Context, table: *const Table.Table, root: C.Hash, entry: Table.RecEntry, index: usize, authenticated: Bridge.Authenticated) !void {
    try entry.validate();
    if (entry.kind != .leaf and entry.kind != .fold) return error.TypedFoldChildKind;
    var payload = try Table.guessRecPayload(ctx, entry);
    payload[5..13].* = authenticated.identity;
    payload[13..21].* = authenticated.fixed_root.words;
    // Only leaf/fold recursion is allowed here; compression has its own stage.
    const one = try Table.constWord(ctx, 1);
    const two = try Table.constWord(ctx, 2);
    const is_leaf = try ctx.sub(payload[0].get(), one.get());
    const is_fold = try ctx.sub(payload[0].get(), two.get());
    try ctx.eq(try ctx.mul(is_leaf, is_fold), ctx.zero());
    try Table.verifyMembership(ctx, .rec, table.depth, &payload, try Table.Witness.guess(ctx, table, index), root);
}

pub fn build(a: std.mem.Allocator, children: []const Child, table: *const Table.Table, trace_only: bool) !Graph {
    if (children.len < 2 or children.len > 4) return error.InvalidFoldArity;
    var values: [4]Summary.Native = undefined;
    for (children, 0..) |child, i| values[i] = try Summary.Native.fromOutputs(child.proof.produced.outputs);
    const native = try Summary.Native.combine(values[0..children.len]);
    var ctx = if (trace_only) try C.Context.initTraceOnly(a, Summary.N_WORDS) else try C.Context.init(a, Summary.N_WORDS);
    errdefer ctx.deinit();
    ctx.assert_eq_on_eval = !trace_only;
    C.lane.begin(&ctx);
    defer C.lane.finish() catch {};
    const parent = try Summary.Wires.guess(&ctx, native);
    const root = try bindTable(&ctx, table, parent);
    var wires: [4]Summary.Wires = undefined;
    for (children, 0..) |child, i| {
        const authenticated = try Bridge.verifyChild(&ctx, child.proof);
        try admit(&ctx, table, root, child.entry, child.index, authenticated);
        wires[i] = try Summary.Wires.bind(&ctx, authenticated.outputs, values[i]);
    }
    try Summary.combine(&ctx, wires[0..children.len], parent);
    try C.lane.check();
    var outputs: [Summary.N_WORDS]C.Var = undefined;
    for (&outputs, parent.raw) |*out, word| out.* = word.get();
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    return .{ .ctx = ctx, .summary = native };
}

test "typed fold admits the exact authenticated child identity and FIXED wires" {
    const a = std.testing.allocator;
    const entry = Table.RecEntry{ .kind = .fold, .arity = 2, .profile = 1, .identity = @splat(7), .fixed_root = @splat(8) };
    var table = try Table.buildRec(a, &.{entry});
    defer table.deinit();
    var raw: [Summary.N_WORDS]u32 = @splat(0);
    raw[0] = Summary.VERSION;
    raw[1] = Summary.N_WORDS;
    raw[Summary.Index.count] = 1;
    const header = Table.recHeader(&table);
    raw[Summary.Index.trec..][0..8].* = Table.digestWords(header);
    for (0..5) |mutation| {
        var ctx = try C.Context.init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        var values = raw;
        if (mutation == 3) values[Summary.Index.trec] ^= 1;
        const parent = try Summary.Wires.guess(&ctx, try Summary.Native.fromWords(&values));
        const root = try bindTable(&ctx, &table, parent);
        var identity = entry.identity;
        var fixed = entry.fixed_root;
        if (mutation == 1) identity[0] ^= 1;
        if (mutation == 2) fixed[0] ^= 1;
        const authenticated = Bridge.Authenticated{ .identity = (try Table.guessHash(&ctx, identity)).words, .fixed_root = try Table.guessHash(&ctx, fixed), .outputs = &.{}, .output_words = &.{} };
        var relabel = entry;
        if (mutation == 4) relabel.arity = 4;
        try admit(&ctx, &table, root, relabel, 0, authenticated);
        try C.lane.check();
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
    // Force Zig to typecheck the complete proof-authenticating constructor;
    // a production proof test remains a separate, stronger gate.
    try std.testing.expectError(error.InvalidFoldArity, build(a, &.{}, &table, false));
}
