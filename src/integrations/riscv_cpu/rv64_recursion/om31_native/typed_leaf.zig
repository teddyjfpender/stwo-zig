//! Shared admission of a native-GKR v2 leaf. Numerical native verification
//! must precede this helper and supply its SAME statement/MAIN/chi handles.
//! Request-specific CPU/truth transitions are separate mandatory constraints.
const std = @import("std");
const C = @import("common.zig");
const Public = @import("frame.zig");
const Hash = @import("canon_hash.zig");
const Summary = @import("node_summary_v3.zig");
const Table = @import("../vk_table.zig");
const Worker = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Canon = @import("../../word16_global_execution/ethereum/canon_native.zig");

/// Source-owned class authority. A receiver constructs it from the same native
/// key/roster as the numerical verifier. Never deserialize it from a receipt.
pub const Authority = struct {
    family: u32,
    rung: u32,
    native_vk: [32]u8,
    profile_identity: [32]u8,
    rung_table_identity: [32]u8,
    config: Worker.PcsConfig,
    table: *const Table.Table,
    index: usize,
};
pub const Authenticated = struct {
    ordinal: Public.Word,
    execution: Public.Digest,
    statement: Public.Digest,
    main: C.Hash,
    chi: Public.Digest,
    /// Internal RAM excludes the separately authenticated INITIAL/TERMINAL
    /// components. The final receiver recomputes those from public cells.
    globals: [3]C.F,
    /// Positive-use bounds constrained from source counts by the CPU/truth
    /// transition adapter. These are never free producer-declared net masses.
    mass: [3]Public.Word,
};
fn same(ctx: *C.Context, a: []const Public.Word, b: []const Public.Word) !void {
    if (a.len != b.len) return error.TypedLeafWordCount;
    for (a, b) |left, right| try ctx.eq(left.get(), right.get());
}
pub fn constrain(ctx: *C.Context, authority: Authority, node: Summary.Wires, expected: Hash.Expected, native: Authenticated) !void {
    try ctx.eq(node.raw[Summary.Index.lo].get(), native.ordinal.get());
    try ctx.eq(node.raw[Summary.Index.hi].get(), native.ordinal.get());
    try ctx.eq(node.raw[Summary.Index.count].get(), ctx.one());
    try ctx.eq(node.raw[Summary.Index.depth].get(), ctx.zero());
    try same(ctx, node.raw[Summary.Index.statement..][0..8], &native.execution);
    try same(ctx, node.raw[Summary.Index.chi..][0..8], &native.chi);
    try same(ctx, node.raw[Summary.Index.image..][0..8], &expected.admission.image_identity);
    const base = try Hash.executionIdentity(ctx, authority.config, expected);
    try same(ctx, node.raw[Summary.Index.expected..][0..8], &base);
    const execution = try Hash.gkrExecutionIdentity(ctx, authority.config, base);
    try same(ctx, &native.execution, &execution);

    const root = try Table.guessHash(ctx, authority.table.root());
    var header: [35]Table.Word = undefined;
    header[0] = try Table.constWord(ctx, 1);
    header[1] = try Table.constWord(ctx, authority.table.depth);
    header[2] = try Table.constWord(ctx, @intCast(authority.table.count));
    header[3..11].* = expected.admission.image_identity;
    header[11..19].* = try Public.constantDigest(ctx, authority.profile_identity);
    header[19..27].* = try Public.constantDigest(ctx, authority.rung_table_identity);
    header[27..35].* = root.words;
    const table_header = try Table.taggedCircuit(ctx, Table.TAG_NAT_HEADER, &header);
    try same(ctx, node.raw[Summary.Index.tnat..][0..8], &table_header.words);
    var payload: [Table.NatEntry.N_PAYLOAD]Table.Word = undefined;
    payload[0] = try Table.constWord(ctx, authority.family);
    payload[1] = try Table.constWord(ctx, authority.rung);
    payload[2..10].* = try Public.constantDigest(ctx, authority.native_vk);
    try Table.verifyMembership(ctx, .nat, authority.table.depth, &payload, try Table.Witness.guessAtConstantIndex(ctx, authority.table, authority.index), root);

    const rho = try Hash.mainOnlyRho(ctx, native.main.words);
    const next = try Hash.chainStep(ctx, node.raw[Summary.Index.m_in..][0..8].*, .{
        .k = native.ordinal,
        .family = payload[0],
        .rung = payload[1],
        .vkhash = payload[2..10].*,
        .stmt = native.statement,
        .s_in = node.raw[Summary.Index.s_in..][0..8].*,
        .s_out = node.raw[Summary.Index.s_out..][0..8].*,
        .rho = rho,
    });
    try same(ctx, node.raw[Summary.Index.m_out..][0..8], &next);
    for (0..3) |relation| {
        try C.eq(ctx, try node.secure(ctx, relation), native.globals[relation]);
        try ctx.eq(node.raw[Summary.Index.mass + relation].get(), native.mass[relation].get());
    }
    try C.lane.check();
}

test "native GKR MAIN-only rho agrees with canonical stage-one framing" {
    const main: [32]u8 = @splat(91);
    const reference = try Canon.rho(main, null, &.{});
    try std.testing.expectEqualSlices(u8, &reference, &Canon.mainOnlyRho(main));
    var ctx = try C.Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    defer C.lane.finish() catch {};
    const actual = try Hash.mainOnlyRho(&ctx, (try Table.guessHash(&ctx, main)).words);
    const constants = try Public.constantDigest(&ctx, reference);
    try same(&ctx, &actual, &constants);
    try C.lane.check();
    try std.testing.expect(try ctx.isCircuitValid());
}

test "typed leaf binds source native table stage-one MAIN scope and globals" {
    const a = std.testing.allocator;
    const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
    const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority_set.zig");
    const expected = @import("../../word16_global_execution/services/fixture.zig").expectedFor(@splat(31));
    const config = Worker.Candidate.configFor(.conjectured128_b2_q108_p20_fold4);
    const entry = Table.NatEntry{ .family = 1, .rung = 2, .vk_hash = @splat(32) };
    var table = try Table.buildNat(a, &.{entry});
    defer table.deinit();
    const profile: [32]u8 = @splat(33);
    const rungs: [32]u8 = @splat(34);
    const main: [32]u8 = @splat(35);
    const statement: [32]u8 = @splat(36);
    const base = Execution.executionIdentity(config, expected);
    const execution = try Fixed.gkrExecutionIdentity(base, config);
    var node = Summary.Native{ .tnat = Table.natHeader(&table, expected.admission.image_identity, profile, rungs), .trec = @splat(37), .image = expected.admission.image_identity, .statement = execution, .chi = @splat(38), .lo = 0, .hi = 0, .count = 1, .m_in = @splat(39), .m_out = undefined, .s_in = @splat(40), .s_out = @splat(41), .bus = @splat(C.O.one()), .mass = .{ 7, 11, 13 }, .ctr_in = @splat(0), .ctr_out = @splat(0), .steps_in = 0, .steps_out = 1, .expected = base, .output = @splat(0), .output_seen = false, .depth = 0 };
    node.m_out = Canon.chainStep(node.m_in, .{ .k = 0, .family = entry.family, .rung = entry.rung, .vkhash = entry.vk_hash, .stmt = statement, .s_in = node.s_in, .s_out = node.s_out, .rho = Canon.mainOnlyRho(main) });
    for (0..6) |mutation| {
        var ctx = try C.Context.init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        const wires = try Summary.Wires.guess(&ctx, node);
        var changed_main = main;
        var changed_execution = execution;
        if (mutation == 1) changed_main[0] ^= 1;
        if (mutation == 2) changed_execution[0] ^= 1;
        var authority = Authority{ .family = entry.family, .rung = entry.rung, .native_vk = entry.vk_hash, .profile_identity = profile, .rung_table_identity = rungs, .config = config, .table = &table, .index = 0 };
        if (mutation == 3) authority.native_vk[0] ^= 1;
        if (mutation == 4) authority.family += 1;
        var mass: [3]Public.Word = undefined;
        for (&mass, node.mass, 0..) |*out, value, i| out.* = try Table.guessWord(&ctx, value + @as(u32, @intFromBool(mutation == 5 and i == 0)));
        try constrain(&ctx, authority, wires, try Hash.guessExpected(&ctx, expected), .{
            .ordinal = try Table.guessWord(&ctx, 0),
            .execution = (try Table.guessHash(&ctx, changed_execution)).words,
            .statement = (try Table.guessHash(&ctx, statement)).words,
            .main = try Table.guessHash(&ctx, changed_main),
            .chi = (try Table.guessHash(&ctx, node.chi)).words,
            .globals = .{ C.F.one(), C.F.one(), C.F.one() },
            .mass = mass,
        });
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
