//! Source Plan projection linking compact CPU counters to the exact AIR count
//! handles. This closes the source-count input of typed_mass.cpu.
const std = @import("std");
const C = @import("common.zig");
const Hash = @import("canon_hash.zig");
const Public = @import("frame.zig");
const Table = @import("../vk_table.zig");
const Summary = @import("node_summary.zig");
const Counter = @import("typed_root.zig").Counter;
const Integer = @import("typed_integer.zig");
const Mass = @import("typed_mass.zig");
const SourceMass = @import("../../word16_global_execution/services/gkr_local/mass_authority.zig");
const Projection = @import("../../word16_global_execution/services/native_gkr/public_projection.zig");
const Plan = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig").Plan;
const Cpu = @import("cpu_leaf.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Part = struct { count: Mass.Count, cap: u32 = 0, present: bool = false };
fn own(part: *Part, count: Mass.Count, cap: u32) !void {
    if (part.present) return error.DuplicateTypedCpuCountRole;
    part.* = .{ .count = count, .cap = cap, .present = true };
}
fn split(ctx: *C.Context, total: Mass.Count, head: Part, tail: Part) !void {
    try Integer.addTo(ctx, head.count.word, tail.count.word, total.word, head.count.value, tail.count.value);
    const active_tail = try Integer.nonzero(ctx, tail.count.word, tail.count.value);
    try ctx.eq(try ctx.mul(active_tail, try ctx.sub(try Integer.canonical(ctx, head.count.word), try ctx.constant(C.Q.fromU32Unchecked(head.cap, 0, 0, 0)))), ctx.zero());
}
pub fn constrain(ctx: *C.Context, plan: *const Plan, metadata: Hash.CompactCpuMetadata, inputs: Cpu.Statement.ChainInputs, node: Summary.Wires, native: anytype) ![3]Public.Word {
    const n = plan.slots.len;
    if (inputs.rows.len != n or inputs.calls.len != n or inputs.first_ids.len != n or native.inputs.rows.len != n) return error.TypedCpuProjectionShape;
    const zero = try Table.constWord(ctx, 0);
    const one = try Table.constWord(ctx, 1);
    const z = Mass.Count{ .word = zero, .value = 0 };
    var counts = SourceMass.CpuCountsFor(Mass.Count){ .ls = .{ .word = metadata.ls_count, .value = native.metadata.ls_count }, .initial = z, .terminal = z, .calls = undefined, .dword = .{ .word = metadata.ls_dword, .value = native.metadata.ls_dword }, .sponge = undefined, .bulk = @splat(z) };
    for (&counts.calls, metadata.calls, native.metadata.calls) |*out, word, value| out.* = .{ .word = word, .value = value };
    for (&counts.sponge, metadata.sponge[0..2], native.metadata.sponge[0..2]) |*out, word, value| out.* = .{ .word = word, .value = value };
    var ls_head = Part{ .count = z };
    var ls_tail = ls_head;
    var dw_head = ls_head;
    var dw_tail = ls_head;
    var families: [T.FAMILIES]bool = @splat(false);
    var bulk: [8]bool = @splat(false);
    var sponge: [2]bool = @splat(false);
    var initial = false;
    var terminal = false;
    for (plan.slots, 0..) |slot, i| {
        const policy = try Projection.forSlot(slot);
        const row = Mass.Count{ .word = inputs.rows[i], .value = native.inputs.rows[i] };
        try Integer.atMost(ctx, row.word, try Table.constWord(ctx, policy.max_rows), row.value, policy.max_rows);
        if (policy.family) |f| {
            if (families[f]) return error.DuplicateTypedCpuCountRole;
            families[f] = true;
            try ctx.eq(inputs.calls[i].get(), metadata.calls[f].get());
            try ctx.eq(inputs.first_ids[i].get(), metadata.first_ids[f].get());
            try Integer.atMost(ctx, metadata.calls[f], try Table.constWord(ctx, policy.max_calls), native.metadata.calls[f], policy.max_calls);
        } else {
            try ctx.eq(inputs.calls[i].get(), zero.get());
            try ctx.eq(inputs.first_ids[i].get(), one.get());
        }
        switch (policy.rows) {
            .zero => try ctx.eq(row.word.get(), zero.get()),
            .initial_boundary => {
                if (initial) return error.DuplicateTypedCpuCountRole;
                initial = true;
                counts.initial = row;
            },
            .terminal_boundary => {
                if (terminal) return error.DuplicateTypedCpuCountRole;
                terminal = true;
                counts.terminal = row;
            },
            .ls_head => try own(&ls_head, row, policy.max_rows),
            .ls_tail => try own(&ls_tail, row, policy.max_rows),
            .dword_head => try own(&dw_head, row, policy.max_rows),
            .dword_tail => try own(&dw_tail, row, policy.max_rows),
            .multiplication, .division => {
                const bound = try Integer.scale(ctx, inputs.steps, native.inputs.steps, policy.steps_multiplier);
                try Integer.atMost(ctx, row.word, bound, row.value, native.inputs.steps * @as(u32, policy.steps_multiplier));
            },
            .bulk => {
                if (bulk[policy.index]) return error.DuplicateTypedCpuCountRole;
                bulk[policy.index] = true;
                try ctx.eq(row.word.get(), metadata.bulk[policy.index].get());
                counts.bulk[policy.index] = row;
            },
            .sponge => {
                if (sponge[policy.index]) return error.DuplicateTypedCpuCountRole;
                sponge[policy.index] = true;
                try ctx.eq(row.word.get(), metadata.sponge[policy.index].get());
            },
            .jump_table => {
                const active = try Integer.nonzero(ctx, metadata.bulk[6], native.metadata.bulk[6]);
                const expected = try ctx.mul(active, try ctx.constant(C.Q.fromU32Unchecked(Projection.JUMP_TABLE_ROWS, 0, 0, 0)));
                try ctx.eq(try Integer.canonical(ctx, row.word), expected);
                counts.bulk[T.bulk_kinds.len - 1] = row;
            },
        }
    }
    for (families, metadata.calls) |present, calls| if (!present) {
        try ctx.eq(calls.get(), zero.get());
    };
    for (bulk, metadata.bulk) |present, rows| if (!present) {
        try ctx.eq(rows.get(), zero.get());
    };
    for (sponge, metadata.sponge[0..2]) |present, rows| if (!present) {
        try ctx.eq(rows.get(), zero.get());
    };
    var relations: u32 = 1;
    if (families[0] or sponge[0] or sponge[1]) relations |= 2;
    for (families[1..]) |present| if (present) {
        relations |= 4;
    };
    try ctx.eq(metadata.relations.get(), (try Table.constWord(ctx, relations)).get());
    try split(ctx, counts.ls, ls_head, ls_tail);
    try split(ctx, counts.dword, dw_head, dw_tail);
    const memory = try Integer.sum(ctx, &.{ metadata.ls_count, metadata.ls_dword }, &.{ native.metadata.ls_count, native.metadata.ls_dword });
    try Integer.atMost(ctx, memory, inputs.steps, native.metadata.ls_count + native.metadata.ls_dword, native.inputs.steps);
    const after_first = try Integer.nonzero(ctx, node.raw[Summary.Index.ctr_in + Counter.cpu_next], node.assignment.ctr_in[Counter.cpu_next]);
    try ctx.eq(try ctx.mul(after_first, try Integer.canonical(ctx, counts.initial.word)), ctx.zero());
    const nonterminal = try ctx.sub(ctx.one(), try node.integer(ctx, Summary.Index.output_seen));
    try ctx.eq(try ctx.mul(nonterminal, try Integer.canonical(ctx, counts.terminal.word)), ctx.zero());
    return Mass.cpu(ctx, counts, metadata.mass);
}
test "source CPU projection binds count roles capacities splits absence and signed masses" {
    const Native = @import("../../word16_global_execution/services/native_gkr/cpu_statement.zig");
    const Slot = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig").Slot;
    const Origin = @import("../../word16_global_execution/services/gkr_local/frame.zig").Origin;
    const origins = [_]Origin{ .{ .core = .initial }, .{ .core = .terminal }, .{ .core = .ls }, .{ .core = .ls_tail }, .{ .bridge = .keccak }, .{ .core = .division }, .{ .core = .rom }, .{ .sponge = .call }, .{ .sponge = .perm }, .{ .bulk = .desc }, .{ .bulk = .copy } };
    var slots: [origins.len]Slot = undefined;
    for (&slots, origins, 0..) |*slot, origin, i| slot.* = .{ .origin = origin, .log = if (i == 4) 6 else 5, .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .binding_index = null, .claim_offset = 0 };
    const plan = Plan{ .allocator = std.testing.allocator, .slots = &slots, .inter_columns = 0, .claim_count = 0, .binding_count = 0 };
    var expected = @import("../../word16_global_execution/services/fixture.zig").expectedFor(@splat(31));
    expected.total_steps = 8;
    expected.max_total_steps = 8;
    var original_rows = [_]u32{ 3, 3, 3, 0, 0, 2, 0, 1, 2, 1, 1 };
    var original_calls: [origins.len]u32 = @splat(0);
    original_calls[4] = 2;
    var first_ids: [origins.len]u32 = @splat(1);
    var native_inputs = Native.Inputs{ .steps = 8, .epoch = 1, .initial_pc = @splat(0), .final_pc = @splat(0), .initial_registers = @splat(@splat(0)), .final_registers = @splat(@splat(0)), .register_clocks = @splat(0), .sponge_first = 3, .rows = &original_rows, .calls = &original_calls, .first_ids = &first_ids };
    var metadata = Native.Metadata{ .ordinal = 0, .execution = @splat(0), .mass = .{}, .relations = 3, .cpu_ordinal = 1, .ls_count = 3, .calls = @splat(0), .sponge = .{ 1, 2, 3 }, .bulk = .{ 1, 1, 0, 0, 0, 0, 0, 0 } };
    metadata.calls[0] = 2;
    const source_counts = SourceMass.CpuCountsFor(u32){ .ls = 3, .initial = 3, .terminal = 3, .calls = metadata.calls, .dword = 0, .sponge = .{ 1, 2 }, .bulk = .{ 1, 1, 0, 0, 0, 0, 0, 0, 0 } };
    metadata.mass = try SourceMass.evaluateCpuCounts(source_counts);
    var raw: [Summary.N_WORDS]u32 = @splat(0);
    raw[0] = Summary.VERSION;
    raw[1] = Summary.N_WORDS;
    raw[Summary.Index.count] = 1;
    raw[Summary.Index.output_seen] = 1;
    raw[Summary.Index.ctr_out + Counter.cpu_next] = 1;
    raw[Summary.Index.steps_out] = 8;
    raw[Summary.Index.ctr_out + Counter.cpu_calls] = 2;
    raw[Summary.Index.ctr_in + Counter.sponge_next] = 3;
    raw[Summary.Index.ctr_out + Counter.sponge_next] = 5;
    for (0..T.FAMILIES) |f| {
        raw[Summary.Index.ctr_in + Counter.truth_next + f] = 1;
        raw[Summary.Index.ctr_out + Counter.truth_next + f] = 1;
    }
    const Canon = @import("../../word16_global_execution/ethereum/canon_native.zig");
    raw[Summary.Index.s_in..][0..8].* = Table.digestWords(Canon.stateDigest(0, @splat(0), false));
    raw[Summary.Index.s_out..][0..8].* = Table.digestWords(Canon.stateDigest(0, @splat(0), true));
    for (0..8) |mutation| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        var rows = original_rows;
        var calls = original_calls;
        var ids = first_ids;
        var assigned_metadata = metadata;
        if (mutation == 1) calls[4] = 3;
        if (mutation == 2) {
            rows[2] = 2;
            rows[3] = 1;
        }
        if (mutation == 3) assigned_metadata.calls[1] = 1;
        if (mutation == 4) ids[4] = 2;
        if (mutation == 7) assigned_metadata.bulk[2] = 1;
        native_inputs.rows = &rows;
        native_inputs.calls = &calls;
        native_inputs.first_ids = &ids;
        const inputs = try Hash.guessCompactCpuInputs(&ctx, native_inputs);
        var wired_metadata = try Hash.guessCompactCpuMetadata(&ctx, assigned_metadata);
        if (mutation == 5) wired_metadata.mass.ram.positive[1] = try Table.guessWord(&ctx, 1);
        var changed = raw;
        if (mutation == 6) changed[Summary.Index.output_seen] = 0;
        const node = try Summary.Wires.guess(&ctx, try Summary.Native.fromWords(&changed));
        _ = try constrain(&ctx, &plan, wired_metadata, inputs, node, .{ .metadata = assigned_metadata, .inputs = native_inputs, .expected = expected });
        if (mutation == 0) _ = try @import("typed_cpu.zig").constrain(&ctx, .{ .cpu_log = 5, .compact_pc = false }, &plan, node, wired_metadata, inputs, try Hash.guessExpected(&ctx, expected), .{ .metadata = assigned_metadata, .inputs = native_inputs, .expected = expected });
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
