//! CPU state/counter transitions for typed leaves. This is one part of leaf
//! admission: compact-public hashing, numerical verification, source count/
//! mass projection and typed_leaf.constrain must also run on the same handles.
const std = @import("std");
const C = @import("common.zig");
const Public = @import("frame.zig");
const Hash = @import("canon_hash.zig");
const Summary = @import("node_summary_v3.zig");
const Counter = @import("typed_root.zig").Counter;
const Integer = @import("typed_integer.zig");
const Cpu = @import("cpu_leaf.zig");
const Native = @import("../../word16_global_execution/services/native_gkr/cpu_statement.zig");
const Expected = @import("../../word16_global_execution/services/protocol.zig").Expected;
const T = @import("../../word16_global_execution/services/types.zig");
const Table = @import("../vk_table.zig");
const Bounds = @import("../node_summary.zig");
pub const Policy = struct {
    cpu_log: u32,
    compact_pc: bool,
    family: @import("../../word16_global_execution/ethereum/canon_native.zig").Family = .cpu_single,
    pub fn fromSetup(source: *const @import("../../word16_global_execution/services/roster.zig").CpuSetup, family: @import("../../word16_global_execution/ethereum/canon_native.zig").Family) Policy {
        return .{.cpu_log=source.materials.geometry.cpu_log,.compact_pc=source.materials.geometry.cpu_compact_decode,.family=family};
    }
};
pub const Assignment = struct { metadata: Native.Metadata, inputs: Native.Inputs, expected: Expected };
pub fn constrain(ctx: *C.Context, policy: Policy, plan: *const @import("../../word16_global_execution/services/gkr_local/cpu_components.zig").Plan,
    node: Summary.Wires, metadata: Hash.CompactCpuMetadata, inputs: Cpu.Statement.ChainInputs, expected: Hash.Expected, assignment: Assignment) ![3]Public.Word {
    try constrainTransitions(ctx,policy,node,metadata,inputs,expected,assignment);
    return @import("typed_cpu_projection.zig").constrain(ctx,plan,metadata,inputs,node,assignment);
}
fn same(ctx: *C.Context, actual: []const Public.Word, wanted: []const Public.Word) !void {
    if (actual.len != wanted.len) return error.TypedCpuWordCount;
    for (actual, wanted) |a, b| try ctx.eq(a.get(), b.get());
}
/// metadata uses the compact visitor's wire-shaped fields. Assignment only
/// supplies range/carry witnesses and never grants authority to those fields.
pub fn constrainTransitions(ctx: *C.Context, policy: Policy, node: Summary.Wires, metadata: anytype, inputs: Cpu.Statement.ChainInputs, expected: Hash.Expected, assignment: Assignment) !void {
    if(policy.cpu_log<5 or policy.cpu_log>22)return error.TypedCpuSourcePolicy;
    const zero = try Table.constWord(ctx, 0);
    const one = try Table.constWord(ctx, 1);
    const n = node.assignment;
    try ctx.eq(metadata.ordinal.get(), node.raw[Summary.Index.lo].get());
    // CPU segments occupy the initial contiguous part of the native chain.
    try ctx.eq(metadata.ordinal.get(),node.raw[Summary.Index.ctr_in+Counter.cpu_next].get());
    try ctx.eq(metadata.steps_in[1].get(), zero.get());
    try ctx.eq(metadata.steps_in[0].get(), node.raw[Summary.Index.steps_in].get());
    try ctx.eq(inputs.epoch.get(), metadata.cpu_ordinal.get());
    try ctx.eq(metadata.cpu_ordinal.get(), node.raw[Summary.Index.ctr_out + Counter.cpu_next].get());
    try Integer.addTo(ctx, node.raw[Summary.Index.ctr_in + Counter.cpu_next], one,
        node.raw[Summary.Index.ctr_out + Counter.cpu_next], n.ctr_in[Counter.cpu_next], 1);
    try Integer.atMost(ctx, one, inputs.steps, 1, assignment.inputs.steps);
    const step_cap=(@as(u32,1)<<@intCast(policy.cpu_log))-1;
    try Integer.atMost(ctx,inputs.steps,try Table.constWord(ctx,step_cap),assignment.inputs.steps,step_cap);
    const clock_bound=try Integer.scale(ctx,inputs.steps,assignment.inputs.steps,4);
    for(inputs.register_clocks,assignment.inputs.register_clocks) |clock,value|
        try Integer.atMost(ctx,clock,clock_bound,value,4*assignment.inputs.steps);
    try ctx.eq(inputs.register_clocks[0].get(),zero.get());
    for(inputs.initial_registers[0]++inputs.final_registers[0]) |limb|try ctx.eq(limb.get(),zero.get());
    try admitPc(ctx,policy,inputs.initial_pc,assignment.inputs.initial_pc);
    try admitPc(ctx,policy,inputs.final_pc,assignment.inputs.final_pc);
    try ctx.eq(expected.admission.max_prefix_steps[1].get(), zero.get());
    try Integer.atMost(ctx, inputs.steps, expected.admission.max_prefix_steps[0], assignment.inputs.steps, @intCast(assignment.expected.admission.max_prefix_steps));
    try Integer.addTo(ctx, node.raw[Summary.Index.steps_in], inputs.steps, node.raw[Summary.Index.steps_out], n.steps_in, assignment.inputs.steps);
    try ctx.eq(expected.total_steps[1].get(), zero.get());
    try Integer.atMost(ctx, node.raw[Summary.Index.steps_out], expected.total_steps[0], n.steps_out, @intCast(assignment.expected.total_steps));
    for (0..T.FAMILIES) |family| {
        try Integer.addTo(ctx, node.raw[Summary.Index.ctr_in + Counter.cpu_calls + family], metadata.calls[family],
            node.raw[Summary.Index.ctr_out + Counter.cpu_calls + family], n.ctr_in[Counter.cpu_calls + family], assignment.metadata.calls[family]);
        try Integer.addTo(ctx, node.raw[Summary.Index.ctr_in + Counter.cpu_calls + family], one,
            metadata.first_ids[family], n.ctr_in[Counter.cpu_calls + family], 1);
        try ctx.eq(node.raw[Summary.Index.ctr_in + Counter.truth_next + family].get(), node.raw[Summary.Index.ctr_out + Counter.truth_next + family].get());
    }
    // Sponge permutations follow ALL plain Keccak calls in the global ID
    // space. They have a separate cumulative cursor across CPU shards.
    try ctx.eq(metadata.sponge[2].get(), inputs.sponge_first.get());
    const active_sponge = try Integer.nonzero(ctx, metadata.sponge[1], assignment.metadata.sponge[1]);
    try ctx.eq(try Integer.canonical(ctx, metadata.sponge[2]), try ctx.mul(active_sponge,
        try node.integer(ctx, Summary.Index.ctr_in + Counter.sponge_next)));
    try Integer.atMost(ctx, metadata.sponge[0], metadata.sponge[1], assignment.metadata.sponge[0], assignment.metadata.sponge[1]);
    const max_per_call = @import("stwo_riscv_frontend").rv64_air.crypto.keccak_sponge.types.Native.MAX_LEN / 136 + 1;
    try Integer.atMostScaled(ctx,metadata.sponge[1],metadata.sponge[0],assignment.metadata.sponge[1],assignment.metadata.sponge[0],max_per_call);
    try Integer.addTo(ctx, node.raw[Summary.Index.ctr_in + Counter.sponge_next], metadata.sponge[1],
        node.raw[Summary.Index.ctr_out + Counter.sponge_next], n.ctr_in[Counter.sponge_next], assignment.metadata.sponge[1]);
    for ([_]usize{Counter.boundary_lo, Counter.boundary_hi}) |index|
        try ctx.eq(node.raw[Summary.Index.ctr_in + index].get(), node.raw[Summary.Index.ctr_out + index].get());

    // A positive-step CPU shard is terminal exactly when it reaches the
    // globally pinned total. Both sums/comparisons above are integer bounded.
    const final_word = node.raw[Summary.Index.output_seen];
    const final = try Integer.canonical(ctx, final_word);
    try ctx.eq(try ctx.mul(final, final), final);
    const difference = try ctx.sub(try Integer.canonical(ctx, expected.total_steps[0]), try node.integer(ctx, Summary.Index.steps_out));
    const value: u32 = @intCast(assignment.expected.total_steps - n.steps_out);
    const inverse = try ctx.guess(if (ctx.trace_only or value == 0) C.Q.zero() else try C.Q.fromU32Unchecked(value, 0, 0, 0).inv());
    try ctx.noteWitnessHint(inverse, .pointwise_inverse_or_zero, difference, ctx.zero());
    try ctx.eq(try ctx.mul(difference, final), ctx.zero());
    try ctx.eq(try ctx.mul(difference, inverse), try ctx.sub(ctx.one(), final));
    switch(policy.family){
        .cpu_first,.cpu_single=>try ctx.eq(node.raw[Summary.Index.ctr_in+Counter.cpu_next].get(),zero.get()),
        .cpu_middle,.cpu_last=>try Integer.atMost(ctx,one,node.raw[Summary.Index.ctr_in+Counter.cpu_next],1,n.ctr_in[Counter.cpu_next]),
        else=>return error.TypedCpuSourcePolicy,
    }
    try ctx.eq(final,if(policy.family==.cpu_last or policy.family==.cpu_single)ctx.one() else ctx.zero());
    const initial = try Hash.state(ctx, inputs.initial_pc, inputs.initial_registers, zero);
    const terminal = try Hash.state(ctx, inputs.final_pc, inputs.final_registers, final_word);
    try same(ctx, node.raw[Summary.Index.s_in..][0..8], &initial);
    try same(ctx, node.raw[Summary.Index.s_out..][0..8], &terminal);
    // The terminal commitment is public here. The root checks it against the
    // pinned image and public terminal RAM, whose claim closes internal RAM.
    // Summary.validate forces zero output on every nonterminal CPU shard.
    try C.lane.check();
}
fn admitPc(ctx:*C.Context,policy:Policy,words:[4]Public.Word,values:[4]u32)!void{
    const quarter=try ctx.guess(C.Q.fromU32Unchecked(values[0]>>2,0,0,0));
    try Bounds.rangeBits(ctx,quarter,14,Bounds.bitsOf(values[0]>>2,14));
    try ctx.eq(try Integer.canonical(ctx,words[0]),try ctx.mul(quarter,try ctx.constant(C.Q.fromU32Unchecked(4,0,0,0))));
    if(policy.compact_pc){
        try ctx.eq(words[2].get(),ctx.zero());try ctx.eq(words[3].get(),ctx.zero());
        try Integer.atMost(ctx,words[1],try Table.constWord(ctx,32767),values[1],32767);
        const imaginary=try ctx.constant(C.Q.fromU32Unchecked(0,1,0,0));
        const raw:Public.Word=.newUnsafe(try ctx.add(words[0].get(),try ctx.mul(words[1].get(),imaginary)));
        const value=try std.math.add(u32,values[0],try std.math.mul(u32,values[1],65536));
        try ctx.eq(try Integer.nonzero(ctx,raw,value),ctx.one());
    }
}

test "typed CPU transitions bind integer steps call cursors epoch state and terminal presence" {
    const Canon = @import("../../word16_global_execution/ethereum/canon_native.zig");
    const e = @import("../../word16_global_execution/services/fixture.zig").expectedFor(@splat(31));
    const native_inputs = Native.Inputs{ .steps = 7, .epoch = 1, .initial_pc = .{4096,0,0,0}, .final_pc = .{4124,0,0,0},
        .initial_registers = @splat(@splat(0)), .final_registers = @splat(@splat(0)), .register_clocks = @splat(0),
        .sponge_first = 0, .rows = &.{}, .calls = &.{}, .first_ids = &.{} };
    var m = Native.Metadata{ .ordinal = 0, .execution = @splat(0), .mass = .{}, .relations = 0, .cpu_ordinal = 1,
        .steps_in = 0, .sponge = .{0,0,0} };
    m.calls[0] = 2;
    var node = Summary.Native{ .tnat = @splat(0), .trec = @splat(0), .image = @splat(0), .statement = @splat(0), .chi = @splat(0),
        .lo = 0, .hi = 0, .count = 1, .m_in = @splat(0), .m_out = @splat(0),
        .s_in = Canon.stateDigest(4096, @splat(0), false), .s_out = Canon.stateDigest(4124, @splat(0), true),
        .bus = @splat(C.O.zero()), .mass = @splat(0), .ctr_in = @splat(0), .ctr_out = @splat(0),
        .steps_in = 0, .steps_out = 7, .expected = @splat(0), .output = @splat(0), .output_seen = true, .depth = 0 };
    node.ctr_out[Counter.cpu_next] = 1;
    node.ctr_out[Counter.cpu_calls] = 2;
    node.ctr_in[Counter.sponge_next] = 3;
    node.ctr_out[Counter.sponge_next] = 3;
    const Metadata = struct { ordinal: Public.Word, cpu_ordinal: Public.Word, steps_in: Hash.U64,
        calls: [T.FAMILIES]Public.Word, first_ids: [T.FAMILIES]Public.Word, sponge: [3]Public.Word };
    for (0..15) |mutation| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        C.lane.begin(&ctx);
        defer C.lane.finish() catch {};
        var changed = node;
        var assigned_metadata = m;
        var assigned_inputs = native_inputs;
        if (mutation == 8) {
            assigned_metadata.sponge = .{1,2,3};
            assigned_inputs.sponge_first = 3;
            changed.ctr_out[Counter.sponge_next] = 5;
        }
        if (mutation == 12) {
            var registers: [32]u64=@splat(0);registers[0]=1;
            changed.s_in=Canon.stateDigest(4096,registers,false);
            assigned_inputs.initial_registers[0][0]=1;
        }
        if (mutation == 1) changed.ctr_out[Counter.cpu_calls] += 1;
        if (mutation == 2) changed.steps_out += 1;
        if (mutation == 3) changed.output_seen = false;
        if (mutation == 4) changed.s_in[0] ^= 1;
        const wires = try Summary.Wires.guess(&ctx, changed);
        var meta: Metadata = .{ .ordinal = try Table.guessWord(&ctx, 0), .cpu_ordinal = try Table.guessWord(&ctx, 1),
            .steps_in = .{try Table.guessWord(&ctx, 0),try Table.guessWord(&ctx, 0)}, .calls = undefined, .first_ids = undefined, .sponge = undefined };
        for (0..T.FAMILIES) |f| {
            meta.calls[f] = try Table.guessWord(&ctx, m.calls[f]);
            meta.first_ids[f] = try Table.guessWord(&ctx, m.first_ids[f] + @as(u32,@intFromBool(mutation == 5 and f == 0)));
        }
        for (&meta.sponge, assigned_metadata.sponge) |*word, value| word.* = try Table.guessWord(&ctx, value);
        var inputs: Cpu.Statement.ChainInputs = .{ .steps = try Table.guessWord(&ctx, 7),
            .epoch = try Table.guessWord(&ctx, if (mutation == 7) 2 else 1), .initial_pc = undefined, .final_pc = undefined,
            .initial_registers = undefined, .final_registers = undefined, .register_clocks = undefined,
            .sponge_first = try Table.guessWord(&ctx, if (mutation == 6) 4 else assigned_inputs.sponge_first), .rows = &.{}, .calls = &.{}, .first_ids = &.{} };
        for (&inputs.initial_pc, native_inputs.initial_pc) |*word, value| word.* = try Table.guessWord(&ctx, value);
        for (&inputs.final_pc, native_inputs.final_pc) |*word, value| word.* = try Table.guessWord(&ctx, value);
        for (0..32) |r| for (0..4) |i| {
            inputs.initial_registers[r][i] = try Table.guessWord(&ctx, 0);
            inputs.final_registers[r][i] = try Table.guessWord(&ctx, 0);
        };
        for (&inputs.register_clocks) |*word| word.* = try Table.guessWord(&ctx, 0);
        if(mutation==10){inputs.register_clocks[0]=try Table.guessWord(&ctx,1);assigned_inputs.register_clocks[0]=1;}
        if(mutation==11){inputs.register_clocks[1]=try Table.guessWord(&ctx,29);assigned_inputs.register_clocks[1]=29;}
        if(mutation==12)inputs.initial_registers[0][0]=try Table.guessWord(&ctx,1);
        const result = constrainTransitions(&ctx,.{.cpu_log=5,.compact_pc=mutation==9,.family=if(mutation==13).cpu_first else if(mutation==14).cpu_last else .cpu_single}, wires, meta, inputs, try Hash.guessExpected(&ctx, e), .{ .metadata = assigned_metadata, .inputs = assigned_inputs, .expected = e });
        const valid = if (result) |_| try ctx.isCircuitValid() else |err| blk: {
            if (mutation != 2 and mutation != 11 and mutation != 14) return err;
            break :blk false;
        };
        try std.testing.expectEqual(mutation == 0 or mutation == 8 or mutation == 9, valid);
    }
}
