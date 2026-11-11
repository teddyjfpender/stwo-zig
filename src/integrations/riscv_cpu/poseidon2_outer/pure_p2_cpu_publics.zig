//! Shared concrete CPU public-word and original OODS authority. This module
//! owns no child proof, receipt, transcript or execution admission. Both callers
//! supply a genuine checked local artifact; no source origin is substituted.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const C = @import("full_p2_common.zig");
const V = @import("../rv64_recursion/om31_native/mod.zig");
const Public = @import("full_p2_frame.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Components = @import("../word16_global_execution/services/gkr_local/cpu_components.zig");
const Oods = @import("../rv64_recursion/om31_native/cpu_oods.zig");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const F = C.F;
pub const ChainInputs = struct {
    steps: Public.Word,
    epoch: Public.Word,
    initial_pc: [4]Public.Word,
    final_pc: [4]Public.Word,
    initial_registers: [32][4]Public.Word,
    final_registers: [32][4]Public.Word,
    register_clocks: [32]Public.Word,
    sponge_first: Public.Word,
    rows: []const Public.Word,
    calls: []const Public.Word,
    first_ids: []const Public.Word,
};
pub fn flag(ctx: *C.Context, count: F, native: u32) !F {
    const nonzero = try F.guess(ctx, if (ctx.trace_only or native == 0) C.O.zero() else C.O.one());
    const inverse = try F.guess(ctx, if (ctx.trace_only or native == 0) C.O.zero() else try C.O.fromBase(core.fields.m31.M31.fromCanonical(native)).inv());
    try ctx.noteWitnessHint(nonzero.c0.v, .is_nonzero, count.c0.v, ctx.zero());
    try ctx.noteWitnessHint(nonzero.c1.v, .zero, ctx.zero(), ctx.zero());
    // count is the canonical M31 projection of an admitted public count.
    try ctx.noteWitnessHint(inverse.c0.v, .pointwise_inverse_or_zero, count.c0.v, ctx.zero());
    try ctx.noteWitnessHint(inverse.c1.v, .zero, ctx.zero(), ctx.zero());
    try C.eq(ctx, nonzero.mul(nonzero.sub(F.one())), F.zero());
    try C.eq(ctx, count.mul(F.one().sub(nonzero)), F.zero());
    try C.eq(ctx, count.mul(inverse), nonzero);
    return nonzero;
}

pub const Terminal = struct { artifact: *const engine.lookups.verifier_kernel.Artifact(F), challenges: @import("../word16_global_execution/services/gkr_local/challenges.zig").For(F), eta: F };
pub const Body = struct { setup: *const R.CpuSetup, plan: Components.Plan, publics: []const Oods.PublicFor(F), chain_inputs: ChainInputs };
pub fn init(frame: *Public.Frame, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, op_span: ?T.OpTowerSpan, local_instances: []const Frame.Instance, terminal: Terminal, claims: []const F, shared: Public.Shared) !Body {
    return initWithEpoch(frame, setup, request, first, op_span, local_instances, terminal, claims, shared, null);
}
/// New typed child scopes can reuse their already exposed epoch word. The old
/// constructor supplies null and retains its exact guess/frame operation order.
pub fn initWithEpoch(frame: *Public.Frame, setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, op_span: ?T.OpTowerSpan, local_instances: []const Frame.Instance, terminal: Terminal, claims: []const F, shared: Public.Shared, bound_epoch: ?Public.PublicU32) !Body {
    const ctx = frame.ctx;
    const a = ctx.scratch();
    if (op_span) |span| {
        if (!setup.op_only) return error.UnsupportedOpPurePoseidonStatement;
        try span.validate(setup.bridges);
    } else if (setup.op_only or setup.bridges.tower != null) return error.UnsupportedOpPurePoseidonStatement;
    const cpu = request.base.cpu;
    const steps_word = try frame.guessU32(cpu.steps);
    const epoch_word = bound_epoch orelse try frame.guessU32(request.base.epoch);
    const steps = steps_word.base;
    const epoch = epoch_word.base;
    var chain_inputs: ChainInputs = undefined;
    chain_inputs.steps = steps_word.word;
    chain_inputs.epoch = epoch_word.word;
    var initial_pc: [4]F = undefined;
    var final_pc: [4]F = undefined;
    for (0..4) |i| {
        const initial = try frame.guessU32(@as(u16, @truncate(cpu.initial_pc >> @as(u6, @intCast(16 * i)))));
        const final = try frame.guessU32(@as(u16, @truncate(cpu.final_pc >> @as(u6, @intCast(16 * i)))));
        initial_pc[i] = initial.base;
        final_pc[i] = final.base;
        chain_inputs.initial_pc[i] = initial.word;
        chain_inputs.final_pc[i] = final.word;
    }
    var source_public = [_]F{F.zero()} ** Oods.Authority.Source.Public.count;
    const SP = Oods.Authority.Source.Public;
    source_public[SP.epoch] = epoch;
    source_public[SP.initial_pc] = initial_pc[0].add(initial_pc[1].mul(F.fromBase(core.fields.m31.M31.fromCanonical(65536))));
    for (0..32) |r| {
        for (0..4) |i| {
            const initial = try frame.guessU32(@as(u16, @truncate(cpu.initial_registers[r] >> @as(u6, @intCast(16 * i)))));
            const final = try frame.guessU32(@as(u16, @truncate(cpu.final_registers[r] >> @as(u6, @intCast(16 * i)))));
            source_public[SP.initial_registers + 4 * r + i] = initial.base;
            source_public[SP.final_registers + 4 * r + i] = final.base;
            chain_inputs.initial_registers[r][i] = initial.word;
            chain_inputs.final_registers[r][i] = final.word;
        }
        const clock = try frame.guessU32(cpu.register_clocks[r]);
        source_public[SP.register_clocks + r] = clock.base;
        chain_inputs.register_clocks[r] = clock.word;
    }
    const inputs = A.word16_execution.types.InputsFor(F){ .steps = steps, .initial_pc = initial_pc, .final_pc = final_pc, .epoch = epoch, .wide_clock = A.word16_execution.layout.wideClock(setup.materials.geometry.cpu_log) };
    const plan = if (op_span != null) try Components.Plan.initForOp(a, setup) else try Components.Plan.init(a, setup);
    if (claims.len != plan.claim_count) return error.InvalidWideCpuClaims;
    const instances = local_instances;
    if (instances.len != plan.binding_count) return error.WideCpuRosterMismatch;
    const publics = try a.alloc(Oods.PublicFor(F), plan.slots.len);
    const ls_counts = try setup.materials.geometry.lsCounts(request.base.memory.ls_count);
    const dword_counts = try T.dwordCounts(setup.bridges, request.ls_dword);
    const sponge_first_word = try frame.guessU32(request.sponge.first_id);
    const sponge_first = sponge_first_word.base;
    chain_inputs.sponge_first = sponge_first_word.word;
    const row_words = try a.alloc(Public.Word, plan.slots.len);
    const call_words = try a.alloc(Public.Word, plan.slots.len);
    const first_words = try a.alloc(Public.Word, plan.slots.len);
    chain_inputs.rows = row_words;
    chain_inputs.calls = call_words;
    chain_inputs.first_ids = first_words;
    for (publics, plan.slots, 0..) |*public, slot, slot_index| {
        var rows_native: u32 = 0;
        var calls_native: u32 = 0;
        var first_native: u32 = 1;
        switch (slot.origin) {
            .core => |role| rows_native = switch (role) {
                .initial => @intCast(request.base.memory.initial.len),
                .terminal => @intCast(request.base.memory.terminal.len),
                .ls => ls_counts.head,
                .ls_tail => ls_counts.tail,
                .multiplication => request.base.multiplication_requests,
                .division => request.base.division_requests,
                else => 0,
            },
            .bridge => |family| {
                calls_native = request.calls[@intFromEnum(family)];
                first_native = first[@intFromEnum(family)];
            },
            .bulk => |kind| rows_native = request.bulk.rows(kind),
            .sponge => |kind| rows_native = request.sponge.rows(kind),
            else => {
                if (slot.origin == .dword) {
                    rows_native = dword_counts[slot.origin.dword];
                } else if (slot.origin == .tower) {
                    const span = op_span orelse return error.UnsupportedOpPurePoseidonStatement;
                    calls_native = span.calls;
                    first_native = span.first_id;
                } else return error.UnsupportedOpPurePoseidonStatement;
            },
        }
        const row_word = try frame.guessU32(rows_native);
        const call_word = try frame.guessU32(calls_native);
        const first_word = try frame.guessU32(first_native);
        const rows = row_word.base;
        const calls = call_word.base;
        const first_id = first_word.base;
        row_words[slot_index] = row_word.word;
        call_words[slot_index] = call_word.word;
        first_words[slot_index] = first_word.word;
        var sp = source_public;
        sp[SP.sponge_first_id] = sponge_first;
        const nclaims = Oods.Authority.Global.claimCount(slot.origin);
        public.* = .{
            .main = .{ .cpu = inputs, .rows = rows, .nonempty = try flag(ctx, rows, rows_native), .span = .{ .calls = calls, .first_id = first_id, .nonempty = try flag(ctx, calls, calls_native) } },
            .source = sp,
            .shared = .{ .ram = shared.ram, .kio = shared.kio, .wire = shared.wire },
            .claims = try Oods.Authority.Global.claimsFromVector(F, slot.origin, claims[slot.claim_offset..][0..nclaims]),
            .local = if (slot.binding_index) |index| try Oods.localFromArtifact(F, a, instances[index], index, terminal.artifact.*, terminal.challenges, terminal.eta) else null,
        };
    }

    return .{ .setup = setup, .plan = plan, .publics = publics, .chain_inputs = chain_inputs };
}
pub fn emitComposition(setup: *const R.CpuSetup, plan: *const Components.Plan, publics: []const Oods.PublicFor(F), ctx: *C.Context, point: V.Point, global_log: u32, sampled: []const []const []const F, accumulator: *E.lane.PointAccumulator(F)) !void {
    for (plan.slots, publics) |slot, public| {
        const descriptor = Oods.Authority.Source.Descriptor{ .origin = slot.origin, .cpu_u8_pairs = setup.materials.geometry.cpu_u8_pairs, .cpu_compact_decode = setup.materials.geometry.cpu_compact_decode };
        _ = try Oods.evaluateRole(F, ctx.scratch(), descriptor, slot, public, .{ .x = point.x, .y = point.y }, global_log, sampled, accumulator);
    }
}

/// Source publics only, no worker kind, child receipt or borrowed fake scope.
pub fn appendExpected(a: std.mem.Allocator, words: *std.ArrayList(u32), setup: *const R.CpuSetup, request: P.Request, first: [T.FAMILIES]u32, op_span: ?T.OpTowerSpan, claims_len: usize, include_epoch: bool) !void {
    const cpu = request.base.cpu;
    try words.append(a, cpu.steps);
    if (include_epoch) try words.append(a, request.base.epoch);
    for (0..4) |i| {
        const shift: u6 = @intCast(i * 16);
        try words.appendSlice(a, &.{ @as(u16, @truncate(cpu.initial_pc >> shift)), @as(u16, @truncate(cpu.final_pc >> shift)) });
    }
    for (0..32) |r| {
        for (0..4) |i| {
            const shift: u6 = @intCast(i * 16);
            try words.appendSlice(a, &.{ @as(u16, @truncate(cpu.initial_registers[r] >> shift)), @as(u16, @truncate(cpu.final_registers[r] >> shift)) });
        }
        try words.append(a, cpu.register_clocks[r]);
    }
    try words.append(a, request.sponge.first_id);
    var plan = if (op_span != null) try Components.Plan.initForOp(a, setup) else try Components.Plan.init(a, setup);
    defer plan.deinit();
    if (claims_len != plan.claim_count) return error.InvalidWideCpuClaims;
    const ls = try setup.materials.geometry.lsCounts(request.base.memory.ls_count);
    const dword = try T.dwordCounts(setup.bridges, request.ls_dword);
    for (plan.slots) |slot| {
        var rows: u32 = 0;
        var calls: u32 = 0;
        var first_id: u32 = 1;
        switch (slot.origin) {
            .core => |role| rows = switch (role) {
                .initial => @intCast(request.base.memory.initial.len),
                .terminal => @intCast(request.base.memory.terminal.len),
                .ls => ls.head,
                .ls_tail => ls.tail,
                .multiplication => request.base.multiplication_requests,
                .division => request.base.division_requests,
                else => 0,
            },
            .bridge => |family| {
                calls = request.calls[@intFromEnum(family)];
                first_id = first[@intFromEnum(family)];
            },
            .bulk => |kind| rows = request.bulk.rows(kind),
            .sponge => |kind| rows = request.sponge.rows(kind),
            else => {
                if (slot.origin == .dword) {
                    rows = dword[slot.origin.dword];
                } else if (slot.origin == .tower) {
                    const span = op_span orelse return error.UnsupportedOpPurePoseidonStatement;
                    calls = span.calls;
                    first_id = span.first_id;
                } else return error.UnsupportedOpPurePoseidonStatement;
            },
        }
        try words.appendSlice(a, &.{ rows, calls, first_id });
    }
}
