//! In-circuit polynomial evaluation for the joined S31FCF01 SHA components.
//!
//! These routines emit the *same ordered constraint lists* as the native
//! components. They do not verify a proof: the joined transcript, shifted
//! openings, composition and FRI checks must all surround them.
const std = @import("std");
const core = @import("stwo_core");
const builder = @import("stwo_circuit_frontend").builder;
const caller = @import("sha_caller_stream_air.zig");
const caller_bus = @import("sha_caller_stream_bus.zig");
const feed = @import("sha_feed_direct_air.zig");
const fused = @import("sha_fused_air.zig");
const fused_word_bus = @import("sha_fused_word_bus.zig");
const fused_word_logup = @import("sha_fused_word_logup.zig");
const feed_word_logup = @import("sha_feed_direct_word_logup.zig");
const word_bus = @import("sha_direct_word_bus.zig");
const logup = @import("stwo_circuit_frontend").stark_verifier.logup;
const gate_relation_id = @import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

fn number(comptime Ctx: type, ctx: *Ctx, value: u32) !Ctx.Var {
    return ctx.constant(QM31.fromBase(M31.fromCanonical(value)));
}

fn sumHalf(comptime Ctx: type, ctx: *Ctx, bits: []const Ctx.Var, start: usize) !Ctx.Var {
    var value = ctx.zero();
    for (0..16) |i| {
        const coefficient = try number(Ctx, ctx, @as(u32, 1) << @intCast(i));
        value = try ctx.add(value, try ctx.mul(bits[start + i], coefficient));
    }
    return value;
}

fn swappedHalf(comptime Ctx: type, ctx: *Ctx, bits: []const Ctx.Var, low_byte: usize, high_byte: usize) !Ctx.Var {
    var value = ctx.zero();
    for (0..8) |i| {
        const low = try number(Ctx, ctx, @as(u32, 1) << @intCast(i));
        const high = try number(Ctx, ctx, @as(u32, 1) << @intCast(i + 8));
        value = try ctx.add(value, try ctx.mul(bits[8 * low_byte + i], low));
        value = try ctx.add(value, try ctx.mul(bits[8 * high_byte + i], high));
    }
    return value;
}

/// The 40 caller constraints in `sha_caller_stream_air.evaluate` order.
/// `fixed` and `main` are current-row OODS samples of committed columns.
pub fn callerConstraints(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [caller.fixed_width]Ctx.Var,
    main: [caller.main_width]Ctx.Var,
) ![caller.n_constraints]Ctx.Var {
    var out: [caller.n_constraints]Ctx.Var = undefined;
    const one = ctx.one();
    const non_byte = try ctx.sub(one, fixed[0]);
    const padding = try ctx.sub(try ctx.sub(non_byte, fixed[1]), fixed[2]);
    const bits = main[6..];
    for (bits, 0..) |bit, i| {
        const boolean = try ctx.mul(fixed[0], try ctx.mul(bit, try ctx.sub(bit, one)));
        out[i] = try ctx.add(boolean, try ctx.mul(non_byte, bit));
    }
    out[32] = try ctx.sub(main[0], try ctx.mul(fixed[0], try sumHalf(Ctx, ctx, bits, 0)));
    out[33] = try ctx.sub(main[1], try ctx.mul(fixed[0], try sumHalf(Ctx, ctx, bits, 16)));
    const swapped = [2]Ctx.Var{
        try swappedHalf(Ctx, ctx, bits, 3, 2),
        try swappedHalf(Ctx, ctx, bits, 1, 0),
    };
    for (0..2) |i| {
        const word = main[2 + i];
        const from_bits = try ctx.mul(fixed[0], try ctx.sub(word, swapped[i]));
        const from_constant = try ctx.mul(fixed[2], try ctx.sub(word, fixed[4 + i]));
        out[34 + i] = try ctx.add(try ctx.add(from_bits, from_constant), try ctx.mul(padding, word));
        out[36 + i] = try ctx.sub(main[4 + i], try ctx.mul(fixed[1], word));
        out[38 + i] = try ctx.mul(fixed[3], try ctx.sub(word, fixed[6 + i]));
    }
    return out;
}

pub fn evaluateCaller(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [caller.fixed_width]Ctx.Var,
    main: [caller.main_width]Ctx.Var,
    acc: anytype,
) !void {
    for (try callerConstraints(Ctx, ctx, fixed, main)) |constraint|
        try acc.addConstraint(ctx, constraint);
}

/// Four caller LogUp batch equations. Slots 0 and 1 close the independent
/// circuit Gate relation, then slots 2 and 3 close the SHA word relation.
/// Their claimed sums must be transcript claims; they are not computed from
/// the main columns by this evaluator.
pub fn callerBusConstraints(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [caller_bus.fixed_width]Ctx.Var,
    main: [caller.main_width]Ctx.Var,
    current: [caller_bus.slots]Ctx.Var,
    gate_previous: Ctx.Var,
    word_previous: Ctx.Var,
    gate_claimed_sum: Ctx.Var,
    word_claimed_sum: Ctx.Var,
    gate_elements: [2]Ctx.Var,
    word_elements: [2]Ctx.Var,
) ![caller_bus.n_constraints]Ctx.Var {
    var out: [caller_bus.n_constraints]Ctx.Var = undefined;
    const inv_rows = try ctx.constant(try QM31.fromBase(M31.fromCanonical(caller_bus.rows)).inv());
    const gate_id = try number(Ctx, ctx, gate_relation_id);
    const word_id = try number(Ctx, ctx, caller.word_relation_id);
    const one = ctx.one();
    const zero = ctx.zero();
    for (&out, 0..) |*constraint, slot| {
        const active = if (slot < 2) fixed[0] else fixed[if (slot == 2) 3 else 7];
        const numerator = if (slot < 2) active else fixed[if (slot == 2) 6 else 10];
        const tuple = if (slot < 2)
            [6]Ctx.Var{ gate_id, fixed[1 + slot], main[slot], zero, zero, zero }
        else blk: {
            const index = slot - 2;
            const base: usize = if (index == 0) 3 else 7;
            break :blk [6]Ctx.Var{ word_id, fixed[base + 1], fixed[base + 2], main[2 + 2 * index], main[3 + 2 * index], zero };
        };
        const raw = try logup.combineTerm(Ctx, ctx, &tuple, if (slot < 2) gate_elements else word_elements);
        const denominator = try ctx.add(one, try ctx.mul(active, try ctx.sub(raw, one)));
        const delta = switch (slot) {
            0 => current[0],
            1 => try ctx.add(try ctx.sub(try ctx.sub(current[1], current[0]), gate_previous), try ctx.mul(gate_claimed_sum, inv_rows)),
            2 => current[2],
            3 => try ctx.add(try ctx.sub(try ctx.sub(current[3], current[2]), word_previous), try ctx.mul(word_claimed_sum, inv_rows)),
            else => unreachable,
        };
        constraint.* = try ctx.sub(try ctx.mul(delta, denominator), numerator);
    }
    return out;
}

pub fn evaluateCallerBus(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [caller_bus.fixed_width]Ctx.Var,
    main: [caller.main_width]Ctx.Var,
    current: [caller_bus.slots]Ctx.Var,
    gate_previous: Ctx.Var,
    word_previous: Ctx.Var,
    gate_claimed_sum: Ctx.Var,
    word_claimed_sum: Ctx.Var,
    gate_elements: [2]Ctx.Var,
    word_elements: [2]Ctx.Var,
    acc: anytype,
) !void {
    for (try callerBusConstraints(Ctx, ctx, fixed, main, current, gate_previous, word_previous, gate_claimed_sum, word_claimed_sum, gate_elements, word_elements)) |constraint|
        try acc.addConstraint(ctx, constraint);
}

/// The 44 feed-forward constraints in `sha_feed_direct_air.evaluate` order.
/// S31FCF01 uses `private_mode=true`; its six boundary halves are instead
/// authenticated by the joined word bus.
pub fn feedConstraints(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [feed.fixed_width]Ctx.Var,
    main: [feed.main_width]Ctx.Var,
    private_mode: bool,
) ![feed.n_constraints]Ctx.Var {
    var out: [feed.n_constraints]Ctx.Var = undefined;
    const one = ctx.one();
    const radix = try number(Ctx, ctx, 1 << 16);
    for (main[0..34], 0..) |bit, i| out[i] = try ctx.mul(bit, try ctx.sub(bit, one));
    const low = try sumHalf(Ctx, ctx, main[0..32], 0);
    const high = try sumHalf(Ctx, ctx, main[0..32], 16);
    out[34] = try ctx.sub(
        try ctx.sub(try ctx.add(main[34], main[36]), low),
        try ctx.mul(radix, main[32]),
    );
    out[35] = try ctx.sub(
        try ctx.sub(try ctx.add(try ctx.add(main[35], main[37]), main[32]), high),
        try ctx.mul(radix, main[33]),
    );
    out[36] = try ctx.sub(low, main[38]);
    out[37] = try ctx.sub(high, main[39]);
    for (0..6) |i| out[38 + i] = if (private_mode)
        ctx.zero()
    else
        try ctx.sub(main[34 + i], fixed[i]);
    return out;
}

pub fn evaluateFeed(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [feed.fixed_width]Ctx.Var,
    main: [feed.main_width]Ctx.Var,
    private_mode: bool,
    acc: anytype,
) !void {
    for (try feedConstraints(Ctx, ctx, fixed, main, private_mode)) |constraint|
        try acc.addConstraint(ctx, constraint);
}

fn xor3(comptime Ctx: type, ctx: *Ctx, x: Ctx.Var, y: Ctx.Var, z: Ctx.Var) !Ctx.Var {
    const xy = try ctx.mul(x, y);
    const xz = try ctx.mul(x, z);
    const yz = try ctx.mul(y, z);
    const two = try number(Ctx, ctx, 2);
    const four = try number(Ctx, ctx, 4);
    const linear = try ctx.add(try ctx.add(x, y), z);
    const pairs = try ctx.add(try ctx.add(xy, xz), yz);
    return ctx.add(try ctx.sub(linear, try ctx.mul(two, pairs)), try ctx.mul(four, try ctx.mul(xy, z)));
}

fn bigSigma(comptime Ctx: type, ctx: *Ctx, bits: [32]Ctx.Var, comptime a: usize, comptime b: usize, comptime c: usize) ![32]Ctx.Var {
    var out: [32]Ctx.Var = undefined;
    for (&out, 0..) |*slot, i| slot.* = try xor3(Ctx, ctx, bits[(i + a) % 32], bits[(i + b) % 32], bits[(i + c) % 32]);
    return out;
}

fn smallSigma(comptime Ctx: type, ctx: *Ctx, bits: [32]Ctx.Var, comptime a: usize, comptime b: usize, comptime shift: usize) ![32]Ctx.Var {
    var out: [32]Ctx.Var = undefined;
    for (&out, 0..) |*slot, i| slot.* = try xor3(Ctx, ctx, bits[(i + a) % 32], bits[(i + b) % 32], if (i + shift < 32) bits[i + shift] else ctx.zero());
    return out;
}

fn chooseBits(comptime Ctx: type, ctx: *Ctx, e: [32]Ctx.Var, f: [32]Ctx.Var, g: [32]Ctx.Var) ![32]Ctx.Var {
    var out: [32]Ctx.Var = undefined;
    for (&out, e, f, g) |*slot, x, y, z| slot.* = try ctx.add(try ctx.mul(x, y), try ctx.mul(try ctx.sub(ctx.one(), x), z));
    return out;
}

fn majorityBits(comptime Ctx: type, ctx: *Ctx, a: [32]Ctx.Var, b: [32]Ctx.Var, c: [32]Ctx.Var) ![32]Ctx.Var {
    var out: [32]Ctx.Var = undefined;
    const two = try number(Ctx, ctx, 2);
    for (&out, a, b, c) |*slot, x, y, z| {
        const xy = try ctx.mul(x, y);
        const xz = try ctx.mul(x, z);
        const yz = try ctx.mul(y, z);
        slot.* = try ctx.sub(try ctx.add(try ctx.add(xy, xz), yz), try ctx.mul(two, try ctx.mul(xy, z)));
    }
    return out;
}

fn carry3(comptime Ctx: type, ctx: *Ctx, bits: [12]Ctx.Var, index: usize) !Ctx.Var {
    var result = ctx.zero();
    for (0..3) |i| result = try ctx.add(result, try ctx.mul(bits[3 * index + i], try number(Ctx, ctx, @as(u32, 1) << @intCast(i))));
    return result;
}

fn carry2(comptime Ctx: type, ctx: *Ctx, bits: [4]Ctx.Var, high: bool) !Ctx.Var {
    const index: usize = if (high) 2 else 0;
    return ctx.add(bits[index], try ctx.mul(bits[index + 1], try number(Ctx, ctx, 2)));
}

/// Native `sha_fused_air.evaluate` translated to circuit builder operations.
/// The window's current row and shifted a/e/W openings must be authenticated
/// by the proof transport before these constraints have verifier meaning.
pub fn fusedConstraints(
    comptime Ctx: type,
    ctx: *Ctx,
    window: fused.Window(Ctx.Var),
    fixed: [fused.fixed_width]Ctx.Var,
) ![fused.n_constraints]Ctx.Var {
    var out: [fused.n_constraints]Ctx.Var = undefined;
    var at: usize = 0;
    const one = ctx.one();
    const radix = try number(Ctx, ctx, 1 << 16);
    const row = window.row;
    const flattened = fused.flatten(Ctx.Var, row);
    for (flattened) |bit| {
        out[at] = try ctx.mul(bit, try ctx.sub(bit, one));
        at += 1;
    }
    const sigma0 = try bigSigma(Ctx, ctx, row.a, 2, 13, 22);
    const sigma1 = try bigSigma(Ctx, ctx, row.e, 6, 11, 25);
    const choose = try chooseBits(Ctx, ctx, row.e, window.prev_e[0], window.prev_e[1]);
    const majority = try majorityBits(Ctx, ctx, row.a, window.prev_a[0], window.prev_a[1]);
    var a_lo = try sumHalf(Ctx, ctx, &window.prev_e[2], 0);
    a_lo = try ctx.add(a_lo, try sumHalf(Ctx, ctx, &sigma1, 0));
    a_lo = try ctx.add(a_lo, try sumHalf(Ctx, ctx, &choose, 0));
    a_lo = try ctx.add(a_lo, fixed[6]);
    a_lo = try ctx.add(a_lo, try sumHalf(Ctx, ctx, &row.w_bits, 0));
    var a_hi = try sumHalf(Ctx, ctx, &window.prev_e[2], 16);
    a_hi = try ctx.add(a_hi, try sumHalf(Ctx, ctx, &sigma1, 16));
    a_hi = try ctx.add(a_hi, try sumHalf(Ctx, ctx, &choose, 16));
    a_hi = try ctx.add(a_hi, fixed[7]);
    a_hi = try ctx.add(a_hi, try sumHalf(Ctx, ctx, &row.w_bits, 16));
    var e_low = try ctx.add(a_lo, try sumHalf(Ctx, ctx, &window.prev_a[2], 0));
    e_low = try ctx.sub(e_low, try sumHalf(Ctx, ctx, &window.next_e, 0));
    e_low = try ctx.sub(e_low, try ctx.mul(radix, try carry3(Ctx, ctx, row.carry_bits, 0)));
    out[at] = try ctx.mul(fixed[0], e_low);
    at += 1;
    var e_high = try ctx.add(a_hi, try sumHalf(Ctx, ctx, &window.prev_a[2], 16));
    e_high = try ctx.add(e_high, try carry3(Ctx, ctx, row.carry_bits, 0));
    e_high = try ctx.sub(e_high, try sumHalf(Ctx, ctx, &window.next_e, 16));
    e_high = try ctx.sub(e_high, try ctx.mul(radix, try carry3(Ctx, ctx, row.carry_bits, 1)));
    out[at] = try ctx.mul(fixed[0], e_high);
    at += 1;
    var next_a_low = try ctx.add(a_lo, try sumHalf(Ctx, ctx, &sigma0, 0));
    next_a_low = try ctx.add(next_a_low, try sumHalf(Ctx, ctx, &majority, 0));
    next_a_low = try ctx.sub(next_a_low, try sumHalf(Ctx, ctx, &window.next_a, 0));
    next_a_low = try ctx.sub(next_a_low, try ctx.mul(radix, try carry3(Ctx, ctx, row.carry_bits, 2)));
    out[at] = try ctx.mul(fixed[0], next_a_low);
    at += 1;
    var next_a_high = try ctx.add(a_hi, try sumHalf(Ctx, ctx, &sigma0, 16));
    next_a_high = try ctx.add(next_a_high, try sumHalf(Ctx, ctx, &majority, 16));
    next_a_high = try ctx.add(next_a_high, try carry3(Ctx, ctx, row.carry_bits, 2));
    next_a_high = try ctx.sub(next_a_high, try sumHalf(Ctx, ctx, &window.next_a, 16));
    next_a_high = try ctx.sub(next_a_high, try ctx.mul(radix, try carry3(Ctx, ctx, row.carry_bits, 3)));
    out[at] = try ctx.mul(fixed[0], next_a_high);
    at += 1;
    const small0 = try smallSigma(Ctx, ctx, window.prev_w[2], 7, 18, 3);
    const small1 = try smallSigma(Ctx, ctx, window.prev_w[0], 17, 19, 10);
    const low_carry = try carry2(Ctx, ctx, row.schedule_carry_bits, false);
    var w_low = try sumHalf(Ctx, ctx, &window.prev_w[3], 0);
    w_low = try ctx.add(w_low, try sumHalf(Ctx, ctx, &small0, 0));
    w_low = try ctx.add(w_low, try sumHalf(Ctx, ctx, &window.prev_w[1], 0));
    w_low = try ctx.add(w_low, try sumHalf(Ctx, ctx, &small1, 0));
    w_low = try ctx.sub(w_low, try sumHalf(Ctx, ctx, &row.w_bits, 0));
    w_low = try ctx.sub(w_low, try ctx.mul(radix, low_carry));
    out[at] = try ctx.mul(fixed[1], w_low);
    at += 1;
    var w_high = try sumHalf(Ctx, ctx, &window.prev_w[3], 16);
    w_high = try ctx.add(w_high, try sumHalf(Ctx, ctx, &small0, 16));
    w_high = try ctx.add(w_high, try sumHalf(Ctx, ctx, &window.prev_w[1], 16));
    w_high = try ctx.add(w_high, try sumHalf(Ctx, ctx, &small1, 16));
    w_high = try ctx.add(w_high, low_carry);
    w_high = try ctx.sub(w_high, try sumHalf(Ctx, ctx, &row.w_bits, 16));
    w_high = try ctx.sub(w_high, try ctx.mul(radix, try carry2(Ctx, ctx, row.schedule_carry_bits, true)));
    out[at] = try ctx.mul(fixed[1], w_high);
    at += 1;
    const no_round = try ctx.sub(one, fixed[0]);
    for (0..4) |i| {
        out[at] = try ctx.mul(no_round, try carry3(Ctx, ctx, row.carry_bits, i));
        at += 1;
    }
    for (row.w_bits) |bit| {
        out[at] = try ctx.mul(no_round, bit);
        at += 1;
    }
    const no_recur = try ctx.sub(one, fixed[1]);
    for (row.schedule_carry_bits) |bit| {
        out[at] = try ctx.mul(no_recur, bit);
        at += 1;
    }
    for ([_]usize{ 0, 16 }) |start| {
        out[at] = try ctx.mul(fixed[5], try sumHalf(Ctx, ctx, &row.a, start));
        at += 1;
        out[at] = try ctx.mul(fixed[5], try sumHalf(Ctx, ctx, &row.e, start));
        at += 1;
    }
    std.debug.assert(at == fused.n_constraints);
    return out;
}

pub fn evaluateFused(
    comptime Ctx: type,
    ctx: *Ctx,
    window: fused.Window(Ctx.Var),
    fixed: [fused.fixed_width]Ctx.Var,
    acc: anytype,
) !void {
    for (try fusedConstraints(Ctx, ctx, window, fixed)) |constraint|
        try acc.addConstraint(ctx, constraint);
}

fn wordBatchConstraints(
    comptime Ctx: type,
    ctx: *Ctx,
    rows: usize,
    tuples: [3][6]Ctx.Var,
    weights: [3]Ctx.Var,
    current: [3]Ctx.Var,
    previous: Ctx.Var,
    claimed_sum: Ctx.Var,
    elements: [2]Ctx.Var,
) ![3]Ctx.Var {
    var out: [3]Ctx.Var = undefined;
    const inv_rows = try ctx.constant(try QM31.fromBase(M31.fromCanonical(@intCast(rows))).inv());
    for (&out, 0..) |*constraint, slot| {
        const denominator = try logup.combineTerm(Ctx, ctx, &tuples[slot], elements);
        const delta = if (slot == 0) current[0] else if (slot == 2)
            try ctx.add(try ctx.sub(try ctx.sub(current[2], current[1]), previous), try ctx.mul(claimed_sum, inv_rows))
        else
            try ctx.sub(current[1], current[0]);
        constraint.* = try ctx.sub(try ctx.mul(delta, denominator), weights[slot]);
    }
    return out;
}

/// Two fused round/schedule word LogUp constraints. The simultaneous a/e
/// state events share one rational fraction. `main` is the current
/// opening of each round column, selected from the shifted proof samples.
pub fn fusedWordBusConstraints(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [fused.fixed_width]Ctx.Var,
    main: [fused.main_width]Ctx.Var,
    current: [fused_word_logup.event_slots]Ctx.Var,
    previous: Ctx.Var,
    claimed_sum: Ctx.Var,
    elements: [2]Ctx.Var,
) ![fused_word_logup.n_constraints]Ctx.Var {
    const id = try number(Ctx, ctx, word_bus.relation_id);
    const zero = ctx.zero();
    const row = fused.unflatten(Ctx.Var, main);
    const w_lo = try sumHalf(Ctx, ctx, &row.w_bits, 0);
    const w_hi = try sumHalf(Ctx, ctx, &row.w_bits, 16);
    const a_lo = try sumHalf(Ctx, ctx, &row.a, 0);
    const a_hi = try sumHalf(Ctx, ctx, &row.a, 16);
    const e_lo = try sumHalf(Ctx, ctx, &row.e, 0);
    const e_hi = try sumHalf(Ctx, ctx, &row.e, 16);
    const weight = try ctx.sub(fixed[3], fixed[2]);
    const tuples = [3][6]Ctx.Var{
        .{ id, fixed[9], try ctx.add(try number(Ctx, ctx, 8), fixed[8]), w_lo, w_hi, zero },
        .{ id, fixed[9], fixed[10], a_lo, a_hi, zero },
        .{ id, fixed[9], try ctx.add(fixed[10], try number(Ctx, ctx, 4)), e_lo, e_hi, zero },
    };
    const d_schedule = try logup.combineTerm(Ctx, ctx, &tuples[0], elements);
    const d_a = try logup.combineTerm(Ctx, ctx, &tuples[1], elements);
    const d_e = try logup.combineTerm(Ctx, ctx, &tuples[2], elements);
    const inv_rows = try ctx.constant(try QM31.fromBase(M31.fromCanonical(fused_word_logup.rows)).inv());
    const delta = try ctx.add(try ctx.sub(try ctx.sub(current[1], current[0]), previous), try ctx.mul(claimed_sum, inv_rows));
    return .{
        try ctx.add(try ctx.mul(current[0], d_schedule), fixed[4]),
        try ctx.sub(try ctx.mul(delta, try ctx.mul(d_a, d_e)), try ctx.add(try ctx.mul(weight, d_a), try ctx.mul(weight, d_e))),
    };
}

pub fn evaluateFusedWordBus(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [fused.fixed_width]Ctx.Var,
    main: [fused.main_width]Ctx.Var,
    current: [fused_word_logup.event_slots]Ctx.Var,
    previous: Ctx.Var,
    claimed_sum: Ctx.Var,
    elements: [2]Ctx.Var,
    acc: anytype,
) !void {
    for (try fusedWordBusConstraints(Ctx, ctx, fixed, main, current, previous, claimed_sum, elements)) |constraint|
        try acc.addConstraint(ctx, constraint);
}

/// Three feed-forward word LogUp constraints for one of the three SHA calls.
/// The call ID is a verifier-owned constant, not a witness-provided column.
pub fn feedWordBusConstraints(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [feed.fixed_width]Ctx.Var,
    main: [feed.main_width]Ctx.Var,
    call_id: Ctx.Var,
    current: [3]Ctx.Var,
    previous: Ctx.Var,
    claimed_sum: Ctx.Var,
    elements: [2]Ctx.Var,
) ![3]Ctx.Var {
    const id = try number(Ctx, ctx, word_bus.relation_id);
    const zero = ctx.zero();
    const one = ctx.one();
    const out_lo = try sumHalf(Ctx, ctx, main[0..32], 0);
    const out_hi = try sumHalf(Ctx, ctx, main[0..32], 16);
    const tuples = [3][6]Ctx.Var{
        .{ id, call_id, fixed[6], main[34], main[35], zero },
        .{ id, call_id, try ctx.add(try number(Ctx, ctx, word_bus.terminal_base), fixed[6]), main[36], main[37], zero },
        .{ id, call_id, try ctx.add(try number(Ctx, ctx, 24), fixed[6]), out_lo, out_hi, zero },
    };
    return wordBatchConstraints(Ctx, ctx, feed_word_logup.rows, tuples, .{ try ctx.sub(zero, one), try ctx.sub(zero, one), one }, current, previous, claimed_sum, elements);
}

pub fn evaluateFeedWordBus(
    comptime Ctx: type,
    ctx: *Ctx,
    fixed: [feed.fixed_width]Ctx.Var,
    main: [feed.main_width]Ctx.Var,
    call_id: Ctx.Var,
    current: [3]Ctx.Var,
    previous: Ctx.Var,
    claimed_sum: Ctx.Var,
    elements: [2]Ctx.Var,
    acc: anytype,
) !void {
    for (try feedWordBusConstraints(Ctx, ctx, fixed, main, call_id, current, previous, claimed_sum, elements)) |constraint|
        try acc.addConstraint(ctx, constraint);
}

fn vars(comptime n: usize, ctx: *builder.Context(QM31), values: [n]QM31) ![n]builder.Var {
    var result: [n]builder.Var = undefined;
    for (values, &result) |value, *slot| slot.* = try ctx.constant(value);
    return result;
}

fn varValue(ctx: *const builder.Context(QM31), variable: builder.Var) QM31 {
    return ctx.values()[variable.idx];
}

test "joined caller in-circuit equations match native on committed and arbitrary secure rows" {
    const allocator = std.testing.allocator;
    const header = [_]u8{0x5a} ** 80;
    const statement = caller.Statement{ .digest_visibility = .private, .config = .{
        .gate_addresses = blk: {
            var addresses: [56]u32 = undefined;
            for (&addresses, 0..) |*address, i| address.* = @intCast(i + 3);
            break :blk addresses;
        },
        .first_call_id = 1,
    } };
    var fixed = try caller.writeFixed(allocator, statement);
    defer fixed.deinit();
    var main = try caller.writeMain(allocator, header);
    defer main.deinit();
    for ([_]usize{ 0, 19, 20, 27, 28, 43, 44, 59, 60, 79, 80, 127 }) |logical| {
        var fv: [caller.fixed_width]QM31 = undefined;
        var mv: [caller.main_width]QM31 = undefined;
        const storage = caller.storageIndex(logical);
        for (&fv, fixed.values) |*slot, column| slot.* = QM31.fromBase(column.values[storage]);
        for (&mv, main.values) |*slot, column| slot.* = QM31.fromBase(column.values[storage]);
        try compareCaller(fv, mv);
    }
    var rng = std.Random.DefaultPrng.init(0x5333_3143_414c_4c52);
    for (0..8) |_| {
        var fv: [caller.fixed_width]QM31 = undefined;
        var mv: [caller.main_width]QM31 = undefined;
        for (&fv) |*slot| slot.* = randomSecure(rng.random());
        for (&mv) |*slot| slot.* = randomSecure(rng.random());
        try compareCaller(fv, mv);
    }
}

fn compareCaller(fv: [caller.fixed_width]QM31, mv: [caller.main_width]QM31) !void {
    var ctx = try builder.Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const actual = try callerConstraints(@TypeOf(ctx), &ctx, try vars(caller.fixed_width, &ctx, fv), try vars(caller.main_width, &ctx, mv));
    const expected = caller.evaluate(QM31, caller.unflatten(QM31, mv), .{
        .byte = fv[0],
        .chain = fv[1],
        .constant = fv[2],
        .digest = fv[3],
        .constant_lo = fv[4],
        .constant_hi = fv[5],
        .digest_lo = fv[6],
        .digest_hi = fv[7],
    });
    for (actual, expected) |a, e| try std.testing.expect(varValue(&ctx, a).eql(e));
}

test "joined feed in-circuit equations match native private and public modes" {
    var rng = std.Random.DefaultPrng.init(0x5333_3146_4545_4438);
    for (0..8) |_| {
        var fv: [feed.fixed_width]QM31 = undefined;
        var mv: [feed.main_width]QM31 = undefined;
        for (&fv) |*slot| slot.* = randomSecure(rng.random());
        for (&mv) |*slot| slot.* = randomSecure(rng.random());
        for ([_]bool{ false, true }) |private_mode| {
            var ctx = try builder.Context(QM31).init(std.testing.allocator, 0);
            defer ctx.deinit();
            const actual = try feedConstraints(@TypeOf(ctx), &ctx, try vars(feed.fixed_width, &ctx, fv), try vars(feed.main_width, &ctx, mv), private_mode);
            const expected = feed.evaluate(QM31, fv, mv, private_mode);
            for (actual, expected) |a, e| try std.testing.expect(varValue(&ctx, a).eql(e));
        }
    }
}

fn secureColumnAt(columns: []const @import("stwo_prover_engine").pcs.ColumnEvaluation, offset: usize, storage: usize) QM31 {
    return QM31.fromM31(
        columns[offset + 0].values[storage],
        columns[offset + 1].values[storage],
        columns[offset + 2].values[storage],
        columns[offset + 3].values[storage],
    );
}

test "joined caller Gate and SHA bus equations close on native committed rows" {
    const allocator = std.testing.allocator;
    const header = [_]u8{0x5a} ** 80;
    const config = @import("sha_caller_stream_equations.zig").Config{
        .gate_addresses = blk: {
            var addresses: [56]u32 = undefined;
            for (&addresses, 0..) |*address, i| address.* = @intCast(i + 3);
            break :blk addresses;
        },
        .first_call_id = 7,
    };
    var main = try caller.writeMain(allocator, header);
    defer main.deinit();
    var fixed = try caller_bus.writeFixed(allocator, config);
    defer fixed.deinit();
    const gate_z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const gate_alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    const word_z = QM31.fromU32Unchecked(29, 3, 5, 7);
    const word_alpha = QM31.fromU32Unchecked(23, 11, 17, 31);
    var interaction = try caller_bus.writeInteraction(
        allocator,
        fixed.values,
        main.values,
        config,
        word_bus.Elements.init(gate_z, gate_alpha),
        word_bus.Elements.init(word_z, word_alpha),
    );
    defer interaction.deinit();
    for ([_]usize{ 0, 19, 20, 27, 28, 43, 44, 59, 60, 79, 80, 127 }) |logical| {
        const storage = caller.storageIndex(logical);
        const previous = core.utils.previousBitReversedCircleDomainIndex(storage, caller_bus.log_size, caller_bus.log_size);
        var fv: [caller_bus.fixed_width]QM31 = undefined;
        var mv: [caller.main_width]QM31 = undefined;
        var current: [caller_bus.slots]QM31 = undefined;
        for (&fv, fixed.values) |*slot, column| slot.* = QM31.fromBase(column.values[storage]);
        for (&mv, main.values) |*slot, column| slot.* = QM31.fromBase(column.values[storage]);
        for (&current, 0..) |*slot, i| slot.* = secureColumnAt(interaction.columns, 4 * i, storage);
        const gate_prev = secureColumnAt(interaction.columns, 4, previous);
        const word_prev = secureColumnAt(interaction.columns, 12, previous);
        var ctx = try builder.Context(QM31).init(allocator, 0);
        defer ctx.deinit();
        const actual = try callerBusConstraints(
            @TypeOf(ctx),
            &ctx,
            try vars(caller_bus.fixed_width, &ctx, fv),
            try vars(caller.main_width, &ctx, mv),
            try vars(caller_bus.slots, &ctx, current),
            try ctx.constant(gate_prev),
            try ctx.constant(word_prev),
            try ctx.constant(interaction.gate_claimed_sum),
            try ctx.constant(interaction.word_claimed_sum),
            .{ try ctx.constant(gate_z), try ctx.constant(gate_alpha) },
            .{ try ctx.constant(word_z), try ctx.constant(word_alpha) },
        );
        for (actual) |constraint| try std.testing.expect(varValue(&ctx, constraint).isZero());
        if (logical == 0) {
            mv[0] = mv[0].add(QM31.one());
            var changed_ctx = try builder.Context(QM31).init(allocator, 0);
            defer changed_ctx.deinit();
            const changed = try callerBusConstraints(
                @TypeOf(changed_ctx),
                &changed_ctx,
                try vars(caller_bus.fixed_width, &changed_ctx, fv),
                try vars(caller.main_width, &changed_ctx, mv),
                try vars(caller_bus.slots, &changed_ctx, current),
                try changed_ctx.constant(gate_prev),
                try changed_ctx.constant(word_prev),
                try changed_ctx.constant(interaction.gate_claimed_sum),
                try changed_ctx.constant(interaction.word_claimed_sum),
                .{ try changed_ctx.constant(gate_z), try changed_ctx.constant(gate_alpha) },
                .{ try changed_ctx.constant(word_z), try changed_ctx.constant(word_alpha) },
            );
            try std.testing.expect(!varValue(&changed_ctx, changed[0]).isZero());
        }
    }
}

fn randomFusedWindow(random: std.Random) fused.Window(QM31) {
    var window: fused.Window(QM31) = undefined;
    for (&window.row.a) |*slot| slot.* = randomSecure(random);
    for (&window.row.e) |*slot| slot.* = randomSecure(random);
    for (&window.row.carry_bits) |*slot| slot.* = randomSecure(random);
    for (&window.row.w_bits) |*slot| slot.* = randomSecure(random);
    for (&window.row.schedule_carry_bits) |*slot| slot.* = randomSecure(random);
    for (&window.prev_a) |*word| for (word) |*slot| {
        slot.* = randomSecure(random);
    };
    for (&window.prev_e) |*word| for (word) |*slot| {
        slot.* = randomSecure(random);
    };
    for (&window.next_a) |*slot| slot.* = randomSecure(random);
    for (&window.next_e) |*slot| slot.* = randomSecure(random);
    for (&window.prev_w) |*word| for (word) |*slot| {
        slot.* = randomSecure(random);
    };
    return window;
}

fn fusedWindowVars(ctx: *builder.Context(QM31), native: fused.Window(QM31)) !fused.Window(builder.Var) {
    var result: fused.Window(builder.Var) = undefined;
    result.row = fused.unflatten(builder.Var, try vars(fused.main_width, ctx, fused.flatten(QM31, native.row)));
    for (native.prev_a, &result.prev_a) |word, *target| target.* = try vars(32, ctx, word);
    for (native.prev_e, &result.prev_e) |word, *target| target.* = try vars(32, ctx, word);
    result.next_a = try vars(32, ctx, native.next_a);
    result.next_e = try vars(32, ctx, native.next_e);
    for (native.prev_w, &result.prev_w) |word, *target| target.* = try vars(32, ctx, word);
    return result;
}

test "joined fused round and schedule in-circuit equations match native at arbitrary secure openings" {
    var rng = std.Random.DefaultPrng.init(0x5333_3146_5553_4544);
    for (0..3) |_| {
        const window = randomFusedWindow(rng.random());
        var fv: [fused.fixed_width]QM31 = undefined;
        for (&fv) |*slot| slot.* = randomSecure(rng.random());
        var ctx = try builder.Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const actual = try fusedConstraints(@TypeOf(ctx), &ctx, try fusedWindowVars(&ctx, window), try vars(fused.fixed_width, &ctx, fv));
        const expected = fused.evaluate(QM31, window, fused.fixedAt(QM31, fv));
        for (actual, expected, 0..) |a, e, i| {
            if (!varValue(&ctx, a).eql(e)) {
                std.debug.print("fused SHA polynomial {d} differs from native\n", .{i});
                return error.FusedPolynomialMismatch;
            }
        }
    }
}

test "joined fused SHA word bus matches native signed tuple equations" {
    var rng = std.Random.DefaultPrng.init(0x5333_3157_4255_5333);
    for (0..4) |_| {
        var fv: [fused.fixed_width]QM31 = undefined;
        var mv: [fused.main_width]QM31 = undefined;
        var sums: [fused_word_logup.event_slots]QM31 = undefined;
        for (&fv) |*slot| slot.* = randomSecure(rng.random());
        for (&mv) |*slot| slot.* = randomSecure(rng.random());
        for (&sums) |*slot| slot.* = randomSecure(rng.random());
        const previous = randomSecure(rng.random());
        const claim = randomSecure(rng.random());
        const z = randomSecure(rng.random());
        const alpha = randomSecure(rng.random());
        var ctx = try builder.Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const actual = try fusedWordBusConstraints(
            @TypeOf(ctx),
            &ctx,
            try vars(fused.fixed_width, &ctx, fv),
            try vars(fused.main_width, &ctx, mv),
            try vars(fused_word_logup.event_slots, &ctx, sums),
            try ctx.constant(previous),
            try ctx.constant(claim),
            .{ try ctx.constant(z), try ctx.constant(alpha) },
        );
        const inv_rows = try QM31.fromBase(M31.fromCanonical(fused_word_logup.rows)).inv();
        const elements = word_bus.Elements.init(z, alpha);
        for (actual, 0..) |variable, slot| {
            const row = fused.unflatten(QM31, mv);
            const fixed = fused.fixedAt(QM31, fv);
            const expr = fused_word_bus.eventExpr(QM31, row, fixed, slot);
            const d = elements.denominator(QM31, expr.values);
            const expected = if (slot == 0) sums[0].mul(d).sub(expr.weight) else blk: {
                const state_e = fused_word_bus.eventExpr(QM31, row, fixed, 2);
                const d_e = elements.denominator(QM31, state_e.values);
                const delta = sums[1].sub(sums[0]).sub(previous).add(claim.mul(inv_rows));
                break :blk delta.mul(d.mul(d_e)).sub(expr.weight.mul(d_e).add(state_e.weight.mul(d)));
            };
            try std.testing.expect(varValue(&ctx, variable).eql(expected));
        }
    }
}

test "joined feed SHA word bus matches native signed tuple equations" {
    var rng = std.Random.DefaultPrng.init(0x5333_3146_4255_5333);
    for (0..4) |_| {
        var fv: [feed.fixed_width]QM31 = undefined;
        var mv: [feed.main_width]QM31 = undefined;
        var sums: [3]QM31 = undefined;
        for (&fv) |*slot| slot.* = randomSecure(rng.random());
        for (&mv) |*slot| slot.* = randomSecure(rng.random());
        for (&sums) |*slot| slot.* = randomSecure(rng.random());
        const previous = randomSecure(rng.random());
        const claim = randomSecure(rng.random());
        const call_id = QM31.fromBase(M31.fromCanonical(19));
        const z = randomSecure(rng.random());
        const alpha = randomSecure(rng.random());
        var ctx = try builder.Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const actual = try feedWordBusConstraints(
            @TypeOf(ctx),
            &ctx,
            try vars(feed.fixed_width, &ctx, fv),
            try vars(feed.main_width, &ctx, mv),
            try ctx.constant(call_id),
            try vars(3, &ctx, sums),
            try ctx.constant(previous),
            try ctx.constant(claim),
            .{ try ctx.constant(z), try ctx.constant(alpha) },
        );
        const inv_rows = try QM31.fromBase(M31.fromCanonical(feed_word_logup.rows)).inv();
        const elements = word_bus.Elements.init(z, alpha);
        for (actual, 0..) |variable, slot| {
            const expr = feed_word_logup.eventExpr(QM31, fv, mv, call_id, slot);
            const delta = if (slot == 0) sums[0] else if (slot == 2)
                sums[2].sub(sums[1]).sub(previous).add(claim.mul(inv_rows))
            else
                sums[1].sub(sums[0]);
            const expected = delta.mul(elements.denominator(QM31, expr.values)).sub(expr.weight);
            try std.testing.expect(varValue(&ctx, variable).eql(expected));
        }
    }
}

fn randomSecure(random: std.Random) QM31 {
    var limbs: [4]u32 = undefined;
    for (&limbs) |*limb| limb.* = random.intRangeLessThan(u32, 0, core.fields.m31.Modulus);
    return QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
}
