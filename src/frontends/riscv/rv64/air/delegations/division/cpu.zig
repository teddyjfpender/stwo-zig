//! Lean CPU representation helpers. Selecting this plan alone is insufficient:
//! a caller must also prove the typed DIV bus and close it against the service.
const E = @import("../../evaluation.zig");
const L = E.L;
const R = @import("../../rows.zig");
const ops = @import("../../operations.zig");
const Encoding = @import("../../encoding.zig");
const Projection = @import("../../projection.zig").Projection;
const D = @import("layout.zig");
const Policy = @import("policy.zig").Policy;
fn boundaryWord(word: L.Word) bool {
    return switch (word) {
        .a, .b, .result, .previous_rd, .memory_before, .memory_after => true,
        else => false,
    };
}
pub fn plan(opcodes: []const E.O) Encoding.Plan {
    return planWithProfile(opcodes, .rv64im);
}
pub fn planWithProfile(opcodes: []const E.O, execution: @import("../../../execution_profile.zig").Profile) Encoding.Plan {
    return buildPlan(opcodes, execution, false);
}
/// Unproved policy until a caller supplies the separately typed MUL provider.
/// Existing CPU constructors reject this policy explicitly.
pub fn planWithMultiplication(opcodes: []const E.O, execution: @import("../../../execution_profile.zig").Profile) Encoding.Plan {
    return buildPlan(opcodes, execution, true);
}
fn buildPlan(opcodes: []const E.O, execution: @import("../../../execution_profile.zig").Profile, multiplication: bool) Encoding.Plan {
    var legacy: Projection = undefined;
    legacy.support = .{ .words = @splat(false), .carries = @splat(false), .slots = @splat(false), .shifts = false, .product = false };
    var math_opcodes: [L.fixed.OPCODES]E.O = undefined;
    var math_count: usize = 0;
    var seen: [L.fixed.OPCODES]bool = @splat(false);
    for (opcodes) |op| {
        if (seen[@intFromEnum(op)]) continue;
        seen[@intFromEnum(op)] = true;
        const effects = @import("../../../execution_profile.zig").effects(execution, op);
        const slots = [4]bool{ effects.reads_rs1, effects.reads_rs2, effects.writes_rd, effects.memory_width != 0 };
        for (&legacy.support.slots, slots) |*supported, enabled| supported.* = supported.* or enabled;
        for (&legacy.support.words, 0..) |*supported, w| {
            const keep = !(ops.div(op) or (multiplication and ops.mul(op))) or boundaryWord(@enumFromInt(w));
            supported.* = supported.* or (keep and ops.wordActive(@enumFromInt(w), op, slots));
        }
        if (ops.div(op) or (multiplication and ops.mul(op))) continue;
        math_opcodes[math_count] = op;
        math_count += 1;
        for (&legacy.support.carries, 0..) |*supported, c| supported.* = supported.* or ops.carryActive(@enumFromInt(c / 8), c % 8, op);
        legacy.support.shifts = legacy.support.shifts or ops.shift(op);
        legacy.support.product = legacy.support.product or ops.mul(op);
    }
    legacy.main_map = @splat(0);
    for (legacy.support.carries, 0..) |supported, c| if (!supported) {
        legacy.main_map[L.carry_start + c] = Encoding.omitted;
    };
    for (D.SCALARS) |c| legacy.main_map[c] = Encoding.omitted;
    for (0..16) |i| legacy.main_map[L.productCarry(i)] = Encoding.derived;
    if (!legacy.support.product) for (L.product_carry_start..L.shift_start) |c| {
        legacy.main_map[c] = Encoding.omitted;
    };
    if (!legacy.support.shifts) for (L.shift_start..L.clock_start) |c| {
        legacy.main_map[c] = Encoding.omitted;
    };
    for (0..4) |slot| {
        legacy.main_map[L.previousClock(slot)] = Encoding.derived;
        legacy.main_map[L.gap(slot)] = Encoding.derived;
        if (!legacy.support.slots[slot]) for (L.previousClock(slot)..L.gap(slot) + 1 + L.CLOCK_BITS) |c| {
            legacy.main_map[c] = Encoding.omitted;
        };
    }
    var result = Encoding.Plan.init(&legacy, math_opcodes[0..math_count]);
    result.wideClocks();
    result.compactProductCarries();
    result.byteOperations(math_opcodes[0..math_count]);
    result.allowed_opcodes = @splat(false);
    for (opcodes) |op| result.allowed_opcodes[@intFromEnum(op)] = true;
    result.arithmetic_policy = if (multiplication) .division_multiplication_services_v3 else .division_service_v2;
    result.execution_profile = execution;
    return result;
}
/// Exact linear substitution, including at extension-valued OODS points.
/// Original selectors/words remain available to state, ROM and the typed bus.
pub fn inlineFixed(original: *const E.Fixed, policy: Policy) E.Fixed {
    return inlineFixedGeneric(E.Q, original, policy);
}
pub fn inlineFixedGeneric(comptime F: type, original: *const E.FixedFor(F), policy: Policy) E.FixedFor(F) {
    var result = original.*;
    if (policy == .inline_v4) return result;
    for (D.OPCODES) |op| removeMathOpcodeGeneric(F, original, &result, op);
    if (policy == .division_multiplication_services_v3) for (@import("../multiplication/layout.zig").OPCODES) |op| removeMathOpcodeGeneric(F, original, &result, op);
    return result;
}
fn removeMathOpcodeGeneric(comptime F: type, original: *const E.FixedFor(F), result: *E.FixedFor(F), op: E.O) void {
    const selector = original[L.fixed.opcode_start + @intFromEnum(op)];
    result[L.fixed.opcode_start + @intFromEnum(op)] = F.zero();
    for (0..L.WORDS) |w| if (!boundaryWord(@enumFromInt(w)) and ops.wordActive(@enumFromInt(w), op, @splat(false))) {
        result[L.fixed.word_start + w] = result[L.fixed.word_start + w].sub(selector);
    };
    for (0..L.CARRIES) |c| if (ops.carryActive(@enumFromInt(c / 8), c % 8, op)) {
        result[L.fixed.carry_start + c] = result[L.fixed.carry_start + c].sub(selector);
    };
}
/// Prover recipe only; mathematical authorization comes from local+bus AIR.
pub fn canonicalizeAdvice(row: *R.Main, op: E.O, policy: Policy) void {
    if (policy == .inline_v4 or !ops.div(op)) return;
    for (D.WORDS) |word| if (!boundaryWord(word)) {
        R.putWord(row, word, 0);
    };
    for (D.CARRIES) |kind| for (0..8) |i| {
        row[L.carry(kind, i)] = @import("stwo_core").fields.m31.M31.zero();
    };
    for (0..16) |i| R.putBounded(row, L.productCarry(i), 11, 0);
    for (D.SCALARS) |c| row[c] = @import("stwo_core").fields.m31.M31.zero();
}
pub fn local(view: E.View, out: *E.Sink, cpu_plan: *const Encoding.Plan, physical: []const E.Q) void {
    return localGeneric(E.Q, view, out, cpu_plan, physical);
}
pub fn localGeneric(comptime F: type, view: E.ViewFor(F), out: *E.SinkFor(F), cpu_plan: *const Encoding.Plan, physical: []const F) void {
    if (cpu_plan.arithmetic_policy == .inline_v4) return @import("../../range/constraints.zig").localGeneric(F, view, out, cpu_plan, physical);
    const fixed = inlineFixedGeneric(F, view.f, cpu_plan.arithmetic_policy);
    @import("../../range/constraints.zig").localGeneric(F, .{ .f = &fixed, .m = view.m }, out, cpu_plan, physical);
}

/// The canonical substitution owns derived bytes/carries; opcode filtering only
/// changes fixed enables and cannot change that logical substitution.
pub fn localInflated(fixed_original: *const E.Fixed, prepared: Encoding.Inflation.Result, out: *E.Sink, cpu_plan: *const Encoding.Plan, physical: []const E.Q) void {
    return localInflatedGeneric(E.Q, fixed_original, prepared, out, cpu_plan, physical);
}
pub fn localInflatedGeneric(comptime F: type, fixed_original: *const E.FixedFor(F), prepared: Encoding.Inflation.ResultFor(F), out: *E.SinkFor(F), cpu_plan: *const Encoding.Plan, physical: []const F) void {
    if (cpu_plan.arithmetic_policy == .inline_v4) return @import("../../range/constraints.zig").localInflatedGeneric(F, fixed_original, prepared, out, cpu_plan, physical);
    const fixed = inlineFixedGeneric(F, fixed_original, cpu_plan.arithmetic_policy);
    @import("../../range/constraints.zig").localInflatedGeneric(F, &fixed, prepared, out, cpu_plan, physical);
}
