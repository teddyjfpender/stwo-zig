//! Shared, integer-sound u32 recursion counter. The two u16 limbs are
//! independently range checked; subtraction uses an explicit Boolean borrow.
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Var = circuit.builder.Var;
const U32 = circuit.builder.wrappers.U32Wrapper(Var);

pub const CounterRelation = struct {
    step: U32,
    previous: U32,
    base: Var,
    recurse: Var,
    inverse: Var,
    borrow: Var,
    previous_low: Var,
};

const CounterWires = struct { low: Var, high: Var, packed_word: U32 };

fn guessCounter(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !CounterWires {
    const low_value = QM31.fromBase(M31.fromCanonical(value & 0xffff));
    const high_value = QM31.fromBase(M31.fromCanonical(value >> 16));
    const low = try circuit.builder.wrappers.guessU16(V, ctx,
        .newUnsafe(circuit.builder.ivalue.fromQm31(V, low_value)));
    const high = try circuit.builder.wrappers.guessU16(V, ctx,
        .newUnsafe(circuit.builder.ivalue.fromQm31(V, high_value)));
    const i = try ctx.constant(QM31.fromU32Unchecked(0, 1, 0, 0));
    return .{
        .low = low.get(),
        .high = high.get(),
        .packed_word = .newUnsafe(try ctx.add(low.get(), try ctx.mul(high.get(), i))),
    };
}

/// At zero the base branch is forced. At a positive step the predecessor is
/// exactly step - 1, including across the low-limb boundary 65536.
pub fn constrainStepCounter(comptime V: type, ctx: *circuit.builder.Context(V), step_value: u32) !CounterRelation {
    const step = try guessCounter(V, ctx, step_value);
    const base_value = QM31.fromBase(M31.fromCanonical(if (step_value == 0) 1 else 0));
    const base = try ctx.guessM31(circuit.builder.ivalue.fromQm31(V, base_value));
    try ctx.eq(try ctx.mul(base, try ctx.sub(base, ctx.one())), ctx.zero());
    const nonzero_sum = try ctx.add(step.low, step.high);
    try ctx.eq(try ctx.mul(nonzero_sum, base), ctx.zero());
    const inverse = try ctx.inv(try ctx.add(nonzero_sum, base));
    const recurse = try ctx.sub(ctx.one(), base);
    const borrow_value = QM31.fromBase(M31.fromCanonical(if (step_value != 0 and (step_value & 0xffff) == 0) 1 else 0));
    const borrow = try ctx.guessM31(circuit.builder.ivalue.fromQm31(V, borrow_value));
    try ctx.eq(try ctx.mul(borrow, try ctx.sub(borrow, ctx.one())), ctx.zero());
    const previous = try guessCounter(V, ctx, if (step_value == 0) 0 else step_value - 1);
    const two_to_sixteen = try ctx.constant(QM31.fromBase(M31.fromCanonical(65536)));
    const expected_low = try ctx.add(try ctx.sub(step.low, recurse), try ctx.mul(borrow, two_to_sixteen));
    try ctx.eq(previous.low, expected_low);
    try ctx.eq(previous.high, try ctx.sub(step.high, borrow));
    return .{
        .step = step.packed_word,
        .previous = previous.packed_word,
        .base = base,
        .recurse = recurse,
        .inverse = inverse,
        .borrow = borrow,
        .previous_low = previous.low,
    };
}
