//! Exact ordered-call constraint replay for secure points and base-field domain rows.

const Root = @import("provider_order_component.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const poseidon2_air = @import("../air/poseidon2_air.zig");
pub const INPUT_START: usize = 1;
pub const OUTPUT_START: usize = 1 + poseidon2_air.N_TEMPORARIES;
const selected_main_count = Root.selected_main_count;
const constraint_count = Root.constraint_count;
const RowConstantsV1 = Root.RowConstantsV1;

pub fn evaluateGeneric(
    comptime S: type,
    main: [poseidon2_air.N_MAIN_COLUMNS]S,
    current: S,
    previous: S,
    is_first: S,
    is_active: S,
    row_power: S,
    accumulator_power: S,
    first_call: u64,
    call_count: u32,
    terminal: S,
) [constraint_count]S {
    var selected: [selected_main_count]S = undefined;
    @memcpy(
        selected[0..poseidon2_air.WIDTH],
        main[INPUT_START..][0..poseidon2_air.WIDTH],
    );
    selected[poseidon2_air.WIDTH] = main[OUTPUT_START];
    return evaluateSelectedGeneric(
        S,
        selected,
        current,
        previous,
        is_first,
        is_active,
        row_power,
        accumulator_power,
        first_call,
        call_count,
        terminal,
    );
}

pub fn evaluateSelectedGeneric(
    comptime S: type,
    selected: [selected_main_count]S,
    current: S,
    previous: S,
    is_first: S,
    is_active: S,
    row_power: S,
    accumulator_power: S,
    first_call: u64,
    call_count: u32,
    terminal: S,
) [constraint_count]S {
    var value = domainValue(S, 0x524f_5731);
    for (selected) |felt| value = value.mul(row_power).add(felt);
    const seed = rangeSeedGeneric(S, first_call, call_count, row_power);
    const first_expected = seed.mul(accumulator_power).add(value);
    const continued = previous.mul(accumulator_power).add(value);
    return .{
        is_first.mul(current.sub(first_expected)),
        is_active.sub(is_first).mul(current.sub(continued)),
        S.one().sub(is_active).mul(current.sub(previous)),
        is_first.mul(previous.sub(terminal)),
    };
}

pub fn rangeSeedGeneric(
    comptime S: type,
    first_call: u64,
    call_count: u32,
    power: S,
) S {
    var result = domainValue(S, 0x524e_4731);
    var first = first_call;
    for (0..5) |_| {
        result = result.mul(power).add(
            domainValue(S, @intCast(first & 0x7fff)),
        );
        first >>= 15;
    }
    var count = call_count;
    for (0..3) |_| {
        result = result.mul(power).add(domainValue(S, count & 0x7fff));
        count >>= 15;
    }
    return result;
}

pub fn callValue(call: poseidon2_air.Call, power: QM31) QM31 {
    var result = domainFelt(0x524f_5731);
    for (call.input) |value|
        result = result.mul(power).add(QM31.fromBase(M31.fromCanonical(value)));
    return result.mul(power).add(
        QM31.fromBase(M31.fromCanonical(call.narrow_output.?)),
    );
}

pub fn rangeSeed(first_call: u64, call_count: u32, power: QM31) QM31 {
    return rangeSeedGeneric(QM31, first_call, call_count, power);
}

pub fn domainFelt(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

pub fn domainValue(comptime S: type, value: u32) S {
    return S.fromBase(M31.fromCanonical(value));
}

/// Exact field-identical restatement of `evaluateSelectedGeneric(QM31, ..)`
/// for domain rows whose selected main and selector values are base-field
/// elements: Horner over QM31 is expanded into a power sum so every selected
/// felt costs one M31-by-QM31 product, and the shard range seed is folded into
/// a hoisted constant.  No reassociation crosses a non-commutative boundary,
/// so the outputs are bitwise identical to the generic evaluator.
pub fn evaluateSelectedRowPrepared(
    constants: RowConstantsV1,
    selected: [selected_main_count]M31,
    current: QM31,
    previous: QM31,
    is_first: M31,
    is_active: M31,
) [constraint_count]QM31 {
    var value = constants.value_base;
    inline for (0..selected_main_count) |index| {
        value = value.add(
            constants.powers[selected_main_count - 1 - index].mulM31(selected[index]),
        );
    }
    const first_expected = constants.seed_times_accumulator.add(value);
    const continued = previous.mul(constants.accumulator_power).add(value);
    return .{
        current.sub(first_expected).mulM31(is_first),
        current.sub(continued).mulM31(is_active.sub(is_first)),
        current.sub(previous).mulM31(M31.one().sub(is_active)),
        previous.sub(constants.terminal).mulM31(is_first),
    };
}

pub fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}
