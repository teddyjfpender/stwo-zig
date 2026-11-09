//! Unrestricted genuine-QM31 witness producer, not an orphan repair table.
//! Four base coordinates emit one complete Var tuple with source-fixed fanout.
const Core = @import("stwo_core");
const M = Core.fields.m31.M31;
pub const MAIN = 4;
pub const FIXED = 2;
pub const INTER = 8;
pub const ROOTS = 1;
fn lit(comptime F: type, value: M) F {
    return if (F == M) value else F.fromBase(value);
}
pub fn portFor(comptime F: type, main: *const [MAIN]F, fixed: *const [FIXED]F) struct { numerator: F, tuple: [6]F } {
    return .{ .numerator = lit(F, M.zero()).sub(fixed[1]), .tuple = .{ lit(F, M.fromCanonical(@import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID)), fixed[0], main[0], main[1], main[2], main[3] } };
}
pub fn rootFor(comptime F: type, main: *const [MAIN]F, fixed: *const [FIXED]F, current: F, previous: F, z: F, powers: [6]F, shift: F) F {
    const port = portFor(F, main, fixed);
    var denominator = lit(F, M.zero()).sub(z);
    for (port.tuple, powers) |v, power| denominator = denominator.add(v.mul(power));
    return denominator.mul(current.sub(previous).add(shift)).sub(port.numerator);
}
