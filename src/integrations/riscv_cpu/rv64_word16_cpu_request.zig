//! Inactive WORD16 CPU-side request projection. This is not a CPU AIR or bus
//! verifier. The future CPU must ROM-authenticate the operation/controls, link
//! A/C to its register/control authority, range-check every limb, and seal all
//! payload/weight columns in stage1 before shared challenges are drawn. Pure
//! function tuples carry no CPU row/owner: full identities belong to the sealed
//! manifest, and multiplicities may reuse one valid fact across many CPU rows.
const air = @import("stwo_riscv_frontend").rv64_air;
const E = air.evaluation;
const O = @import("stwo_riscv_frontend").rv64.decode.Opcode;
const Operations = air.word16_v1.operations;
// Payload0 uses the canonical disjoint global function IDs, not family-local
// selector indices. All families may therefore share one PureFun relation.
pub const PAYLOAD = 13;
pub const MUX_CONSTRAINTS = 4;
pub const NEW_ADVICE = 4;
pub const physical_bus_closed = false;
pub fn ViewFor(comptime F: type) type {
    return struct {
        // These are committed columns or direct affine views of committed
        // columns. In particular C must not be a selector*result expression
        // inside the lookup denominator. Branch C is [taken,0,0,0].
        bus_id: F,
        use_immediate: F,
        a: [4]F,
        register_b: [4]F,
        immediate: [4]F,
        effective_b: [4]F,
        c: [4]F,
    };
}
pub fn payload(comptime F: type, view: ViewFor(F)) [PAYLOAD]F {
    var result: [PAYLOAD]F = undefined;
    result[0] = view.bus_id;
    @memcpy(result[1..5], &view.a);
    @memcpy(result[5..9], &view.effective_b);
    @memcpy(result[9..13], &view.c);
    return result;
}
/// Exactly four quadratic equations. use_immediate is authenticated by ROM,
/// rather than admitted as a producer-chosen Boolean. No active masking: the
/// future geometry must also assign canonical inputs to padding rows.
pub fn evaluate(comptime F: type, view: ViewFor(F), out: *E.SinkFor(F)) void {
    for (0..4) |i| out.emit(view.effective_b[i].sub(view.register_b[i]).sub(view.use_immediate.mul(view.immediate[i].sub(view.register_b[i]))));
}
pub const Native = struct {
    operation: Operations.Operation,
    values: [PAYLOAD]u16,
};
/// Hint construction only; expectedOpcode must come from immutable ROM in the
/// eventual caller. This helper neither re-executes nor verifies arithmetic.
pub fn project(expectedOpcode: O, lhs: u64, rhs: u64, immediate: u64, result: u64, taken: bool) ?Native {
    const operation = Operations.classify(expectedOpcode) orelse return null;
    var values: [PAYLOAD]u16 = undefined;
    values[0] = operation.busId();
    const b = if (operation.use_immediate) immediate else rhs;
    const c = if (operation.branch_predicate) @as(u64, @intFromBool(taken)) else result;
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        values[1 + i] = @truncate(lhs >> shift);
        values[5 + i] = @truncate(b >> shift);
        values[9 + i] = @truncate(c >> shift);
    }
    return .{ .operation = operation, .values = values };
}
