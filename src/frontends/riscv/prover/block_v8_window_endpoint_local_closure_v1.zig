//! Pure joined-window algebra. This grants NO original/recursive proof
//! authority and does not relax the native-only endpoint admission guard.
//! In the future joined protocol the exact caller roster, identical local
//! clock/address namespace, arithmetic partitions and endpoint scope must be
//! independently admitted before invoking this equation.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Native = struct { ram: Q, ram_clock: Q, state_residual: Q, register_residual: Q };
pub const Caller = struct {
    /// Roster order is independently derived, never inferred from claims.
    index: u32,
    window_identity: [32]u8,
    ram: Q,
    state: Q,
    registers: Q,
    /// arithmetic - program - state - registers - tables - RAM.
    /// Private hash/elliptic-curve provider relations must already be closed.
    internal_residual: Q,
};
pub fn close(window_identity: [32]u8, expected_callers: usize, native: Native, callers: []const Caller, endpoint_supplier: Q) !void {
    if (expected_callers > 64 or expected_callers != callers.len or std.mem.allEqual(u8, &window_identity, 0)) return error.InvalidEndpointWindowRoster;
    inline for (std.meta.fields(Native)) |field| try canonical(@field(native, field.name));
    try canonical(endpoint_supplier);
    var ram = native.ram.add(native.ram_clock).add(endpoint_supplier);
    var state = native.state_residual;
    var registers = native.register_residual;
    for (callers, 0..) |caller, index| {
        if (caller.index != index or !std.meta.eql(caller.window_identity, window_identity)) return error.UntrustedEndpointWindowCaller;
        inline for (.{ "ram", "state", "registers", "internal_residual" }) |name| try canonical(@field(caller, name));
        // Do not permit a bad caller's arithmetic residual to cancel another
        // caller's residual, even inside the same local clock namespace.
        if (!caller.internal_residual.isZero()) return error.UnclosedEndpointCallerArithmetic;
        ram = ram.add(caller.ram);
        state = state.add(caller.state);
        registers = registers.add(caller.registers);
    }
    if (!ram.isZero()) return error.UnclosedEndpointWindowRam;
    if (!state.isZero() or !registers.isZero()) return error.UnclosedEndpointWindowState;
}
fn canonical(value: Q) !void {
    for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointWindowClaim;
}
