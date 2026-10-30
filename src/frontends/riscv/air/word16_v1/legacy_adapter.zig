//! Linear compatibility surface for ALL remaining native and caller byte
//! components. This is not an adapter between standalone old and new proofs:
//! the old arithmetic equations and new word events must share authenticated
//! source columns inside the NEW original, under the NEW challenge schedule.
const A = @import("abi.zig");
const R = @import("relations.zig");
pub const Space = enum(u32) { register = 0, ram = 1 };
pub const signed_immediate_range16_requests: u32 = 3;
/// old={space,address,clock,b0,b1,b2,b3}. `space` is selected from the admitted
/// typed event descriptor, never by branching on an untrusted field value.
pub fn access(comptime S: type, comptime space: Space, comptime source_degree: u8, comptime activation_degree: u8, old: [7]S, active: S, multiplicity: S, constraints: anytype, events: anytype) void {
    // Legacy callers can expose polynomial expressions instead of raw main
    // cells. Inherit their compiler-audited degree; never relabel them linear
    // merely because halfword packing itself is affine.
    constraints.add(active.mul(old[0].sub(A.c(S, @intFromEnum(space)))), source_degree + activation_degree);
    const domain: R.Domain = if (space == .register) .register_word else .ram_word;
    events.access(domain, multiplicity, R.legacyTuple(S, old[1], old[2], .{ old[3], old[4], old[5], old[6] }));
}
/// For old immediate-ALU families only, preserve both old AIR equations and
/// bounded sign authority while emitting the new ROM's signed coordinate.
/// No conversion may reinterpret another opcode's operand convention.
pub fn signedImmediate(comptime S: type, low12: S, sign: S, active: S, constraints: anytype, events: anytype) S {
    A.enforce(S, constraints, active, A.boolResidual(S, sign), 2);
    // Unlike the new immediate kernel, this compatibility helper has no
    // independent signed-ROM equality to bound low12 before scaling. Make the
    // integer lift explicit rather than relying only on an old producer bound.
    events.range16(active, low12);
    events.range16(active, low12.mul(A.c(S, 16)));
    events.range16(active, low12.sub(sign.mul(A.c(S, 2048))).mul(A.c(S, 32)));
    return low12.sub(sign.mul(A.c(S, 4096)));
}
/// Public ports are independently derived from pinned CPU/snapshot admission.
/// Range is proved by the public-key factory, not by accepting these host args.
pub fn publicAccess(comptime S: type, comptime space: Space, address: u32, clock: u32, value: u32, multiplicity: S, events: anytype) void {
    events.access(if (space == .register) R.Domain.register_word else R.Domain.ram_word, multiplicity, R.publicTuple(S, address, clock, value));
}
