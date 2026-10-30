//! All eight load/store instructions. Semantic rows deliberately retain some
//! redundant views; an independently audited physical lowering is still needed.
const A = @import("abi.zig");
const R = @import("relations.zig");
pub const Load = enum(u32) { lb = 19, lh = 20, lw = 21, lbu = 22, lhu = 23 };
pub const Store = enum(u32) { sb = 24, sh = 25, sw = 26 };
/// This is a trusted KEY parameter, not a caller-nominated witness. Before
/// any future proof/key is admitted, the receiver must independently bind the
/// address to its pinned ELF, validate alignment/platform bounds, and bind a
/// permitted native cycle to the actual terminal local frame/full boundary.
/// Writer validation is hygiene only; evaluate intentionally bypasses writers.
/// A wrong policy address can make an actual halt write appear as hit=0.
pub const Halt = struct { address: u32, permitted_native_cycle: ?u32 = null };
pub fn Address(comptime S: type) type {
    return struct { quarter_low14: S, quarter_high14: S, offset_bits: [2]S };
}
fn offset(comptime S: type, address: Address(S)) S {
    return address.offset_bits[0].add(address.offset_bits[1].mul(A.c(S, 2)));
}
pub fn byteAddress(comptime S: type, address: Address(S)) S {
    // This address is <2^30, so this field expression is injective.
    return address.quarter_low14.mul(A.c(S, 4)).add(address.quarter_high14.mul(A.c(S, 65536))).add(offset(S, address));
}
pub fn alignedAddress(comptime S: type, address: Address(S)) S {
    return address.quarter_low14.mul(A.c(S, 4)).add(address.quarter_high14.mul(A.c(S, 65536)));
}
fn addressConstraints(comptime S: type, constraints: anytype, events: anytype, active: S, base: A.Word(S), immediate: S, address: Address(S), comptime width: u3) void {
    for (address.offset_bits) |bit| A.enforce(S, constraints, active, A.boolResidual(S, bit), 2);
    if (width == 4) {
        A.enforce(S, constraints, active, address.offset_bits[0], 1);
        A.enforce(S, constraints, active, address.offset_bits[1], 1);
    } else if (width == 2) A.enforce(S, constraints, active, address.offset_bits[0], 1);
    // Preserve released platform restriction base<2^30, not generic u32 wrap.
    events.range16(active, base.hi.mul(A.c(S, 4)));
    // The scaled lookup ALONE does not prove an integer 14-bit quarter:
    // q=4^{-1} in M31 would satisfy range16(4*q)=range16(1).
    // First bound q itself; then 4*q<2^18<p has no modular alias.
    events.range16(active, address.quarter_low14);
    events.range16(active, address.quarter_low14.mul(A.c(S, 4)));
    // qHigh additionally equals canonical base.hi + a ternary carry below.
    // Therefore qHigh is in [-1,65536] as an integer before this scaled check:
    // qHigh=-1 maps to p-4 and fails, and positive 4*qHigh cannot wrap p.
    events.range16(active, address.quarter_high14.mul(A.c(S, 4)));
    const effective_low = address.quarter_low14.mul(A.c(S, 4)).add(offset(S, address));
    const carry = A.divide65536(S, base.lo.add(immediate).sub(effective_low));
    A.enforce(S, constraints, active, A.ternaryResidual(S, carry), 3);
    A.enforce(S, constraints, active, base.hi.add(carry).sub(address.quarter_high14), 1);
}
fn view(comptime S: type, constraints: anytype, events: anytype, active: S, word: A.Word(S), bytes: [4]S) void {
    A.equalWord(S, constraints, active, word, A.Word(S).packedBytes(bytes));
    R.byteViewRange(S, events, active, bytes);
}
fn selectors(comptime S: type, address: Address(S)) [4]S {
    const low = address.offset_bits[0];
    const high = address.offset_bits[1];
    return .{ S.one().sub(low).mul(S.one().sub(high)), low.mul(S.one().sub(high)), S.one().sub(low).mul(high), low.mul(high) };
}
/// First halt is checked at EVERY authenticated RAM access. Caller adapters
/// must always supply null permitted_native_cycle. Terminal permission only
/// exempts the exact admitted native last cycle; full boundary AIR still must
/// prove that the final halt value is one and expected output is correct.
fn haltConstraints(comptime S: type, constraints: anytype, active: S, policy: Halt, clock: S, address: S, after: A.Word(S), auxiliary: [2]S) void {
    const delta = address.sub(A.c(S, policy.address));
    const hit = auxiliary[0];
    const inverse = auxiliary[1];
    A.enforce(S, constraints, active, A.boolResidual(S, hit), 2);
    A.enforce(S, constraints, active, delta.mul(hit), 2);
    A.enforce(S, constraints, active, delta.mul(inverse).sub(S.one()).add(hit), 2);
    A.enforce(S, constraints, active, hit.mul(inverse), 2);
    const gate = if (policy.permitted_native_cycle) |last| hit.mul(clock.sub(A.c(S, last))) else hit;
    // Conservative fixed degree ceiling for both policy variants.
    constraints.add(active.mul(gate).mul(after.lo), 4);
    constraints.add(active.mul(gate).mul(after.hi), 4);
}
pub fn LoadRow(comptime S: type) type {
    return struct {
        clock: S,
        pc: S,
        base: A.Read(S),
        memory: A.Read(S),
        destination: A.Write(S),
        immediate: S,
        address: Address(S),
        memory_bytes: [4]S,
        selected: S,
        sign: S,
        result: A.Word(S),
        rd_nonzero: S,
        rd_inverse: S,
        halt_auxiliary: [2]S,
    };
}
pub fn load(comptime S: type, comptime op: Load, row: LoadRow(S), active: S, policy: Halt, constraints: anytype, events: anytype) void {
    A.padding(S, constraints, active, row);
    const width: u3 = switch (op) {
        .lw => 4,
        .lh, .lhu => 2,
        else => 1,
    };
    addressConstraints(S, constraints, events, active, row.base.value, row.immediate, row.address, width);
    A.enforce(S, constraints, active, row.memory.address.sub(alignedAddress(S, row.address)), 1);
    if (op == .lw) {
        A.equalWord(S, constraints, active, row.result, row.memory.value);
        for (row.memory_bytes) |byte| A.enforce(S, constraints, active, byte, 1);
        A.enforce(S, constraints, active, row.selected, 1);
        A.enforce(S, constraints, active, row.sign, 1);
    } else {
        view(S, constraints, events, active, row.memory.value, row.memory_bytes);
        A.enforce(S, constraints, active, A.boolResidual(S, row.sign), 2);
        if (width == 1) {
            const select = selectors(S, row.address);
            var selected = S.zero();
            for (select, row.memory_bytes) |weight, byte| selected = selected.add(weight.mul(byte));
            A.enforce(S, constraints, active, row.selected.sub(selected), 3);
            if (op == .lb) events.range16(active, row.selected.sub(row.sign.mul(A.c(S, 128))).mul(A.c(S, 512))) else A.enforce(S, constraints, active, row.sign, 1);
            A.enforce(S, constraints, active, row.result.lo.sub(row.selected.add(row.sign.mul(A.c(S, 65280)))), 1);
            A.enforce(S, constraints, active, row.result.hi.sub(row.sign.mul(A.c(S, 65535))), 1);
        } else {
            const lower = row.memory.value.lo;
            const upper = row.memory.value.hi;
            const selected = lower.add(row.address.offset_bits[1].mul(upper.sub(lower)));
            A.enforce(S, constraints, active, row.selected.sub(selected), 2);
            if (op == .lh) events.range16(active, row.selected.sub(row.sign.mul(A.c(S, 32768))).mul(A.c(S, 2))) else A.enforce(S, constraints, active, row.sign, 1);
            A.enforce(S, constraints, active, row.result.lo.sub(row.selected), 1);
            A.enforce(S, constraints, active, row.result.hi.sub(row.sign.mul(A.c(S, 65535))), 1);
        }
    }
    A.destination(S, constraints, active, row.destination, row.result, row.rd_nonzero, row.rd_inverse);
    haltConstraints(S, constraints, active, policy, row.clock, row.memory.address, row.memory.value, row.halt_auxiliary);
    R.read(S, events, .register_word, active, row.base, A.accessClock(S, row.clock, 0));
    R.read(S, events, .ram_word, active, row.memory, A.accessClock(S, row.clock, 1));
    R.write(S, events, .register_word, active, row.destination, A.accessClock(S, row.clock, 2));
    events.rom(active, row.pc, @intFromEnum(op), row.destination.address, row.base.address, row.immediate);
    R.sequential(S, events, active, row.clock, row.pc);
}
pub fn StoreRow(comptime S: type) type {
    return struct {
        clock: S,
        pc: S,
        base: A.Read(S),
        source: A.Read(S),
        memory: A.Write(S),
        immediate: S,
        address: Address(S),
        source_bytes: [4]S,
        before_bytes: [4]S,
        after_bytes: [4]S,
        halt_auxiliary: [2]S,
    };
}
pub fn store(comptime S: type, comptime op: Store, row: StoreRow(S), active: S, policy: Halt, constraints: anytype, events: anytype) void {
    A.padding(S, constraints, active, row);
    const width: u3 = switch (op) {
        .sw => 4,
        .sh => 2,
        .sb => 1,
    };
    addressConstraints(S, constraints, events, active, row.base.value, row.immediate, row.address, width);
    A.enforce(S, constraints, active, row.memory.address.sub(alignedAddress(S, row.address)), 1);
    if (op == .sw) {
        A.equalWord(S, constraints, active, row.memory.after, row.source.value);
        for (row.source_bytes) |byte| A.enforce(S, constraints, active, byte, 1);
        for (row.before_bytes) |byte| A.enforce(S, constraints, active, byte, 1);
        for (row.after_bytes) |byte| A.enforce(S, constraints, active, byte, 1);
    } else {
        view(S, constraints, events, active, row.source.value, row.source_bytes);
        view(S, constraints, events, active, row.memory.before, row.before_bytes);
        // Do not range-check arbitrary replacement bytes instead of proving
        // unchanged portions: ALL four exact replacement equations are below.
        A.equalWord(S, constraints, active, row.memory.after, A.Word(S).packedBytes(row.after_bytes));
        if (op == .sb) {
            const select = selectors(S, row.address);
            for (0..4) |i| A.enforce(S, constraints, active, row.after_bytes[i].sub(row.before_bytes[i].add(select[i].mul(row.source_bytes[0].sub(row.before_bytes[i])))), 3);
        } else {
            const high = row.address.offset_bits[1];
            for (0..4) |i| {
                const selected = if (i < 2) S.one().sub(high) else high;
                A.enforce(S, constraints, active, row.after_bytes[i].sub(row.before_bytes[i].add(selected.mul(row.source_bytes[i % 2].sub(row.before_bytes[i])))), 2);
            }
        }
        // Bounds of after bytes flow from exact replacement of bounded inputs.
    }
    haltConstraints(S, constraints, active, policy, row.clock, row.memory.address, row.memory.after, row.halt_auxiliary);
    R.read(S, events, .register_word, active, row.base, A.accessClock(S, row.clock, 0));
    R.read(S, events, .register_word, active, row.source, A.accessClock(S, row.clock, 1));
    R.write(S, events, .ram_word, active, row.memory, A.accessClock(S, row.clock, 2));
    events.rom(active, row.pc, @intFromEnum(op), row.source.address, row.base.address, row.immediate);
    R.sequential(S, events, active, row.clock, row.pc);
}
