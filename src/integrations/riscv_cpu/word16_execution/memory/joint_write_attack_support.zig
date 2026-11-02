//! Independent matrix-level repair for mathematical negative tests. Native
//! metadata stores u64 values, so it cannot represent the noncanonical limb
//! aliases these tests must commit. No production prover calls this module.
const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const X = A.word16_execution;
const LS = A.memory.load_store_v2;
const V = A.memory.load_store_v1;
const R = A.memory.closed_ram;
pub const M = core.fields.m31.M31;
pub const Q = core.fields.qm31.QM31;
pub const N: usize = 32;
pub const ADDRESS: u64 = 0x8000;
pub const VALUE: u64 = 1 << 32;
pub const WORDS = [_]u32{ 0x00053083, 0x00153023, 0x00000093, 0x00053083, 0x00053023, 0x00000093 };
const marker: u8 = 0;
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address != ADDRESS) return error.UntrustedJointWriteAddress;
    return VALUE;
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address >= ADDRESS + 8) return error.UntrustedJointWriteAddress;
    return 3;
}
pub fn image() @import("statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
pub fn registers() [32]u64 {
    var out: [32]u64 = @splat(0);
    out[10] = ADDRESS;
    return out;
}
pub fn boundary(first: usize, count: usize) X.types.Boundary {
    var clocks: [32]u32 = @splat(0);
    for (first..first + count, 0..) |instruction, local| {
        const tick: u32 = @intCast(4 * local);
        if (instruction % 3 != 2) clocks[10] = tick + 1;
        if (instruction == 1) clocks[1] = tick + 2;
        if (instruction % 3 != 1) clocks[1] = tick + 3;
    }
    return .{ .steps = @intCast(count), .initial_pc = 4096 + 4 * first, .final_pc = 4096 + 4 * (first + count), .initial_registers = registers(), .final_registers = registers(), .register_clocks = clocks };
}
pub fn tape(a: std.mem.Allocator, first: usize, count: usize) !front.rv64.compact_tape.Tape {
    var out = try front.rv64.compact_tape.Tape.init(a, @intCast(count), 4096 + 4 * first, first, .ethereum_services_v2);
    errdefer out.deinit();
    for (first..first + count, 0..) |instruction, local| {
        const load = instruction % 3 == 0;
        const store = instruction % 3 == 1;
        var memory_index: u32 = front.rv64.compact_tape.NO_MEMORY;
        if (load or store) {
            memory_index = @intCast(out.memory_before.items.len);
            try out.memory_before.append(a, VALUE);
        }
        out.storage[local] = .{ .next_pc = 4096 + 4 * (instruction + 1), .lhs = if (load or store) ADDRESS else 0, .rhs = if (instruction == 1) VALUE else 0, .previous_rd = if (instruction % 3 == 2) VALUE else 0, .result = if (load) VALUE else 0, .memory_index = memory_index, .flags = 0 };
    }
    out.len = @intCast(count);
    return out;
}
fn alias(matrix: []M, logical: usize, start: usize) void {
    const p = X.layout.physical(logical, 5);
    matrix[(start + 1) * N + p] = matrix[(start + 1) * N + p].add(M.fromCanonical(65536));
    matrix[(start + 2) * N + p] = matrix[(start + 2) * N + p].sub(M.one());
}
pub fn forge(cpu: []M, ls: []M, first: usize, count: usize) void {
    var ls_row: usize = 0;
    for (first..first + count, 0..) |instruction, local| {
        if (instruction % 3 == 0) {
            alias(cpu, local, X.layout.main.c);
            for ([_]usize{ 14, 18, V.layout.c }) |start| aliasLs(ls, ls_row, start);
            ls_row += 1;
        } else if (instruction % 3 == 1) {
            aliasLs(ls, ls_row, 14);
            if (instruction == 1) {
                alias(cpu, local, X.layout.main.b);
                aliasLs(ls, ls_row, V.layout.b);
                aliasLs(ls, ls_row, 18);
            }
            ls_row += 1;
        } else alias(cpu, local, X.layout.main.previous_rd);
    }
}
fn aliasLs(matrix: []M, logical: usize, start: usize) void {
    const p = X.layout.physical(logical, 5);
    matrix[LS.layout.projection.column(start + 1) * N + p] = matrix[LS.layout.projection.column(start + 1) * N + p].add(M.fromCanonical(65536));
    matrix[LS.layout.projection.column(start + 2) * N + p] = matrix[LS.layout.projection.column(start + 2) * N + p].sub(M.one());
}
pub const CpuAudit = struct { total: Q = Q.zero(), register: Q = Q.zero(), owner: Q = Q.zero(), function: Q = Q.zero() };
pub fn repairCpu(main: []const M, inter: []M, public: X.types.Boundary, epoch: u16, ch: X.types.Challenges) !CpuAudit {
    var audit = CpuAudit{};
    var sum = Q.zero();
    const inputs = try X.types.inputs(public, epoch, 5);
    for (0..N) |logical| {
        const p = X.layout.physical(logical, 5);
        var row: [X.layout.main.COUNT]M = undefined;
        for (&row, 0..) |*value, c| value.* = main[c * N + p];
        const fixed = [_]M{ M.fromCanonical(@intCast(logical)), M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical + 1 == N)) };
        const ds = X.equations.nativeDenominators(&fixed, &row, inputs, ch);
        const denominators = X.equations.inverseDenominatorsFor(Q, ds);
        var inverses: [9]Q = undefined;
        for (denominators, &inverses, 0..) |d, *inverse, j| {
            inverse.* = try d.inv();
            R.trace.store(inter, N, p, 4 * j, inverse.*);
        }
        const weights = X.equations.weightsFor(M, &row);
        for (0..3) |slot| audit.register = audit.register.add(ds.after[slot].sub(ds.before[slot]).mul(inverses[slot]).mulM31(weights.registers[slot]));
        audit.owner = audit.owner.add((try ds.affine[0].inv()).mulM31(weights.owner));
        audit.function = audit.function.add(inverses[3].mulM31(weights.function));
        sum = sum.add(X.equations.nativeContribution(ds, &row, inverses));
        R.trace.store(inter, N, p, X.layout.inter.sum, sum);
    }
    R.trace.center(inter, N, X.layout.inter.sum, sum);
    audit.total = sum;
    return audit;
}
pub fn repairLs(main: []const M, inter: []M, ch: LS.types.Challenges) !LS.types.Claims {
    var claims = LS.types.Claims.zero();
    for (0..N) |logical| {
        const p = X.layout.physical(logical, 5);
        var physical: [LS.layout.MAIN]Q = undefined;
        for (&physical, 0..) |*v, c| v.* = Q.fromBase(main[c * N + p]);
        const m = LS.layout.projection.expandFor(Q, &physical);
        const before = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, m[0..28], false));
        const after = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, m[0..28], true));
        const inverse = try before.mul(after).inv();
        R.trace.store(inter, N, p, 0, inverse);
        claims.ram = claims.ram.add(after.sub(before).mul(inverse).mul(m[0]));
        R.trace.store(inter, N, p, 4, claims.ram);
        var inv: [LS.layout.LOCAL_FRACTIONS]Q = undefined;
        inv[0] = try ch.owner.denominatorFor(Q, LS.equations.ownerTupleForLogical(Q, &m)).neg().inv();
        claims.owner = claims.owner.add(inv[0].mul(m[0]));
        for (LS.layout.LOGICAL_U16, 0..) |column, j| {
            inv[1 + j] = try ch.range16.denominatorFor(Q, m[column]).inv();
            claims.range16 = claims.range16.add(inv[1 + j]);
        }
        for (LS.layout.LOGICAL_U8, 0..) |column, j| {
            inv[1 + LS.layout.U16.len + j] = try ch.range8.denominatorFor(Q, m[column]).inv();
            claims.range8 = claims.range8.add(inv[1 + LS.layout.U16.len + j]);
        }
        inv[inv.len - 1] = try ch.selection.denominatorFor(Q, V.equations.selectionTuple(Q, &m)).inv();
        claims.selection = claims.selection.add(inv[inv.len - 1]);
        for (0..LS.layout.LOCAL_PAIRS) |pair| R.trace.store(inter, N, p, LS.layout.LOCAL_INVERSES + 4 * pair, inv[2 * pair].mul(inv[2 * pair + 1]));
        R.trace.store(inter, N, p, LS.layout.LOCAL_PREFIX, claims.owner.add(claims.range16).add(claims.range8).add(claims.selection));
    }
    R.trace.center(inter, N, 4, claims.ram);
    R.trace.center(inter, N, LS.layout.LOCAL_PREFIX, claims.owner.add(claims.range16).add(claims.range8).add(claims.selection));
    return claims;
}
/// A locally valid CPU read of a non-existent register token. No other bus
/// carries previous_rd, so this isolates per-CPU REG closure from global RAM.
pub fn forgeRegisterOrphan(cpu: []M) void {
    alias(cpu, 2, X.layout.main.previous_rd);
}
