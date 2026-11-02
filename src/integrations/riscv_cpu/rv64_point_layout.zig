//! Flat lane-value layouts for one RV64 Ethereum batch proof.
//!
//! Challenges follow `rv64_authenticated_execution.drawView` exactly: one entry
//! per `drawSecureFelt`, in draw order (the RAM relation block is the single
//! `drawSecureFelts(24)` call, twelve `(z, alpha)` pairs in schema order).
//! Derived copies (bridge.ram = cpu.state, bridge.bytes = cpu.bytes, the secp
//! and RAM shared BYTE/state challenges) refer to the original entries; derived
//! values (packed ROM byte coefficients, BYTE alpha powers, tagged RAM offsets,
//! Poseidon2 alpha powers) are recomputed over the lane by the lifts.
//! Claims follow `rv64_authenticated_execution.mixClaims` exactly. Publics are
//! the base-field scalars constraints read; see `Publics`.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const rv = A.rv;
const E = rv.evaluation;
const Q = A.Q;
const T = A.T;
const K = rv.crypto.keccak;
const Secp = rv.crypto.secp256k1;
const R = rv.memory;

pub const STATE_DRAWS = 1 + rv.relations.ARITY;
pub const COMPACT_ROM_DRAWS = 1 + rv.program.compact.COUNT;
pub const PACKED_ROM_DRAWS = 1 + rv.program.packed_control.COUNT;
pub const TABLE_DRAWS = 1 + rv.providers.tables.MAX_ARITY;
pub const DIVISION_DRAWS = 1 + rv.arithmetic.division.layout.TUPLE;
pub const MULTIPLICATION_DRAWS = 1 + rv.arithmetic.multiplication.layout.TUPLE;
pub const KECCAK_IO_DRAWS = 1 + K.layout.IO_ARITY;
pub const KECCAK_DRAWS = 2 * TABLE_DRAWS + KECCAK_IO_DRAWS;
pub const BRIDGE_CALL_DRAWS = 11;
pub const SECP_WIRE_DRAWS = 1 + Secp.layout.WIRE_ARITY;
pub const SECP_CALL_DRAWS = 12;
pub const SECP_DRAWS = 1 + SECP_WIRE_DRAWS + SECP_CALL_DRAWS;
pub const RAM_RELATION_DRAWS = R.permutation_point.RELATION_DRAWS;
pub const RAM_INTERNAL_DRAWS = 1 + R.internal_relations.ARITY;
pub const RAM_POLICY_DRAWS = 19;
pub const RAM_DRAWS = RAM_RELATION_DRAWS + RAM_INTERNAL_DRAWS + RAM_POLICY_DRAWS;
pub const CPU_CLAIMS = 5;
pub const SERVICE_CLAIMS = 7;
pub const SECP_CLAIMS = 7;
pub const MULTIPLICATION_CLAIMS = 2;
pub const RAM_PROVIDER_CLAIMS = R.permutation_point.N_SUMS;
pub const FRAME_PUBLICS = 17;
pub const SPAN_PUBLICS = 3;
pub const TABLE_PUBLICS = 2;

/// Static roster flags that fix every layout; derived from a receiver key view.
pub const Flags = struct {
    control: rv.control_policy.Policy,
    profile: A.frontend.rv64.execution_profile.Profile,
    multiplication_challenges: bool,
    has_and: bool,
    has_shift: bool,
    has_division: bool,
    has_multiplication: bool,
    has_crypto: bool,
    secp_present: [2]bool,
    has_ram: bool,
    pub fn fromView(view: A.VerificationView) Flags {
        const plan = view.cpu.base.plan;
        return .{ .control = plan.control_policy, .profile = plan.execution_profile, .multiplication_challenges = plan.arithmetic_policy == .division_multiplication_services_v3, .has_and = view.cpu.base.has_and, .has_shift = view.cpu.base.has_shift, .has_division = view.cpu.has_division, .has_multiplication = view.cpu.has_multiplication, .has_crypto = view.cpu.has_crypto, .secp_present = .{ view.cpu.secp[0] != null, view.cpu.secp[1] != null }, .has_ram = view.has_ram };
    }
    /// Secp challenges, the CPU secp header bus and both call spans exist together.
    pub fn secp(self: Flags) bool {
        return self.profile != .keccak_service_v1;
    }
    /// The CPU Keccak header bus exists for every service profile.
    pub fn keccakBus(self: Flags) bool {
        return self.profile != .rv64im;
    }
};
fn take(at: *usize, count: usize) usize {
    const start = at.*;
    at.* += count;
    return start;
}
fn affine(comptime C: type, comptime arity: usize, flat: []const C, start: usize) struct { offset: C, coefficients: [arity]C } {
    return .{ .offset = flat[start], .coefficients = flat[start + 1 ..][0..arity].* };
}
fn writeAffine(out: []Q, start: usize, offset: Q, coefficients: []const Q) void {
    out[start] = offset;
    @memcpy(out[start + 1 ..][0..coefficients.len], coefficients);
}

/// Challenge entry offsets. Each `*For` accessor rebuilds a component-typed
/// challenge structure over constant lane C from the flat slice.
pub const Challenges = struct {
    flags: Flags,
    state: usize,
    rom: usize,
    bytes: usize,
    bitwise: ?usize,
    shifts: ?usize,
    division: usize,
    multiplication: ?usize,
    keccak: usize,
    bridge_call: usize,
    secp: ?usize,
    ram: ?usize,
    len: usize,
    pub fn init(flags: Flags) Challenges {
        var at: usize = 0;
        const state = take(&at, STATE_DRAWS);
        const rom = take(&at, if (flags.control == .bytes_v1) COMPACT_ROM_DRAWS else PACKED_ROM_DRAWS);
        const bytes = take(&at, 1);
        const bitwise: ?usize = if (flags.has_and) take(&at, TABLE_DRAWS) else null;
        const shifts: ?usize = if (flags.has_shift) take(&at, TABLE_DRAWS) else null;
        const division = take(&at, DIVISION_DRAWS);
        const multiplication: ?usize = if (flags.multiplication_challenges) take(&at, MULTIPLICATION_DRAWS) else null;
        const keccak = take(&at, KECCAK_DRAWS);
        const bridge_call = take(&at, BRIDGE_CALL_DRAWS);
        const secp: ?usize = if (flags.secp()) take(&at, SECP_DRAWS) else null;
        const ram: ?usize = if (flags.has_ram) take(&at, RAM_DRAWS) else null;
        return .{ .flags = flags, .state = state, .rom = rom, .bytes = bytes, .bitwise = bitwise, .shifts = shifts, .division = division, .multiplication = multiplication, .keccak = keccak, .bridge_call = bridge_call, .secp = secp, .ram = ram, .len = at };
    }
    pub fn stateFor(self: Challenges, comptime C: type, flat: []const C) rv.relations.ChallengesFor(C) {
        const values = affine(C, rv.relations.ARITY, flat, self.state);
        return .{ .offset = values.offset, .coefficients = values.coefficients };
    }
    /// ROM coefficients: compact41 draws one coefficient per retained field;
    /// packed26 draws one per limb source and derives `c * 256^j` per byte.
    pub fn romFor(self: Challenges, comptime C: type, flat: []const C) rv.program.provider.ChallengesFor(C) {
        var result = rv.program.provider.ChallengesFor(C){ .offset = flat[self.rom], .coefficients = @splat(C.zero()) };
        if (self.flags.control == .bytes_v1) {
            for (rv.program.compact.fields, flat[self.rom + 1 ..][0..rv.program.compact.COUNT]) |index, value| result.coefficients[index] = value;
        } else {
            for (rv.program.packed_control.sources, flat[self.rom + 1 ..][0..rv.program.packed_control.COUNT]) |source, drawn| {
                var coefficient = drawn;
                for (0..source.bytes) |j| {
                    result.coefficients[source.start + j] = coefficient;
                    coefficient = coefficient.mul(E.qFor(C, 256));
                }
            }
        }
        return result;
    }
    pub fn bytesFor(self: Challenges, comptime C: type, flat: []const C) C {
        return flat[self.bytes];
    }
    fn tableFor(comptime C: type, flat: []const C, start: ?usize) rv.providers.tables.ChallengesFor(C) {
        const at = start orelse return .{ .offset = C.one(), .coefficients = @splat(C.zero()) };
        const values = affine(C, rv.providers.tables.MAX_ARITY, flat, at);
        return .{ .offset = values.offset, .coefficients = values.coefficients };
    }
    pub fn bitwiseFor(self: Challenges, comptime C: type, flat: []const C) rv.providers.tables.ChallengesFor(C) {
        return tableFor(C, flat, self.bitwise);
    }
    pub fn shiftsFor(self: Challenges, comptime C: type, flat: []const C) rv.providers.tables.ChallengesFor(C) {
        return tableFor(C, flat, self.shifts);
    }
    pub fn divisionFor(self: Challenges, comptime C: type, flat: []const C) rv.arithmetic.division.provider.ChallengesFor(C) {
        const values = affine(C, rv.arithmetic.division.layout.TUPLE, flat, self.division);
        return .{ .offset = values.offset, .coefficients = values.coefficients };
    }
    pub fn multiplicationFor(self: Challenges, comptime C: type, flat: []const C) ?rv.arithmetic.multiplication.provider.ChallengesFor(C) {
        const values = affine(C, rv.arithmetic.multiplication.layout.TUPLE, flat, self.multiplication orelse return null);
        return .{ .offset = values.offset, .coefficients = values.coefficients };
    }
    pub fn keccakFor(self: Challenges, comptime C: type, flat: []const C) K.equations.ChallengesFor(C) {
        const io = affine(C, K.layout.IO_ARITY, flat, self.keccak + 2 * TABLE_DRAWS);
        return .{ .chi = tableFor(C, flat, self.keccak), .xor5 = tableFor(C, flat, self.keccak + TABLE_DRAWS), .io = .{ .offset = io.offset, .coefficients = io.coefficients } };
    }
    pub fn bridgeCallFor(self: Challenges, comptime C: type, flat: []const C) K.bridge.equations.CallChallengesFor(C) {
        const values = affine(C, 10, flat, self.bridge_call);
        return .{ .offset = values.offset, .coefficients = values.coefficients };
    }
    pub fn SecpFor(comptime C: type) type {
        return struct { polynomial: C, wire: Secp.equations.WireFor(C), call: Secp.bridge.equations.CallChallengesFor(C) };
    }
    pub fn secpFor(self: Challenges, comptime C: type, flat: []const C) ?SecpFor(C) {
        const start = self.secp orelse return null;
        const wire = affine(C, Secp.layout.WIRE_ARITY, flat, start + 1);
        const call = affine(C, 11, flat, start + 1 + SECP_WIRE_DRAWS);
        return .{ .polynomial = flat[start], .wire = .{ .offset = wire.offset, .coefficients = wire.coefficients }, .call = .{ .offset = call.offset, .coefficients = call.coefficients } };
    }
    pub fn ramDrawsFor(self: Challenges, comptime C: type, flat: []const C) ?*const [RAM_RELATION_DRAWS]C {
        return flat[self.ram orelse return null ..][0..RAM_RELATION_DRAWS];
    }
    pub fn ramInternalFor(self: Challenges, comptime C: type, flat: []const C) ?R.internal_relations.PreparedFor(C) {
        const values = affine(C, R.internal_relations.ARITY, flat, (self.ram orelse return null) + RAM_RELATION_DRAWS);
        return (R.internal_relations.ChallengeFor(C){ .offset = values.offset, .coefficients = values.coefficients }).prepare();
    }
    pub fn ramPolicyFor(self: Challenges, comptime C: type, flat: []const C) ?R.policy_air.PolicyChallengeFor(C) {
        const values = affine(C, 18, flat, (self.ram orelse return null) + RAM_RELATION_DRAWS + RAM_INTERNAL_DRAWS);
        return .{ .offset = values.offset, .coefficients = values.coefficients };
    }
};
/// Native draws in transcript order; `ch` comes from `drawView`.
pub fn flattenChallenges(a: std.mem.Allocator, layout: Challenges, ch: A.Challenges) ![]Q {
    const out = try a.alloc(Q, layout.len);
    errdefer a.free(out);
    const cpu = ch.cpu.cpu;
    writeAffine(out, layout.state, cpu.state.offset, &cpu.state.coefficients);
    out[layout.rom] = cpu.rom.offset;
    if (layout.flags.control == .bytes_v1) {
        for (rv.program.compact.fields, 0..) |index, i| out[layout.rom + 1 + i] = cpu.rom.coefficients[index];
    } else {
        for (rv.program.packed_control.sources, 0..) |source, i| out[layout.rom + 1 + i] = cpu.rom.coefficients[source.start];
    }
    out[layout.bytes] = cpu.bytes;
    if (layout.bitwise) |start| writeAffine(out, start, cpu.bitwise.offset, &cpu.bitwise.coefficients);
    if (layout.shifts) |start| writeAffine(out, start, cpu.shifts.offset, &cpu.shifts.coefficients);
    writeAffine(out, layout.division, ch.cpu.division.offset, &ch.cpu.division.coefficients);
    if (layout.multiplication) |start| {
        const multiplication = ch.cpu.multiplication orelse return error.MissingRv64Challenge;
        writeAffine(out, start, multiplication.offset, &multiplication.coefficients);
    }
    writeAffine(out, layout.keccak, ch.cpu.keccak.chi.offset, &ch.cpu.keccak.chi.coefficients);
    writeAffine(out, layout.keccak + TABLE_DRAWS, ch.cpu.keccak.xor5.offset, &ch.cpu.keccak.xor5.coefficients);
    writeAffine(out, layout.keccak + 2 * TABLE_DRAWS, ch.cpu.keccak.io.offset, &ch.cpu.keccak.io.coefficients);
    writeAffine(out, layout.bridge_call, ch.cpu.bridge.call.offset, &ch.cpu.bridge.call.coefficients);
    if (layout.secp) |start| {
        const secp = ch.cpu.secp orelse return error.MissingRv64Challenge;
        out[start] = secp.arithmetic.polynomial;
        writeAffine(out, start + 1, secp.arithmetic.wire.offset, &secp.arithmetic.wire.coefficients);
        writeAffine(out, start + 1 + SECP_WIRE_DRAWS, secp.call.offset, &secp.call.coefficients);
    }
    if (layout.ram) |start| {
        const ram = ch.ram orelse return error.MissingRv64Challenge;
        try ram.permutations.writeDraws(out[start..][0..RAM_RELATION_DRAWS]);
        // The tag offsets derive from the draw; tag zero carries the raw offset.
        writeAffine(out, start + RAM_RELATION_DRAWS, ram.ram.offsets[0], &ram.ram.coefficients);
        writeAffine(out, start + RAM_RELATION_DRAWS + RAM_INTERNAL_DRAWS, ram.policy.offset, &ram.policy.coefficients);
    }
    return out;
}

/// Claim entry offsets in `mixClaims` order: CPU (state, rom, bytes, bitwise,
/// shifts), services (division, header, permutation, chi, xor5, bridge,
/// bytes), secp (header, add product/linear/bridge, double product/linear/
/// bridge), multiplication (bus, provider), RAM callers per table in
/// `private_trace.TABLES` order, RAM provider (2), RAM policy (1).
pub const Claims = struct {
    flags: Flags,
    cpu: usize,
    service: usize,
    secp: ?usize,
    multiplication: ?usize,
    ram_tables: ?[8]usize,
    ram_provider: ?usize,
    ram_policy: ?usize,
    len: usize,
    pub fn init(flags: Flags) Claims {
        var at: usize = 0;
        const cpu = take(&at, CPU_CLAIMS);
        const service = take(&at, SERVICE_CLAIMS);
        const secp: ?usize = if (flags.secp()) take(&at, SECP_CLAIMS) else null;
        const multiplication: ?usize = if (flags.multiplication_challenges) take(&at, MULTIPLICATION_CLAIMS) else null;
        var tables: ?[8]usize = null;
        var provider: ?usize = null;
        var policy: ?usize = null;
        if (flags.has_ram) {
            var offsets: [8]usize = undefined;
            for (T.TABLES, 0..) |table, i| offsets[i] = take(&at, T.sumCount(table));
            tables = offsets;
            provider = take(&at, RAM_PROVIDER_CLAIMS);
            policy = take(&at, 1);
        }
        return .{ .flags = flags, .cpu = cpu, .service = service, .secp = secp, .multiplication = multiplication, .ram_tables = tables, .ram_provider = provider, .ram_policy = policy, .len = at };
    }
};
pub fn flattenClaims(a: std.mem.Allocator, layout: Claims, claims: A.Claims) ![]Q {
    const out = try a.alloc(Q, layout.len);
    errdefer a.free(out);
    const cpu = claims.cpu;
    @memcpy(out[layout.cpu..][0..CPU_CLAIMS], &[_]Q{ cpu.cpu.state, cpu.cpu.rom, cpu.cpu.bytes, cpu.cpu.bitwise, cpu.cpu.shifts });
    @memcpy(out[layout.service..][0..SERVICE_CLAIMS], &[_]Q{ cpu.division, cpu.header, cpu.permutation, cpu.chi, cpu.xor5, cpu.bridge, cpu.bytes });
    if (layout.secp) |start| @memcpy(out[start..][0..SECP_CLAIMS], &[_]Q{ cpu.secp_header, cpu.secp_add.product, cpu.secp_add.linear, cpu.secp_add.bridge, cpu.secp_double.product, cpu.secp_double.linear, cpu.secp_double.bridge });
    if (layout.multiplication) |start| @memcpy(out[start..][0..MULTIPLICATION_CLAIMS], &[_]Q{ cpu.multiplication, cpu.multiplication_provider });
    if (layout.ram_tables) |tables| {
        const ram = claims.ram orelse return error.MissingRv64Claim;
        for (T.TABLES, tables) |table, start| @memcpy(out[start..][0..T.sumCount(table)], ram.callers.slice(table));
        @memcpy(out[layout.ram_provider.?..][0..RAM_PROVIDER_CLAIMS], &ram.provider);
        out[layout.ram_policy.?] = ram.policy;
    }
    return out;
}

/// Public scalar entry offsets. Frame: steps, eight little-endian initial PC
/// bytes, eight final PC bytes. Keccak span: calls, first call ID, `calls != 0`
/// (shared by the CPU header bus, permutation and bridge). Secp spans (add,
/// double): the same triple per group (shared by the CPU bus and every group
/// component). Division/multiplication: public request count. RAM: per table
/// in `TABLES` order, active row count and `count != 0`.
pub const Publics = struct {
    flags: Flags,
    steps: usize,
    initial_pc: usize,
    final_pc: usize,
    keccak: ?usize,
    secp: ?[2]usize,
    division_count: ?usize,
    multiplication_count: ?usize,
    ram: ?[8]usize,
    len: usize,
    pub fn init(flags: Flags) Publics {
        var at: usize = 0;
        const steps = take(&at, 1);
        const initial_pc = take(&at, 8);
        const final_pc = take(&at, 8);
        const keccak: ?usize = if (flags.keccakBus()) take(&at, SPAN_PUBLICS) else null;
        const secp: ?[2]usize = if (flags.secp()) .{ take(&at, SPAN_PUBLICS), take(&at, SPAN_PUBLICS) } else null;
        const division_count: ?usize = if (flags.has_division) take(&at, 1) else null;
        const multiplication_count: ?usize = if (flags.has_multiplication) take(&at, 1) else null;
        var ram: ?[8]usize = null;
        if (flags.has_ram) {
            var offsets: [8]usize = undefined;
            for (&offsets) |*offset| offset.* = take(&at, TABLE_PUBLICS);
            ram = offsets;
        }
        return .{ .flags = flags, .steps = steps, .initial_pc = initial_pc, .final_pc = final_pc, .keccak = keccak, .secp = secp, .division_count = division_count, .multiplication_count = multiplication_count, .ram = ram, .len = at };
    }
};
pub fn activeRows(shapes: T.Shapes, table: T.Table) u32 {
    return switch (table) {
        .chunk => shapes.chunk.activeRows(),
        .common_cells => shapes.common_cells.activeRows(),
        .edge_cells => shapes.edge_cells.activeRows(),
        .leaf => shapes.leaf.leaves,
        .node => shapes.node.nodes,
        .side => shapes.side.sides,
        .common_permits => shapes.common_permits.certificates,
        .edge_permits => shapes.edge_permits.certificates,
    };
}
fn span(out: []Q, start: usize, calls: u32, first_id: u32) void {
    out[start] = E.q(calls);
    out[start + 1] = E.q(first_id);
    out[start + 2] = E.q(@intFromBool(calls != 0));
}
pub fn flattenPublics(a: std.mem.Allocator, layout: Publics, public: A.Public) ![]Q {
    const out = try a.alloc(Q, layout.len);
    errdefer a.free(out);
    const statement = public.cpu.statement;
    out[layout.steps] = E.q(statement.steps);
    for (0..8) |i| {
        const shift: u6 = @intCast(8 * i);
        out[layout.initial_pc + i] = E.q(@intCast((statement.initial_pc >> shift) & 255));
        out[layout.final_pc + i] = E.q(@intCast((statement.final_pc >> shift) & 255));
    }
    if (layout.keccak) |start| span(out, start, public.cpu.keccak_calls, public.cpu.first_call_id);
    if (layout.secp) |starts| for (starts, public.cpu.secp.groups()) |start, group| span(out, start, group.calls, group.first_id);
    if (layout.division_count) |start| out[start] = E.q(public.cpu.division_requests);
    if (layout.multiplication_count) |start| out[start] = E.q(public.cpu.multiplication_requests);
    if (layout.ram) |starts| {
        const counts = public.ram orelse return error.MissingRv64Public;
        const shapes = try counts.shapes(public.geometry);
        for (T.TABLES, starts) |table, start| {
            const rows = activeRows(shapes, table);
            out[start] = E.q(rows);
            out[start + 1] = E.q(@intFromBool(rows != 0));
        }
    }
    return out;
}
