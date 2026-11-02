//! Lifts the native batch roster into lane-typed component instances whose
//! challenges, claims and publics come from the flat slices of
//! rv64_point_layout.zig. Shape fields (logs, offsets, plans, kinds) are
//! copied from the native instances; no lane value is ever read from them.
//!
//! Per component, the slice indices read (C = challenge, M = claim, P = public):
//!   cpu            C state, rom, bytes, bitwise?, shifts?, division, keccak
//!                  bridge call, multiplication?, secp call?; M cpu[0..5],
//!                  service[0] (division bus), service[1] (header bus),
//!                  multiplication[0], secp[0]; P frame, keccak span, secp spans
//!   program        C rom; M -cpu[1]
//!   bytes          C bytes; M service[6] (the joined BYTE claim overrides -cpu[2])
//!   bitwise/shifts C bitwise/shifts; M -cpu[3]/-cpu[4]
//!   division       C division; M -service[0]; P division count
//!   multiplication C multiplication, bytes; M multiplication[1]; P mul count
//!   permutation    C keccak; M service[2]; P keccak span
//!   chi/xor5       C keccak; M service[3]/service[4]
//!   bridge         C keccak io, bridge call, state, bytes; M service[5]; P keccak span
//!   secp k product C secp polynomial/wire, bytes; M secp[1+3k]; P secp span k
//!   secp k linear  same challenges; M secp[2+3k]
//!   secp k bridge  C secp wire/call, state, bytes; M secp[3+3k]; P secp span k
//!   RAM table t    C ram internal (+ ram relation pair 5 for chunk/node,
//!                  state for cells, policy for permits), bytes; M table t; P ram t
//!   RAM provider   C ram relation draws; M ram provider
//!   RAM policy     C ram policy; M ram policy
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const Layout = @import("rv64_point_layout.zig");
const Key = @import("rv64_execution_verifier_key.zig");
const rv = A.rv;
const E = rv.evaluation;
const Q = A.Q;
const T = A.T;
const Cpu = rv.full.component;
const Rom = rv.program.component;
const Byte = rv.providers.byte;
const Table = rv.providers.table_component;
const Division = rv.arithmetic.division.component;
const Multiplication = rv.arithmetic.multiplication.component;
const K = rv.crypto.keccak;
const Secp = rv.crypto.secp256k1;
const R = rv.memory;

pub const Layouts = struct {
    challenges: Layout.Challenges,
    claims: Layout.Claims,
    publics: Layout.Publics,
    pub fn init(flags: Layout.Flags) Layouts {
        return .{ .challenges = .init(flags), .claims = .init(flags), .publics = .init(flags) };
    }
};
pub fn Slices(comptime C: type) type {
    return struct { challenges: []const C, claims: []const C, publics: []const C };
}
pub fn SecpGroupFor(comptime C: type) type {
    return struct { product: Secp.component.ComponentFor(C), linear: Secp.component.ComponentFor(C), bridge: Secp.bridge.component.ComponentFor(C) };
}
pub fn RamFor(comptime C: type) type {
    return struct {
        chunk: R.chunk_component.ComponentFor(C),
        common_cells: R.cell_component.ComponentFor(C),
        edge_cells: R.cell_component.ComponentFor(C),
        leaf: R.leaf_component.ComponentFor(C),
        node: R.node_component.ComponentFor(C),
        side: R.side_component.ComponentFor(C),
        common_permits: R.permit_component.ComponentFor(C),
        edge_permits: R.permit_component.ComponentFor(C),
        permutations: R.permutation_point.ComponentFor(C),
        policy: R.policy_component.ComponentFor(C),
    };
}
/// The batch roster over constant lane C, in verifier handle order.
pub fn LiftedFor(comptime C: type) type {
    return struct {
        cpu: Cpu.ComponentFor(C),
        program: Rom.ComponentFor(C),
        bytes: Byte.ComponentFor(C),
        bitwise: ?Table.ComponentFor(C),
        shifts: ?Table.ComponentFor(C),
        division: ?Division.ComponentFor(C),
        multiplication: ?Multiplication.ComponentFor(C),
        permutation: ?K.component.ComponentFor(C),
        chi: ?K.component.ComponentFor(C),
        xor5: ?K.component.ComponentFor(C),
        bridge: ?K.bridge.component.ComponentFor(C),
        secp: [2]?SecpGroupFor(C),
        ram: ?RamFor(C),
    };
}

inline fn countOr(comptime C: type, native: anytype, publics: []const C, index: ?usize) !E.CountFor(C) {
    if (comptime E.isExternalLane(C)) return publics[index orelse return error.MissingRv64LanePublic];
    return @intCast(native);
}
inline fn constCount(comptime C: type, value: u32) E.CountFor(C) {
    if (comptime E.isExternalLane(C)) return C.fromU32(value);
    return value;
}
inline fn flagOr(comptime C: type, publics: []const C, index: ?usize) !E.FlagFor(C) {
    if (comptime E.isExternalLane(C)) return publics[index orelse return error.MissingRv64LanePublic];
    return {};
}
inline fn spanOr(comptime C: type, native: E.CallSpanFor(Q), publics: []const C, base: ?usize) !E.CallSpanFor(C) {
    if (comptime E.isExternalLane(C)) {
        const start = base orelse return error.MissingRv64LanePublic;
        return .{ .calls = publics[start], .first_id = publics[start + 1], .nonempty = publics[start + 2] };
    }
    return native;
}
inline fn activeOr(comptime C: type, publics: []const C, base: ?usize) !R.prefix.ActiveFor(C) {
    if (comptime E.isExternalLane(C)) {
        const start = base orelse return error.MissingRv64LanePublic;
        return .{ .rows = publics[start], .nonempty = publics[start + 1] };
    }
    return {};
}
fn offsetAt(base: ?usize, offset: usize) ?usize {
    return if (base) |start| start + offset else null;
}
fn tableIndex(tables: ?[8]usize, table: usize, offset: usize) ?usize {
    return if (tables) |starts| starts[table] + offset else null;
}

pub fn lift(comptime C: type, native: *const Key.Components, layouts: Layouts, slices: Slices(C)) !LiftedFor(C) {
    E.assertConstLane(C);
    const ch = slices.challenges;
    const cl = slices.claims;
    const pb = slices.publics;
    const CH = layouts.challenges;
    const CL = layouts.claims;
    const PB = layouts.publics;
    if (ch.len != CH.len or cl.len != CL.len or pb.len != PB.len) return error.InvalidRv64LaneSliceLength;
    const state = CH.stateFor(C, ch);
    const rom = CH.romFor(C, ch);
    const bytes = CH.bytesFor(C, ch);
    const division = CH.divisionFor(C, ch);
    const multiplication = CH.multiplicationFor(C, ch);
    const keccak = CH.keccakFor(C, ch);
    const bridge_call = CH.bridgeCallFor(C, ch);
    const secp = CH.secpFor(C, ch);
    const base = &native.cpu.base;
    const n = &base.cpu;
    var result: LiftedFor(C) = undefined;
    result.cpu = .{
        .log_size = n.log_size,
        .plan = n.plan,
        .public = if (comptime E.isExternalLane(C)) .{ .steps = pb[PB.steps], .initial_pc = pb[PB.initial_pc..][0..8].*, .final_pc = pb[PB.final_pc..][0..8].* } else n.public,
        .challenges = .{ .state = state, .rom = rom, .bytes = bytes, .bitwise = CH.bitwiseFor(C, ch), .shifts = CH.shiftsFor(C, ch) },
        .claims = .{ .state = cl[CL.cpu], .rom = cl[CL.cpu + 1], .bytes = cl[CL.cpu + 2], .bitwise = cl[CL.cpu + 3], .shifts = cl[CL.cpu + 4] },
        .offsets = n.offsets,
        .constraint_count = n.constraint_count,
        .inflation = n.inflation,
        .byte_alpha = rv.range.cpu.PreparedAlphaFor(C).init(bytes),
        .division_bus = if (n.division_bus != null) .{ .challenges = division, .claim = cl[CL.service] } else null,
        .keccak_bus = if (n.keccak_bus) |bus| .{ .challenges = bridge_call, .claim = cl[CL.service + 1], .calls = try countOr(C, bus.calls, pb, offsetAt(PB.keccak, 0)), .first_call_id = try countOr(C, bus.first_call_id, pb, offsetAt(PB.keccak, 1)) } else null,
        .multiplication_bus = if (n.multiplication_bus != null) .{ .challenges = multiplication orelse return error.MissingRv64Challenge, .claim = cl[CL.multiplication orelse return error.MissingRv64Claim] } else null,
        .secp_bus = if (n.secp_bus) |bus| .{
            .challenges = (secp orelse return error.MissingRv64Challenge).call,
            .claim = cl[CL.secp orelse return error.MissingRv64Claim],
            .calls = .{ try countOr(C, bus.calls[0], pb, offsetAt(if (PB.secp) |s| s[0] else null, 0)), try countOr(C, bus.calls[1], pb, offsetAt(if (PB.secp) |s| s[1] else null, 0)) },
            .first_ids = .{ try countOr(C, bus.first_ids[0], pb, offsetAt(if (PB.secp) |s| s[0] else null, 1)), try countOr(C, bus.first_ids[1], pb, offsetAt(if (PB.secp) |s| s[1] else null, 1)) },
            .execution_profile = bus.execution_profile,
        } else null,
    };
    result.program = .{ .log_size = base.program.log_size, .encoding = base.program.encoding, .fixed_offset = base.program.fixed_offset, .main_offset = base.program.main_offset, .interaction_offset = base.program.interaction_offset, .challenges = rom, .claim = cl[CL.cpu + 1].neg() };
    result.bytes = .{ .log_size = base.bytes.log_size, .fixed_offset = base.bytes.fixed_offset, .main_offset = base.bytes.main_offset, .interaction_offset = base.bytes.interaction_offset, .alpha = bytes, .claim = cl[CL.service + 6] };
    result.bitwise = if (base.bitwise) |t| .{ .kind = t.kind, .fixed_offset = t.fixed_offset, .main_offset = t.main_offset, .interaction_offset = t.interaction_offset, .challenges = CH.bitwiseFor(C, ch), .claim = cl[CL.cpu + 3].neg() } else null;
    result.shifts = if (base.shifts) |t| .{ .kind = t.kind, .fixed_offset = t.fixed_offset, .main_offset = t.main_offset, .interaction_offset = t.interaction_offset, .challenges = CH.shiftsFor(C, ch), .claim = cl[CL.cpu + 4].neg() } else null;
    result.division = if (native.cpu.division) |d| .{ .log_size = d.log_size, .count = try countOr(C, d.count, pb, PB.division_count), .fixed_offset = d.fixed_offset, .main_offset = d.main_offset, .interaction_offset = d.interaction_offset, .challenges = division, .claim = cl[CL.service].neg(), .reference_domain = d.reference_domain } else null;
    result.multiplication = if (native.cpu.multiplication) |m| .{ .log_size = m.log_size, .count = try countOr(C, m.count, pb, PB.multiplication_count), .fixed_offset = m.fixed_offset, .main_offset = m.main_offset, .interaction_offset = m.interaction_offset, .challenges = multiplication orelse return error.MissingRv64Challenge, .claim = cl[(CL.multiplication orelse return error.MissingRv64Claim) + 1], .byte_alpha = rv.range.cpu.PreparedAlphaFor(C).init(bytes), .reference_domain = m.reference_domain } else null;
    result.permutation = if (native.cpu.permutation) |k| .{ .kind = k.kind, .log_size = k.log_size, .calls = try countOr(C, k.calls, pb, offsetAt(PB.keccak, 0)), .first_call_id = try countOr(C, k.first_call_id, pb, offsetAt(PB.keccak, 1)), .calls_nonzero = try flagOr(C, pb, offsetAt(PB.keccak, 2)), .offsets = k.offsets, .challenges = keccak, .claim = cl[CL.service + 2] } else null;
    result.chi = if (native.cpu.chi) |k| .{ .kind = k.kind, .log_size = k.log_size, .calls = constCount(C, 0), .first_call_id = constCount(C, 1), .calls_nonzero = try flagOr(C, pb, offsetAt(PB.keccak, 2)), .offsets = k.offsets, .challenges = keccak, .claim = cl[CL.service + 3] } else null;
    result.xor5 = if (native.cpu.xor5) |k| .{ .kind = k.kind, .log_size = k.log_size, .calls = constCount(C, 0), .first_call_id = constCount(C, 1), .calls_nonzero = try flagOr(C, pb, offsetAt(PB.keccak, 2)), .offsets = k.offsets, .challenges = keccak, .claim = cl[CL.service + 4] } else null;
    result.bridge = if (native.cpu.bridge) |b| .{ .log_size = b.log_size, .calls = try countOr(C, b.calls, pb, offsetAt(PB.keccak, 0)), .first_call_id = try countOr(C, b.first_call_id, pb, offsetAt(PB.keccak, 1)), .calls_nonzero = try flagOr(C, pb, offsetAt(PB.keccak, 2)), .offsets = b.offsets, .challenges = .{ .io = keccak.io, .call = bridge_call, .ram = state, .bytes = bytes }, .claim = cl[CL.service + 5] } else null;
    for (&result.secp, native.cpu.secp, 0..) |*out, group, k| {
        out.* = null;
        const g = group orelse continue;
        const challenges = secp orelse return error.MissingRv64Challenge;
        const claims_start = (CL.secp orelse return error.MissingRv64Claim) + 1 + 3 * k;
        const span_start: ?usize = if (PB.secp) |s| s[k] else null;
        out.* = .{
            .product = .{ .kind = .product, .program = g.product.program, .log_size = g.product.log_size, .public = try spanOr(C, g.product.public, pb, span_start), .offsets = g.product.offsets, .challenges = .{ .polynomial = challenges.polynomial, .bytes = bytes, .wire = challenges.wire }, .claim = cl[claims_start] },
            .linear = .{ .kind = .linear, .program = g.linear.program, .log_size = g.linear.log_size, .public = try spanOr(C, g.linear.public, pb, span_start), .offsets = g.linear.offsets, .challenges = .{ .polynomial = challenges.polynomial, .bytes = bytes, .wire = challenges.wire }, .claim = cl[claims_start + 1] },
            .bridge = .{ .log_size = g.bridge.log_size, .program = g.bridge.program, .calls = try countOr(C, g.bridge.calls, pb, offsetAt(span_start, 0)), .packet_format = g.bridge.packet_format, .first_call_id = try countOr(C, g.bridge.first_call_id, pb, offsetAt(span_start, 1)), .calls_nonzero = try flagOr(C, pb, offsetAt(span_start, 2)), .offsets = g.bridge.offsets, .challenges = .{ .wire = challenges.wire, .call = challenges.call, .ram = state, .bytes = bytes }, .claim = cl[claims_start + 2] },
        };
    }
    result.ram = null;
    if (native.ram) |*r| {
        const draws = CH.ramDrawsFor(C, ch) orelse return error.MissingRv64Challenge;
        const internal = CH.ramInternalFor(C, ch) orelse return error.MissingRv64Challenge;
        const policy = CH.ramPolicyFor(C, ch) orelse return error.MissingRv64Challenge;
        const io = R.chunk_air.PermutationChallengeFor(C).init(draws[2 * R.permutation_point.POSEIDON2_IO_INDEX], draws[2 * R.permutation_point.POSEIDON2_IO_INDEX + 1]);
        const tables = CL.ram_tables orelse return error.MissingRv64Claim;
        const publics = PB.ram;
        const t = struct {
            fn at(comptime table: T.Table) usize {
                return @intFromEnum(table);
            }
        };
        result.ram = .{
            .chunk = .{ .shape = r.chunk.shape, .offsets = r.chunk.offsets, .challenges = .{ .ram = internal, .io = io }, .claims = cl[tables[t.at(.chunk)]..][0..R.chunk_air.SUMS].*, .active = try activeOr(C, pb, if (publics) |p| p[t.at(.chunk)] else null) },
            .common_cells = .{ .shape = r.common_cells.shape, .offsets = r.common_cells.offsets, .challenges = .{ .ram = internal, .state = state, .bytes = bytes }, .claims = cl[tables[t.at(.common_cells)]..][0..R.cell_air.SUMS].*, .active = try activeOr(C, pb, if (publics) |p| p[t.at(.common_cells)] else null) },
            .edge_cells = .{ .shape = r.edge_cells.shape, .offsets = r.edge_cells.offsets, .challenges = .{ .ram = internal, .state = state, .bytes = bytes }, .claims = cl[tables[t.at(.edge_cells)]..][0..R.cell_air.SUMS].*, .active = try activeOr(C, pb, if (publics) |p| p[t.at(.edge_cells)] else null) },
            .leaf = .{ .shape = r.leaf.shape, .offsets = r.leaf.offsets, .challenges = .{ .ram = internal, .bytes = bytes }, .claims = cl[tables[t.at(.leaf)]..][0..R.leaf_air.SUMS].*, .active = try activeOr(C, pb, if (publics) |p| p[t.at(.leaf)] else null) },
            .node = .{ .shape = r.node.shape, .offsets = r.node.offsets, .challenges = .{ .io = io, .ram = internal, .bytes = bytes }, .claims = cl[tables[t.at(.node)]..][0..R.node_air.SUMS].*, .active = try activeOr(C, pb, if (publics) |p| p[t.at(.node)] else null) },
            .side = .{ .shape = r.side.shape, .offsets = r.side.offsets, .challenges = .{ .ram = internal, .bytes = bytes }, .claims = cl[tables[t.at(.side)]..][0..R.side_air.SUMS].*, .active = try activeOr(C, pb, if (publics) |p| p[t.at(.side)] else null) },
            .common_permits = .{ .shape = r.common_permits.shape, .offsets = r.common_permits.offsets, .challenges = .{ .bytes = bytes, .policy = policy, .permit = internal.permitChallenge() }, .claims = cl[tables[t.at(.common_permits)]..][0..R.permit_air.SUMS].*, .active = try activeOr(C, pb, if (publics) |p| p[t.at(.common_permits)] else null) },
            .edge_permits = .{ .shape = r.edge_permits.shape, .offsets = r.edge_permits.offsets, .challenges = .{ .bytes = bytes, .policy = policy, .permit = internal.permitChallenge() }, .claims = cl[tables[t.at(.edge_permits)]..][0..R.permit_air.SUMS].*, .active = try activeOr(C, pb, if (publics) |p| p[t.at(.edge_permits)] else null) },
            .permutations = .{ .log_size = r.permutations.log_size, .is_first_col_idx = r.permutations.is_first_col_idx, .main_col_offset = r.permutations.main_col_offset, .interaction_col_offset = r.permutations.interaction_col_offset, .relations = if (C == Q) r.permutations.relations else R.permutation_point.RelationsFor(C).fromDraws(draws), .claims = cl[CL.ram_provider orelse return error.MissingRv64Claim ..][0..R.permutation_point.N_SUMS].* },
            .policy = .{ .shape = r.policy.shape, .offsets = r.policy.offsets, .challenges = .{ .policy = policy }, .claims = .{cl[CL.ram_policy orelse return error.MissingRv64Claim]} },
        };
    }
    return result;
}
