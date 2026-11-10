//! Conditional complete pairing four-role fixture. Public inputs independently
//! expected; physical production/VM authority is intentionally not admitted.
const std = @import("std");
const core = @import("stwo_core");
const S = @import("spec.zig");
const L = @import("lowering.zig");
const NW = @import("normalized_witness.zig");
const Mac = @import("../bn254_mac12/source.zig");
const Hint = @import("../bn254_hint/source.zig");
const E = @import("../../evaluation.zig");
pub const Q = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const Wire = @import("../curves/equations.zig").WireFor(Q);
pub const Role = enum { frontier, arithmetic, hints, table };
pub const KIND: u32 = 0x504d3132;
pub const FRONTIER_ROWS = L.FRONTIER_ROWS;
pub fn logSize(role: Role) u32 {
    return switch (role) {
        .arithmetic => 15,
        .hints, .frontier => 11,
        .table => 8,
    };
}
pub fn mainWidth(comptime role: Role) usize {
    return switch (role) {
        .arithmetic => Mac.MAIN,
        .hints => Hint.MAIN,
        .frontier => 33,
        .table => 1,
    };
}
pub fn fixedWidth(comptime role: Role) usize {
    return switch (role) {
        .arithmetic => Mac.FIXED,
        .hints => Hint.FIXED,
        .frontier => 35,
        .table => 1,
    };
}
fn k(comptime F: type, n: u32) F {
    return E.qFor(F, n);
}
pub fn ssaFraction(comptime role: Role, comptime F: type, v: anytype, wire: Wire, lane: usize) struct { F, E.SecureFor(F) } {
    var tuple: [35]F = undefined;
    var weight = F.zero();
    tuple[0] = k(F, KIND);
    tuple[1] = F.one();
    if (role == .hints) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        tuple = Hint.ssaTuple(F, v, k(F, KIND), F.one());
        weight = Hint.ssaWeight(F, v);
    } else if (role == .frontier) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        tuple[2] = v.fixed(1);
        for (0..32) |i| tuple[3 + i] = v.main(1 + i);
        weight = v.main(0).mul(v.fixed(2));
    } else if (role == .arithmetic) {
        if (lane > 25) return .{ F.zero(), E.SecureFor(F).one() };
        if (lane < 25) {
            tuple[2] = v.fixed(Mac.INPUT_ID + lane);
            weight = v.main(Mac.ACTIVE).neg();
            for (0..32) |i| tuple[3 + i] = v.main(Mac.INPUT + 32 * lane + i);
        } else {
            tuple[2] = v.fixed(Mac.WRITER_ID);
            weight = v.main(Mac.ACTIVE).mul(v.fixed(Mac.FANOUT));
            for (0..32) |i| tuple[3 + i] = v.main(Mac.OUTPUT + i);
        }
    } else return .{ F.zero(), E.SecureFor(F).one() };
    return .{ weight, E.denominatorFor(F, wire.offset, &wire.coefficients, &tuple, true) };
}
pub fn byteFraction(comptime role: Role, comptime F: type, v: anytype, beta: Q, lane: usize) struct { F, E.SecureFor(F) } {
    if (role == .table) {
        if (lane != 0) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.main(0).neg(), E.splatFor(F, beta).sub(E.liftFor(F, v.fixed(0))) };
    }
    if (role == .arithmetic) {
        if (lane >= Mac.BYTE_QUERIES) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.main(Mac.ACTIVE), E.splatFor(F, beta).sub(E.liftFor(F, Mac.byteQuery(F, v, lane))) };
    }
    if (role == .hints) {
        if (lane >= Hint.BYTE_QUERIES) return .{ F.zero(), E.SecureFor(F).one() };
        return .{ v.fixed(Hint.ACTIVE), E.splatFor(F, beta).sub(E.liftFor(F, Hint.byteQuery(F, v, lane))) };
    }
    return .{ F.zero(), E.SecureFor(F).one() };
}
pub fn constraints(comptime role: Role) usize {
    return switch (role) {
        .arithmetic => Mac.CONSTRAINTS,
        .hints => Hint.CONSTRAINTS,
        .frontier => 33,
        .table => 0,
    };
}
pub fn emit(comptime role: Role, comptime F: type, v: anytype, sink: anytype) void {
    if (role == .arithmetic) Mac.emit(F, v, sink) else if (role == .hints) Hint.emitCanonical(F, v, sink) else if (role == .frontier) {
        sink.emit(v.main(0).sub(v.fixed(0)));
        for (0..32) |i| sink.emit(v.main(1 + i).sub(v.fixed(3 + i)));
    }
}
fn physical(logical: usize, log: u32) usize {
    return @import("../../memory/closed_ram/trace.zig").physical(logical, log);
}
fn signed(n: i32) Q {
    const x = Q.fromBase(M.fromCanonical(@intCast(@abs(n))));
    return if (n < 0) x.neg() else x;
}
pub const Model = struct {
    plan: *const L.Program,
    witness: *const NW.Witness,
    public: [S.INITIAL]u256,
    table: [256]u32 = @splat(0),
    columns: [4]?[]const M = @splat(null),
    table_ready: bool = false,
    pub fn init(plan: *const L.Program, witness: *const NW.Witness, expected: *const [S.INITIAL]u256) !Model {
        if (plan.stages.len > 32768 or plan.hints.len > 2048 or FRONTIER_ROWS > 2048) return error.PairingFixtureGeometry;
        for (expected) |v| if (v >= S.B.BN254_P) return error.NonCanonicalPairingFrontier;
        for (expected[24..], S.LITERALS.values[0..S.LITERALS.len]) |actual, literal| if (actual != literal) return error.PairingLiteralAuthority;
        return .{ .plan = plan, .witness = witness, .public = expected.* };
    }
    pub fn activeRows(m: *const Model, role: Role) usize {
        return switch (role) {
            .arithmetic => m.plan.stages.len,
            .hints => m.plan.hints.len,
            .frontier => FRONTIER_ROWS,
            .table => 256,
        };
    }
    pub fn installColumns(m: *Model, role: Role, main: []const M) !void {
        const rows = @as(usize, 1) << @intCast(logSize(role));
        const width = switch (role) {
            inline else => |r| mainWidth(r),
        };
        if (main.len != rows * width) return error.PairingFixtureColumns;
        if (m.columns[@intFromEnum(role)] != null) return error.PairingFixtureDuplicateColumns;
        m.columns[@intFromEnum(role)] = main;
    }
    pub fn requireColumns(m: *const Model) !void {
        for (m.columns) |columns| if (columns == null) return error.PairingFixtureMissingColumns;
    }
    pub fn materialize(m: *Model, role: Role, row: usize) !Materialized {
        if (row >= @as(usize, 1) << @intCast(logSize(role))) return error.PairingFixtureRow;
        var out = Materialized{ .model = m, .role = role, .row = row, .main_values = @splat(0) };
        if (role == .arithmetic) {
            if (row < m.plan.stages.len) {
                const values = try m.witness.row(m.plan, row);
                @memcpy(out.main_values[0..Mac.MAIN], &values);
            }
        } else if (role == .hints) {
            if (row < m.plan.hints.len) {
                const values = try m.witness.hintRow(m.plan, row);
                @memcpy(out.main_values[0..Hint.MAIN], &values);
            }
        } else if (role == .frontier) {
            if (row < FRONTIER_ROWS) {
                out.main_values[0] = 1;
                const value = m.witness.values[m.plan.frontierId(row)];
                for (0..32) |i| out.main_values[1 + i] = @intCast((value >> @intCast(8 * i)) & 255);
            }
        } else {
            if (!m.table_ready) try m.recount();
            out.main_values[0] = m.table[row];
        }
        return out;
    }
    pub fn view(m: *const Model, role: Role, row: usize) View {
        return .{ .model = m, .role = role, .row = row };
    }
    pub fn fixed(m: *const Model, role: Role, row: usize, col: usize) Q {
        var n: i32 = 0;
        if (role == .table) n = @intCast(row) else if (row < m.activeRows(role)) switch (role) {
            .arithmetic => {
                const stage = m.plan.stages[row];
                n = if (col == Mac.FIX_ACTIVE) 1 else if (col < Mac.INPUT_ID) stage.coefficients[col - Mac.COEFFICIENT] else if (col < Mac.WRITER_ID) @intCast(stage.input[col - Mac.INPUT_ID]) else if (col == Mac.WRITER_ID) @intCast(stage.writer) else @intCast(m.plan.fanout[stage.writer]);
            },
            .hints => {
                const hint = m.plan.hints[row];
                n = if (col == Hint.ACTIVE) 1 else if (col == Hint.WRITER_ID) @intCast(hint.writer) else @intCast(m.plan.fanout[hint.writer]);
            },
            .frontier => {
                n = if (col == 0) 1 else if (col == 1) @intCast(m.plan.frontierId(row)) else if (col == 2) m.plan.frontierWeight(row) else S.B.limbOf(m.plan.frontierExpected(row, &m.public), col - 3);
            },
            .table => unreachable,
        };
        return signed(n);
    }
    pub fn recount(m: *Model) !void {
        if (m.columns[@intFromEnum(Role.arithmetic)] == null or m.columns[@intFromEnum(Role.hints)] == null) return error.PairingFixtureMissingColumns;
        m.table = @splat(0);
        inline for (.{ Role.arithmetic, Role.hints }) |role| {
            const count = if (role == .arithmetic) Mac.BYTE_QUERIES else Hint.BYTE_QUERIES;
            for (0..m.activeRows(role)) |row| {
                const v = m.view(role, row);
                for (0..count) |i| {
                    const query = if (role == .arithmetic) Mac.byteQuery(Q, &v, i) else Hint.byteQuery(Q, &v, i);
                    const words = query.toM31Array();
                    if (words[0].v >= 256) return error.PairingFixtureByte;
                    for (words[1..]) |word| if (word.v != 0) return error.PairingFixtureByte;
                    m.table[words[0].v] = std.math.add(u32, m.table[words[0].v], 1) catch return error.PairingFixtureByteMass;
                }
            }
        }
        m.table_ready = true;
    }
};
pub const View = struct {
    model: *const Model,
    role: Role,
    row: usize,
    pub fn main(v: *const @This(), col: usize) Q {
        const columns = v.model.columns[@intFromEnum(v.role)] orelse unreachable;
        const rows = @as(usize, 1) << @intCast(logSize(v.role));
        return Q.fromBase(columns[col * rows + physical(v.row, logSize(v.role))]);
    }
    pub fn fixed(v: *const @This(), col: usize) Q {
        return v.model.fixed(v.role, v.row, col);
    }
};
pub const Materialized = struct {
    model: *const Model,
    role: Role,
    row: usize,
    main_values: [Mac.MAIN]u32,
    pub fn main(v: *const @This(), col: usize) Q {
        return Q.fromBase(M.fromCanonical(v.main_values[col]));
    }
    pub fn fixed(v: *const @This(), col: usize) Q {
        return v.model.fixed(v.role, v.row, col);
    }
};

pub fn sourceDigest() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&L.sourceDigest());
    h.update(@embedFile("fixture.zig"));
    return h.finalResult();
}
