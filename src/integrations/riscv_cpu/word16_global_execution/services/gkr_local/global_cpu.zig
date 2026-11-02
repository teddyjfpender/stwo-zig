//! Exact global RAM/KIO/Wire queries for CPU-shard roles. These relations never
//! enter the local GKR sum; EVERY physical claim is transcript-bound and must
//! close independently at the complete execution receiver.
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const R = A.memory.closed_ram;
const K = A.crypto.keccak.word16_bridge;
const S = A.crypto.secp256k1.word16_bridge;
const G = A.main_only.global_classic;
const Frame = @import("frame.zig");
pub const Relation = enum { ram, kio, wire };
pub fn ClaimsFor(comptime C: type) type {
    return struct {
        ram: C,
        kio: C,
        wire: C,
        pub fn zero() @This() {
            return .{ .ram = C.zero(), .kio = C.zero(), .wire = C.zero() };
        }
    };
}
pub const Layout = struct {
    ram_queries: usize = 0,
    other_queries: usize = 0,
    cleared_other: bool = false,
    pub fn ramWidth(self: @This()) usize {
        return if (self.ram_queries == 0) 0 else 8 * ((self.ram_queries + 1) / 2 + 1);
    }
    pub fn otherWidth(self: @This()) usize {
        return if (self.other_queries == 0) 0 else if (self.cleared_other) 16 else 8 * ((self.other_queries + 1) / 2 + 1);
    }
    pub fn width(self: @This()) usize {
        return self.ramWidth() + self.otherWidth();
    }
    pub fn constraints(self: @This()) usize {
        return (if (self.ram_queries == 0) @as(usize, 0) else (self.ram_queries + 1) / 2 + 2) + (if (self.other_queries == 0) @as(usize, 0) else if (self.cleared_other) 3 else (self.other_queries + 1) / 2 + 2);
    }
    pub fn previous(self: @This(), column: usize) bool {
        if (column >= self.width()) return false;
        const ram = self.ramWidth();
        return (ram != 0 and column >= ram - 8 and column < ram) or (self.otherWidth() != 0 and column >= self.width() - 8);
    }
};
pub fn layout(origin: Frame.Origin) Layout {
    return switch (origin) {
        .bulk => |kind| .{ .ram_queries = @import("bulk_projection.zig").ramTerms(kind) },
        .core => |role| switch (role) {
            .ls, .ls_tail => .{ .ram_queries = 2 },
            .initial, .terminal => .{ .ram_queries = 1 },
            else => .{},
        },
        .bridge => |family| if (family == .keccak) .{ .ram_queries = 2, .other_queries = 2 } else .{ .ram_queries = 8, .other_queries = 2, .cleared_other = true },
    };
}
/// Shared polynomial tuple/weight authority. Sink emits raw signed fractions;
/// native metadata generation and authenticated MAIN-mask constraints use it.
pub fn queriesFor(comptime F: type, origin: Frame.Origin, fixed: []const F, main: []const F, sink: anytype) !void {
    switch (origin) {
        .bulk => |kind| switch (kind) {
            inline else => |k| @import("bulk_projection.zig").emitGlobalFor(F, k, fixed, main, sink),
        },
        .core => |role| switch (role) {
            .ls, .ls_tail => {
                const logical = A.memory.load_store_v2.layout.projection.expandFor(F, main);
                sink.emit(.ram, R.equations.ramTuple(F, .transition, &logical, false), logical[0]);
                sink.emit(.ram, R.equations.ramTuple(F, .transition, &logical, true), logical[0].neg());
            },
            .initial, .terminal => sink.emit(.ram, R.equations.ramTuple(F, if (role == .initial) .initial else .terminal, main, false), if (role == .initial) main[0].neg() else main[0]),
            else => {},
        },
        .bridge => |family| switch (family) {
            .keccak => {
                sink.emit(.ram, R.equations.ramTuple(F, .transition, main[0..28], false), main[0]);
                sink.emit(.ram, R.equations.ramTuple(F, .transition, main[0..28], true), main[0].neg());
                sink.emit(.kio, K.equations.ioTuple(F, fixed, main, false), main[0].neg());
                sink.emit(.kio, K.equations.ioTuple(F, fixed, main, true), main[0].neg());
            },
            else => {
                const kind: A.crypto.secp256k1.word16_bridge.types.Kind = @import("../types.zig").bridgeKind(family);
                for (0..4) |lane| {
                    const row = S.equations.ramRow(F, main, lane);
                    sink.emit(.ram, R.equations.ramTuple(F, .transition, &row, false), main[0]);
                    sink.emit(.ram, R.equations.ramTuple(F, .transition, &row, true), main[0].neg());
                }
                sink.emit(.wire, S.equations.wireTuple(F, kind, fixed, main, false), main[0]);
                sink.emit(.wire, S.equations.wireTuple(F, kind, fixed, main, true), main[0].mul(fixed[6]).neg());
            },
        },
    }
}
/// Per-row stack query sink. Shared has exactly the typed manifest namespaces;
/// no challenge is sampled here and no producer degree flag exists.
pub fn QuerySinkFor(comptime F: type, comptime Shared: type) type {
    return struct {
        shared: *const Shared,
        ram: [18]E.SecureFor(F) = undefined,
        ram_weights: [18]F = undefined,
        ram_count: usize = 0,
        other: [2]E.SecureFor(F) = undefined,
        other_weights: [2]F = undefined,
        other_count: usize = 0,
        pub fn emit(self: *@This(), relation: Relation, tuple: anytype, weight: F) void {
            switch (relation) {
                .ram => {
                    self.ram[self.ram_count] = E.denominatorFor(F, self.shared.ram.offset, &self.shared.ram.coefficients, &tuple, true);
                    self.ram_weights[self.ram_count] = weight;
                    self.ram_count += 1;
                },
                .kio => {
                    self.other[self.other_count] = E.denominatorFor(F, self.shared.kio.offset, &self.shared.kio.coefficients, &tuple, true);
                    self.other_weights[self.other_count] = weight;
                    self.other_count += 1;
                },
                .wire => {
                    self.other[self.other_count] = E.denominatorFor(F, self.shared.wire.offset, &self.shared.wire.coefficients, &tuple, true);
                    self.other_weights[self.other_count] = weight;
                    self.other_count += 1;
                },
            }
        }
    };
}
pub fn emitFor(comptime F: type, origin: Frame.Origin, shared: anytype, claims: ClaimsFor(E.ConstFor(F)), fixed: []const F, main: []const F, current: []const F, previous: []const F, out: *E.SinkFor(F)) !void {
    const l = layout(origin);
    if (current.len != l.width() or previous.len != l.width()) return error.InvalidWideGlobalShape;
    var queries = QuerySinkFor(F, @TypeOf(shared)){ .shared = &shared };
    try queriesFor(F, origin, fixed, main, &queries);
    if (queries.ram_count != l.ram_queries or queries.other_count != l.other_queries) return error.InvalidWideGlobalShape;
    const ram = l.ramWidth();
    if (l.ram_queries != 0) try G.linearPairsFor(F, queries.ram[0..queries.ram_count], queries.ram_weights[0..queries.ram_count], current[0..ram], previous[0..ram], fixed[1], fixed[2], claims.ram, out);
    if (l.other_queries != 0) {
        const claim = if (origin.bridge == .keccak) claims.kio else claims.wire;
        if (l.cleared_other) try G.clearedPairFor(F, queries.other, queries.other_weights, current[ram..], previous[ram..], fixed[1], fixed[2], claim, out) else try G.linearPairsFor(F, &queries.other, &queries.other_weights, current[ram..], previous[ram..], fixed[1], fixed[2], claim, out);
    }
}
/// Receiver-owned slot roster: absent fields are never free cancellation debt.
pub fn claimCount(origin: Frame.Origin) usize {
    const l = layout(origin);
    return @intFromBool(l.ram_queries != 0) + @as(usize, @intFromBool(l.other_queries != 0));
}
pub fn claimsFromVector(comptime C: type, origin: Frame.Origin, values: []const C) !ClaimsFor(C) {
    if (values.len != claimCount(origin)) return error.InvalidWideGlobalClaimShape;
    var out = ClaimsFor(C).zero();
    var at: usize = 0;
    const l = layout(origin);
    if (l.ram_queries != 0) {
        out.ram = values[at];
        at += 1;
    }
    if (l.other_queries != 0) {
        if (origin.bridge == .keccak) out.kio = values[at] else out.wire = values[at];
    }
    return out;
}
pub fn validateClaims(origin: Frame.Origin, claims: ClaimsFor(@import("stwo_core").fields.om31.OM31)) !void {
    const l = layout(origin);
    if (l.ram_queries == 0 and !claims.ram.isZero()) return error.NonzeroAbsentWideGlobalClaim;
    const has_k = l.other_queries != 0 and origin == .bridge and origin.bridge == .keccak;
    const has_wire = l.other_queries != 0 and origin == .bridge and origin.bridge != .keccak;
    if ((!has_k and !claims.kio.isZero()) or (!has_wire and !claims.wire.isZero())) return error.NonzeroAbsentWideGlobalClaim;
}
