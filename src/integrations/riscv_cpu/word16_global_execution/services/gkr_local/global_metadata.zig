//! Durable CPU/service metadata to the shared classic inverse/prefix driver.
//! One row/tuple of scratch; no MAIN rows or coefficient expansion are retained.
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const R = @import("../roster.zig");
const Frame = @import("frame.zig");
const G = @import("global_cpu.zig");
const Manifest = @import("manifest.zig");
const Classic = @import("classic_witness.zig");
fn lift(values: anytype) [values.len]O {
    var out: [values.len]O = undefined;
    for (values, &out) |v, *d| d.* = O.fromBase(v);
    return out;
}
const Sink = struct {
    shared: *const Manifest.Shared,
    ram: [58]O = undefined,
    ram_weights: [58]M = undefined,
    ram_count: usize = 0,
    other: [50]O = undefined,
    other_weights: [50]M = undefined,
    other_count: usize = 0,
    invalid: bool = false,
    fn denominator(ch: anytype, tuple: anytype) O {
        if (comptime ch.coefficients.len != tuple.len) return O.zero();
        var d = ch.offset;
        for (ch.coefficients, tuple) |c, v| d = d.sub(c.mulM31(v));
        return d;
    }
    pub fn emitBase(self: *@This(), relation: G.Relation, tuple: anytype, weight: M) void {
        const expected: usize = switch (relation) {
            .ram => 14,
            .kio => 11,
            .wire => 35,
        };
        if (tuple.len != expected) {
            self.invalid = true;
            return;
        }
        switch (relation) {
            .ram => {
                if (self.ram_count >= 58) {
                    self.invalid = true;
                    return;
                }
                self.ram[self.ram_count] = denominator(self.shared.ram, tuple);
                self.ram_weights[self.ram_count] = weight;
                self.ram_count += 1;
            },
            .kio => {
                if (self.other_count >= 50) {
                    self.invalid = true;
                    return;
                }
                self.other[self.other_count] = denominator(self.shared.kio, tuple);
                self.other_weights[self.other_count] = weight;
                self.other_count += 1;
            },
            .wire => {
                if (self.other_count >= 50) {
                    self.invalid = true;
                    return;
                }
                self.other[self.other_count] = denominator(self.shared.wire, tuple);
                self.other_weights[self.other_count] = weight;
                self.other_count += 1;
            },
        }
    }
    pub fn emit(self: *@This(), relation: G.Relation, tuple: anytype, weight: O) void {
        const w = weight.toM31Array();
        for (w[1..]) |c| if (!c.isZero()) {
            self.invalid = true;
            return;
        };
        var bases: [tuple.len]M = undefined;
        for (tuple, &bases) |v, *d| {
            const c = v.toM31Array();
            for (c[1..]) |x| if (!x.isZero()) {
                self.invalid = true;
                return;
            };
            d.* = c[0];
        }
        self.emitBase(relation, bases, w[0]);
    }
};
pub fn groups(origin: Frame.Origin) ![]const Classic.Group {
    const l = G.layout(origin);
    if (l.ram_queries == 0) return error.MissingWideGlobalRole;
    if (origin == .sponge) return switch (origin.sponge) {
        inline else => |kind| &.{ .{ .inverses = @intCast((@import("sponge_projection.zig").ramTerms(kind) + 1) / 2) }, .{ .inverses = @intCast((@import("sponge_projection.zig").kioTerms(kind) + 1) / 2) } },
    };
    return if (origin == .bulk) switch (origin.bulk) {
        inline else => |kind| if (@import("bulk_projection.zig").ramTerms(kind) == 0) error.MissingWideGlobalRole else &.{.{ .inverses = comptime @as(u16, @intCast((@import("bulk_projection.zig").ramTerms(kind) + 1) / 2)) }},
    } else if (l.other_queries == 0) &.{.{ .inverses = 1 }} else if (l.ram_queries == 2) &.{ .{ .inverses = 1 }, .{ .inverses = 1 } } else &.{ .{ .inverses = 4 }, .{ .inverses = 1 } };
}
pub const Provider = struct {
    /// Validated metadata and challenge inputs are immutable; fill allocates nothing.
    pub const PARALLEL_SAFE = true;
    source: *const R.Sources,
    origin: Frame.Origin,
    log_size: u32,
    shared: Manifest.Shared,
    pub fn fill(self: *const @This(), logical: usize, denominators: []O, numerators: []Classic.Numerator) !void {
        const l = G.layout(self.origin);
        if (self.log_size < 5 or self.log_size > 22) return error.InvalidWideGlobalMetadata;
        const n: usize = @as(usize, 1) << @intCast(self.log_size);
        if (self.log_size < 5 or self.log_size > 22 or logical >= n or denominators.len != (l.ram_queries + 1) / 2 + (l.other_queries + 1) / 2 or numerators.len != denominators.len) return error.InvalidWideGlobalMetadata;
        var sink = Sink{ .shared = &self.shared };
        switch (self.origin) {
            .dword => |index| {
                const src = &(self.source.ls_dword[index] orelse return error.MissingLocalGkrBridge);
                if (src.log_size != self.log_size or src.metadata.len != n) return error.InvalidWideGlobalMetadata;
                @import("dword_projection.zig").emitGlobalMetadata(src.metadata[logical], &sink);
            },
            .sponge => |kind| switch (kind) {
                inline else => |k| {
                    const src = &(self.source.sponge[@intFromEnum(k)] orelse return error.MissingLocalGkrBridge);
                    if (src.kind != k or src.log_size != self.log_size) return error.InvalidWideGlobalMetadata;
                    const fixed = [_]O{ O.fromBase(M.fromCanonical(@intCast(logical))), O.fromBase(M.fromCanonical(@intFromBool(logical == 0))), O.fromBase(M.fromCanonical(@intFromBool(logical + 1 == n))) };
                    @import("sponge_projection.zig").emitGlobalFor(O, k, &fixed, &lift(src.plan.row(k, logical, src.first_id)), src.first_id, &sink);
                },
            },
            .bulk => |kind| switch (kind) {
                inline else => |k| {
                    const src = &(self.source.bulk[@intFromEnum(k)] orelse return error.MissingLocalGkrBridge);
                    if (src.kind != k or src.log_size != self.log_size) return error.InvalidWideGlobalMetadata;
                    // RAM tuples depend only on durable call/word metadata.
                    // Fixed columns may already have retired with the local child.
                    const fixed = [_]O{O.zero()} ** A.crypto.bulk_memory.layout.fixedWidth(k);
                    try G.queriesFor(O, self.origin, &fixed, &lift(src.row(k, logical)), &sink);
                },
            },
            .core => |role| switch (role) {
                .ls, .ls_tail => {
                    const src = if (role == .ls) &self.source.core.memory.ls else &(self.source.core.memory.ls_tail orelse return error.MissingLocalGkrTail);
                    if (src.log_size != self.log_size or src.metadata.len != n) return error.InvalidWideGlobalMetadata;
                    const meta = src.metadata[logical];
                    sink.emitBase(.ram, meta.ramTuple(false), meta.active());
                    sink.emitBase(.ram, meta.ramTuple(true), meta.active().neg());
                },
                .initial, .terminal => {
                    const src = if (role == .initial) &self.source.core.memory.initial else &self.source.core.memory.terminal;
                    if (src.log_size != self.log_size or src.metadata.len != n) return error.InvalidWideGlobalMetadata;
                    const meta = src.metadata[logical];
                    sink.emitBase(.ram, meta.tuple(), if (role == .initial) meta.active().neg() else meta.active());
                },
                else => return error.MissingWideGlobalRole,
            },
            .bridge => |family| switch (family) {
                .keccak => {
                    const src = self.source.keccak orelse return error.MissingLocalGkrBridge;
                    if (src.log_size != self.log_size) return error.InvalidWideGlobalMetadata;
                    const lane = logical % 25;
                    const index = logical / 25;
                    const row = A.crypto.keccak.word16_bridge.source.nativeRow(if (index < src.calls.len) src.calls[index] else null, lane, src.first_id + @as(u32, @intCast(index)));
                    var fixed: [6]O = @splat(O.zero());
                    fixed[3] = O.fromBase(M.fromCanonical(@intCast(lane)));
                    try G.queriesFor(O, self.origin, &fixed, &lift(row), &sink);
                },
                .add, .double => {
                    const src = (if (family == .add) self.source.add else self.source.double) orelse return error.MissingLocalGkrBridge;
                    if (src.log_size != self.log_size) return error.InvalidWideGlobalMetadata;
                    const coords = A.crypto.secp256k1.word16_bridge.types.coordinates(src.kind);
                    const coord = logical % coords;
                    const index = logical / coords;
                    const row = A.crypto.secp256k1.word16_bridge.source.nativeRow(src.kind, if (index < src.calls.len) src.calls[index] else null, coord, src.first_id + @as(u32, @intCast(index)));
                    var fixed: [8]O = @splat(O.zero());
                    fixed[3] = O.fromBase(M.fromCanonical(@intCast(coord)));
                    fixed[6] = O.fromBase(M.fromCanonical(@intFromBool(coord < 3)));
                    fixed[7] = O.fromBase(M.fromCanonical(if (coord < 3) A.crypto.secp256k1.program.get(if (family == .add) .add else .double).outputs[coord] else 0));
                    try G.queriesFor(O, self.origin, &fixed, &lift(row), &sink);
                },
                // Outside the v2 scope (see v2_scope.zig); admission rejects earlier.
                else => return error.GkrV3ServiceUnsupported,
            },
        }
        if (sink.invalid or sink.ram_count != l.ram_queries or sink.other_count != l.other_queries) return error.InvalidWideGlobalMetadata;
        var at: usize = 0;
        while (at < (l.ram_queries + 1) / 2) : (at += 1) {
            const first = 2 * at;
            if (first + 1 == l.ram_queries) {
                denominators[at] = sink.ram[first];
                numerators[at] = .{ .base = sink.ram_weights[first] };
            } else {
                denominators[at] = sink.ram[first].mul(sink.ram[first + 1]);
                numerators[at] = .{ .secure = sink.ram[first + 1].mulM31(sink.ram_weights[first]).add(sink.ram[first].mulM31(sink.ram_weights[first + 1])) };
            }
        }
        var other_at: usize = 0;
        while (other_at < l.other_queries) : (other_at += 2) {
            const first = other_at;
            if (first + 1 == l.other_queries) {
                denominators[at] = sink.other[first];
                numerators[at] = .{ .base = sink.other_weights[first] };
            } else {
                denominators[at] = sink.other[first].mul(sink.other[first + 1]);
                numerators[at] = .{ .secure = sink.other[first + 1].mulM31(sink.other_weights[first]).add(sink.other[first].mulM31(sink.other_weights[first + 1])) };
            }
            at += 1;
        }
    }
};
