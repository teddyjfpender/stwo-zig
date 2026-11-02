//! LS-D64 witness. Rows come from the shared LS32 native oracle (logicalRow)
//! projected onto the 39 committed columns; lookup inputs survive MAIN
//! adoption as the LS32 82-byte metadata, and the interaction reuses the LS32
//! dictionary checks and RAM/OWNER denominator authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("../closed_ram/mod.zig");
const V2 = @import("../load_store_v2/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const M = T.M;
const Q = T.Q;
pub const Event = V2.native.Event;
pub const Metadata = V2.source.Metadata;
const CHUNK: usize = 4096;

/// Only naturally aligned 8-byte LD/SD events are admitted (anything else is
/// an LS32 row). The full LS32 event semantics check still applies.
/// The routing rule: opcode AND natural 8-byte alignment of the effective
/// address. A misaligned LD/SD traps in the executor, but the router must
/// never send one to this row (it would fail `validate`, not fall back).
pub fn admits(event: Event) bool {
    return (event.opcode == .LD or event.opcode == .SD) and (event.a +% event.immediate) & 7 == 0;
}
pub fn validate(event: Event) !void {
    if (!admits(event)) return error.NotDwordLoadStoreEvent;
    try V2.native.validate(event);
    if ((event.a +% event.immediate) & 7 != 0) return error.InvalidLoadStoreEvent;
}
/// Committed row of one event (or padding).
pub fn row(event: ?Event) [L.MAIN]M {
    const logical = V2.native.logicalRow(event);
    return L.projectFor(M, &logical);
}
pub fn fixed(a: std.mem.Allocator, log: u32) ![]M {
    return V2.source.fixed(a, log);
}
pub fn sizeForLog(log: u32) !usize {
    return V2.source.sizeForLog(log);
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: u32,
    fixed: []M,
    main: []M,
    owns_main: bool,
    interaction: []M = &.{},
    metadata: []Metadata,
    counts16: []u64,
    counts8: []u64,
    pub fn init(a: std.mem.Allocator, events: []const Event, log: u32) !Source {
        const n = try sizeForLog(log);
        // Every present instance keeps one inactive terminal row.
        if (events.len >= n) return error.LsCapacityExceeded;
        _ = try @import("../../word16_v1/function_bus.zig").admitPositiveMass(&.{ L.LOGICAL_U16.len * @as(u64, @intCast(n)), L.LOGICAL_U8.len * @as(u64, @intCast(n)) });
        for (events) |e| try validate(e);
        const geometry = try fixed(a, log);
        errdefer a.free(geometry);
        const c16 = try a.alloc(u64, 65536);
        errdefer a.free(c16);
        const c8 = try a.alloc(u64, 256);
        errdefer a.free(c8);
        const metadata = try a.alloc(Metadata, n);
        errdefer a.free(metadata);
        const main = try a.alloc(M, L.MAIN * n);
        errdefer a.free(main);
        @memset(c16, 0);
        @memset(c8, 0);
        for (0..n) |logical| {
            const values = V2.native.logicalRow(if (logical < events.len) events[logical] else null);
            const pos = R.trace.physical(logical, log);
            for (L.STORED, 0..) |c, physical| main[physical * n + pos] = values[c];
            const meta = &metadata[logical];
            for (V2.layout.RELATION_U16, 0..) |c, i| meta.range16[i] = @intCast(values[c].v);
            for (V2.layout.RELATION_U8, 0..) |c, i| meta.range8[i] = @intCast(values[c].v);
            meta.selection_words = .{ 0, 0 };
            meta.opcode = @intCast(values[@import("../load_store_v1/layout.zig").opcode].v);
            meta.flags = @intCast(values[0].v | (values[22].v << 1) | (values[23].v << 2));
            for (L.LOGICAL_U16) |c| c16[values[c].v] += 1;
            for (L.LOGICAL_U8) |c| c8[values[c].v] += 1;
        }
        return .{ .allocator = a, .log_size = log, .rows = @intCast(events.len), .fixed = geometry, .main = main, .owns_main = true, .metadata = metadata, .counts16 = c16, .counts8 = c8 };
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) void {
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
        self.owns_main = false;
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.interaction);
        a.free(self.metadata);
        a.free(self.counts16);
        a.free(self.counts8);
        self.* = undefined;
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const values = switch (tree) {
            0 => self.fixed,
            1 => if (self.main.len != 0) self.main else return error.LsMainUnavailable,
            2 => if (self.interaction.len != 0) self.interaction else return error.LsInteractionUnavailable,
            else => return error.InvalidLsTree,
        };
        const n = self.size();
        const headers = try a.alloc(engine.pcs.ColumnEvaluation, values.len / n);
        for (headers, 0..) |*h, i| h.* = .{ .log_size = self.log_size, .values = values[i * n ..][0..n] };
        return headers;
    }
    /// One serial pass in logical row order (the prefix order); MAIN may
    /// already be committed and released.
    pub fn generate(self: *Source, ch: T.Challenges, dict16: []const Q, dict8: []const Q) !T.Claims {
        const I = V2.interaction;
        const n = self.size();
        if (self.interaction.len != 0 or self.metadata.len != n or self.rows >= n) return error.InvalidLsPhase;
        for (self.metadata, 0..) |meta, i| if (meta.flags & ~@as(u8, 7) != 0 or (meta.flags & 1) != @intFromBool(i < self.rows)) return error.InvalidLsMetadata;
        try I.validateDictionary(ch.range16, dict16, 65536);
        try I.validateDictionary(ch.range8, dict8, 256);
        const a = self.allocator;
        var claims = T.Claims.zero();
        claims.range16 = try I.countDot(self.counts16, dict16);
        claims.range8 = try I.countDot(self.counts8, dict8);
        const output = try a.alloc(M, L.INTERACTION * n);
        errdefer a.free(output);
        const scratch = try a.alloc(Q, 5 * CHUNK);
        defer a.free(scratch);
        // ram, owner, range16 - claim, range8 - claim.
        var prefix: [4]Q = .{ Q.zero(), Q.zero(), claims.range16.neg(), claims.range8.neg() };
        var start: usize = 0;
        while (start < n) : (start += CHUNK) {
            const count: usize = @min(CHUNK, n - start);
            const product = scratch[0..count];
            const delta = scratch[CHUNK..][0..count];
            const owner = scratch[2 * CHUNK ..][0..count];
            const inv = scratch[3 * CHUNK ..][0..count];
            const inv_owner = scratch[4 * CHUNK ..][0..count];
            I.ParallelSupport.rowDenominators(self.metadata[start..][0..count], ch, product, delta, owner);
            try core.fields.batchInverseInPlace(Q, product, inv);
            try core.fields.batchInverseInPlace(Q, owner, inv_owner);
            for (0..count) |k| {
                const logical = start + k;
                const pos = R.trace.physical(logical, self.log_size);
                const meta = self.metadata[logical];
                R.trace.store(output, n, pos, 0, inv[k]);
                prefix[0] = prefix[0].add(delta[k].mul(inv[k]).mulM31(meta.active()));
                R.trace.store(output, n, pos, 4, prefix[0]);
                prefix[1] = prefix[1].add(inv_owner[k].mulM31(meta.active()));
                var local: [L.LOCAL_FRACTIONS]Q = undefined;
                local[0] = inv_owner[k];
                for (L.U16_CACHE, 0..) |cache, j| {
                    local[1 + j] = dict16[meta.range16[cache]];
                    prefix[2] = prefix[2].add(local[1 + j]);
                }
                for (L.U8_CACHE, 0..) |cache, j| {
                    local[1 + L.LOGICAL_U16.len + j] = dict8[meta.range8[cache]];
                    prefix[3] = prefix[3].add(local[1 + L.LOGICAL_U16.len + j]);
                }
                for (0..L.LOCAL_PAIRS) |pair| {
                    const value = if (2 * pair + 1 < L.LOCAL_FRACTIONS) local[2 * pair].mul(local[2 * pair + 1]) else local[2 * pair];
                    R.trace.store(output, n, pos, L.LOCAL_INVERSES + 4 * pair, value);
                }
                R.trace.store(output, n, pos, L.LOCAL_PREFIX, prefix[1].add(prefix[2]).add(prefix[3]));
            }
        }
        if (!prefix[2].isZero() or !prefix[3].isZero()) return error.InvalidLsCounts;
        claims.ram = prefix[0];
        claims.owner = prefix[1];
        R.trace.center(output, n, 4, claims.ram);
        R.trace.center(output, n, L.LOCAL_PREFIX, claims.owner);
        self.interaction = output;
        a.free(self.metadata);
        self.metadata = &.{};
        return claims;
    }
};
