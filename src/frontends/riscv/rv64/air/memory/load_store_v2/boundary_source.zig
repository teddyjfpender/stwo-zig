//! Scalable public-boundary witness, domain-only fixed key; no onehot image.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("../closed_ram/mod.zig");
const T = @import("types.zig");
const L = @import("layout.zig");
const Native = @import("native.zig");
const SourceSupport = @import("source.zig");
const I = @import("interaction.zig");
const M = T.M;
const Q = T.Q;
pub const Cell = R.types.Cell;
pub const Metadata = struct {
    range16: [14]u16,
    high: u8,
    flags: u8,
    pub fn active(self: @This()) M {
        return M.fromCanonical(self.flags & 1);
    }
    pub fn tuple(self: @This()) [14]M {
        var t: [14]M = undefined;
        t[0] = M.one();
        for (0..4) |i| {
            t[1 + i] = M.fromCanonical(self.range16[i]);
            t[8 + i] = M.fromCanonical(self.range16[4 + i]);
        }
        t[5] = M.fromCanonical(self.range16[8]);
        t[6] = M.fromCanonical(self.range16[9]);
        t[7] = M.fromCanonical(self.high);
        t[12] = M.fromCanonical((self.flags >> 1) & 1);
        t[13] = M.fromCanonical((self.flags >> 2) & 1);
        return t;
    }
};
comptime {
    std.debug.assert(@sizeOf(Metadata) == 30);
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    kind: L.Kind,
    log_size: u32,
    rows: u32,
    fixed: []M,
    main: []M,
    owns_main: bool,
    interaction: []M = &.{},
    metadata: []Metadata,
    counts16: []u64,
    counts8: []u64,
    pub fn init(a: std.mem.Allocator, kind: L.Kind, cells: []const Cell, log: u32) !Source {
        return initInternal(a, kind, cells, log, null);
    }
    pub fn initWithMainBuffers(a: std.mem.Allocator, kind: L.Kind, cells: []const Cell, log: u32, buffers: SourceSupport.MainBuffers) !Source {
        return initInternal(a, kind, cells, log, buffers);
    }
    fn initInternal(a: std.mem.Allocator, kind: L.Kind, cells: []const Cell, log: u32, buffers: ?SourceSupport.MainBuffers) !Source {
        if (kind != .initial and kind != .terminal) return error.InvalidBoundaryKind;
        const n = try SourceSupport.sizeForLog(log);
        if (cells.len >= n) return error.BoundaryCapacityExceeded;
        for (cells, 0..) |cell, i| if (cell.address & 7 != 0 or (i != 0 and cells[i - 1].address >= cell.address)) return error.InvalidBoundaryOrder;
        if (buffers) |b| {
            if (b.main.len != 23 * n) return error.InvalidBoundaryMain;
            const x = @intFromPtr(b.main.ptr);
            const y = @intFromPtr(cells.ptr);
            const xe = std.math.add(usize, x, std.mem.sliceAsBytes(b.main).len) catch return error.InvalidMemoryInputSpan;
            const ye = std.math.add(usize, y, std.mem.sliceAsBytes(cells).len) catch return error.InvalidMemoryInputSpan;
            if (cells.len != 0 and x < ye and y < xe) return error.OverlappingBoundaryInputs;
        }
        const f = try SourceSupport.fixed(a, log);
        errdefer a.free(f);
        const c16 = try a.alloc(u64, 65536);
        errdefer a.free(c16);
        const c8 = try a.alloc(u64, 256);
        errdefer a.free(c8);
        const meta = try a.alloc(Metadata, n);
        errdefer a.free(meta);
        const main = if (buffers) |b| b.main else try a.alloc(M, 23 * n);
        @memset(c16, 0);
        @memset(c8, 0);
        for (0..n) |pos| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(pos, log), log);
            const row = Native.boundaryRow(cells, logical);
            for (row, 0..) |v, c| main[c * n + pos] = v;
            for (R.layout.B_U16, 0..) |c, i| {
                meta[logical].range16[i] = @intCast(row[c].v);
                c16[row[c].v] += 1;
            }
            meta[logical].high = @intCast(row[11].v);
            c8[row[11].v] += 1;
            meta[logical].flags = @intCast(row[0].v | (row[12].v << 1) | (row[13].v << 2));
        }
        return .{ .allocator = a, .kind = kind, .log_size = log, .rows = @intCast(cells.len), .fixed = f, .main = main, .owns_main = buffers == null, .metadata = meta, .counts16 = c16, .counts8 = c8 };
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
        const data = switch (tree) {
            0 => self.fixed,
            1 => if (self.main.len != 0) self.main else return error.BoundaryMainUnavailable,
            2 => if (self.interaction.len != 0) self.interaction else return error.BoundaryInteractionUnavailable,
            else => return error.InvalidBoundaryTree,
        };
        const n = self.size();
        const columns_ = try a.alloc(engine.pcs.ColumnEvaluation, data.len / n);
        for (columns_, 0..) |*c, i| c.* = .{ .log_size = self.log_size, .values = data[i * n ..][0..n] };
        return columns_;
    }
    pub fn generate(self: *Source, ch: T.Challenges, dict16: []const Q, dict8: []const Q) !T.Claims {
        const n = self.size();
        const a = self.allocator;
        if (self.interaction.len != 0 or self.metadata.len != n) return error.InvalidBoundaryPhase;
        try I.validateDictionary(ch.range16, dict16, 65536);
        try I.validateDictionary(ch.range8, dict8, 256);
        var claims = T.Claims.zero();
        claims.range16 = try I.countDot(self.counts16, dict16);
        claims.range8 = try I.countDot(self.counts8, dict8);
        const output = try a.alloc(M, 48 * n);
        errdefer a.free(output);
        const denominator = try a.alloc(Q, n);
        defer a.free(denominator);
        const inverse = try a.alloc(Q, n);
        defer a.free(inverse);
        for (self.metadata, denominator) |meta, *d| {
            var tuple: [14]Q = undefined;
            for (meta.tuple(), &tuple) |value, *q| q.* = Q.fromBase(value);
            d.* = ch.ram.denominatorFor(Q, tuple);
        }
        try core.fields.batchInverseInPlace(Q, denominator, inverse);
        var p16 = claims.range16.neg();
        var p8 = claims.range8.neg();
        for (self.metadata, inverse, 0..) |meta, inv, logical| {
            if (meta.flags & ~@as(u8, 7) != 0 or (meta.flags & 1) != @intFromBool(logical < self.rows)) return error.InvalidBoundaryMetadata;
            const pos = R.trace.physical(logical, self.log_size);
            R.trace.store(output, n, pos, 0, inv);
            const value = inv.mulM31(meta.active());
            claims.ram = if (self.kind == .initial) claims.ram.sub(value) else claims.ram.add(value);
            R.trace.store(output, n, pos, 4, claims.ram);
            for (0..7) |batch| {
                const x = dict16[meta.range16[2 * batch]];
                const y = dict16[meta.range16[2 * batch + 1]];
                R.trace.store(output, n, pos, 8 + 4 * batch, x.mul(y));
                p16 = p16.add(x).add(y);
            }
            R.trace.store(output, n, pos, 36, p16);
            const x = dict8[meta.high];
            R.trace.store(output, n, pos, 40, x);
            p8 = p8.add(x);
            R.trace.store(output, n, pos, 44, p8);
        }
        if (!p16.isZero() or !p8.isZero()) return error.InvalidBoundaryCounts;
        R.trace.center(output, n, 4, claims.ram);
        self.interaction = output;
        a.free(self.metadata);
        self.metadata = &.{};
        return claims;
    }
};
/// Receiver supplies the independently authorized complete tuple list. Digest
/// must enter FS before roots; expected RAM debt is recomputed after challenges.
pub fn expectedClaim(cells: []const Cell, initial: bool, ch: R.types.RamChallenges) !Q {
    var claim = Q.zero();
    for (cells) |cell| {
        var tuple: [14]Q = @splat(Q.zero());
        tuple[0] = Q.one();
        @memcpy(tuple[1..5], &R.types.word(Q, cell.address));
        tuple[5] = @import("../../evaluation.zig").q(cell.state.epoch);
        tuple[6] = @import("../../evaluation.zig").q(@as(u16, @truncate(cell.state.tick)));
        tuple[7] = @import("../../evaluation.zig").q(cell.state.tick >> 16);
        @memcpy(tuple[8..12], &R.types.word(Q, cell.state.value));
        tuple[12] = @import("../../evaluation.zig").q(cell.state.rights & 1);
        tuple[13] = @import("../../evaluation.zig").q(cell.state.rights >> 1);
        const inv = try ch.denominatorFor(Q, tuple).inv();
        claim = if (initial) claim.sub(inv) else claim.add(inv);
    }
    return claim;
}
