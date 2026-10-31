//! Independently sized exact tables; counts sealed before challenge drawing.
const std = @import("std");
const Storage = @import("../main_storage.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const physical = @import("../../witness.zig").physical;
const I = @import("interaction.zig");
const C = @import("component.zig");
const E = @import("equations.zig");
const schema = @import("../../../../air/guest_precompile/keccakf_tables.zig");
pub const Trace = struct {
    allocator: std.mem.Allocator,
    kind: C.Kind,
    log_size: u32,
    fixed: []M,
    main: []M,
    main_allocator: ?std.mem.Allocator = null,
    owns_main: bool = true,
    multiplicities: []u32 = &.{},
    interaction: []M = &.{},
    pub fn init(a: std.mem.Allocator, kind: C.Kind, counts: []const u64) !Trace {
        return initWithMainAllocator(a, a, kind, counts);
    }
    pub fn initWithMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, kind: C.Kind, counts: []const u64) !Trace {
        return build(a, .{ .owned = main_allocator }, kind, counts);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, kind: C.Kind, counts: []const u64, main: []M) !Trace {
        return build(a, .{ .borrowed = main }, kind, counts);
    }
    fn build(a: std.mem.Allocator, storage: Storage.Buffer, kind: C.Kind, counts: []const u64) !Trace {
        if (kind == .permutation) return error.InvalidKeccakTable;
        const old: schema.Kind = if (kind == .chi) .chi else .xor5;
        const log = schema.logSize(old);
        const n = schema.size(old);
        if (counts.len != n) return error.InvalidKeccakTableCounts;
        var total: u64 = 0;
        for (counts) |count| {
            total = try std.math.add(u64, total, count);
            if (total >= core.fields.m31.Modulus) return error.InvalidKeccakTableCounts;
        }
        try storage.validate(n);
        if (storage == .borrowed) try Storage.exclude(&.{.{ .values = storage.borrowed, .cells = n }}, std.mem.sliceAsBytes(counts));
        const fixed = try a.alloc(M, 7 * n);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        const multiplicities = try a.alloc(u32, n);
        errdefer a.free(multiplicities);
        const main = try storage.acquire(n);
        errdefer storage.release(main);
        for (counts, 0..) |count, i| {
            const r = physical(i, log);
            const tuple = try schema.tupleAt(old, i);
            for (tuple, 0..) |v, c| fixed[c * n + r] = v;
            fixed[6 * n + r] = M.fromCanonical(@intFromBool(i == 0));
            main[r] = M.fromCanonical(@intCast(count));
            multiplicities[i] = @intCast(count);
        }
        return .{ .allocator = a, .kind = kind, .log_size = log, .fixed = fixed, .main = main, .main_allocator = storage.allocator(), .owns_main = storage == .owned, .multiplicities = multiplicities };
    }
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.fixed);
        if (self.owns_main and self.main.len != 0) (self.main_allocator orelse self.allocator).free(self.main);
        self.allocator.free(self.multiplicities);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn size(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn validateMetadata(self: *const Trace) !void {
        if (self.kind == .permutation or self.log_size != @as(u32, if (self.kind == .chi) 13 else 10) or self.multiplicities.len != self.size()) return error.InvalidKeccakTableCounts;
        var total: u64 = 0;
        for (self.multiplicities) |count| {
            total = try std.math.add(u64, total, count);
            if (total >= core.fields.m31.Modulus) return error.InvalidKeccakTableCounts;
        }
    }
    pub fn takeMain(self: *Trace) ![]M {
        if (!self.owns_main) return error.BorrowedCryptoMain;
        try self.validateMetadata();
        if (self.main.len != self.size()) return error.InvalidKeccakMainPhase;
        const data = self.main;
        self.main = &.{};
        return data;
    }
    pub fn releaseMain(self: *Trace) !void {
        try self.validateMetadata();
        if (self.main.len != self.size()) return error.InvalidCryptoMainPhase;
        if (self.owns_main) (self.main_allocator orelse self.allocator).free(self.main);
        self.main = &.{};
    }
    pub fn generateInteraction(self: *Trace, challenges: E.Challenges) !Q {
        if (self.interaction.len != 0) return error.KeccakInteractionAlreadyGenerated;
        const n = self.size();
        try self.validateMetadata();
        const data = try self.allocator.alloc(M, 4 * n);
        errdefer self.allocator.free(data);
        const ch = if (self.kind == .chi) challenges.chi else challenges.xor5;
        var sum = Q.zero();
        for (0..n) |i| {
            const r = physical(i, self.log_size);
            var tuple: [6]Q = undefined;
            for (&tuple, 0..) |*v, c| v.* = Q.fromBase(self.fixed[c * n + r]);
            sum = sum.add((try ch.denominator(&tuple).inv()).mulM31(M.fromCanonical(self.multiplicities[i])));
            I.store(data, n, r, 0, sum);
        }
        self.interaction = data;
        return sum;
    }
};
