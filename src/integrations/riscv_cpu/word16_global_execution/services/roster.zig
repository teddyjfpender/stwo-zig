//! Explicit optional K/ADD/DOUBLE bridge roster, independently typed truths.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const K = A.crypto.keccak.word16_bridge;
const S = A.crypto.secp256k1.word16_bridge;
const Mat = @import("../../word16_execution/setup.zig");
const Core = @import("../../word16_execution/sources.zig");
const Commit = @import("../../word16_execution/main_ownership.zig").Commit;
const Key = @import("../keccak/shared/key.zig").Key;
const T = @import("types.zig");
const append = @import("../keccak/roster.zig").append;
const M = core.fields.m31.M31;
const Col = engine.pcs.ColumnEvaluation;
pub const CpuSetup = struct {
    materials: Mat.Materials,
    bridges: T.Logs,
    fixed: [3][]M,
    key: Key,
    pub fn initProgram(a: std.mem.Allocator, program: A.program.setup.Program, g: Mat.Geometry, bridges: T.Logs) !CpuSetup {
        var m = try Mat.Materials.init(a, program, g);
        errdefer m.deinit();
        return seal(a, m, bridges);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, authority: *const @import("../../rv64_full.zig").ProgramAuthority, g: Mat.Geometry, bridges: T.Logs) !CpuSetup {
        var m = try Mat.Materials.initWithAuthority(a, authority, g);
        errdefer m.deinit();
        return seal(a, m, bridges);
    }
    fn seal(a: std.mem.Allocator, m: Mat.Materials, bridges: T.Logs) !CpuSetup {
        var self = CpuSetup{ .materials = m, .bridges = bridges, .fixed = @splat(&.{}), .key = undefined };
        var done: usize = 0;
        errdefer for (self.fixed[0..done]) |f| a.free(f);
        for (0..3) |k| {
            const family: T.Family = @enumFromInt(k);
            if (bridges.at(family)) |log| self.fixed[k] = if (k == 0) try K.source.fixed(a, log) else try S.source.fixed(a, @enumFromInt(k), log);
            done += 1;
        }
        const columns = try self.fixedColumns(a);
        defer a.free(columns);
        self.key = try Key.seal(a, columns);
        return self;
    }
    pub fn deinit(self: *CpuSetup) void {
        self.key.deinit();
        for (self.fixed) |f| self.materials.allocator.free(f);
        self.materials.deinit();
    }
    pub fn total(self: *const CpuSetup, tree: usize) usize {
        var n: usize = 0;
        for (self.materials.shapes()) |s| n += s.widths[tree];
        return n;
    }
    pub fn offset(self: *const CpuSetup, family: T.Family, tree: usize) usize {
        var n = self.total(tree);
        for (0..@intFromEnum(family)) |k| if (self.bridges.at(@enumFromInt(k)) != null) {
            n += T.widths(@enumFromInt(k))[tree];
        };
        return n;
    }
    pub fn columnCount(self: *const CpuSetup, tree: usize) usize {
        var n = self.total(tree);
        for (0..3) |k| if (self.bridges.at(@enumFromInt(k)) != null) {
            n += T.widths(@enumFromInt(k))[tree];
        };
        return n;
    }
    pub fn fixedColumns(self: *const CpuSetup, a: std.mem.Allocator) ![]Col {
        const old = try self.materials.fixedColumns(a);
        defer a.free(old);
        const out = try a.alloc(Col, self.columnCount(0));
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (0..3) |k| if (self.bridges.at(@enumFromInt(k))) |log| {
            append(out, &at, self.fixed[k], log);
        };
        return out;
    }
    pub fn logs(self: *const CpuSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const old = try self.materials.logs(a, tree);
        defer a.free(old);
        const out = try a.alloc(u32, self.columnCount(tree));
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (0..3) |k| if (self.bridges.at(@enumFromInt(k))) |log| {
            const width = T.widths(@enumFromInt(k))[tree];
            @memset(out[at..][0..width], log);
            at += width;
        };
        return out;
    }
};
pub const Sources = struct {
    core: Core.Source,
    keccak: ?K.source.Source = null,
    add: ?S.source.Source = null,
    double: ?S.source.Source = null,
    pub fn deinit(self: *Sources) void {
        if (self.keccak) |*s| s.deinit();
        if (self.add) |*s| s.deinit();
        if (self.double) |*s| s.deinit();
        self.core.deinit();
    }
    pub fn main(self: *Sources, family: T.Family) ?*[]M {
        return self.matrixPtr(family, 1);
    }
    fn matrixPtr(self: *Sources, family: T.Family, tree: usize) ?*[]M {
        return switch (family) {
            .keccak => if (self.keccak) |*s| if (tree == 1) &s.main else &s.interaction else null,
            .add => if (self.add) |*s| if (tree == 1) &s.main else &s.interaction else null,
            .double => if (self.double) |*s| if (tree == 1) &s.main else &s.interaction else null,
        };
    }
    fn matrix(self: *const Sources, family: T.Family, tree: usize) ?[]const M {
        return switch (family) {
            .keccak => if (self.keccak) |s| if (tree == 1) s.main else s.interaction else null,
            .add => if (self.add) |s| if (tree == 1) s.main else s.interaction else null,
            .double => if (self.double) |s| if (tree == 1) s.main else s.interaction else null,
        };
    }
    pub fn columns(self: *const Sources, a: std.mem.Allocator, setup: *const CpuSetup, tree: usize) ![]Col {
        const old = try self.core.columns(a, tree);
        defer a.free(old);
        const out = try a.alloc(Col, setup.columnCount(tree));
        errdefer a.free(out);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (0..3) |k| {
            const f: T.Family = @enumFromInt(k);
            if (setup.bridges.at(f)) |log| {
                const data = self.matrix(f, tree) orelse return error.MissingCombinedServiceSource;
                if (data.len != T.widths(f)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                append(out, &at, data, log);
            } else if (self.matrix(f, tree) != null) return error.UnexpectedCombinedServiceSource;
        }
        return out;
    }
    pub fn mergeRanges(self: *Sources) !void {
        if (self.keccak) |*s| try merge(&self.core, s.counts16, s.counts8);
        if (self.add) |*s| try merge(&self.core, s.counts16, s.counts8);
        if (self.double) |*s| try merge(&self.core, s.counts16, s.counts8);
    }
    pub fn releaseMain(self: *Sources) !void {
        try self.core.releaseMain();
        if (self.keccak) |*s| s.releaseMain();
        if (self.add) |*s| s.releaseMain();
        if (self.double) |*s| s.releaseMain();
    }
    /// Preflight all allocations and cross-family spans before moving anything.
    /// After core's own success-only handoff, only infallible slice moves remain.
    pub fn takeMain(self: *Sources, setup: *const CpuSetup) !Commit {
        return self.take(setup, 1);
    }
    pub fn takeInteraction(self: *Sources, setup: *const CpuSetup) !Commit {
        return self.take(setup, 2);
    }
    fn take(self: *Sources, setup: *const CpuSetup, tree: usize) !Commit {
        const a = self.core.allocator;
        const headers = try self.columns(a, setup, tree);
        errdefer a.free(headers);
        var count: usize = 0;
        for (setup.materials.shapes()) |shape| if (shape.widths[tree] != 0) {
            count += 1;
        };
        for (0..3) |k| if (setup.bridges.at(@enumFromInt(k)) != null) {
            count += 1;
        };
        const backings = try a.alloc([]M, count);
        errdefer a.free(backings);
        inline for (.{ "keccak", "add", "double" }) |name| if (@field(self, name)) |*s| {
            if ((tree == 1 and (!s.owns_main or s.interaction.len != 0)) or !A.memory.ownership.same(a, s.allocator)) return error.InvalidCombinedMainOwner;
        };
        for (0..3) |k| {
            const family: T.Family = @enumFromInt(k);
            const data = (self.matrixPtr(family, tree) orelse continue).*;
            const end = try spanEnd(data);
            for (headers[0..setup.total(tree)]) |c| {
                if (overlap(data, try spanEnd(c.values), c.values, end)) return error.AliasedCombinedMain;
            }
            for (0..k) |j| {
                const prior = (self.matrixPtr(@enumFromInt(j), tree) orelse continue).*;
                if (overlap(data, try spanEnd(prior), prior, end)) return error.AliasedCombinedMain;
            }
        }
        const old = if (tree == 1) try self.core.takeMainForCommit() else try self.core.takeInteractionForCommit();
        @memcpy(headers[0..old.columns.len], old.columns);
        @memcpy(backings[0..old.backings.len], old.backings);
        var at = old.backings.len;
        a.free(old.columns);
        a.free(old.backings);
        inline for (.{ "keccak", "add", "double" }) |name| if (@field(self, name)) |*s| {
            if (tree == 1) {
                backings[at] = s.main;
                s.main = &.{};
                s.owns_main = false;
            } else {
                backings[at] = s.interaction;
                s.interaction = &.{};
            }
            at += 1;
        };
        return .{ .columns = headers, .backings = backings };
    }
};
fn spanEnd(data: []const M) !usize {
    return std.math.add(usize, @intFromPtr(data.ptr), try std.math.mul(usize, data.len, @sizeOf(M)));
}
fn overlap(data: []const M, other_end: usize, other: []const M, end: usize) bool {
    return data.len != 0 and other.len != 0 and @intFromPtr(data.ptr) < other_end and @intFromPtr(other.ptr) < end;
}
fn merge(base: *Core.Source, c16: []const u64, c8: []const u64) !void {
    if (base.range16.interaction.len != 0 or base.range8.interaction.len != 0 or base.range16.main.len != 65536 or base.range8.main.len != 256) return error.InvalidCombinedRangePhase;
    inline for (.{ base.counts16, base.counts8 }, .{ c16, c8 }, .{ base.range16.main, base.range8.main }, [_]u32{ 16, 8 }) |counts, extra, main, log| {
        var mass: u64 = 0;
        for (counts, extra, 0..) |*c, x, row| {
            c.* = try std.math.add(u64, c.*, x);
            mass = try std.math.add(u64, mass, c.*);
            if (mass >= core.fields.m31.Modulus) return error.CombinedRangeMassExceeded;
            main[A.witness.physical(row, log)] = M.fromCanonical(@intCast(c.*));
        }
    }
}

pub const Truth = union(enum) {
    keccak: struct { setup: *const @import("../keccak/shared/roster.zig").TruthSetup, first_id: u32, calls: u32 },
    secp: struct { setup: *const @import("../secp/roster.zig").TruthSetup, first_id: u32, calls: u32 },
    pub fn family(self: @This()) T.Family {
        return switch (self) {
            .keccak => .keccak,
            .secp => |t| if (t.setup.kind == .add) .add else .double,
        };
    }
    pub fn first(self: @This()) u32 {
        return switch (self) {
            inline else => |t| t.first_id,
        };
    }
    pub fn count(self: @This()) u32 {
        return switch (self) {
            inline else => |t| t.calls,
        };
    }
    pub fn key(self: @This()) *const Key {
        return switch (self) {
            inline else => |t| &t.setup.key,
        };
    }
    pub fn logs(self: @This(), a: std.mem.Allocator, tree: usize) ![]u32 {
        return switch (self) {
            .keccak => |t| t.setup.logs(a, tree),
            .secp => |t| t.setup.columnLogs(a, tree),
        };
    }
};
pub const TruthSource = union(enum) {
    keccak: @import("../keccak/shared/roster.zig").TruthSource,
    secp: @import("../secp/roster.zig").TruthSource,
    pub fn init(a: std.mem.Allocator, truth: Truth, advice: *const @import("collector.zig").Advice) !TruthSource {
        if (truth.first() == 0) return error.InvalidCombinedTruthSpan;
        const begin: usize = truth.first() - 1;
        const end = begin + truth.count();
        return switch (truth) {
            .keccak => |t| block: {
                const inputs = try a.alloc(A.crypto.keccak.trace.State, t.calls);
                defer a.free(inputs);
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.keccak) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc.len);
                    if (lo < hi) {
                        for (cc[lo - offset .. hi - offset]) |call| {
                            inputs[written] = call.before;
                            written += 1;
                        }
                    }
                    offset += cc.len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .keccak = try @import("../keccak/shared/roster.zig").TruthSource.initSpan(a, inputs, t.first_id, t.setup.log) };
            },
            .secp => |t| block: {
                const inputs = try a.alloc(S.types.Call, t.calls);
                defer a.free(inputs);
                const family = @intFromEnum(t.setup.kind) - 1;
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.secp) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc[family].len);
                    if (lo < hi) {
                        const selected = cc[family][lo - offset .. hi - offset];
                        @memcpy(inputs[written..][0..selected.len], selected);
                        written += selected.len;
                    }
                    offset += cc[family].len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .secp = try @import("../secp/roster.zig").TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
        };
    }
    pub fn deinit(self: *TruthSource) void {
        switch (self.*) {
            inline else => |*s| s.deinit(),
        }
    }
    pub fn releaseMain(self: *TruthSource) !void {
        switch (self.*) {
            inline else => |*s| try s.releaseMain(),
        }
    }
    pub fn columns(self: *const TruthSource, a: std.mem.Allocator, tree: usize) ![]Col {
        return switch (self.*) {
            inline else => |s| s.columns(a, tree),
        };
    }
};
