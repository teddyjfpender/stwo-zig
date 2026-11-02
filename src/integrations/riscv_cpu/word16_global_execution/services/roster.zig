//! Explicit optional K/ADD/DOUBLE bridge roster, independently typed truths.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const K = A.crypto.keccak.word16_bridge;
const S = A.crypto.secp256k1.word16_bridge;
const BM = A.crypto.bulk_memory;
const KS = A.crypto.keccak_sponge;
const ZS = A.word16_v1.binary_zbb_source;
const BS = A.word16_v1.binary_source;
const Mat = @import("../../word16_execution/setup.zig");
const Core = @import("../../word16_execution/sources.zig");
const Commit = @import("../../word16_execution/main_ownership.zig").Commit;
const Key = @import("../keccak/shared/key.zig").Key;
const T = @import("types.zig");
const append = @import("../keccak/roster.zig").append;
const Sha = @import("../sha256/roster.zig");
const Arith = @import("../arith256/roster.zig");
const Curve = @import("../curves/roster.zig");
const M = core.fields.m31.M31;
const Col = engine.pcs.ColumnEvaluation;
pub const CpuSetup = struct {
    materials: Mat.Materials,
    bridges: T.Logs,
    fixed: [T.FAMILIES][]M,
    /// Bulk-memory fixed columns (desc, copy, set), after every family.
    bulk_fixed: [T.bulk_kinds.len][]M = @splat(&.{}),
    /// Keccak-sponge fixed columns (call, perm), after the bulk block.
    sponge_fixed: [2][]M = @splat(&.{}),
    /// Zbb BINARY fixed (first/last) columns, after the sponge block.
    zbb_fixed: []M = &.{},
    key: Key,
    pub fn initProgram(a: std.mem.Allocator, program: A.program.setup.Program, g: Mat.Geometry, bridges: T.Logs) !CpuSetup {
        return initProgramWithSuite(a, program, g, bridges, Mat.Suite.production());
    }
    /// Program ROM under an explicit execution profile (Zbb fixtures).
    pub fn initProgramWithProfile(a: std.mem.Allocator, program: A.program.setup.Program, g: Mat.Geometry, bridges: T.Logs, profile: front.rv64.execution_profile.Profile) !CpuSetup {
        var m = try Mat.Materials.initWithSuiteAndProfile(a, program, g, Mat.Suite.production(), profile);
        errdefer m.deinit();
        return seal(a, m, bridges);
    }
    pub fn initProgramWithSuite(a: std.mem.Allocator, program: A.program.setup.Program, g: Mat.Geometry, bridges: T.Logs, suite: Mat.Suite) !CpuSetup {
        var m = try Mat.Materials.initWithSuite(a, program, g, suite);
        errdefer m.deinit();
        return seal(a, m, bridges);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, authority: *const @import("../../rv64_full.zig").ProgramAuthority, g: Mat.Geometry, bridges: T.Logs) !CpuSetup {
        return initWithAuthorityAndSuite(a, authority, g, bridges, Mat.Suite.production());
    }
    pub fn initWithAuthorityAndSuite(a: std.mem.Allocator, authority: *const @import("../../rv64_full.zig").ProgramAuthority, g: Mat.Geometry, bridges: T.Logs, suite: Mat.Suite) !CpuSetup {
        var m = try Mat.Materials.initWithAuthorityAndSuite(a, authority, g, suite);
        errdefer m.deinit();
        return seal(a, m, bridges);
    }
    pub fn initWithAuthorityAndNativeCache(a: std.mem.Allocator, authority: *const @import("../../rv64_full.zig").ProgramAuthority, g: Mat.Geometry, bridges: T.Logs, cache: *const Mat.NativeCache.Cache) !CpuSetup {
        return initWithAuthorityAndSuiteAndNativeCache(a, authority, g, bridges, Mat.Suite.production(), cache);
    }
    pub fn initWithAuthorityAndSuiteAndNativeCache(a: std.mem.Allocator, authority: *const @import("../../rv64_full.zig").ProgramAuthority, g: Mat.Geometry, bridges: T.Logs, suite: Mat.Suite, cache: *const Mat.NativeCache.Cache) !CpuSetup {
        return initWithAuthorityAndSuiteAndCaches(a, authority, g, bridges, suite, .{ .native = cache });
    }
    pub fn initWithAuthorityAndSuiteAndCaches(a: std.mem.Allocator, authority: *const @import("../../rv64_full.zig").ProgramAuthority, g: Mat.Geometry, bridges: T.Logs, suite: Mat.Suite, caches: Mat.ImmutableCaches) !CpuSetup {
        var m = try Mat.Materials.initWithAuthorityAndSuiteAndMetadataCache(a, authority, g, suite, caches.program);
        errdefer m.deinit();
        return sealWithCache(a, m, bridges, caches.native);
    }
    fn seal(a: std.mem.Allocator, m: Mat.Materials, bridges: T.Logs) !CpuSetup {
        return sealWithCache(a, m, bridges, null);
    }
    fn sealWithCache(a: std.mem.Allocator, m: Mat.Materials, bridges: T.Logs, cache: ?*const Mat.NativeCache.Cache) !CpuSetup {
        var self = CpuSetup{ .materials = m, .bridges = bridges, .fixed = @splat(&.{}), .key = undefined };
        var done: usize = 0;
        errdefer for (self.fixed[0..done]) |f| a.free(f);
        for (0..T.FAMILIES) |k| {
            const family: T.Family = @enumFromInt(k);
            if (bridges.at(family)) |log| self.fixed[k] = if (k == 0) try K.source.fixed(a, log) else try S.source.fixed(a, T.bridgeKind(family), log);
            done += 1;
        }
        var bulk_done: usize = 0;
        errdefer for (self.bulk_fixed[0..bulk_done]) |f| a.free(f);
        for (T.bulk_kinds, 0..) |kind, k| {
            if (bridges.bulk.at(kind)) |log| {
                _ = try BM.types.validateGeometry(kind, 0, log);
                self.bulk_fixed[k] = try BM.source.fixed(a, log);
            }
            bulk_done += 1;
        }
        var sponge_done: usize = 0;
        errdefer for (self.sponge_fixed[0..sponge_done]) |f| a.free(f);
        for (T.sponge_kinds, 0..) |kind, k| {
            if (bridges.sponge.at(kind)) |log| {
                _ = try KS.types.validateGeometry(kind, 0, log);
                self.sponge_fixed[k] = try KS.source.fixed(a, log);
            }
            sponge_done += 1;
        }
        errdefer a.free(self.zbb_fixed);
        if (bridges.zbb) |log| {
            // Only a Zbb-profile ROM can request FUNCTION ids 19..24; any
            // other program with a Zbb component is rejected (fail closed).
            if (!A.word16_execution.features.zbbProfile(m.program.profile)) return error.UnexpectedZbbComponent;
            self.zbb_fixed = try BS.fixedForLog(a, log);
        }
        const columns = try self.fixedColumns(a);
        defer a.free(columns);
        self.key = try Key.sealWithSuiteAndCache(a, columns, m.suite, cache);
        return self;
    }
    /// The complete sealed key retains independent coefficient/tree ownership.
    pub fn releaseFixedWitness(self: *CpuSetup) !void {
        try self.materials.releaseFixedWitness();
        for (&self.fixed) |*data| {
            self.materials.allocator.free(data.*);
            data.* = &.{};
        }
        for (&self.bulk_fixed) |*data| {
            self.materials.allocator.free(data.*);
            data.* = &.{};
        }
        for (&self.sponge_fixed) |*data| {
            self.materials.allocator.free(data.*);
            data.* = &.{};
        }
        self.materials.allocator.free(self.zbb_fixed);
        self.zbb_fixed = &.{};
    }
    pub fn deinit(self: *CpuSetup) void {
        self.key.deinit();
        for (self.fixed) |f| self.materials.allocator.free(f);
        for (self.bulk_fixed) |f| self.materials.allocator.free(f);
        for (self.sponge_fixed) |f| self.materials.allocator.free(f);
        self.materials.allocator.free(self.zbb_fixed);
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
    /// Bulk components follow the three families in kind order.
    pub fn bulkOffset(self: *const CpuSetup, kind: T.BulkKind, tree: usize) usize {
        var n = self.familyEnd(tree);
        for (T.bulk_kinds) |k| {
            if (k == kind) break;
            if (self.bridges.bulk.at(k) != null) n += T.bulkWidths(k)[tree];
        }
        return n;
    }
    fn familyEnd(self: *const CpuSetup, tree: usize) usize {
        var n = self.total(tree);
        for (0..T.FAMILIES) |k| if (self.bridges.at(@enumFromInt(k)) != null) {
            n += T.widths(@enumFromInt(k))[tree];
        };
        return n;
    }
    fn bulkEnd(self: *const CpuSetup, tree: usize) usize {
        var n = self.familyEnd(tree);
        for (T.bulk_kinds) |k| if (self.bridges.bulk.at(k) != null) {
            n += T.bulkWidths(k)[tree];
        };
        return n;
    }
    /// Sponge components follow the bulk block in kind order (call, perm).
    pub fn spongeOffset(self: *const CpuSetup, kind: T.SpongeKind, tree: usize) usize {
        var n = self.bulkEnd(tree);
        for (T.sponge_kinds) |k| {
            if (k == kind) break;
            if (self.bridges.sponge.at(k) != null) n += T.spongeWidths(k)[tree];
        }
        return n;
    }
    fn spongeEnd(self: *const CpuSetup, tree: usize) usize {
        var n = self.bulkEnd(tree);
        for (T.sponge_kinds) |k| if (self.bridges.sponge.at(k) != null) {
            n += T.spongeWidths(k)[tree];
        };
        return n;
    }
    /// The Zbb BINARY component follows the sponge block.
    pub fn zbbOffset(self: *const CpuSetup, tree: usize) usize {
        return self.spongeEnd(tree);
    }
    pub fn columnCount(self: *const CpuSetup, tree: usize) usize {
        return self.spongeEnd(tree) + if (self.bridges.zbb != null) T.zbbWidths()[tree] else 0;
    }
    pub fn fixedColumns(self: *const CpuSetup, a: std.mem.Allocator) ![]Col {
        const old = try self.materials.fixedColumns(a);
        defer a.free(old);
        const out = try a.alloc(Col, self.columnCount(0));
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (0..T.FAMILIES) |k| if (self.bridges.at(@enumFromInt(k))) |log| {
            append(out, &at, self.fixed[k], log);
        };
        for (T.bulk_kinds, 0..) |kind, k| if (self.bridges.bulk.at(kind)) |log| {
            append(out, &at, self.bulk_fixed[k], log);
        };
        for (T.sponge_kinds, 0..) |kind, k| if (self.bridges.sponge.at(kind)) |log| {
            append(out, &at, self.sponge_fixed[k], log);
        };
        if (self.bridges.zbb) |log| append(out, &at, self.zbb_fixed, log);
        return out;
    }
    pub fn logs(self: *const CpuSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const old = try self.materials.logs(a, tree);
        defer a.free(old);
        const out = try a.alloc(u32, self.columnCount(tree));
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (0..T.FAMILIES) |k| if (self.bridges.at(@enumFromInt(k))) |log| {
            const width = T.widths(@enumFromInt(k))[tree];
            @memset(out[at..][0..width], log);
            at += width;
        };
        for (T.bulk_kinds) |kind| if (self.bridges.bulk.at(kind)) |log| {
            const width = T.bulkWidths(kind)[tree];
            @memset(out[at..][0..width], log);
            at += width;
        };
        for (T.sponge_kinds) |kind| if (self.bridges.sponge.at(kind)) |log| {
            const width = T.spongeWidths(kind)[tree];
            @memset(out[at..][0..width], log);
            at += width;
        };
        if (self.bridges.zbb) |log| {
            const width = T.zbbWidths()[tree];
            @memset(out[at..][0..width], log);
            at += width;
        }
        return out;
    }
};
pub const Sources = struct {
    core: Core.Source,
    keccak: ?K.source.Source = null,
    add: ?S.source.Source = null,
    double: ?S.source.Source = null,
    sha256: ?S.source.Source = null,
    arith256_mod: ?S.source.Source = null,
    /// Curve/field bridges (families 5..11, curves.Op order).
    curves: [T.CURVES]?S.source.Source = @splat(null),
    bulk: [T.bulk_kinds.len]?BM.source.Source = @splat(null),
    /// Keccak-sponge plan (owned) and its call/perm sources.
    sponge_plan: ?*KS.source.Plan = null,
    sponge: [2]?KS.source.Source = @splat(null),
    /// Zbb BINARY truth provider (FUNCTION ids 19..24 of this CPU proof).
    zbb: ?BS.Source = null,
    pub fn deinit(self: *Sources) void {
        if (self.zbb) |*s| s.deinit();
        for (&self.sponge) |*b| if (b.*) |*s| s.deinit();
        if (self.sponge_plan) |plan| {
            plan.deinit(self.core.allocator);
            self.core.allocator.destroy(plan);
        }
        if (self.keccak) |*s| s.deinit();
        if (self.add) |*s| s.deinit();
        if (self.double) |*s| s.deinit();
        if (self.sha256) |*s| s.deinit();
        if (self.arith256_mod) |*s| s.deinit();
        for (&self.curves) |*c| if (c.*) |*s| s.deinit();
        for (&self.bulk) |*b| if (b.*) |*s| s.deinit();
        self.core.deinit();
    }
    fn bulkMatrix(self: *Sources, k: usize, tree: usize) ?*[]M {
        return if (self.bulk[k]) |*s| (if (tree == 1) &s.main else &s.interaction) else null;
    }
    pub fn main(self: *Sources, family: T.Family) ?*[]M {
        return self.matrixPtr(family, 1);
    }
    fn matrixPtr(self: *Sources, family: T.Family, tree: usize) ?*[]M {
        return switch (family) {
            .keccak => if (self.keccak) |*s| if (tree == 1) &s.main else &s.interaction else null,
            .add => if (self.add) |*s| if (tree == 1) &s.main else &s.interaction else null,
            .double => if (self.double) |*s| if (tree == 1) &s.main else &s.interaction else null,
            .sha256 => if (self.sha256) |*s| if (tree == 1) &s.main else &s.interaction else null,
            .arith256_mod => if (self.arith256_mod) |*s| if (tree == 1) &s.main else &s.interaction else null,
            else => if (self.curves[@intFromEnum(family) - T.FIRST_CURVE]) |*s| if (tree == 1) &s.main else &s.interaction else null,
        };
    }
    fn matrix(self: *const Sources, family: T.Family, tree: usize) ?[]const M {
        return switch (family) {
            .keccak => if (self.keccak) |s| if (tree == 1) s.main else s.interaction else null,
            .add => if (self.add) |s| if (tree == 1) s.main else s.interaction else null,
            .double => if (self.double) |s| if (tree == 1) s.main else s.interaction else null,
            .sha256 => if (self.sha256) |s| if (tree == 1) s.main else s.interaction else null,
            .arith256_mod => if (self.arith256_mod) |s| if (tree == 1) s.main else s.interaction else null,
            else => if (self.curves[@intFromEnum(family) - T.FIRST_CURVE]) |s| if (tree == 1) s.main else s.interaction else null,
        };
    }
    pub fn columns(self: *const Sources, a: std.mem.Allocator, setup: *const CpuSetup, tree: usize) ![]Col {
        const old = try self.core.columns(a, tree);
        defer a.free(old);
        const out = try a.alloc(Col, setup.columnCount(tree));
        errdefer a.free(out);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (0..T.FAMILIES) |k| {
            const f: T.Family = @enumFromInt(k);
            if (setup.bridges.at(f)) |log| {
                const data = self.matrix(f, tree) orelse return error.MissingCombinedServiceSource;
                if (data.len != T.widths(f)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                append(out, &at, data, log);
            } else if (self.matrix(f, tree) != null) return error.UnexpectedCombinedServiceSource;
        }
        for (T.bulk_kinds, 0..) |kind, k| {
            if (setup.bridges.bulk.at(kind)) |log| {
                const s = self.bulk[k] orelse return error.MissingCombinedServiceSource;
                const data = if (tree == 1) s.main else s.interaction;
                if (s.kind != kind or data.len != T.bulkWidths(kind)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                append(out, &at, data, log);
            } else if (self.bulk[k] != null) return error.UnexpectedCombinedServiceSource;
        }
        for (T.sponge_kinds, 0..) |kind, k| {
            if (setup.bridges.sponge.at(kind)) |log| {
                const s = self.sponge[k] orelse return error.MissingCombinedServiceSource;
                const data = if (tree == 1) s.main else s.interaction;
                if (s.kind != kind or data.len != T.spongeWidths(kind)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                append(out, &at, data, log);
            } else if (self.sponge[k] != null) return error.UnexpectedCombinedServiceSource;
        }
        if (setup.bridges.zbb) |log| {
            const s = self.zbb orelse return error.MissingCombinedServiceSource;
            const data = switch (tree) {
                1 => s.main,
                2 => s.interaction,
                else => return error.InvalidCombinedServiceSource,
            };
            if (s.log_size != log or data.len != T.zbbWidths()[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
            append(out, &at, data, log);
        } else if (self.zbb != null) return error.UnexpectedCombinedServiceSource;
        return out;
    }
    pub fn mergeRanges(self: *Sources) !void {
        if (self.keccak) |*s| try merge(&self.core, s.counts16, s.counts8);
        if (self.add) |*s| try merge(&self.core, s.counts16, s.counts8);
        if (self.double) |*s| try merge(&self.core, s.counts16, s.counts8);
        if (self.sha256) |*s| try merge(&self.core, s.counts16, s.counts8);
        if (self.arith256_mod) |*s| try merge(&self.core, s.counts16, s.counts8);
        for (&self.curves) |*c| if (c.*) |*s| try merge(&self.core, s.counts16, s.counts8);
        for (&self.bulk) |*b| if (b.*) |*s| try merge(&self.core, s.counts16, s.counts8);
        for (&self.sponge) |*b| if (b.*) |*s| {
            try merge(&self.core, s.counts16, s.counts8);
            if (s.counts_and.len != 0) try mergeAnd(&self.core, s.counts_and);
        };
        // Zbb byte-AND lookups (8 per physical row, padding included) join the
        // core AND table exactly like the BINARY chip's own requests.
        if (self.zbb) |*s| try mergeAnd(&self.core, s.and_counts);
    }
    pub fn releaseMain(self: *Sources) !void {
        try self.core.releaseMain();
        if (self.keccak) |*s| s.releaseMain();
        if (self.add) |*s| s.releaseMain();
        if (self.double) |*s| s.releaseMain();
        if (self.sha256) |*s| s.releaseMain();
        if (self.arith256_mod) |*s| s.releaseMain();
        for (&self.curves) |*c| if (c.*) |*s| s.releaseMain();
        for (&self.bulk) |*b| if (b.*) |*s| s.releaseMain();
        for (&self.sponge) |*b| if (b.*) |*s| s.releaseMain();
        if (self.zbb) |*s| s.releaseMain();
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
        for (0..T.FAMILIES) |k| if (setup.bridges.at(@enumFromInt(k)) != null) {
            count += 1;
        };
        for (T.bulk_kinds) |kind| if (setup.bridges.bulk.at(kind) != null) {
            count += 1;
        };
        for (T.sponge_kinds) |kind| if (setup.bridges.sponge.at(kind) != null) {
            count += 1;
        };
        if (setup.bridges.zbb != null) count += 1;
        const backings = try a.alloc([]M, count);
        errdefer a.free(backings);
        inline for (.{ "keccak", "add", "double", "sha256", "arith256_mod" }) |name| if (@field(self, name)) |*s| {
            if ((tree == 1 and (!s.owns_main or s.interaction.len != 0)) or !A.memory.ownership.same(a, s.allocator)) return error.InvalidCombinedMainOwner;
        };
        for (&self.curves) |*c| if (c.*) |*s| {
            if ((tree == 1 and (!s.owns_main or s.interaction.len != 0)) or !A.memory.ownership.same(a, s.allocator)) return error.InvalidCombinedMainOwner;
        };
        for (&self.bulk) |*b| if (b.*) |*s| {
            if ((tree == 1 and (!s.owns_main or s.interaction.len != 0)) or !A.memory.ownership.same(a, s.allocator)) return error.InvalidCombinedMainOwner;
        };
        for (&self.sponge) |*b| if (b.*) |*s| {
            if ((tree == 1 and (!s.owns_main or s.interaction.len != 0)) or !A.memory.ownership.same(a, s.allocator)) return error.InvalidCombinedMainOwner;
            const data = if (tree == 1) s.main else s.interaction;
            const end = try spanEnd(data);
            for (headers[0..setup.total(tree)]) |c| {
                if (overlap(data, try spanEnd(c.values), c.values, end)) return error.AliasedCombinedMain;
            }
        };
        if (self.zbb) |*s| {
            if ((tree == 1 and (!s.owns_main or s.interaction.len != 0)) or !A.memory.ownership.same(a, s.allocator)) return error.InvalidCombinedMainOwner;
            const data = if (tree == 1) s.main else s.interaction;
            const end = try spanEnd(data);
            for (headers[0..setup.total(tree)]) |c| {
                if (overlap(data, try spanEnd(c.values), c.values, end)) return error.AliasedCombinedMain;
            }
        }
        for (0..T.FAMILIES) |k| {
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
        for (0..3) |k| {
            const data = (self.bulkMatrix(k, tree) orelse continue).*;
            const end = try spanEnd(data);
            for (headers[0..setup.total(tree)]) |c| {
                if (overlap(data, try spanEnd(c.values), c.values, end)) return error.AliasedCombinedMain;
            }
            for (0..T.FAMILIES) |j| {
                const prior = (self.matrixPtr(@enumFromInt(j), tree) orelse continue).*;
                if (overlap(data, try spanEnd(prior), prior, end)) return error.AliasedCombinedMain;
            }
            for (0..k) |j| {
                const prior = (self.bulkMatrix(j, tree) orelse continue).*;
                if (overlap(data, try spanEnd(prior), prior, end)) return error.AliasedCombinedMain;
            }
        }
        const old = if (tree == 1) try self.core.takeMainForCommit() else try self.core.takeInteractionForCommit();
        @memcpy(headers[0..old.columns.len], old.columns);
        @memcpy(backings[0..old.backings.len], old.backings);
        var at = old.backings.len;
        a.free(old.columns);
        a.free(old.backings);
        inline for (.{ "keccak", "add", "double", "sha256", "arith256_mod" }) |name| if (@field(self, name)) |*s| {
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
        for (&self.curves) |*c| if (c.*) |*s| {
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
        for (&self.bulk) |*b| if (b.*) |*s| {
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
        for (&self.sponge) |*b| if (b.*) |*s| {
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
        if (self.zbb) |*s| {
            if (tree == 1) {
                backings[at] = s.main;
                s.main = &.{};
                s.owns_main = false;
            } else {
                backings[at] = s.interaction;
                s.interaction = &.{};
            }
            at += 1;
        }
        return .{ .columns = headers, .backings = backings };
    }
};
fn spanEnd(data: []const M) !usize {
    return std.math.add(usize, @intFromPtr(data.ptr), try std.math.mul(usize, data.len, @sizeOf(M)));
}
fn overlap(data: []const M, other_end: usize, other: []const M, end: usize) bool {
    return data.len != 0 and other.len != 0 and @intFromPtr(data.ptr) < other_end and @intFromPtr(other.ptr) < end;
}
/// Keccak-sponge byte-AND lookups join the CPU proof's canonical AND table:
/// the table's multiplicities grow by the sponge counts (mass kept below p).
fn mergeAnd(base: *Core.Source, extra: []const u64) !void {
    const table = &base.and_table;
    if (table.interaction.len != 0 or table.main.len != 65536 or extra.len != 65536) return error.InvalidCombinedRangePhase;
    var mass: u64 = 0;
    for (extra, 0..) |x, row| {
        const p = A.witness.physical(row, 16);
        const total = try std.math.add(u64, table.main[p].v, x);
        mass = try std.math.add(u64, mass, total);
        if (mass >= core.fields.m31.Modulus) return error.CombinedRangeMassExceeded;
        table.main[p] = M.fromCanonical(@intCast(total));
    }
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
    sha256: struct { setup: *const Sha.TruthSetup, first_id: u32, calls: u32 },
    arith256_mod: struct { setup: *const Arith.TruthSetup, first_id: u32, calls: u32 },
    curve: struct { setup: *const Curve.TruthSetup, first_id: u32, calls: u32 },
    pub fn family(self: @This()) T.Family {
        return switch (self) {
            .keccak => .keccak,
            .secp => |t| if (t.setup.kind == .add) .add else .double,
            .sha256 => .sha256,
            .arith256_mod => .arith256_mod,
            .curve => |t| T.curveFamily(t.setup.op),
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
            .sha256 => |t| t.setup.logs(a, tree),
            .arith256_mod => |t| t.setup.logs(a, tree),
            .curve => |t| t.setup.logs(a, tree),
        };
    }
};
pub const TruthSource = union(enum) {
    keccak: @import("../keccak/shared/roster.zig").TruthSource,
    secp: @import("../secp/roster.zig").TruthSource,
    sha256: Sha.TruthSource,
    arith256_mod: Arith.TruthSource,
    curve: Curve.TruthSource,
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
                // Keccak-sponge permutations follow every Keccak-f call in the
                // shared IO11 ID space (shard order, then permutation order).
                for (advice.sponge) |shard| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + shard.inputs.len);
                    if (lo < hi) {
                        for (shard.inputs[lo - offset .. hi - offset]) |state| {
                            inputs[written] = state;
                            written += 1;
                        }
                    }
                    offset += shard.inputs.len;
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
            .sha256 => |t| block: {
                const inputs = try a.alloc(S.types.Call, t.calls);
                defer a.free(inputs);
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.sha256) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc.len);
                    if (lo < hi) {
                        const selected = cc[lo - offset .. hi - offset];
                        @memcpy(inputs[written..][0..selected.len], selected);
                        written += selected.len;
                    }
                    offset += cc.len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .sha256 = try Sha.TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
            .arith256_mod => |t| block: {
                const inputs = try a.alloc(S.types.Call, t.calls);
                defer a.free(inputs);
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.arith256_mod) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc.len);
                    if (lo < hi) {
                        const selected = cc[lo - offset .. hi - offset];
                        @memcpy(inputs[written..][0..selected.len], selected);
                        written += selected.len;
                    }
                    offset += cc.len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .arith256_mod = try Arith.TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
            .curve => |t| block: {
                const inputs = try a.alloc(S.types.Call, t.calls);
                defer a.free(inputs);
                const k = @intFromEnum(t.setup.op) - T.FIRST_CURVE;
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.curves) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc[k].len);
                    if (lo < hi) {
                        const selected = cc[k][lo - offset .. hi - offset];
                        @memcpy(inputs[written..][0..selected.len], selected);
                        written += selected.len;
                    }
                    offset += cc[k].len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .curve = try Curve.TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
        };
    }
    /// Transfers the three original wide allocations, preserving only the
    /// secp BYTE provider's 256 multiplicities as narrow generator input.
    /// Every validation/allocation precedes mutation; PCS consumes Commit.
    pub fn takeMain(self: *TruthSource) !Commit {
        return self.take(1);
    }
    pub fn takeInteraction(self: *TruthSource) !Commit {
        return self.take(2);
    }
    fn take(self: *TruthSource, tree: usize) !Commit {
        if (self.* == .sha256) return takeSha(&self.sha256.source, tree);
        if (self.* == .arith256_mod) return takeArith(&self.arith256_mod.source, tree);
        if (self.* == .curve) return switch (self.curve) {
            inline else => |*s| takeCurve(s, tree),
        };
        const a = switch (self.*) {
            .keccak => |s| s.permutation.allocator,
            .secp => |s| s.batch.product.allocator,
            .sha256, .arith256_mod, .curve => unreachable,
        };
        var matrices: [3]*[]M = undefined;
        var expected: [3]usize = undefined;
        var protected: [6][]const M = undefined;
        switch (self.*) {
            .keccak => |*s| {
                if (s.chi.kind != .chi or s.xor5.kind != .xor5) return error.InvalidTruthBufferPhase;
                try s.permutation.validateMetadata();
                try s.chi.validateMetadata();
                try s.xor5.validateMetadata();
                inline for (.{ "permutation", "chi", "xor5" }, 0..) |name, i| {
                    const part = &@field(s, name);
                    if (!A.memory.ownership.same(a, part.allocator) or (tree == 1 and (!part.owns_main or !A.memory.ownership.same(a, part.main_allocator orelse part.allocator) or part.interaction.len != 0))) return error.InvalidTruthBufferOwner;
                    protected[i] = part.fixed;
                    protected[3 + i] = if (tree == 1) part.interaction else part.main;
                    matrices[i] = if (tree == 1) &part.main else &part.interaction;
                    const width: usize = if (i == 0) (if (tree == 1) A.crypto.keccak.layout.MAIN else A.crypto.keccak.layout.INTERACTION) else (if (tree == 1) 1 else 4);
                    expected[i] = try std.math.mul(usize, width, part.size());
                }
            },
            .secp => |*s| {
                if (s.batch.product.kind != .product or s.batch.linear.kind != .linear) return error.InvalidTruthBufferPhase;
                try s.batch.product.validateMetadata();
                try s.batch.linear.validateMetadata();
                inline for (.{ "product", "linear" }, 0..) |name, i| {
                    const part = &@field(s.batch, name);
                    if (!A.memory.ownership.same(a, part.allocator) or (tree == 1 and (!part.owns_main or !A.memory.ownership.same(a, part.main_allocator orelse part.allocator) or part.interaction.len != 0))) return error.InvalidTruthBufferOwner;
                    protected[i] = part.fixed;
                    protected[3 + i] = if (tree == 1) part.interaction else part.main;
                    matrices[i] = if (tree == 1) &part.main else &part.interaction;
                    expected[i] = try std.math.mul(usize, if (tree == 1) A.crypto.secp256k1.layout.main(part.kind) else A.crypto.secp256k1.layout.interactionFor(part.kind, part.byte_policy), part.size());
                }
                if (!A.memory.ownership.same(a, s.bytes.allocator) or (tree == 1 and s.bytes.interaction.len != 0)) return error.InvalidTruthBufferOwner;
                protected[2] = s.bytes.fixed;
                protected[5] = if (tree == 1) s.bytes.interaction else s.bytes.main;
                matrices[2] = if (tree == 1) &s.bytes.main else &s.bytes.interaction;
                expected[2] = (if (tree == 1) @as(usize, 1) else 8) * 256;
            },
            .sha256, .arith256_mod, .curve => unreachable,
        }
        for (matrices, expected, 0..) |matrix, size, i| {
            if (matrix.len != size) return error.InvalidTruthBufferPhase;
            const end = try spanEnd(matrix.*);
            for (protected) |other| if (overlap(matrix.*, try spanEnd(other), other, end)) return error.AliasedTruthBuffers;
            for (matrices[0..i]) |previous| if (overlap(matrix.*, try spanEnd(previous.*), previous.*, end)) return error.AliasedTruthBuffers;
        }
        const headers = try self.columns(a, tree);
        errdefer a.free(headers);
        const backings = try a.alloc([]M, 3);
        errdefer a.free(backings);
        const byte_counts = if (tree == 1 and self.* == .secp) try a.dupe(M, self.secp.bytes.main) else null;
        // No fallible operation may follow this point.
        for (matrices, backings) |matrix, *backing| {
            backing.* = matrix.*;
            matrix.* = &.{};
        }
        if (tree == 1) switch (self.*) {
            .keccak => |*s| {
                s.permutation.owns_main = false;
                s.chi.owns_main = false;
                s.xor5.owns_main = false;
            },
            .secp => |*s| {
                s.batch.product.owns_main = false;
                s.batch.linear.owns_main = false;
                s.bytes.main = byte_counts.?;
            },
            .sha256, .arith256_mod, .curve => unreachable,
        };
        return .{ .columns = headers, .backings = backings };
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
/// One wide SHA-256 MAIN/INTER matrix moves to the PCS; fixed stays key-owned.
fn takeSha(s: *A.crypto.sha256.trace.Source, tree: usize) !Commit {
    const a = s.allocator;
    try s.validateMetadata();
    const L = A.crypto.sha256.layout;
    const matrix = if (tree == 1) &s.main else &s.interaction;
    if (tree == 1 and (!s.owns_main or !A.memory.ownership.same(a, s.main_allocator orelse s.allocator))) return error.InvalidTruthBufferOwner;
    if ((tree == 1 and s.interaction.len != 0) or matrix.len != @as(usize, if (tree == 1) L.MAIN else L.INTERACTION) * s.size()) return error.InvalidTruthBufferPhase;
    const end = try spanEnd(matrix.*);
    const other = if (tree == 1) s.interaction else s.main;
    if (overlap(matrix.*, try spanEnd(s.fixed), s.fixed, end) or overlap(matrix.*, try spanEnd(other), other, end)) return error.AliasedTruthBuffers;
    const headers = try a.alloc(Col, L.widths()[tree]);
    errdefer a.free(headers);
    var at: usize = 0;
    append(headers, &at, matrix.*, s.log_size);
    const backings = try a.alloc([]M, 1);
    // No fallible operation may follow this point.
    backings[0] = matrix.*;
    matrix.* = &.{};
    if (tree == 1) s.owns_main = false;
    return .{ .columns = headers, .backings = backings };
}
/// One wide arith256 MAIN/INTER matrix moves to the PCS; fixed stays key-owned.
fn takeArith(s: *A.crypto.arith256.trace.Source, tree: usize) !Commit {
    const a = s.allocator;
    try s.validateMetadata();
    const L = A.crypto.arith256.layout;
    const matrix = if (tree == 1) &s.main else &s.interaction;
    if (tree == 1 and (!s.owns_main or !A.memory.ownership.same(a, s.main_allocator orelse s.allocator))) return error.InvalidTruthBufferOwner;
    if ((tree == 1 and s.interaction.len != 0) or matrix.len != @as(usize, if (tree == 1) L.MAIN else L.INTERACTION) * s.size()) return error.InvalidTruthBufferPhase;
    const end = try spanEnd(matrix.*);
    const other = if (tree == 1) s.interaction else s.main;
    if (overlap(matrix.*, try spanEnd(s.fixed), s.fixed, end) or overlap(matrix.*, try spanEnd(other), other, end)) return error.AliasedTruthBuffers;
    const headers = try a.alloc(Col, L.widths()[tree]);
    errdefer a.free(headers);
    var at: usize = 0;
    append(headers, &at, matrix.*, s.log_size);
    const backings = try a.alloc([]M, 1);
    // No fallible operation may follow this point.
    backings[0] = matrix.*;
    matrix.* = &.{};
    if (tree == 1) s.owns_main = false;
    return .{ .columns = headers, .backings = backings };
}
/// One wide curve/field MAIN/INTER matrix moves to the PCS; fixed stays key-owned.
fn takeCurve(s: anytype, tree: usize) !Commit {
    const a = s.allocator;
    try s.validateMetadata();
    const Src = @typeInfo(@TypeOf(s)).pointer.child;
    const L = @import("stwo_riscv_frontend").rv64_air.crypto.curves.trace.Trace(Src.OP).L;
    const matrix = if (tree == 1) &s.main else &s.interaction;
    if (tree == 1 and (!s.owns_main or !A.memory.ownership.same(a, s.main_allocator orelse s.allocator))) return error.InvalidTruthBufferOwner;
    if ((tree == 1 and s.interaction.len != 0) or matrix.len != @as(usize, if (tree == 1) L.MAIN else L.INTERACTION) * s.size()) return error.InvalidTruthBufferPhase;
    const end = try spanEnd(matrix.*);
    const other = if (tree == 1) s.interaction else s.main;
    if (overlap(matrix.*, try spanEnd(s.fixed), s.fixed, end) or overlap(matrix.*, try spanEnd(other), other, end)) return error.AliasedTruthBuffers;
    const headers = try a.alloc(Col, L.widths()[tree]);
    errdefer a.free(headers);
    var at: usize = 0;
    append(headers, &at, matrix.*, s.log_size);
    const backings = try a.alloc([]M, 1);
    // No fallible operation may follow this point.
    backings[0] = matrix.*;
    matrix.* = &.{};
    if (tree == 1) s.owns_main = false;
    return .{ .columns = headers, .backings = backings };
}
