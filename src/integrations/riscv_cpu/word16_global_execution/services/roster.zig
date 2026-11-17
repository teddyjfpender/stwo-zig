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
const LSD = A.memory.load_store_dword;
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
const SecpRow = @import("../secp/row_roster.zig");
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
    /// LS-D64 fixed columns (row index, first, last), after the sponge block.
    dword_fixed: [T.DWORD_INSTANCES][]M = @splat(&.{}),
    /// Zbb BINARY fixed (first/last) columns, after the LS-D64 block.
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
                self.bulk_fixed[k] = try BM.source.fixedFor(a, kind, log);
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
        var dword_done: usize = 0;
        errdefer for (self.dword_fixed[0..dword_done]) |f| a.free(f);
        if (bridges.ls_dword_tail != null and bridges.ls_dword == null) return error.InvalidCombinedBridgePresence;
        for (0..T.DWORD_INSTANCES) |k| {
            if (bridges.dwordLog(k)) |log| {
                if (log < 5 or log > T.DWORD_MAX_LOG) return error.InvalidCombinedServiceCount;
                self.dword_fixed[k] = try LSD.source.fixed(a, log);
            }
            dword_done += 1;
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
        for (&self.dword_fixed) |*data| {
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
        for (self.dword_fixed) |f| self.materials.allocator.free(f);
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
    /// The LS-D64 instances (head, tail) follow the sponge block.
    pub fn dwordOffset(self: *const CpuSetup, k: usize, tree: usize) usize {
        var n = self.spongeEnd(tree);
        for (0..k) |j| if (self.bridges.dwordLog(j) != null) {
            n += T.dwordWidthsFor(self.materials.geometry)[tree];
        };
        return n;
    }
    /// The Zbb BINARY component follows the LS-D64 block.
    pub fn zbbOffset(self: *const CpuSetup, tree: usize) usize {
        return self.dwordOffset(T.DWORD_INSTANCES, tree);
    }
    pub fn columnCount(self: *const CpuSetup, tree: usize) usize {
        return self.zbbOffset(tree) + if (self.bridges.zbb != null) T.zbbWidths()[tree] else 0;
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
        for (0..T.DWORD_INSTANCES) |k| if (self.bridges.dwordLog(k)) |log| append(out, &at, self.dword_fixed[k], log);
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
        for (0..T.DWORD_INSTANCES) |k| if (self.bridges.dwordLog(k)) |log| {
            const width = T.dwordWidthsFor(self.materials.geometry)[tree];
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
    /// Persists after MAIN handoff so cleanup never treats device headers as CPU tombstones.
    device_generated: bool = false,
    device_main: ?@import("device_main.zig").Owner = null,
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
    /// LS-D64 source: every LD/SD event of this CPU proof.
    ls_dword: [T.DWORD_INSTANCES]?LSD.source.Source = @splat(null),
    /// Zbb BINARY truth provider (FUNCTION ids 19..24 of this CPU proof).
    zbb: ?BS.Source = null,
    pub fn deinit(self: *Sources) void {
        if (self.device_main) |*owner| owner.release();
        self.device_main = null;
        if (self.zbb) |*s| s.deinit();
        for (&self.ls_dword) |*b| if (b.*) |*s| s.deinit();
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
        for (0..T.DWORD_INSTANCES) |k| {
            if (setup.bridges.dwordLog(k)) |log| {
                const s = self.ls_dword[k] orelse return error.MissingCombinedServiceSource;
                const data = if (tree == 1) s.main else s.interaction;
                if (s.log_size != log or data.len != T.dwordWidthsFor(setup.materials.geometry)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                append(out, &at, data, log);
            } else if (self.ls_dword[k] != null) return error.UnexpectedCombinedServiceSource;
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
    pub fn mainTraceColumns(self: *const Sources, a: std.mem.Allocator, setup: *const CpuSetup) ![]@import("stwo_prover_api").device_pcs.TraceColumn {
        if (self.device_main) |owner| {
            const logs = try setup.logs(a, 1);
            defer a.free(logs);
            try owner.validate(owner.scope, logs);
            return a.dupe(@import("stwo_prover_api").device_pcs.TraceColumn, owner.columns);
        }
        const tree = 1;
        const old = try self.core.mainTraceColumns(a);
        defer a.free(old);
        const out = try a.alloc(@import("stwo_prover_api").device_pcs.TraceColumn, setup.columnCount(tree));
        errdefer a.free(out);
        @memcpy(out[0..old.len], old);
        var at = old.len;
        for (0..T.FAMILIES) |k| {
            const f: T.Family = @enumFromInt(k);
            if (setup.bridges.at(f)) |log| {
                const data = self.matrix(f, tree) orelse return error.MissingCombinedServiceSource;
                if (data.len != T.widths(f)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                appendTrace(out, &at, data, log);
            } else if (self.matrix(f, tree) != null) return error.UnexpectedCombinedServiceSource;
        }
        for (T.bulk_kinds, 0..) |kind, k| {
            if (setup.bridges.bulk.at(kind)) |log| {
                const s = self.bulk[k] orelse return error.MissingCombinedServiceSource;
                const data = if (tree == 1) s.main else s.interaction;
                if (s.kind != kind or data.len != T.bulkWidths(kind)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                appendTrace(out, &at, data, log);
            } else if (self.bulk[k] != null) return error.UnexpectedCombinedServiceSource;
        }
        for (T.sponge_kinds, 0..) |kind, k| {
            if (setup.bridges.sponge.at(kind)) |log| {
                const s = self.sponge[k] orelse return error.MissingCombinedServiceSource;
                const data = if (tree == 1) s.main else s.interaction;
                if (s.kind != kind or data.len != T.spongeWidths(kind)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                appendTrace(out, &at, data, log);
            } else if (self.sponge[k] != null) return error.UnexpectedCombinedServiceSource;
        }
        for (0..T.DWORD_INSTANCES) |k| {
            if (setup.bridges.dwordLog(k)) |log| {
                const s = self.ls_dword[k] orelse return error.MissingCombinedServiceSource;
                const data = if (tree == 1) s.main else s.interaction;
                if (s.log_size != log or data.len != T.dwordWidthsFor(setup.materials.geometry)[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
                appendTrace(out, &at, data, log);
            } else if (self.ls_dword[k] != null) return error.UnexpectedCombinedServiceSource;
        }
        if (setup.bridges.zbb) |log| {
            const s = self.zbb orelse return error.MissingCombinedServiceSource;
            const data = switch (tree) {
                1 => s.main,
                2 => s.interaction,
                else => return error.InvalidCombinedServiceSource,
            };
            if (s.log_size != log or data.len != T.zbbWidths()[tree] * (@as(usize, 1) << @intCast(log))) return error.InvalidCombinedServiceSource;
            appendTrace(out, &at, data, log);
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
        if (self.core.materials.geometry.ls_dword_fused_pairs) {
            // Fused-pair LS-D64: the two U8 queries per row are one AND-relation
            // byte pair, merged into the AND table's pair column.
            const zero8: [256]u64 = @splat(0);
            for (&self.ls_dword) |*b| if (b.*) |*s| {
                try merge(&self.core, s.counts16, &zero8);
                const pairs = try self.core.allocator.alloc(u64, 65536);
                defer self.core.allocator.free(pairs);
                @memset(pairs, 0);
                try s.addBytePairCounts(pairs);
                try mergeAndPairTable(&self.core.and_table, pairs);
            };
        } else for (&self.ls_dword) |*b| if (b.*) |*s| try merge(&self.core, s.counts16, s.counts8);
        // Zbb byte-AND lookups (8 per physical row, padding included) join the
        // core AND table exactly like the BINARY chip's own requests.
        if (self.zbb) |*s| try mergeAnd(&self.core, s.and_counts);
    }
    pub fn releaseMain(self: *Sources) !void {
        if (self.device_main) |*owner| {
            owner.release();
            self.device_main = null;
            // CPU37 may retain its own disjoint formatter lease. Other roles
            // are headers only: no dummy host matrices exist to release.
            self.core.cpu.releaseMain();
            return;
        }
        try self.core.releaseMain();
        if (self.keccak) |*s| s.releaseMain();
        if (self.add) |*s| s.releaseMain();
        if (self.double) |*s| s.releaseMain();
        if (self.sha256) |*s| s.releaseMain();
        if (self.arith256_mod) |*s| s.releaseMain();
        for (&self.curves) |*c| if (c.*) |*s| s.releaseMain();
        for (&self.bulk) |*b| if (b.*) |*s| s.releaseMain();
        for (&self.sponge) |*b| if (b.*) |*s| s.releaseMain();
        for (&self.ls_dword) |*b| if (b.*) |*s| s.releaseMain();
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
        for (0..T.DWORD_INSTANCES) |k| count += @intFromBool(setup.bridges.dwordLog(k) != null);
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
        for (&self.ls_dword) |*b| if (b.*) |*s| {
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
        for (0..T.bulk_kinds.len) |k| {
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
        for (&self.ls_dword) |*b| if (b.*) |*s| {
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
const truth_roster = @import("truth_roster.zig");
pub const Truth = truth_roster.Truth;
pub const TruthSource = truth_roster.TruthSource;
const spanEnd = truth_roster.spanEnd;
const overlap = truth_roster.overlap;
const appendTrace = truth_roster.appendTrace;

/// Keccak-sponge byte-AND lookups join the CPU proof's canonical AND table:
/// the table's AND multiplicities grow by the sponge counts. Under the U8-pair
/// CPU layout (Geometry.cpu_u8_pairs) the table carries a second column, the
/// CPU byte-pair multiplicity, in the SAME LogUp relation: service AND
/// queries still land only in the first (AND) column, the pair column is kept
/// untouched, and the joint AND + pair mass stays below p (the bound
/// Request.initWithPairs admits). The table must be in its main phase.
fn mergeAnd(base: *Core.Source, extra: []const u64) !void {
    try mergeAndTable(&base.and_table, base.materials.geometry.cpu_u8_pairs, extra);
}
pub fn mergeAndTable(table: *A.providers.tables.Request, pairs: bool, extra: []const u64) !void {
    const size: usize = 65536;
    if (table.kind != .byte_and or table.interaction.len != 0 or table.pair_dictionary.len != 0 or extra.len != size) return error.InvalidCombinedRangePhase;
    if (table.pairs != pairs or table.main.len != (if (pairs) 2 * size else size)) return error.InvalidCombinedRangePhase;
    var mass: u64 = 0;
    if (pairs) for (table.main[size..]) |m| {
        mass = try std.math.add(u64, mass, m.v);
    };
    for (extra, 0..) |x, row| {
        const p = A.witness.physical(row, 16);
        const total = try std.math.add(u64, table.main[p].v, x);
        mass = try std.math.add(u64, mass, total);
        if (mass >= core.fields.m31.Modulus) return error.CombinedRangeMassExceeded;
        table.main[p] = M.fromCanonical(@intCast(total));
    }
}
/// Adds service byte-pair multiplicities to the pair column of the
/// pair-capable AND table (main phase), keeping the joint AND + pair mass
/// below p exactly as Request.initWithPairs admits.
pub fn mergeAndPairTable(table: *A.providers.tables.Request, extra: []const u64) !void {
    const size: usize = 65536;
    if (table.kind != .byte_and or table.interaction.len != 0 or table.pair_dictionary.len != 0 or extra.len != size or !table.pairs or table.main.len != 2 * size) return error.InvalidCombinedRangePhase;
    var mass: u64 = 0;
    for (table.main[0..size]) |m| mass = try std.math.add(u64, mass, m.v);
    for (extra, 0..) |x, row| {
        const p = size + A.witness.physical(row, 16);
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
