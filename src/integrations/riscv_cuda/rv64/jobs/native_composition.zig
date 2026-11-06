//! Enqueue-only NATIVE composition for NativeStage2 (spec §3.5 item 2:
//! "composition (coefficient drawn on device)"). A port of the deployed
//! native configuration of resident_composition.zig Job.run
//! (STWO_RV64_COMPOSITION_ENQUEUE=1, DIRECT=1, DIRECT_EL2=1, no role
//! workspace, no selected columns, no sparse truth role, no outer chunks):
//!
//!   powers alpha^0..alpha^(total-1)         (device, from the DEVICE alpha)
//!   for each role, in order:
//!     staged coefficients (columns that are not degree el-1 / el-2)
//!     auxiliary columns (hc: auxiliary kernel + B2N; last: anchor + B2N)
//!     twiddles + LDE descriptors into the role arena
//!     LDE: direct n2b_columns / n2b_columns_compact runs straight from the
//!          committed coefficient views, addressed n2b for staged runs
//!     role kernel, accumulating into the per-eval-log quotient bucket
//!   finish (bucket fold + interpolation + split) → coefficient chunks (kept)
//!   commit LDE (compact for beta 2) + one Merkle segment → root (device)
//!
//! Same kernels, same arena layout per role, same values: the only
//! differences are custody. Parameters/masks/denominators/twiddles are staged
//! in phase 1 (pure host, class geometry), alpha and its powers never reach
//! the host, nothing joins, and the root is D2D-copied into a slab field.
//! Direct vs staged LDE is an exact-field storage choice (identical
//! evaluations); the job takes the direct path whenever the degree allows,
//! because every source is a device coefficient view here.
//!
//! Role descriptions (`RoleSpec`) are built outside jobs/ from the frontend
//! authorities (rv64/m8_native_composition_roles.zig), because that mapping
//! reads legacy owner-path metadata the sync lint forbids under jobs/.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const api = @import("api.zig");
const C = @import("native_commit.zig");
const Abi = @import("../abi.zig");

const M = core.fields.m31.M31;

pub const RoleKernel = *const @TypeOf(Abi.stwo_rv64_composition_role_on);
pub const Finish = *const @TypeOf(Abi.stwo_rv64_composition_finish_on);
pub const Auxiliary = *const @TypeOf(Abi.stwo_rv64_composition_auxiliary_on);
pub const N2bCompact = *const fn ([*]const u32, usize, [*]const u32, [*]u32, usize, u32, u32, [*]const u32, u32, u32, usize, ?*anyopaque, *u32) callconv(.c) c_int;
pub const Powers = *const fn (*anyopaque, u32, [*]const u32, u32, [*]u32, [*]u32) callconv(.c) c_int;
pub const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;

pub const Symbols = struct {
    role: RoleKernel,
    truth_role: ?RoleKernel,
    finish: Finish,
    auxiliary: Auxiliary,
    n2b_columns: C.N2bColumns,
    n2b_compact: N2bCompact,
    n2b_addressed: C.N2bAddressed,
    b2n: C.B2n,
    tree: C.Tree,
    copy_d2d: C.CopyD2d,
    memset: Memset,
    powers: Powers,
    /// `base`: the frozen base image; `addon`: libstwo-rv64-jobs.so.
    pub fn load(base: *std.DynLib, addon: *std.DynLib) !Symbols {
        return .{
            .role = base.lookup(RoleKernel, "stwo_rv64_composition_role_on") orelse return error.MissingNativeCompositionSymbol,
            .truth_role = base.lookup(RoleKernel, "stwo_rv64_truth_composition_role_on"),
            .finish = base.lookup(Finish, "stwo_rv64_composition_finish_on") orelse return error.MissingNativeCompositionSymbol,
            .auxiliary = base.lookup(Auxiliary, "stwo_rv64_composition_auxiliary_on") orelse return error.MissingNativeCompositionSymbol,
            .n2b_columns = base.lookup(C.N2bColumns, "stwo_lde_n2b_columns_on") orelse return error.MissingNativeCompositionSymbol,
            .n2b_compact = base.lookup(N2bCompact, "stwo_lde_n2b_columns_compact_on") orelse return error.MissingNativeCompositionSymbol,
            .n2b_addressed = base.lookup(C.N2bAddressed, "stwo_lde_n2b_addressed_on") orelse return error.MissingNativeCompositionSymbol,
            .b2n = base.lookup(C.B2n, "stwo_ntt_b2n_columns_compact_on") orelse return error.MissingNativeCompositionSymbol,
            .tree = base.lookup(C.Tree, "stwo_rv64_trace_tree_on") orelse return error.MissingNativeCompositionSymbol,
            .copy_d2d = base.lookup(C.CopyD2d, "stwo_exec_context_memcpy_d2d_async") orelse return error.MissingNativeCompositionSymbol,
            .memset = base.lookup(Memset, "stwo_exec_context_memset_async") orelse return error.MissingNativeCompositionSymbol,
            .powers = addon.lookup(Powers, "stwo_rv64_jobs_native_powers_v1_on") orelse return error.MissingNativeCompositionSymbol,
        };
    }
};

pub const Kernel = enum { cpu, truth };
pub const Aux = enum { none, hc, last };

/// One composition role as the frontend authority binds it
/// (resident_composition.zig RuntimeRole, host values only).
pub const RoleSpec = struct {
    id: u32,
    kernel: Kernel = .cpu,
    trace_log: u32,
    eval_log: u32,
    /// Source widths per tree (FIXED, MAIN, INTER), without auxiliary columns.
    widths: [3]u32,
    offsets: [3]u32,
    fixed_indices: ?[]const u32 = null,
    aux: Aux = .none,
    /// aux == .hc: 2 * trace_log * 8 words (the legacy `hc[0 .. 16 * rl]`).
    hc: []const u32 = &.{},
    /// 8 words per parameter (canonical OM31 coordinates).
    parameters: []const u32,
    /// Program input column indices (geometry masks = column * n).
    mask_columns: []const u32,
    constraints: u32,
    /// Parameters that are global-interaction claims (ram/kio/wire): their
    /// staged words are overwritten on the device, before the role kernel,
    /// from the job's DEVICE claims buffer (8 words per claim). That buffer is
    /// the one Stage2 mixes, in the native_claims.zig Layout (the producer,
    /// native_global, writes each slot's claims at the same place).
    claim_slots: []const ClaimSlot = &.{},
};

/// `parameter`: the role's parameter index; `claim`: the claim index in the
/// Stage2 claims buffer (native_claims.Slot.index[relation]), not an index
/// private to one role.
pub const ClaimSlot = struct { parameter: u32, claim: u32 };

pub const Spec = struct {
    roles: []const RoleSpec,
    log: u32,
    split: u32,
    total: u32,
    beta: u32,
    /// Coefficient log of every ORIGINAL column of FIXED, MAIN, INTER.
    tree_logs: [3][]const u32,
};

const Source = struct { tree: u8, index: u32, log: u32 };

/// Per-role arena geometry, exactly as resident_composition.zig lays it out:
/// [staging | evaluations (columns * n) | twiddles(el) | descriptors (6/col)].
const RolePlan = struct {
    spec: RoleSpec,
    sources: []Source,
    columns: u32,
    aux_count: u32,
    direct: []bool,
    staging_offsets: []usize,
    staging_words: usize,
    tw_base: usize,
    desc_base: usize,
    arena_words: usize,
    /// Offsets (words) into the staged table.
    t_logs: usize,
    t_params: usize,
    t_masks: usize,
    t_denoms: usize,
    t_hc: usize,
    t_desc: usize,
    denominator_words: usize,
};

pub const Plan = struct {
    a: std.mem.Allocator,
    log: u32,
    split: u32,
    total: u32,
    beta: u32,
    roles: []RolePlan,
    /// Distinct twiddle logs held in the class twiddle region (log → offset).
    /// The host trees are built only by `stage` when the region is fresh.
    tw_offsets: [29]?usize = @splat(null),
    tw_words: usize = 0,
    table: []u32,
    /// Offsets of the global table entries.
    t_one: usize,
    t_commit_desc: usize,
    key: [32]u8,
    max_role_arena: usize,
    buckets: [29]bool = @splat(false),
    /// Original-order offsets of the output coefficient chunks (for the PCS).
    offsets: []usize,
    // Staged in phase 1.
    tw_device: ?api.DeviceBuffer = null,
    table_device: ?api.DeviceBuffer = null,
    /// `detach`: class slices (masks, claim slots, FIXED indices) copied into
    /// plan-owned storage, so a cached plan outlives the Roles it was built from.
    owned_words: std.ArrayListUnmanaged([]u32) = .empty,
    owned_slots: std.ArrayListUnmanaged([]ClaimSlot) = .empty,
    detached: bool = false,

    pub fn chunkLog(self: *const Plan) u32 {
        return self.log - self.split;
    }
    pub fn outputColumns(self: *const Plan) u32 {
        return @as(u32, 8) << @intCast(self.split);
    }
    pub fn commitLog(self: *const Plan) u32 {
        return self.chunkLog() + self.beta;
    }
    pub fn coefficientWords(self: *const Plan) usize {
        return @as(usize, 8) << @intCast(self.log);
    }
    pub fn treeWords(self: *const Plan) usize {
        return ((@as(usize, 2) << @intCast(self.commitLog())) - 1) * 8;
    }
    fn commitEvalWords(self: *const Plan) usize {
        return @as(usize, self.outputColumns()) << @intCast(self.commitLog());
    }
    fn scratchLayout(self: *const Plan) struct { tw: usize, desc: usize, words: usize } {
        // Separate coefficients (beta 1 or 2): evaluations at 0, then the
        // commit twiddles, then one log per output column.
        const tw = self.commitEvalWords();
        const desc = std.mem.alignForward(usize, tw + twLen(self.commitLog()), 2);
        return .{ .tw = tw, .desc = desc, .words = desc + self.outputColumns() };
    }

    pub fn init(a: std.mem.Allocator, spec: Spec) !Plan {
        if (spec.roles.len == 0 or spec.log < 5 or spec.log > 28 or spec.split < 1 or spec.split > 2 or spec.beta < 1 or spec.beta > 2) return error.UnsupportedNativeCompositionGeometry;
        var self: Plan = .{ .a = a, .log = spec.log, .split = spec.split, .total = spec.total, .beta = spec.beta, .roles = &.{}, .table = &.{}, .t_one = 0, .t_commit_desc = 0, .key = undefined, .max_role_arena = 0, .offsets = &.{} };
        errdefer self.freeShared();
        if (self.commitLog() > 28) return error.UnsupportedNativeCompositionGeometry;
        var key = std.crypto.hash.sha2.Sha256.init(.{});
        key.update("rv64-m8-native-composition/v1");
        key.update(std.mem.asBytes(&[_]u32{ spec.log, spec.split, spec.total, spec.beta }));
        self.roles = try a.alloc(RolePlan, spec.roles.len);
        var made: usize = 0;
        errdefer {
            for (self.roles[0..made]) |*r| freeRole(a, r);
            a.free(self.roles);
            self.roles = &.{};
        }
        var needed: [29]bool = @splat(false);
        var table_words: usize = 0;
        var constraints: u64 = 0;
        for (spec.roles, self.roles) |rs, *r| {
            const rl = rs.trace_log;
            const el = rs.eval_log;
            if (rl < 4 or el < rl + 1 or el > rl + 2 or el > spec.log or rs.constraints == 0 or rs.parameters.len % 8 != 0) return error.InvalidNativeCompositionRole;
            if (rs.aux == .hc and rs.hc.len != 16 * rl) return error.InvalidNativeCompositionRole;
            for (rs.claim_slots) |slot| if (slot.parameter >= rs.parameters.len / 8) return error.InvalidNativeCompositionRole;
            constraints += rs.constraints;
            const n = @as(usize, 1) << @intCast(el);
            const aux: u32 = switch (rs.aux) {
                .none => 0,
                .hc => 10,
                .last => 1,
            };
            const source_count = rs.widths[0] + rs.widths[1] + rs.widths[2];
            const columns = source_count + aux;
            const sources = try a.alloc(Source, source_count);
            errdefer a.free(sources);
            var at: usize = 0;
            for (0..3) |tree| for (0..rs.widths[tree]) |c| {
                const index: u32 = if (tree == 0 and rs.fixed_indices != null) rs.fixed_indices.?[c] else rs.offsets[tree] + @as(u32, @intCast(c));
                if (index >= spec.tree_logs[tree].len) return error.InvalidNativeCompositionRole;
                const log = spec.tree_logs[tree][index];
                if (log > el) return error.InvalidNativeCompositionRole;
                sources[at] = .{ .tree = @intCast(tree), .index = index, .log = log };
                at += 1;
            };
            const direct = try a.alloc(bool, columns);
            errdefer a.free(direct);
            const staging_offsets = try a.alloc(usize, columns);
            errdefer a.free(staging_offsets);
            var staging: usize = 0;
            for (direct, staging_offsets, 0..) |*d, *o, i| {
                o.* = staging;
                d.* = false;
                if (i < source_count) {
                    const log = sources[i].log;
                    if (log + 1 == el or (el >= 3 and log + 2 == el)) {
                        d.* = true;
                        continue;
                    }
                    staging += @as(usize, 1) << @intCast(log);
                } else staging += @as(usize, 1) << @intCast(rl);
            }
            const tw_len = twLen(el);
            needed[el] = true;
            if (aux != 0) needed[rl] = true;
            const tw_base = staging + columns * n;
            const desc_base = std.mem.alignForward(usize, tw_base + tw_len, 2);
            r.* = .{ .spec = rs, .sources = sources, .columns = columns, .aux_count = aux, .direct = direct, .staging_offsets = staging_offsets, .staging_words = staging, .tw_base = tw_base, .desc_base = desc_base, .arena_words = desc_base + columns * 6, .t_logs = 0, .t_params = 0, .t_masks = 0, .t_denoms = 0, .t_hc = 0, .t_desc = 0, .denominator_words = @as(usize, 1) << @intCast(el - rl) };
            r.t_logs = table_words;
            table_words += columns;
            r.t_params = table_words;
            table_words += @max(rs.parameters.len, 1);
            // u64 mask offsets: 8-byte aligned inside the 256-byte aligned table.
            table_words = std.mem.alignForward(usize, table_words, 2);
            r.t_masks = table_words;
            table_words += @max(2 * rs.mask_columns.len, 1);
            r.t_denoms = table_words;
            table_words += r.denominator_words;
            r.t_hc = table_words;
            table_words += rs.hc.len;
            r.t_desc = table_words;
            table_words += 6 * columns;
            table_words = std.mem.alignForward(usize, table_words, 2);
            self.max_role_arena = @max(self.max_role_arena, r.arena_words);
            self.buckets[el] = true;
            key.update(std.mem.asBytes(&[_]u32{ rs.id, @intFromEnum(rs.kernel), rl, el, rs.widths[0], rs.widths[1], rs.widths[2], @intFromEnum(rs.aux), rs.constraints, @intCast(rs.mask_columns.len), @intCast(rs.parameters.len) }));
            for (sources) |s| key.update(std.mem.asBytes(&s.log));
            made += 1;
        }
        if (constraints != spec.total) return error.WrongNativeCompositionConstraintCount;
        needed[self.commitLog()] = true;
        needed[self.log] = true;
        // Class twiddle region: twiddles ++ itwiddles of every needed log.
        for (needed, 0..) |want, log| if (want) {
            self.tw_offsets[log] = self.tw_words;
            self.tw_words += 2 * twLen(@intCast(log));
            key.update(std.mem.asBytes(&@as(u32, @intCast(log))));
        };
        self.t_one = table_words;
        table_words += 2;
        self.t_commit_desc = table_words;
        table_words += self.outputColumns();
        self.table = try a.alloc(u32, table_words);
        @memset(self.table, 0);
        try self.fillTable();
        self.key = key.finalResult();
        self.offsets = try a.alloc(usize, self.outputColumns());
        for (self.offsets, 0..) |*o, i| o.* = i << @intCast(self.chunkLog());
        return self;
    }

    /// Length of the forward (and of the inverse) twiddles of
    /// precomputeM31(CanonicCoset(log).circleDomain().half_coset): the half
    /// coset's size. `stage` checks it against the trees it builds.
    fn twLen(log: u32) usize {
        return @as(usize, 1) << @intCast(log - 1);
    }

    fn fillTable(self: *Plan) !void {
        const t = self.table;
        for (self.roles) |*r| {
            const rs = r.spec;
            const el = rs.eval_log;
            const n = @as(usize, 1) << @intCast(el);
            // Direct LDE source logs (el-1 or el-2), one per column.
            for (0..r.columns) |i| t[r.t_logs + i] = if (i < r.sources.len and r.direct[i] and r.sources[i].log + 2 == el) el - 2 else el - 1;
            @memcpy(t[r.t_params..][0..rs.parameters.len], rs.parameters);
            for (rs.mask_columns, 0..) |column, i| {
                const offset = @as(u64, column) * n;
                t[r.t_masks + 2 * i] = @truncate(offset);
                t[r.t_masks + 2 * i + 1] = @truncate(offset >> 32);
            }
            const denominators = try A.geometry.denominatorInverses(self.a, rs.trace_log, el);
            defer self.a.free(denominators);
            if (denominators.len != r.denominator_words) return error.InvalidNativeCompositionRole;
            for (denominators, 0..) |d, i| t[r.t_denoms + i] = d.v;
            @memcpy(t[r.t_hc..][0..rs.hc.len], rs.hc);
            // Addressed LDE descriptors: {staging offset, absolute eval offset, degree}.
            const eval_base = r.staging_words;
            for (0..r.columns) |i| {
                const degree: u32 = if (i < r.sources.len) r.sources[i].log else rs.trace_log;
                const src = r.staging_offsets[i];
                const dst = eval_base + i * n;
                t[r.t_desc + 6 * i ..][0..6].* = .{ @truncate(src), @truncate(@as(u64, src) >> 32), @truncate(dst), @truncate(@as(u64, dst) >> 32), degree, 0 };
            }
        }
        t[self.t_one] = 1;
        @memset(t[self.t_commit_desc..][0..self.outputColumns()], self.chunkLog());
    }

    fn freeRole(a: std.mem.Allocator, r: *RolePlan) void {
        a.free(r.sources);
        a.free(r.direct);
        a.free(r.staging_offsets);
    }

    fn freeShared(self: *Plan) void {
        if (self.table.len != 0) self.a.free(self.table);
        if (self.offsets.len != 0) self.a.free(self.offsets);
        self.table = &.{};
        self.offsets = &.{};
    }
    pub fn deinit(self: *Plan) void {
        for (self.roles) |*r| freeRole(self.a, r);
        if (self.roles.len != 0) self.a.free(self.roles);
        self.freeShared();
        for (self.owned_words.items) |w| self.a.free(w);
        self.owned_words.deinit(self.a);
        for (self.owned_slots.items) |w| self.a.free(w);
        self.owned_slots.deinit(self.a);
        self.* = undefined;
    }

    /// Class-cache form (M8 GPU-native framing cache, rv64-m8-gpu-native.md
    /// §3.1, H9): make the plan independent of the RoleSpec storage it was
    /// built from. Class slices are copied; each role's `parameters` and `hc`
    /// become views of the plan's own staged table (the only per-request
    /// words, rewritten by `rebind`).
    pub fn detach(self: *Plan) !void {
        if (self.detached) return;
        for (self.roles) |*r| {
            const rs = &r.spec;
            const masks = try self.a.dupe(u32, rs.mask_columns);
            errdefer self.a.free(masks);
            try self.owned_words.append(self.a, masks);
            rs.mask_columns = masks;
            if (rs.fixed_indices) |fi| {
                const copy = try self.a.dupe(u32, fi);
                errdefer self.a.free(copy);
                try self.owned_words.append(self.a, copy);
                rs.fixed_indices = copy;
            }
            const slots = try self.a.dupe(ClaimSlot, rs.claim_slots);
            errdefer self.a.free(slots);
            try self.owned_slots.append(self.a, slots);
            rs.claim_slots = slots;
            rs.parameters = self.table[r.t_params..][0..rs.parameters.len];
            rs.hc = self.table[r.t_hc..][0..rs.hc.len];
        }
        self.detached = true;
    }

    /// Per-request parameters of a cached class plan: every staged-table word
    /// other than each role's parameters and hc rows is class geometry
    /// (fillTable), so rewriting those two spans equals a fresh `init` on the
    /// same class (test below). `specs` must describe the same class: any
    /// geometric difference fails closed (the cache key was wrong).
    pub fn rebind(self: *Plan, specs: []const RoleSpec) !void {
        if (!self.detached) return error.NativeCompositionNotDetached;
        if (specs.len != self.roles.len) return error.NativeCompositionClassMismatch;
        for (self.roles, specs) |*r, rs| if (!sameClass(r.spec, rs)) return error.NativeCompositionClassMismatch;
        for (self.roles, specs) |*r, rs| {
            @memcpy(self.table[r.t_params..][0..rs.parameters.len], rs.parameters);
            @memcpy(self.table[r.t_hc..][0..rs.hc.len], rs.hc);
        }
        self.table_device = null;
        self.tw_device = null;
    }

    fn sameClass(x: RoleSpec, y: RoleSpec) bool {
        if (x.id != y.id or x.kernel != y.kernel or x.trace_log != y.trace_log or x.eval_log != y.eval_log or x.aux != y.aux or x.constraints != y.constraints) return false;
        if (!std.mem.eql(u32, &x.widths, &y.widths) or !std.mem.eql(u32, &x.offsets, &y.offsets)) return false;
        if (x.parameters.len != y.parameters.len or x.hc.len != y.hc.len) return false;
        if (!std.mem.eql(u32, x.mask_columns, y.mask_columns)) return false;
        if ((x.fixed_indices == null) != (y.fixed_indices == null)) return false;
        if (x.fixed_indices) |fi| if (!std.mem.eql(u32, fi, y.fixed_indices.?)) return false;
        if (x.claim_slots.len != y.claim_slots.len) return false;
        for (x.claim_slots, y.claim_slots) |p, q| if (p.parameter != q.parameter or p.claim != q.claim) return false;
        return true;
    }

    pub fn classKey(self: *const Plan) [32]u8 {
        return self.key;
    }
    fn bucketWords(self: *const Plan) usize {
        var words: usize = 0;
        for (self.buckets, 0..) |used, log| if (used) {
            words += std.mem.alignForward(usize, @as(usize, 8) << @intCast(log), 64);
        };
        return words;
    }
    /// Phase-1 arena words (the staged table).
    pub fn stagedWords(self: *const Plan) usize {
        return std.mem.alignForward(usize, self.table.len, 64);
    }
    /// Class-persistent words (the twiddle region).
    pub fn persistentWords(self: *const Plan) usize {
        return self.tw_words;
    }
    /// Pinned words `stage` may use (table + a fresh twiddle region).
    pub fn pinnedWords(self: *const Plan) usize {
        return self.table.len + self.tw_words + 64;
    }
    /// Enqueue-time peak (excluding the staged table and the twiddle region):
    /// kept output + powers + buckets + max(role arena, finish/commit scratch).
    pub fn enqueueWords(self: *const Plan) usize {
        const g = 64;
        const fixed = std.mem.alignForward(usize, self.coefficientWords(), g) + std.mem.alignForward(usize, 8 * @as(usize, self.total), g) + self.bucketWords() + g;
        const tail = std.mem.alignForward(usize, self.coefficientWords(), g) + std.mem.alignForward(usize, self.scratchLayout().words, g) + std.mem.alignForward(usize, self.treeWords(), g);
        return fixed + @max(std.mem.alignForward(usize, self.max_role_arena, g), tail) + 4 * g;
    }

    /// Phase 1: the class twiddle region (persistent, filled by the first job
    /// of the class: only then are the host trees built) and the role table
    /// (parameters, masks, denominators, hc, LDE logs and descriptors).
    pub fn stage(self: *Plan, s: *api.Stager) !void {
        const region = try s.persistent(self.key, self.tw_words);
        if (region.fresh) {
            const pinned = try s.pinned(self.tw_words);
            for (self.tw_offsets, 0..) |maybe, log| if (maybe) |o| {
                var t = try engine.poly.twiddles.precomputeM31(self.a, core.poly.circle.canonic.CanonicCoset.new(@intCast(log)).circleDomain().half_coset);
                defer engine.poly.twiddles.deinitM31(self.a, &t);
                const n = twLen(@intCast(log));
                if (t.twiddles.len != n or t.itwiddles.len != n) return error.InvalidNativeCompositionTwiddles;
                @memcpy(pinned[o..][0..n], mWords(t.twiddles));
                @memcpy(pinned[o + n ..][0..n], mWords(t.itwiddles));
            };
            try s.upload(region.buffer, pinned);
        }
        self.tw_device = region.buffer;
        const table = try s.alloc(self.table.len);
        const pinned = try s.pinned(self.table.len);
        @memcpy(pinned, self.table);
        try s.upload(table, pinned);
        self.table_device = table;
    }

    fn twOf(self: *const Plan, log: u32) struct { fwd: [*]const u32, fwd_len: usize, inv: [*]const u32, inv_len: usize } {
        const base = self.tw_device.?.ptr + self.tw_offsets[log].?;
        const n = twLen(log);
        return .{ .fwd = base, .fwd_len = n, .inv = base + n, .inv_len = n };
    }

    /// Phase 2. `trees`: FIXED, MAIN, INTER coefficient views (device, job
    /// exec context), indexed by original column. `alpha`: the device-drawn
    /// composition coefficient (8 words). `root_out`: 8-word slab field (not
    /// mixed). `status`: 1 device word (cleared here; bit 0 = noncanonical
    /// alpha, then no powers are written): the job's finish must reject a
    /// nonzero status (native_stage2.accept). Returns the kept coefficient
    /// chunks (free them after the PCS).
    pub fn enqueue(self: *const Plan, sym: Symbols, e: anytype, trees: [3]Columns, alpha: [*]const u32, root_out: api.DeviceBuffer, status: [*]u32) !C.Committed {
        return self.enqueueWithClaims(sym, e, trees, alpha, null, root_out, status);
    }
    /// As `enqueue`; `claims` (device, 8 words per claim) patches every role's
    /// claim parameters first. Roles with claim slots require it.
    pub fn enqueueWithClaims(self: *const Plan, sym: Symbols, e: anytype, trees: [3]Columns, alpha: [*]const u32, claims: ?api.DeviceBuffer, root_out: api.DeviceBuffer, status: [*]u32) !C.Committed {
        const table = (self.table_device orelse return error.NativeCompositionNotStaged).ptr;
        if (self.tw_device == null) return error.NativeCompositionNotStaged;
        if (root_out.words < 8) return error.InvalidNativeCompositionOutput;
        const ctx = e.ctx();
        const stream = e.stream();
        var launches: u32 = 0;
        for (self.roles) |*r| for (r.spec.claim_slots) |slot| {
            const source = claims orelse return error.NativeCompositionClaimsRequired;
            if ((@as(usize, slot.claim) + 1) * 8 > source.words) return error.NativeCompositionClaimOutOfRange;
            try check(sym.copy_d2d(ctx, table + r.t_params + 8 * @as(usize, slot.parameter), source.ptr + 8 * @as(usize, slot.claim), 32));
        };
        const output = try e.alloc(self.coefficientWords());
        const powers = try e.alloc(8 * @as(usize, self.total));
        try check(sym.memset(ctx, status, 0, 4));
        try check(sym.powers(ctx, 0, alpha, self.total, powers.ptr, status));
        var buckets: [29]?api.DeviceBuffer = @splat(null);
        for (self.buckets, 0..) |used, log| if (used) {
            const words = @as(usize, 8) << @intCast(log);
            const b = try e.alloc(words);
            try check(sym.memset(ctx, b.ptr, 0, words * 4));
            buckets[log] = b;
        };
        var next: usize = self.total;
        for (self.roles) |*r| {
            const rs = r.spec;
            const rl = rs.trace_log;
            const el = rs.eval_log;
            const n = @as(usize, 1) << @intCast(el);
            const arena = try e.alloc(r.arena_words);
            const base = arena.ptr;
            const eval_base = r.staging_words;
            // Staged coefficients (non-direct sources), arena-local copies.
            for (r.sources, 0..) |s, i| if (!r.direct[i]) {
                const src = try trees[s.tree].at(s.index, s.log);
                try check(sym.copy_d2d(ctx, base + r.staging_offsets[i], src, (@as(usize, 1) << @intCast(s.log)) * 4));
            };
            if (r.aux_count != 0) {
                const at = base + r.staging_offsets[r.sources.len];
                const rows = @as(usize, 1) << @intCast(rl);
                switch (rs.aux) {
                    .hc => try check(sym.auxiliary(ctx, 0, table + r.t_hc, at, rl, &launches)),
                    .last => {
                        // Native truth last anchor: logical last, physical row 1.
                        try check(sym.memset(ctx, at, 0, rows * 4));
                        try check(sym.copy_d2d(ctx, at + 1, table + self.t_one, 4));
                    },
                    .none => unreachable,
                }
                const it = self.twOf(rl);
                try check(sym.b2n(at, rows, at, rows, rl, r.aux_count, it.inv, @intCast(it.inv_len), @intCast(rows / 2), stream, &launches));
            }
            const t = self.twOf(el);
            try check(sym.copy_d2d(ctx, base + r.tw_base, t.fwd, t.fwd_len * 4));
            try check(sym.copy_d2d(ctx, base + r.desc_base, table + r.t_desc, 6 * @as(usize, r.columns) * 4));
            const logs = table + r.t_logs;
            var column: usize = 0;
            while (column < r.columns) {
                var end = column + 1;
                if (r.direct[column]) {
                    const s = r.sources[column];
                    const stride = @as(usize, 1) << @intCast(s.log);
                    const first = try trees[s.tree].at(s.index, s.log);
                    // Merge columns whose views are adjacent with one stride.
                    while (end < r.columns and r.direct[end] and r.sources[end].log == s.log) : (end += 1) {
                        const following = try trees[r.sources[end].tree].at(r.sources[end].index, s.log);
                        if (following != first + (end - column) * stride) break;
                    }
                    const dst = base + eval_base + column * n;
                    const twp = base + r.tw_base + t.fwd_len - n / 2;
                    if (stride == n / 2) {
                        try check(sym.n2b_columns(first, n / 2, logs + column, dst, n, el, @intCast(end - column), twp, @intCast(n / 2), @intCast(n / 2), stream, &launches));
                    } else {
                        try check(sym.n2b_compact(first, stride, logs + column, dst, n, el, @intCast(end - column), twp, @intCast(n / 2), @intCast(n / 2), stride, stream, &launches));
                    }
                } else {
                    while (end < r.columns and !r.direct[end]) : (end += 1) {}
                    try check(sym.n2b_addressed(base, r.arena_words, base + r.desc_base + 6 * column, @intCast(end - column), eval_base + column * n, el, base + r.tw_base, @intCast(t.fwd_len), @intCast(n / 2), stream, 1, &launches));
                }
                column = end;
            }
            if (rs.constraints > next) return error.NotEnoughCoefficients;
            next -= rs.constraints;
            const w = [3]usize{ rs.widths[0], rs.widths[1], rs.widths[2] + r.aux_count };
            const packet = Abi.CompositionRole{
                .role = rs.id,
                .trace_log = rl,
                .eval_log = el,
                .first_row = 0,
                .row_count = @intCast(n),
                .trees = .{ base + eval_base, base + eval_base + w[0] * n, base + eval_base + (w[0] + w[1]) * n },
                .tree_words = .{ @max(1, w[0] * n), @max(1, w[1] * n), @max(1, w[2] * n) },
                .column_offsets = @ptrCast(@alignCast(table + r.t_masks)),
                .mask_count = rs.mask_columns.len,
                .parameters = table + r.t_params,
                .parameter_count = rs.parameters.len / 8,
                .powers = powers.ptr + 8 * next,
                .constraint_count = rs.constraints,
                .denominator_inverses = table + r.t_denoms,
                .output = buckets[el].?.ptr,
            };
            const kernel = switch (rs.kernel) {
                .cpu => sym.role,
                .truth => sym.truth_role orelse return error.MissingNativeCompositionSymbol,
            };
            try check(kernel(ctx, 0, &packet, &launches));
            e.free(arena);
        }
        if (next != 0) return error.UnusedCompositionCoefficients;
        // Finish: fold buckets (ascending log), interpolate, split.
        var list: [29]Abi.CompositionBucket = undefined;
        var listed: u32 = 0;
        for (buckets, 0..) |bucket, log| if (bucket) |b| {
            list[listed] = .{ .words = b.ptr, .log = @intCast(log) };
            listed += 1;
        };
        const accumulator = try e.alloc(self.coefficientWords());
        const layout = self.scratchLayout();
        const scratch = try e.alloc(layout.words);
        const inv = self.twOf(self.log);
        try check(sym.finish(ctx, 0, &list, listed, accumulator.ptr, output.ptr, self.log, self.split, inv.inv, @intCast(inv.inv_len), &launches));
        const ct = self.twOf(self.commitLog());
        try check(sym.copy_d2d(ctx, scratch.ptr + layout.tw, ct.fwd, ct.fwd_len * 4));
        try check(sym.copy_d2d(ctx, scratch.ptr + layout.desc, table + self.t_commit_desc, @as(usize, self.outputColumns()) * 4));
        const commit_log = self.commitLog();
        const rows = @as(usize, 1) << @intCast(commit_log);
        const source_words = @as(usize, 1) << @intCast(self.chunkLog());
        if (self.beta == 2) {
            try check(sym.n2b_compact(output.ptr, source_words, scratch.ptr + layout.desc, scratch.ptr, rows, commit_log, self.outputColumns(), scratch.ptr + layout.tw, @intCast(ct.fwd_len), @intCast(rows / 2), source_words, stream, &launches));
        } else {
            try check(sym.n2b_columns(output.ptr, source_words, scratch.ptr + layout.desc, scratch.ptr, rows, commit_log, self.outputColumns(), scratch.ptr + layout.tw, @intCast(ct.fwd_len), @intCast(rows / 2), stream, &launches));
        }
        const tree = try e.alloc(self.treeWords());
        const segment = C.MixedSegment{ .columns = scratch.ptr, .stride_words = rows, .capacity_words = self.commitEvalWords(), .source_size = @intCast(rows) };
        try check(sym.tree(ctx, 0, @ptrCast(&segment), 1, commit_log, tree.ptr, tree.words));
        try check(sym.copy_d2d(ctx, root_out.ptr, tree.ptr + self.treeWords() - 8, 32));
        e.free(tree);
        e.free(scratch);
        e.free(accumulator);
        var i: usize = buckets.len;
        while (i > 0) {
            i -= 1;
            if (buckets[i]) |b| e.free(b);
        }
        e.free(powers);
        return .{ .coefficients = output, .root = root_out.ptr };
    }
};

/// Device coefficient views of one tree, by original column index:
/// `base + offsets[index]`, `1 << log` words each (C.CommitPlan.offsets).
pub const Columns = struct {
    base: ?[*]const u32 = null,
    offsets: []const usize = &.{},
    /// Alternative: explicit per-column pointers (e.g. mirrored inputs).
    pointers: []const [*]const u32 = &.{},
    pub fn at(self: Columns, index: u32, log: u32) ![*]const u32 {
        _ = log;
        if (self.pointers.len != 0) {
            if (index >= self.pointers.len) return error.NativeCompositionColumnOutOfRange;
            return self.pointers[index];
        }
        if (index >= self.offsets.len) return error.NativeCompositionColumnOutOfRange;
        return (self.base orelse return error.NativeCompositionColumnOutOfRange) + self.offsets[index];
    }
};

fn mWords(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}
fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

test "native composition plan mirrors the legacy role arena layout and power order" {
    const a = std.testing.allocator;
    // Role 0: rl 5, el 6; FIXED col 0 log 5 (direct el-1), MAIN col 0 log 4
    // (direct el-2), MAIN col 1 log 3 (staged), INTER col 0 log 5 (direct).
    const fixed_logs = [_]u32{5};
    const main_logs = [_]u32{ 4, 3 };
    const inter_logs = [_]u32{ 5, 5 };
    const params = [_]u32{0} ** 16;
    const masks = [_]u32{ 0, 1, 3 };
    var hc: [16 * 5]u32 = @splat(0);
    const roles = [_]RoleSpec{
        .{ .id = 3, .trace_log = 5, .eval_log = 6, .widths = .{ 1, 2, 1 }, .offsets = .{ 0, 0, 0 }, .parameters = &params, .mask_columns = &masks, .constraints = 4 },
        .{ .id = 7, .trace_log = 5, .eval_log = 7, .widths = .{ 0, 0, 1 }, .offsets = .{ 0, 0, 1 }, .aux = .hc, .hc = &hc, .parameters = params[0..8], .mask_columns = masks[0..1], .constraints = 2 },
    };
    var plan = try Plan.init(a, .{ .roles = &roles, .log = 8, .split = 1, .total = 6, .beta = 2, .tree_logs = .{ &fixed_logs, &main_logs, &inter_logs } });
    defer plan.deinit();
    const r0 = plan.roles[0];
    try std.testing.expectEqual(@as(u32, 4), r0.columns);
    try std.testing.expectEqualSlices(bool, &.{ true, true, false, true }, r0.direct);
    // Staging holds only the staged MAIN column (8 words); evals 4 * 64.
    try std.testing.expectEqual(@as(usize, 8), r0.staging_words);
    try std.testing.expectEqual(@as(usize, 8 + 4 * 64), r0.tw_base);
    // Direct LDE logs: el-1 for log-5 sources, el-2 for the log-4 source.
    try std.testing.expectEqualSlices(u32, &.{ 5, 4, 5, 5 }, plan.table[r0.t_logs..][0..4]);
    // Mask offsets are column * n (u64 little-endian pairs).
    try std.testing.expectEqual(@as(u32, 3 * 64), plan.table[r0.t_masks + 4]);
    const r1 = plan.roles[1];
    try std.testing.expectEqual(@as(u32, 11), r1.columns);
    try std.testing.expectEqual(@as(usize, 10 * 32), r1.staging_words); // aux columns at rl
    try std.testing.expectEqual(@as(usize, 4), r1.denominator_words);
    try std.testing.expectEqual(@as(u32, 16), plan.outputColumns());
    try std.testing.expectEqual(@as(u32, 9), plan.commitLog());
    try std.testing.expect(plan.tw_offsets[6] != null and plan.tw_offsets[7] != null and plan.tw_offsets[5] != null and plan.tw_offsets[9] != null and plan.tw_offsets[8] != null);
    try std.testing.expectEqual(@as(u32, 7), plan.table[plan.t_commit_desc]);
    try std.testing.expectError(error.WrongNativeCompositionConstraintCount, Plan.init(a, .{ .roles = roles[0..1], .log = 8, .split = 1, .total = 6, .beta = 2, .tree_logs = .{ &fixed_logs, &main_logs, &inter_logs } }));
}

test "framing cache: a detached plan rebound to new parameters equals a fresh plan" {
    const a = std.testing.allocator;
    const fixed_logs = [_]u32{5};
    const main_logs = [_]u32{ 4, 3 };
    const inter_logs = [_]u32{ 5, 5 };
    var params_a: [16]u32 = undefined;
    var params_b: [16]u32 = undefined;
    for (&params_a, &params_b, 0..) |*x, *y, i| {
        x.* = @intCast(100 + i);
        y.* = @intCast(900 + 3 * i);
    }
    var hc_a: [16 * 5]u32 = undefined;
    var hc_b: [16 * 5]u32 = undefined;
    for (&hc_a, &hc_b, 0..) |*x, *y, i| {
        x.* = @intCast(i);
        y.* = @intCast(7 * i + 1);
    }
    const masks = [_]u32{ 0, 1, 3 };
    const slots = [_]ClaimSlot{.{ .parameter = 1, .claim = 0 }};
    const Roles = struct {
        fn of(p: []const u32, hc: []const u32, m: []const u32, s: []const ClaimSlot) [2]RoleSpec {
            return .{
                .{ .id = 3, .trace_log = 5, .eval_log = 6, .widths = .{ 1, 2, 1 }, .offsets = .{ 0, 0, 0 }, .parameters = p, .mask_columns = m, .constraints = 4, .claim_slots = s },
                .{ .id = 7, .trace_log = 5, .eval_log = 7, .widths = .{ 0, 0, 1 }, .offsets = .{ 0, 0, 1 }, .aux = .hc, .hc = hc, .parameters = p[0..8], .mask_columns = m[0..1], .constraints = 2 },
            };
        }
    };
    const spec = Spec{ .roles = &.{}, .log = 8, .split = 1, .total = 6, .beta = 2, .tree_logs = .{ &fixed_logs, &main_logs, &inter_logs } };
    // The cached plan is built from storage that is freed before it is reused.
    const scratch_params = try a.dupe(u32, &params_a);
    const scratch_hc = try a.dupe(u32, &hc_a);
    const scratch_masks = try a.dupe(u32, &masks);
    const scratch_slots = try a.dupe(ClaimSlot, &slots);
    var cached_spec = spec;
    const roles_a = Roles.of(scratch_params, scratch_hc, scratch_masks, scratch_slots);
    cached_spec.roles = &roles_a;
    var cached = try Plan.init(a, cached_spec);
    defer cached.deinit();
    try cached.detach();
    a.free(scratch_params);
    a.free(scratch_hc);
    a.free(scratch_masks);
    a.free(scratch_slots);
    const roles_b = Roles.of(&params_b, &hc_b, &masks, &slots);
    var fresh_spec = spec;
    fresh_spec.roles = &roles_b;
    var fresh = try Plan.init(a, fresh_spec);
    defer fresh.deinit();
    try std.testing.expect(!std.mem.eql(u32, cached.table, fresh.table));
    try cached.rebind(&roles_b);
    try std.testing.expectEqualSlices(u32, fresh.table, cached.table);
    try std.testing.expectEqualSlices(u8, &fresh.key, &cached.key);
    try std.testing.expectEqualSlices(u32, &params_b, cached.roles[0].spec.parameters);
    try std.testing.expectEqualSlices(u32, &masks, cached.roles[0].spec.mask_columns);
    try std.testing.expectEqual(@as(u32, 1), cached.roles[0].spec.claim_slots[0].parameter);
    // Any geometric difference fails closed.
    var other = roles_b;
    other[1].trace_log = 6;
    try std.testing.expectError(error.NativeCompositionClassMismatch, cached.rebind(&other));
    other = roles_b;
    other[0].mask_columns = masks[0..2];
    try std.testing.expectError(error.NativeCompositionClassMismatch, cached.rebind(&other));
    other = roles_b;
    other[0].claim_slots = &.{};
    try std.testing.expectError(error.NativeCompositionClassMismatch, cached.rebind(&other));
    try std.testing.expectError(error.NativeCompositionClassMismatch, cached.rebind(roles_b[0..1]));
}

test "twiddle region lengths match precomputeM31 (host trees are built only for a fresh region)" {
    const a = std.testing.allocator;
    for ([_]u32{ 4, 5, 9, 13 }) |log| {
        var t = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        defer engine.poly.twiddles.deinitM31(a, &t);
        try std.testing.expectEqual(Plan.twLen(log), t.twiddles.len);
        try std.testing.expectEqual(Plan.twLen(log), t.itwiddles.len);
    }
}
