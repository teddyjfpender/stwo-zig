//! Immutable class statics owner: authenticated catalog, twiddles, counted cache and pins.
const Schema = @import("outer_job_prestage.zig");
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Source = @import("outer_source.zig");
const Plan = @import("jobs/outer_plan.zig");
const St = @import("jobs/outer_staged.zig");
const TC = @import("jobs/outer_trace_commit.zig");
const Comp = @import("jobs/outer_composition.zig");
const Aot = @import("outer_aot.zig");
const Code = @import("composition_codegen.zig");
const RvAir = @import("stwo_riscv_frontend").rv64_air;
const NativePcs = @import("jobs/native_pcs.zig");
const ClassPlan = @import("jobs/outer_class_plan.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const CP = engine.air.component_prover.ForField(Outer.protocol.O);
const O = Outer.protocol.O;

fn samplePoints(a: std.mem.Allocator, key: *const Schema.Authority) !*core.pcs.TreeVec([][]D.Point) {
    const placeholder = try NativePcs.placeholderPoint();
    const claims: [Plan.n_components]O = @splat(O.zero());
    const bound = try Outer.prove.bind(a, key, O.one(), O.one(), Outer.witness.Claims.fromArray(claims));
    defer a.free(bound);
    const components = try a.alloc(CP.ComponentProver, bound.len);
    defer a.free(components);
    for (components, bound) |*out, *c| out.* = c.asProverComponent();
    const provers = CP.ComponentProvers{ .components = components, .n_preprocessed_columns = key.fixed_logs.len };
    const log = provers.compositionLogDegreeBound();
    const split = try provers.compositionLogSplit();
    if (split != 1 or log != key.bound.max_evaluation_log_size) return error.InvalidOuterCompositionAuthority;
    const mask_log = core.verifier_types.compositionMaskLogSize(log, split) orelse return error.InvalidOuterCompositionAuthority;
    var view = try provers.componentsView(a);
    defer view.deinit(a);
    var points = try view.maskPointsWithWorkCapture(a, placeholder, mask_log, false, null);
    errdefer points.deinitDeep(a);
    const columns = core.verifier_types.compositionColumnCount(split, 8) orelse return error.InvalidOuterCompositionAuthority;
    const tree = try a.alloc([]D.Point, columns);
    for (tree) |*col| {
        col.* = try a.alloc(D.Point, 1);
        col.*[0] = placeholder;
    }
    const out = try a.alloc([][]D.Point, points.items.len + 1);
    @memcpy(out[0..points.items.len], points.items);
    out[points.items.len] = tree;
    a.free(points.items);
    points.items = out;
    const boxed = try a.create(core.pcs.TreeVec([][]D.Point));
    boxed.* = points;
    return boxed;
}

const Catalogue = struct {
    const Group = struct { component: u32, roots: u32, masks: []u32, slots: []u32 };
    var mutex: std.Thread.Mutex = .{};
    var groups: ?[]Group = null;
    var identity: [32]u8 = undefined;
    const IdentityFn = *const fn (u32, [*]u8) callconv(.c) c_int;
    fn bodyIdentity(key: *const Schema.Authority) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(@import("stwo_circuit_cpu_integration").air.bundle_sha256);
        var word: [8]u8 = undefined;
        for (key.bound.components) |component| for (component.parts) |part| {
            std.mem.writeInt(u64, &word, part.program.semanticHash(), .little);
            hash.update(&word);
        };
        return hash.finalResult();
    }
    pub fn get(key: *const Schema.Authority, library: *std.DynLib) ![]const Group {
        mutex.lock();
        defer mutex.unlock();
        const body = bodyIdentity(key);
        if (groups) |g| {
            if (!std.mem.eql(u8, &identity, &body)) return error.ChangedOm31CircuitProgram;
            return g;
        }
        const a = std.heap.c_allocator;
        const ident = library.lookup(IdentityFn, "stwo_circuit_om31_composition_identity") orelse return error.MissingOuterCompositionKernel;
        const catalogue = try Aot.groups(a, &key.bound);
        defer a.free(catalogue);
        const out = try a.alloc(Group, catalogue.len);
        for (catalogue, out, 0..) |group, *dst, id| {
            var artifact = try Outer.record.record(a, &key.bound.components[group.component], group.part, group.first, group.count);
            defer artifact.deinit();
            var actual: [64]u8 = undefined;
            if (ident(@intCast(id), &actual) != 0) return error.Om31OuterAotIdentityMismatch;
            if (!std.mem.eql(u8, actual[0..32], &artifact.program.identity) or !std.mem.eql(u8, actual[32..], &(try Code.identity(&artifact.program)))) return error.Om31OuterAotIdentityMismatch;
            const masks = try a.alloc(u32, artifact.program.inputs.len);
            for (masks, artifact.program.inputs) |*m, input| m.* = input.column;
            dst.* = .{ .component = group.component, .roots = @intCast(artifact.program.roots.len), .masks = masks, .slots = try a.dupe(u32, artifact.parameter_slots) };
        }
        groups = out;
        identity = body;
        return out;
    }
};

/// Composition statics of one class: role descriptions plus one class-region
/// blob (FIXED coefficients, masks, denominators, LDE logs, parameter table,
/// commit logs). The blob sits at class-region offset 0.
const Rc = struct {
    static: Comp.Static,
    points: *core.pcs.TreeVec([][]D.Point),
    blob: []u32,
    roles: []Comp.RoleStatic,
    sources: []Comp.Source,
    fixed_offsets: []u64,
    fn deinit(self: *Rc, a: std.mem.Allocator) void {
        self.points.deinitDeep(a);
        a.destroy(self.points);
        a.free(self.blob);
        a.free(self.roles);
        a.free(self.sources);
        a.free(self.fixed_offsets);
    }
    pub fn init(a: std.mem.Allocator, key: *const Schema.Authority, library: *std.DynLib, fixed_plan: *const Plan.TreePlan) !Rc {
        const groups = try Catalogue.get(key, library);
        var blob: std.ArrayList(u32) = .empty;
        errdefer blob.deinit(a);
        const Take = struct {
            fn take(list: *std.ArrayList(u32), al: std.mem.Allocator, words: []const u32) !St.Range {
                const at = list.items.len;
                try list.appendSlice(al, words);
                while (list.items.len % 2 != 0) try list.append(al, 0);
                return .{ .region = .class, .offset = at, .words = words.len };
            }
        };
        // FIXED coefficients live in the worker-persistent `.fixed` region, in
        // the FIXED commit's sorted layout (committed on device; any authority).
        const fixed_offsets = try a.dupe(u64, fixed_plan.offsets);
        errdefer a.free(fixed_offsets);
        const fixed = St.Range{ .region = .fixed, .offset = 0, .words = fixed_plan.coefficient_words };
        const roles = try a.alloc(Comp.RoleStatic, groups.len);
        errdefer a.free(roles);
        var sources: std.ArrayList(Comp.Source) = .empty;
        errdefer sources.deinit(a);
        const source_first = try a.alloc(usize, groups.len + 1);
        defer a.free(source_first);
        var params: std.ArrayList(u32) = .empty;
        defer params.deinit(a);
        var param_total: u32 = 0;
        const M = Outer.protocol.M;
        for (groups, roles, 0..) |group, *role, id| {
            const component = &key.bound.components[group.component];
            const main = try Outer.geometry.span(component.*, 1);
            const inter = try Outer.geometry.span(component.*, 2);
            const rl = component.trace_log_size;
            const el = component.evaluation_log_size;
            const n = @as(u64, 1) << @intCast(el);
            source_first[id] = sources.items.len;
            for (component.preprocessed_indices) |index| try sources.append(a, .{ .tree = 0, .index = @intCast(index) });
            for (main.start..main.end) |index| try sources.append(a, .{ .tree = 1, .index = @intCast(index) });
            for (inter.start..inter.end) |index| try sources.append(a, .{ .tree = 2, .index = @intCast(index) });
            const columns = sources.items.len - source_first[id];
            const masks = try a.alloc(u32, group.masks.len * 2);
            defer a.free(masks);
            for (group.masks, 0..) |column, i| {
                const offset = @as(u64, column) * n;
                masks[2 * i] = @truncate(offset);
                masks[2 * i + 1] = @truncate(offset >> 32);
            }
            const denominators = try RvAir.geometry.denominatorInverses(a, rl, el);
            defer a.free(denominators);
            const logs = try a.alloc(u32, columns);
            defer a.free(logs);
            @memset(logs, el - 1);
            for (group.slots) |slot| {
                var entry: [16]u32 = @splat(0);
                switch (component.ext_sources[slot]) {
                    .constant => |w| {
                        entry[0] = 0;
                        for (Outer.program.embed(Schema.Q.fromU32Unchecked(w[0], w[1], w[2], w[3])).toM31Array(), 0..) |m, j| entry[4 + j] = m.v;
                    },
                    .lookup_z => entry[0] = 1,
                    .lookup_alpha_power => |power| {
                        entry[0] = 2;
                        entry[1] = power;
                    },
                    .lookup_alpha_power_scaled => |x| {
                        entry[0] = 3;
                        entry[1] = x.power;
                        entry[2] = M.fromCanonical(x.scale).v;
                    },
                    .claimed_sum_scaled => {
                        entry[0] = 4;
                        entry[2] = (try M.fromCanonical(@as(u32, 1) << @intCast(rl)).inv()).v;
                        entry[3] = group.component;
                    },
                }
                try params.appendSlice(a, &entry);
            }
            role.* = .{
                .id = @intCast(id),
                .trace_log = rl,
                .eval_log = el,
                .widths = .{ @intCast(component.preprocessed_indices.len), @intCast(main.end - main.start), @intCast(inter.end - inter.start) },
                .sources = &.{},
                .roots = group.roots,
                .masks = try Take.take(&blob, a, masks),
                .mask_count = @intCast(group.masks.len),
                .denominators = try Take.take(&blob, a, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(denominators))),
                .logs = try Take.take(&blob, a, logs),
                .param_count = @intCast(group.slots.len),
                .param_first = param_total,
            };
            param_total += @intCast(group.slots.len);
        }
        source_first[groups.len] = sources.items.len;
        const config = try Outer.protocol.targetConfig();
        const log = key.bound.max_evaluation_log_size;
        const split: u32 = 1;
        var static = Comp.Static{
            .roles = roles,
            .log = log,
            .split = split,
            .total = @intCast(key.bound.total_constraints),
            .beta = config.fri_config.log_blowup_factor,
            .param_total = param_total,
            .param_table = try Take.take(&blob, a, params.items),
            .commit_logs = undefined,
            .fixed = fixed,
            .fixed_offsets = fixed_offsets,
        };
        const commit = try a.alloc(u32, static.outputColumns());
        defer a.free(commit);
        @memset(commit, static.chunkLog());
        static.commit_logs = try Take.take(&blob, a, commit);
        const owned_sources = try sources.toOwnedSlice(a);
        for (roles, 0..) |*role, id| role.sources = owned_sources[source_first[id]..source_first[id + 1]];
        const points = try samplePoints(a, key);
        return .{ .static = static, .points = points, .blob = try blob.toOwnedSlice(a), .roles = roles, .sources = owned_sources, .fixed_offsets = fixed_offsets };
    }
};

pub const Statics = struct {
    public: St.Statics,
    allocator: std.mem.Allocator,
    gather: [Plan.n_components][]u32,
    gathered: []u32,
    rc: ?Rc = null,
    fixed_plan: ?Plan.TreePlan = null,
    fixed_sorted: []u32 = &.{},
    /// Whole-node plan of the class (outer_class_plan.zig), attached only to
    /// cached statics under STWO_RV64_M8_OUTER_CLASS_PLAN=1.
    slot: ClassPlan.Slot = .{},
    /// Bytes charged to StaticsCache.budget (0: not charged).
    charged: u64 = 0,
    /// Class-plan cache only (StaticsCache.mutex): Staged instances borrowing
    /// this entry, and the cache tick of the last borrow (LRU eviction).
    refs: u32 = 0,
    last_use: u64 = 0,

    pub fn init(a: std.mem.Allocator, key: *const Schema.Authority, library: *std.DynLib, composition: bool) !*Statics {
        const self = try a.create(Statics);
        errdefer a.destroy(self);
        self.* = .{ .public = undefined, .allocator = a, .gather = undefined, .gathered = &.{} };
        var made: usize = 0;
        errdefer for (self.gather[0..made]) |g| a.free(g);
        for (&self.gather, 0..) |*g, c| {
            g.* = try Source.lookupIndices(a, key, c);
            made += 1;
        }
        var pairs: [Plan.n_components]usize = undefined;
        for (&pairs, std.enums.values(circuit.common.component_list.ComponentList)) |*p, kind| p.* = (circuit.witness.trace.RawLookupRows.count(kind) + 1) / 2;
        var geometry = try Plan.Geometry.init(key.logs.toArray(), circuit.witness.trace.traceWidths(), pairs);
        geometry.fixed_logs = &key.fixed_logs;
        for (&geometry.gather, self.gather) |*dst, src| dst.* = src;
        geometry.n_outputs = @intCast(key.pp.n_outputs);
        geometry.beta = (try Outer.protocol.targetConfig()).fri_config.log_blowup_factor;
        geometry.total_constraints = @intCast(key.bound.total_constraints);
        geometry.composition_log = key.bound.max_evaluation_log_size;
        geometry.first_permutation_row = @intCast(key.pp.first_permutation_row);
        const main_logs = try key.treeLogs(a, 1);
        defer a.free(main_logs);
        const inter_logs = try key.treeLogs(a, 2);
        defer a.free(inter_logs);
        var plan = try Plan.ClassPlan.init(a, geometry);
        errdefer plan.deinit(a);
        // Validated by init; never read later. Fold statics are cached past
        // the authority that `key` is, so keep no pointer into it.
        plan.geometry.fixed_logs = &.{};
        // The plan's rosters must be the authority's own tree logs.
        if (!std.mem.eql(u32, plan.main.logs, main_logs) or !std.mem.eql(u32, plan.inter.logs, inter_logs)) return error.OuterPlanRosterMismatch;
        if (plan.main.eval_log != plan.inter.eval_log) return error.OuterTreeHeightsDiffer;
        self.gathered = try a.alloc(u32, @intCast(plan.gathered_fixed_words));
        errdefer a.free(self.gathered);
        for (self.gather, plan.gathered_offsets, plan.geometry.components) |indices, offset, c| {
            const rows = @as(usize, 1) << @intCast(c.log);
            for (indices, 0..) |index, k| {
                const values = key.pp.columns[index].values;
                if (values.len != rows) return error.InvalidOuterFixedGather;
                @memcpy(self.gathered[@as(usize, @intCast(offset)) + k * rows ..][0..rows], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(values)));
            }
        }
        self.public = .{ .identity = key.identity, .plan = plan, .gather = undefined, .gathered_fixed = self.gathered, .main_logs = undefined, .inter_logs = undefined };
        for (&self.public.gather, self.gather) |*dst, src| dst.* = src;
        try self.addTable(plan.main.eval_log);
        if (composition) {
            self.fixed_plan = try Plan.TreePlan.init(a, &key.fixed_logs, geometry.beta);
            const fp = &self.fixed_plan.?;
            self.fixed_sorted = try a.alloc(u32, fp.order.len);
            TC.sortedLogs(fp, self.fixed_sorted);
            self.public.fixed_plan = fp.*;
            self.public.fixed_sorted_logs = self.fixed_sorted;
            try self.addTable(fp.eval_log);
            self.rc = try Rc.init(a, key, library, fp);
            errdefer self.rc.?.deinit(a);
            self.public.composition = self.rc.?.static;
            self.public.rc_blob = self.rc.?.blob;
            for (self.rc.?.static.roles) |role| try self.addTable(role.eval_log);
            try self.addTable(self.rc.?.static.log);
            try self.addTable(self.rc.?.static.commitLog());
        }
        TC.sortedLogs(&self.public.plan.main, &self.public.main_logs);
        TC.sortedLogs(&self.public.plan.inter, &self.public.inter_logs);
        return self;
    }
    fn addTable(self: *Statics, log: u32) !void {
        if (log >= 29) return error.InvalidOuterTwiddles;
        if (self.public.tables[log] != null) return;
        const tw = try Twiddles.get(log);
        self.public.tables[log] = .{ .twiddles = tw.twiddles, .itwiddles = tw.itwiddles };
    }
    /// Host bytes this class keeps alive while cached (the large parts).
    fn hostBytes(self: *const Statics) u64 {
        var n: u64 = self.gathered.len;
        for (self.gather) |g| n += g.len;
        if (self.rc) |*rc| n += rc.blob.len;
        return 4 * n;
    }
    pub fn destroy(self: *Statics) void {
        const a = self.allocator;
        self.slot.deinit();
        if (self.rc) |*rc| rc.deinit(a);
        if (self.fixed_plan) |*fp| fp.deinit(a);
        a.free(self.fixed_sorted);
        a.free(self.gathered);
        for (self.gather) |g| a.free(g);
        self.public.plan.deinit(a);
        a.destroy(self);
    }
};

/// Eval-height twiddle trees, process lifetime (trace_commit.zig keeps the
/// same trees per context; a profile uses one or two heights).
pub const Twiddles = struct {
    twiddles: []const u32,
    itwiddles: []const u32,
    var mutex: std.Thread.Mutex = .{};
    var cache: [29]?*Twiddles = @splat(null);
    pub fn get(log: u32) !*const Twiddles {
        if (log > 28) return error.InvalidOuterTwiddles;
        mutex.lock();
        defer mutex.unlock();
        if (cache[log]) |hit| return hit;
        const a = std.heap.page_allocator;
        const tree = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        const self = try a.create(Twiddles);
        self.* = .{ .twiddles = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.twiddles)), .itwiddles = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)) };
        cache[log] = self;
        return self;
    }
};

/// Fold classes reuse statics; by default a leaf owns its statics. Under
/// STWO_RV64_M8_OUTER_CLASS_PLAN=1 every class is cached by authority identity
/// (statics are a pure function of the authority: identity binds the FIXED
/// root, the component logs and the output count) within a host-byte budget,
/// and carries a whole-node plan slot. Under the class plan the cache is
/// reference counted: a new class that does not fit (entry limit or host
/// budget) evicts the least recently used classes no node still borrows, and
/// stays per node (correct, only slower) only when every entry is in use.
/// Without eviction the cache froze after the first few block shapes (each
/// block brings its own leaf classes: 15 on 24628607 [M outer-fold-p3]) and
/// every later leaf rebuilt its statics with up to 64 stale classes pinned.
pub const StaticsCache = struct {
    var mutex: std.Thread.Mutex = .{};
    var entries: std.ArrayList(*Statics) = .empty;
    const limit: usize = 16;
    /// Entry limit under the class plan: 24628607 has 15 leaves + 4 fold
    /// classes + root [M outer-fold-p3]; 64 leaves headroom for a class mix of
    /// several block shapes (bounded by the host-byte budget anyway).
    const class_plan_limit: usize = 64;
    var budget: ?ClassPlan.Budget = null;
    var tick: u64 = 0;
    const Acquired = struct { statics: *Statics, owned: bool, counted: bool = false };
    fn find(key: *const Schema.Authority, composition: bool) ?*Statics {
        for (entries.items) |s| if (std.mem.eql(u8, &s.public.identity, &key.identity) and (s.rc != null) == composition) return s;
        return null;
    }
    pub fn acquire(key: *const Schema.Authority, reusable: bool, library: *std.DynLib, composition: bool) !Acquired {
        const a = std.heap.c_allocator;
        if (try ClassPlan.selected()) return acquireCounted(a, key, library, composition);
        if (!reusable) return .{ .statics = try Statics.init(a, key, library, composition), .owned = true };
        mutex.lock();
        defer mutex.unlock();
        if (find(key, composition)) |s| return .{ .statics = s, .owned = false };
        const s = try Statics.init(a, key, library, composition);
        if (entries.items.len >= limit) return .{ .statics = s, .owned = true };
        entries.append(a, s) catch return .{ .statics = s, .owned = true };
        return .{ .statics = s, .owned = false };
    }
    /// Must hold `mutex`.
    fn borrow(s: *Statics) Acquired {
        tick += 1;
        s.refs += 1;
        s.last_use = tick;
        return .{ .statics = s, .owned = false, .counted = true };
    }
    /// Must hold `mutex`: destroy the LRU unreferenced entry; false when none.
    fn evictOne() bool {
        var refs: [class_plan_limit]u32 = undefined;
        var last: [class_plan_limit]u64 = undefined;
        const n = @min(entries.items.len, class_plan_limit);
        for (entries.items[0..n], refs[0..n], last[0..n]) |s, *r, *t| {
            r.* = s.refs;
            t.* = s.last_use;
        }
        const i = ClassPlan.lruVictim(refs[0..n], last[0..n]) orelse return false;
        const victim = entries.swapRemove(i);
        if (victim.charged != 0) budget.?.release(victim.charged);
        victim.destroy();
        _ = evictions.fetchAdd(1, .monotonic);
        return true;
    }
    pub var evictions: std.atomic.Value(u64) = .init(0);
    /// STWO_RV64_M8_OUTER_CLASS_PLAN=1: every class by identity. The miss
    /// builds OUTSIDE the cache lock (leaf prestages of different classes run
    /// concurrently on the lanes' threads, 0.18-0.34 s each [M, feeder gate-c
    /// 24628607]); a racing builder of the same class keeps the first entry.
    fn acquireCounted(a: std.mem.Allocator, key: *const Schema.Authority, library: *std.DynLib, composition: bool) !Acquired {
        {
            mutex.lock();
            defer mutex.unlock();
            if (find(key, composition)) |s| return borrow(s);
            // Parsed before the build so no error can leak a built class.
            if (budget == null) budget = .{ .limit = try ClassPlan.hostBudgetBytes() };
        }
        const s = try Statics.init(a, key, library, composition);
        mutex.lock();
        defer mutex.unlock();
        if (find(key, composition)) |hit| {
            s.destroy();
            return borrow(hit);
        }
        const bytes = s.hostBytes();
        while (entries.items.len >= class_plan_limit) if (!evictOne()) return .{ .statics = s, .owned = true };
        while (!budget.?.reserve(bytes)) if (!evictOne()) return .{ .statics = s, .owned = true };
        s.charged = bytes;
        entries.append(a, s) catch {
            budget.?.release(s.charged);
            s.charged = 0;
            return .{ .statics = s, .owned = true };
        };
        // Only a cached class gets a slot: its plan lives as long as the class.
        if (composition) s.public.class_plan = @ptrCast(&s.slot);
        return borrow(s);
    }
    /// The borrowing Staged is gone (Owner.release / prestage error path).
    pub fn unref(s: *Statics) void {
        mutex.lock();
        defer mutex.unlock();
        std.debug.assert(s.refs != 0);
        s.refs -= 1;
    }
};

/// A counted borrow of a cached class's statics for a holder outside any
/// Staged (the GPU-native recursion class registry, jobs/outer_device.zig):
/// while held, LRU eviction never destroys the entry (lruVictim skips
/// referenced entries), so a sealed ClassCache entry never dangles.
pub const ClassPin = struct {
    statics: *anyopaque,
    /// `plan` is a cached entry's `public` (St.Statics) pointer;
    /// error.OuterClassNotCached if no cached entry owns it (an uncached,
    /// per-node statics can never back a warmed class).
    pub fn take(plan: *anyopaque) !ClassPin {
        StaticsCache.mutex.lock();
        defer StaticsCache.mutex.unlock();
        for (StaticsCache.entries.items) |s| if (@as(*anyopaque, @ptrCast(&s.public)) == plan) {
            _ = StaticsCache.borrow(s);
            return .{ .statics = s };
        };
        return error.OuterClassNotCached;
    }
    pub fn retain(raw: *anyopaque) void {
        StaticsCache.mutex.lock();
        defer StaticsCache.mutex.unlock();
        _ = StaticsCache.borrow(@ptrCast(@alignCast(raw)));
    }
    pub fn release(raw: *anyopaque) void {
        StaticsCache.unref(@ptrCast(@alignCast(raw)));
    }
};

comptime {
    // Analyzed with this file (its only caller, the GPU-native warm entry, is not landed).
    _ = &ClassPin.take;
    _ = &ClassPin.retain;
    _ = &ClassPin.release;
}
