//! Product capture inventory and bounded install/miss registration ownership.
const Child = CPU.rv64_gkr_child;
const M = core.fields.m31.M31;
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const Class = @import("native_class_build.zig").Class;
const Config = @import("native_class_build.zig").Config;
const DP = CPU.rv64_device_pcs;
const Env = @import("native_class_build.zig").Env;
const FirstIds = @import("native_class_build.zig").FirstIds;
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const Inputs = @import("native_class_build.zig").Inputs;
const ND = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device;
const ProductCPU = @import("ethereum_cpu_component");
const Request = @import("native_class_build.zig").Request;
const S1 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage1;
const S2 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage2;
const Setup = @import("native_class_build.zig").Setup;
const WP = CPU.rv64_gkr_worker_protocol;
const addReplicas = @import("native_class_build.zig").addReplicas;
const build = @import("native_class_build.zig").build;
const placeholderPending = @import("native_class_inputs.zig").placeholderPending;
const placeholderShared = @import("native_class_inputs.zig").placeholderShared;
const std = @import("std");
const stubSource = @import("native_class_inputs.zig").stubSource;

pub const Capture = ProductCPU.rv64_ethereum_capture;
pub const Plan = ProductCPU.rv64_ethereum_plan;
pub const Image = ProductCPU.rv64_expected_image;
pub const Keys = ProductCPU.rv64_ethereum_keys.Owner;
pub const FixedAuthority = CPU.rv64_gkr_fixed_authority;
pub const FixedSet = CPU.rv64_gkr_fixed_authority_set.Set;
pub const Coordinator = CPU.rv64_gkr_coordinator;
pub const Execution = CPU.rv64_gkr_execution;
pub const LocalRoster = CPU.rv64_gkr_local_roster;
pub const Suite = CPU.rv64_pcs_suite.Suite;
pub const RequestConfig = ProductCPU.rv64_ethereum_request.Config;

/// One block's install-time inventory: gkr_main's declarations (+ canonical
/// rungs) and request views (requestView / routeDword / assignSpongeIds,
/// first ids), sequentially; then per segment, in the parallel class build,
/// its setup keys and FIXED authority (`prepare`: Keys over the one
/// declaration + FixedSet over the one setup, as early_segments.zig builds
/// them per segment). Truths are not needed for the native classes.
pub const Inventory = struct {
    a: std.mem.Allocator,
    config: Config,
    image: *const Image.Owner,
    decls: []Decl,
    fixed_cache: FixedAuthority.Fixed.Cache,
    requests: []Request,
    first_ids: []FirstIds,
    segs: []Seg,

    pub const Decl = std.meta.Child(@typeInfo(@typeInfo(@TypeOf(Plan.cpus)).@"fn".return_type.?).error_union.payload);
    pub const Seg = struct {
        keys: ?Keys = null,
        fixed: ?FixedSet = null,
        /// Host wall of this segment's keys + FIXED authority [M].
        setup_ns: u64 = 0,
    };

    pub fn init(a: std.mem.Allocator, capture: G.CaptureEnd, config: Config, fixed_setup_bytes: usize) !*Inventory {
        const owner: *const Capture.Owner = @ptrCast(@alignCast(capture.owner));
        const image: *const Image.Owner = @ptrCast(@alignCast(capture.image));
        const rconfig: *const RequestConfig = @ptrCast(@alignCast(capture.config));
        const layout = Plan.CpuLayout.forGkrProfile(rconfig.execution_profile);
        const cpu = try Plan.cpus(a, owner, layout);
        errdefer a.free(cpu);
        const strict = (try CPU.rv64_native_policy.current()).strictRoster();
        const canon_flag = false;
        if (strict or canon_flag) {
            const classes = try a.alloc(Plan.CanonClass, cpu.len);
            defer a.free(classes);
            try Plan.canonicalCpusMode(owner, layout, cpu, CPU.rv64_native_rungs, classes, strict);
        }
        const n = owner.native.items.len;
        if (n != cpu.len or n != capture.segments) return error.GnShapeInventoryShape;
        const self = try a.create(Inventory);
        errdefer a.destroy(self);
        self.* = .{ .a = a, .config = config, .image = image, .decls = cpu, .fixed_cache = undefined, .requests = &.{}, .first_ids = &.{}, .segs = &.{} };
        self.fixed_cache = try FixedAuthority.Fixed.Cache.init(a, fixed_setup_bytes);
        errdefer self.fixed_cache.deinit();
        self.requests = try a.alloc(Request, n);
        errdefer a.free(self.requests);
        // The declaration's bridges ARE the setup's (early_segments.take
        // requires {geometry, bridges} equal), so routing needs no keys.
        for (self.requests, 0..) |*r, i| {
            r.* = try Coordinator.requestView(owner.native.items, &owner.advice, i);
            try Coordinator.routeDword(r, cpu[i].bridges, owner.advice.events[i]);
        }
        try Coordinator.assignSpongeIds(self.requests);
        self.first_ids = try a.alloc(FirstIds, n);
        errdefer a.free(self.first_ids);
        // Execution.Inventory's first ids: per family, 1 + the calls before.
        var next: [@typeInfo(FirstIds).array.len]u64 = @splat(1);
        for (self.requests, self.first_ids) |r, *f| {
            for (next, f) |id, *out| out.* = std.math.cast(u32, id) orelse return error.GlobalGkrManifestOrdinal;
            for (&next, r.calls) |*id, calls| id.* = try std.math.add(u64, id.*, calls);
        }
        self.segs = try a.alloc(Seg, n);
        @memset(self.segs, .{});
        return self;
    }
    /// Segment `i`'s setup keys and FIXED authority (thread safe across
    /// segments: the FIXED cache is internally locked).
    pub fn prepare(self: *Inventory, i: usize) !void {
        const seg = &self.segs[i];
        if (seg.fixed != null) return;
        var t = try std.time.Timer.start();
        seg.keys = try Keys.initWithSuiteAndCaches(self.a, self.image, self.decls[i .. i + 1], &.{}, true, Suite.experimentalFold4(), .{});
        errdefer {
            seg.keys.?.deinit();
            seg.keys = null;
        }
        seg.fixed = try FixedSet.init(self.a, &self.fixed_cache, seg.keys.?.cpus, seg.keys.?.truths, self.config);
        seg.setup_ns = t.read();
    }
    pub fn setup(self: *const Inventory, i: usize) *const Setup {
        return self.segs[i].keys.?.cpus[0];
    }
    pub fn binding(self: *const Inventory, i: usize) *const FixedAuthority.Binding {
        return self.segs[i].fixed.?.at(0);
    }
    pub fn deinit(self: *Inventory) void {
        const a = self.a;
        for (self.segs) |*seg| {
            if (seg.fixed) |*f| f.deinit();
            if (seg.keys) |*k| k.deinit();
        }
        a.free(self.segs);
        a.free(self.first_ids);
        a.free(self.requests);
        self.fixed_cache.deinit();
        a.free(self.decls);
        a.destroy(self);
    }
    pub fn count(self: *const Inventory) usize {
        return self.requests.len;
    }
};

/// Build segment `i` of an inventory (FIXED via the authority binding into a
/// throwaway scheme, exactly CpuWorker.prepareMain's append).
pub fn buildFromInventory(env: *const Env, inv: *Inventory, i: usize) !*Class {
    const a = env.a;
    try inv.prepare(i);
    const setup = inv.setup(i);
    const binding = inv.binding(i);
    var scheme = try WP.Prover.init(a, env.config);
    defer scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    const expected = try Execution.localCpuExpected(a, setup, inv.requests[i], @intCast(i), inv.first_ids[i], env.config, binding);
    defer a.free(expected.local_instances.?);
    var ch = binding.begin(env.config, expected);
    try binding.append(a, &setup.key, expected.fixed, &scheme, &ch);
    const coefficients = scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
    const fixed = try a.alloc(DP.Column, coefficients.len);
    defer a.free(fixed);
    for (coefficients, fixed) |c, *d| d.* = .{ .log_size = c.logSize(), .coefficients = c.coefficients() };
    const main_logs = try setup.logs(a, 1);
    defer a.free(main_logs);
    const instances = try LocalRoster.fromSetup(a, setup);
    defer a.free(instances);
    var native = stubSource(setup, inv.requests[i]);
    var pending = try placeholderPending(a, instances);
    defer pending.deinit(a);
    const in = Inputs{
        .ordinal = @intCast(i),
        .setup = setup,
        .request = inv.requests[i],
        .first = inv.first_ids[i],
        .fixed = fixed,
        .fixed_root = expected.fixed,
        .main_logs = main_logs,
        .instances = instances,
        .native = &native,
        .pending = &pending,
        .shared = placeholderShared(),
    };
    const cl = try build(env, in);
    errdefer cl.deinit();
    try addReplicas(env, in, cl, env.framing_instances -| 1);
    return cl;
}

// ---------------------------------------------------------------------------
// The shape hook: install-time class mix per block
// ---------------------------------------------------------------------------

pub const BlockRecord = struct {
    block: u64,
    keys: []G.ClassKey,
    rows: []u64,
    public_inputs: [][]u32 = &.{},
    /// Host wall of the block's class build at install [M].
    build_ns: u64,
    /// Of which: the sequential inventory (declarations, request views) [M].
    inventory_ns: u64 = 0,
    /// Of which: the per-segment setup keys + FIXED authority (CPU FIXED
    /// commit) + class builds, `threads` in parallel [M].
    classes_ns: u64 = 0,
    threads: u32 = 1,
    miss: bool,
    /// Classes first seen in this block, and the wall of registering them
    /// (on the miss path incl. their host + device warm) [M].
    new_classes: u32 = 0,
    register_ns: u64 = 0,
};

/// The native factory's install-time class builder. Owns every class it
/// built; registers each class ONCE with the Stage-1 registry and the
/// Stage-2 factory (when bound). `shape` is NativeFactory.shape.
pub const Builder = struct {
    a: std.mem.Allocator,
    env: Env,
    registry: ?*S1.Registry = null,
    factory: ?*S2.Factory = null,
    /// Stage-2 instances per class (Factory.instances_per_device * GPUs).
    framing_instances: usize = 2,
    /// Parallel segment class builds (0 = one thread per segment, max 64).
    build_threads: usize = 0,
    fixed_setup_bytes: usize = 4 << 30,
    mutex: std.Thread.Mutex = .{},
    classes: std.AutoArrayHashMapUnmanaged(G.ClassKey, *Class) = .empty,
    /// Serialises whole block builds (install and miss path): one block's
    /// inventory, class build and registration at a time.
    build_mutex: std.Thread.Mutex = .{},
    blocks: std.ArrayListUnmanaged(BlockRecord) = .empty,
    misses: u64 = 0,
    missed_classes: u64 = 0,
    /// Miss path after install: the service's class cache (reopened to warm
    /// a new block's classes) and the GPUs to warm them on (0 = the
    /// registry's warmed devices). Null: a miss with new classes fails
    /// closed with GnShapeMissWarmNotBound (the build is still receipted).
    miss_cache: ?*G.ClassCache = null,
    miss_devices: u32 = 0,
    /// GPU-native capture binding borrows setup/public views between
    /// requests. The corresponding warm Capture.Owner must outlive Builder.
    retain_inventories: bool = false,
    inventories: std.AutoHashMapUnmanaged(u64, *Inventory) = .empty,

    pub fn deinit(self: *Builder) void {
        var inventories = self.inventories.valueIterator();
        while (inventories.next()) |inv| inv.*.deinit();
        self.inventories.deinit(self.a);
        for (self.blocks.items) |b| {
            for (b.public_inputs) |values| self.a.free(values);
            self.a.free(b.public_inputs);
            self.a.free(b.keys);
            self.a.free(b.rows);
        }
        self.blocks.deinit(self.a);
        for (self.classes.values()) |c| c.deinit();
        self.classes.deinit(self.a);
    }

    /// ND.Native.shape_hooks of this builder.
    pub fn hooks(self: *Builder) ND.ShapeHooks {
        return .{ .ctx = self, .shape = hShape, .class_of = hClassOf };
    }
    fn of(raw: *anyopaque) *Builder {
        return @ptrCast(@alignCast(raw));
    }
    fn hShape(raw: *anyopaque, a: std.mem.Allocator, wb: G.WarmBlock) anyerror![]u64 {
        return of(raw).shape(a, wb);
    }
    fn hClassOf(raw: *anyopaque, block: ?u64, segment: u32, rows: u64) anyerror!G.ClassKey {
        return of(raw).classOf(block, segment, rows);
    }

    /// NativeFactory.shape: build (or reuse) every segment class of the
    /// block from its warm capture, register them, return the segment rows.
    pub fn shape(self: *Builder, a: std.mem.Allocator, wb: G.WarmBlock) ![]u64 {
        // After install (registry sealed) a new block is a class miss.
        const rec = try self.buildBlock(wb, if (self.registry) |r| r.sealed else false);
        return a.dupe(u64, rec.rows);
    }

    /// Class miss on a new block after install: the same build on the miss
    /// path, receipted (`misses`, BlockRecord.miss). Classes already known
    /// are reused; new ones are returned for the factory's device warm.
    pub fn missBlock(self: *Builder, wb: G.WarmBlock) !BlockRecord {
        return self.buildBlock(wb, true);
    }

    const BuildSlot = struct {
        cl: ?*Class = null,
        err: ?anyerror = null,
        fn run(env: *const Env, inv: *Inventory, i: usize, slot: *BuildSlot) void {
            var t = std.time.Timer.start() catch unreachable;
            slot.cl = buildFromInventory(env, inv, i) catch |err| {
                slot.err = err;
                return;
            };
            slot.cl.?.build_ns = t.read();
            slot.cl.?.setup_ns = inv.segs[i].setup_ns;
        }
    };

    fn knownBlock(self: *Builder, block: u64) ?BlockRecord {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.blocks.items) |b| if (b.block == block) return b;
        return null;
    }

    fn buildBlock(self: *Builder, wb: G.WarmBlock, miss: bool) !BlockRecord {
        self.build_mutex.lock();
        defer self.build_mutex.unlock();
        var timer = try std.time.Timer.start();
        if (self.knownBlock(wb.block)) |b| return b;
        self.env.framing_instances = @max(1, if (self.factory != null) self.framing_instances else 1);
        const inv = try Inventory.init(self.a, wb.capture, self.env.config, self.fixed_setup_bytes);
        var keep_inventory = false;
        defer if (!keep_inventory) inv.deinit();
        const inventory_ns = timer.read();
        const n = inv.count();
        const keys = try self.a.alloc(G.ClassKey, n);
        errdefer self.a.free(keys);
        const rows = try self.a.alloc(u64, n);
        errdefer self.a.free(rows);
        const public_inputs = try self.a.alloc([]u32, n);
        @memset(public_inputs, &.{});
        errdefer {
            for (public_inputs) |values| self.a.free(values);
            self.a.free(public_inputs);
        }
        // Segment classes are independent: build them in parallel (the
        // allocator must be thread safe; gcatalogue is guarded by gmutex).
        const slots = try self.a.alloc(BuildSlot, n);
        defer self.a.free(slots);
        @memset(slots, .{});
        const threads: usize = @min(64, if (self.build_threads == 0) n else @min(n, self.build_threads));
        var next: usize = 0;
        while (next < n) {
            const batch = @min(threads, n - next);
            var pool: [64]?std.Thread = @splat(null);
            for (0..batch) |k| {
                const i = next + k;
                pool[k] = std.Thread.spawn(.{ .stack_size = 64 << 20 }, BuildSlot.run, .{ &self.env, inv, i, &slots[i] }) catch blk: {
                    BuildSlot.run(&self.env, inv, i, &slots[i]);
                    break :blk null;
                };
            }
            for (pool[0..batch]) |t| if (t) |th| th.join();
            next += batch;
        }
        const classes_ns = timer.read() - inventory_ns;
        errdefer for (slots) |sl| if (sl.cl) |c| c.deinit();
        for (slots) |sl| if (sl.err) |err| return err;
        var fresh: std.ArrayListUnmanaged(*Class) = .empty;
        defer fresh.deinit(self.a);
        for (0..n) |i| {
            const cl = slots[i].cl.?;
            slots[i].cl = null;
            var owned = true;
            errdefer if (owned) cl.deinit();
            keys[i] = cl.key;
            rows[i] = cl.rows;
            public_inputs[i] = try self.a.dupe(u32, cl.public_values);
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.classes.get(cl.key)) |old| {
                cl.deinit();
                owned = false;
                // Known but not fully registered (an earlier build of a block
                // failed in registration / the miss warm): register it now.
                if (!self.registered(old) and std.mem.indexOfScalar(*Class, fresh.items, old) == null) try fresh.append(self.a, old);
                continue;
            }
            try self.classes.put(self.a, cl.key, cl);
            owned = false;
            try fresh.append(self.a, cl);
        }
        var warm_ns: u64 = 0;
        if (fresh.items.len != 0) {
            var wt = try std.time.Timer.start();
            try self.registerFresh(fresh.items);
            warm_ns = wt.read();
        }
        const rec = BlockRecord{ .block = wb.block, .keys = keys, .rows = rows, .public_inputs = public_inputs, .build_ns = timer.read(), .inventory_ns = inventory_ns, .classes_ns = classes_ns, .threads = @intCast(threads), .miss = miss, .new_classes = @intCast(fresh.items.len), .register_ns = warm_ns };
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.retain_inventories) {
            try self.inventories.put(self.a, wb.block, inv);
            keep_inventory = true;
        }
        try self.blocks.append(self.a, rec);
        if (miss) {
            self.misses += 1;
            self.missed_classes += fresh.items.len;
        }
        return rec;
    }

    /// Register classes first seen in this block. At install (registry
    /// open) that is all; after the registry sealed (a class miss on a new
    /// block) the classes are also warmed on the miss path: registry and
    /// class cache reopened, Stage-1 warm (host plans + entries), Stage-2
    /// cache insert, one WarmJob per (class, GPU) (device FIXED commit +
    /// root check; already-warm classes only copy their root), resealed.
    fn registerFresh(self: *Builder, fresh: []const *Class) !void {
        const r = self.registry orelse {
            for (fresh) |cl| try self.registerClass(cl);
            return;
        };
        if (!r.sealed) {
            for (fresh) |cl| try self.registerClass(cl);
            return;
        }
        const cache = self.miss_cache orelse return error.GnShapeMissWarmNotBound;
        const devices: u32 = if (self.miss_devices != 0) self.miss_devices else r.warmed_devices;
        if (devices == 0 or r.workers.len < devices) return error.GnShapeMissWarmNotBound;
        {
            r.mutex.lock();
            defer r.mutex.unlock();
            r.sealed = false;
        }
        defer r.seal();
        cache.reopen();
        defer cache.seal();
        for (fresh) |cl| try self.registerClass(cl);
        try r.warm(cache, devices);
        if (self.factory) |f| try f.warm(cache);
        try r.warmDevices(r.workers[0..devices]);
    }

    fn registered(self: *const Builder, cl: *const Class) bool {
        if (self.registry != null and !cl.s1_registered) return false;
        if (self.factory != null and cl.s2_registered < cl.framingInstances()) return false;
        // After install (miss path) a class is done only once warmed into
        // the service's class cache (a failed miss warm is retried).
        if (self.registry) |r| if (r.sealed) if (self.miss_cache) |c| {
            if (!cacheHas(c, cl.key)) return false;
            if (self.factory != null and !cacheHas(c, Class.framingKey(cl.key))) return false;
        };
        return true;
    }
    /// Lookup without ClassCache.get's request-miss accounting.
    fn cacheHas(c: *G.ClassCache, key: G.ClassKey) bool {
        c.mutex.lock();
        defer c.mutex.unlock();
        return c.map.contains(key);
    }

    pub fn registerClassForTest(self: *Builder, cl: *Class) !void {
        if (!@import("builtin").is_test) @compileError("test only");
        return self.registerClass(cl);
    }
    /// Idempotent: registers what is not yet registered (a retry after a
    /// failed registration never registers an instance twice).
    fn registerClass(self: *Builder, cl: *Class) !void {
        if (self.registry) |r| if (!cl.s1_registered) {
            // Registry.by_rows is keyed by rows only: classes are resolved
            // through `classOf` (block, segment) here, so the registry gets
            // a per-class token instead of the (ambiguous) row count.
            try r.register(cl.spec(), rowsToken(cl.key));
            cl.s1_registered = true;
        };
        if (self.factory) |f| {
            // The prototype, then each replica: exclusive pool instances
            // (Stage2Job leases one each; none shares mutable Stage-2 state).
            while (cl.s2_registered < cl.framingInstances()) : (cl.s2_registered += 1) try f.register(cl.framingInstance(cl.s2_registered));
        }
    }

    /// Class of `segment` (rows checked). With the block (preferred), exact;
    /// without, the unique class of (segment, rows) over every warmed block.
    pub fn classOf(self: *Builder, block: ?u64, segment: u32, rows: u64) !G.ClassKey {
        self.mutex.lock();
        defer self.mutex.unlock();
        var found: ?G.ClassKey = null;
        for (self.blocks.items) |b| {
            if (block) |want| if (b.block != want) continue;
            if (segment >= b.keys.len or b.rows[segment] != rows) continue;
            if (found) |k| {
                if (!std.mem.eql(u8, &k, &b.keys[segment])) return error.GnShapeClassAmbiguous;
            } else found = b.keys[segment];
        }
        return found orelse error.GpuNativeClassNotWarmed;
    }
    pub fn class(self: *Builder, key: G.ClassKey) ?*Class {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.classes.get(key);
    }
};

/// The Stage-1 registry's row token of a class (see registerClass).
pub fn rowsToken(key: G.ClassKey) u64 {
    return std.mem.readInt(u64, key[0..8], .little) | (@as(u64, 1) << 63);
}
