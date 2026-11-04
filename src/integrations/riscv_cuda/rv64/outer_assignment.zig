//! Device assignments from the original topology and explicit input origins.
//! Production trace-only builders retain compact seeds without CPU assignment
//! storage. Optional reference reconstruction is restricted to qualification;
//! graph construction and schedule preparation remain host work.
const std = @import("std");
const Circuit = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const Schedule = Circuit.builder.witness_plan;
const SC = @import("session_context.zig");
const N = @import("pcs_native_abi.zig");
const Events = @import("cuda_events.zig");
const Span = enum { seed, levels };
const Recorder = Events.RecorderFor(Span);
const Pack = @import("outer_assignment_pack.zig");
const Runs = @import("assignment_runs.zig");
const Dev = @import("stwo_circuit_cpu_integration").om31.device_prove;
pub const Task = Pack.Task;
pub const Seed = extern struct { out: u32, value: [4]u32 };
pub const Job = extern struct { values: [*]u32, records: [*]const u32, indices: ?[*]const u32, status: *u32, value_count: u32, record_count: u32, index_count: u32, first: u32, count: u32, reserved: u32 = 0 };
pub const Launch = *const fn (*anyopaque, u32, *const Job) callconv(.c) c_int;
pub const LaunchRun = *const fn (*anyopaque, u32, *const Job, [*]const u32, u32) callconv(.c) c_int;
/// M6 hint-tape chain runs (circuit_fill_chain.cu): device level ends, first level, level count.
pub const LaunchChain = *const fn (*anyopaque, u32, *const Job, [*]const u32, u32, u32) callconv(.c) c_int;
/// Level grouping for the device DAG. Chain runs (default when the image has
/// them; STWO_RV64_OUTER_ASSIGNMENT_CHAIN=0 off, =1 required) take precedence
/// over the M5 narrow runs (STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1). All
/// groupings execute the same tasks in the same level order: proof-neutral.
const Grouping = struct {
    plan: ?Runs.Plan,
    narrow: ?LaunchRun,
    chain: ?LaunchChain,
    narrow_enabled: bool,
    chain_enabled: bool,
    fn init(a: std.mem.Allocator, library: *std.DynLib, level_ends: []const usize, task_count: usize) !Grouping {
        const option = std.process.getEnvVarOwned(a, "STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (option) |value| a.free(value);
        const narrow_enabled = try Runs.parseOptIn(option);
        const narrow = library.lookup(LaunchRun, "stwo_circuit_assignment_narrow_run_on");
        if (narrow_enabled and narrow == null) return error.MissingCircuitAssignmentNarrowRunKernel;
        const chain = library.lookup(LaunchChain, "stwo_circuit_assignment_chain_run_on");
        const width = library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_chain_max_width");
        const chain_option = std.posix.getenv("STWO_RV64_OUTER_ASSIGNMENT_CHAIN");
        const chain_enabled = if (chain_option) |value| blk: {
            if (std.mem.eql(u8, value, "0")) break :blk false;
            if (std.mem.eql(u8, value, "1")) break :blk true;
            return error.InvalidAssignmentChainOption;
        } else chain != null and width != null;
        if (chain_enabled and (chain == null or width == null)) return error.MissingCircuitAssignmentChainKernel;
        const plan: ?Runs.Plan = if (chain_enabled) try Runs.Plan.initChain(a, level_ends, task_count, width.?()) else if (narrow_enabled) try Runs.Plan.init(a, level_ends, task_count) else null;
        return .{ .plan = plan, .narrow = narrow, .chain = chain, .narrow_enabled = narrow_enabled, .chain_enabled = chain_enabled };
    }
};
pub fn requireProductionMask(mask: u32) !void {
    if (mask & 0xffff != 0xffff) return error.UnsupportedCircuitAssignmentHint;
}
pub fn requireProductionCapabilities(library: *std.DynLib) !void {
    _ = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
    _ = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
    const query = library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities") orelse return error.MissingCircuitAssignmentKernel;
    try requireProductionMask(query());
}
/// Producer-only, in-process fold-class assignment templates. A v2 fold's
/// topology is a function of its class (om31_outer.classKey), so tasks,
/// permutation indices, level ends and the seed-variable layout are reused;
/// only seed VALUES are re-read from the new graph. Proof-neutral: an equal
/// plan yields the equal assignment. A wrong reuse cannot be accepted (the
/// receiver checks every proof under its own authority) and the seed-layout
/// check below rejects any graph whose constants/guesses differ in layout.
/// STWO_RV64_OUTER_PLAN_CLASS_CACHE=0 off, =check rebuild+compare, default on.
pub const ClassCache = struct {
    pub const Mode = enum { off, on, check };
    /// `constants` are the values of the class's interned constants, in seed
    /// order (the first `n_constants` seeds). A v2 fold's constants are class
    /// data; every full-graph hit re-checks them and a disagreement clears
    /// `constants_stable`, which disables the seed tape (HT1) for that class.
    const Template = struct { key: [32]u8, n_vars: u32, n_constants: usize, n_origins: usize, seed_vars: []u32, constants: [][4]u32, tasks: []Task, indices: []u32, level_ends: []usize, identity: [32]u8, bytes: usize, persisted: bool = false, capability_checked: bool = true, rejected: bool = false, constants_stable: bool = true };
    const gpa = std.heap.smp_allocator;
    var mutex: std.Thread.Mutex = .{};
    var entries: std.ArrayListUnmanaged(*Template) = .empty;
    var held_bytes: usize = 0;
    pub var hits: usize = 0;
    pub var misses: usize = 0;
    pub var checked: usize = 0;
    /// M6 hint-tape: fold plans built from a seed tape (no verifier graph).
    pub var tape_hits: usize = 0;
    pub var tape_refusals: usize = 0;
    pub fn mode() Mode {
        const value = std.posix.getenv("STWO_RV64_OUTER_PLAN_CLASS_CACHE") orelse return .on;
        if (std.mem.eql(u8, value, "0")) return .off;
        if (std.mem.eql(u8, value, "check")) return .check;
        return .on;
    }
    fn limit() usize {
        const value = std.posix.getenv("STWO_RV64_OUTER_PLAN_CLASS_CACHE_BYTES") orelse return 6 << 30;
        return std.fmt.parseUnsigned(usize, value, 10) catch 6 << 30;
    }
    fn find(key: [32]u8) ?*Template {
        {
            mutex.lock();
            defer mutex.unlock();
            // A rejected (disk-loaded) template is never used again and its file
            // is not re-read: the class is rebuilt fresh on every use.
            for (entries.items) |t| if (std.mem.eql(u8, &t.key, &key)) return if (t.rejected) null else t;
        }
        return Store.load(key);
    }
    /// A disk-loaded template that fails a use-time check (library capability,
    /// shape, seed layout) is a logged miss, not a request failure.
    fn reject(t: *Template, err: anyerror) void {
        mutex.lock();
        t.rejected = true;
        mutex.unlock();
        std.debug.print("GPU_OUTER_PLAN_CLASS store_reject_on_use class={x} error={s}\n", .{ t.key[0..8], @errorName(err) });
    }
    pub var disk_hits: usize = 0;
    pub var disk_stores: usize = 0;
    /// M4 resident ArtifactStore: fold-class templates persisted across service
    /// processes (STWO_RV64_OUTER_PLAN_CLASS_STORE=<dir>). A file is bound to
    /// the class key and to SHA-256(own executable); on load the plan identity
    /// (schedule_identity over tasks, indices, level ends) is recomputed and must
    /// equal the stored one, and the usual seed-layout/shape checks still run on
    /// every use. Any mismatch is a miss-and-rebuild of THIS class and is logged;
    /// proof bytes cannot depend on the store (an equal plan is the equal
    /// assignment; the receiver never reads it).
    pub const Store = struct {
        /// v2 (M6 hint-tape) appends the class constant values after the seed
        /// variables; a v1 file is a logged miss and is rewritten as v2.
        const MAGIC = "RV64CLS2";
        const HEADER = 8 + 4 + 4 + 32 + 32 + 32 + 4 + 4 + 8 * 6;
        var code: ?[32]u8 = null;
        var code_mutex: std.Thread.Mutex = .{};
        fn directory() ?[]const u8 {
            const value = std.posix.getenv("STWO_RV64_OUTER_PLAN_CLASS_STORE") orelse return null;
            return if (value.len == 0) null else value;
        }
        fn codeIdentity() ![32]u8 {
            code_mutex.lock();
            defer code_mutex.unlock();
            if (code) |c| return c;
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const path = try std.fs.selfExePath(&buffer);
            const file = try std.fs.openFileAbsolute(path, .{});
            defer file.close();
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update("rv64-m4-class-store/code/v1\x00");
            var chunk: [1 << 20]u8 = undefined;
            while (true) {
                const n = try file.read(&chunk);
                if (n == 0) break;
                h.update(chunk[0..n]);
            }
            code = h.finalResult();
            return code.?;
        }
        fn pathFor(buffer: []u8, dir: []const u8, key: [32]u8) ![]const u8 {
            return std.fmt.bufPrint(buffer, "{s}/{s}.rv64-class", .{ dir, std.fmt.bytesToHex(key, .lower) });
        }
        fn load(key: [32]u8) ?*Template {
            const dir = directory() orelse return null;
            // check mode also loads, so a persisted store can be validated against fresh plans.
            if (mode() == .off) return null;
            var timer = std.time.Timer.start() catch return null;
            const t = loadImpl(dir, key) catch |err| {
                if (err != error.FileNotFound) std.debug.print("GPU_OUTER_PLAN_CLASS store_reject class={x} error={s}\n", .{ key[0..8], @errorName(err) });
                return null;
            };
            mutex.lock();
            defer mutex.unlock();
            for (entries.items) |e| if (std.mem.eql(u8, &e.key, &key)) {
                destroy(t);
                return if (e.rejected) null else e;
            };
            if (held_bytes + t.bytes > limit()) {
                destroy(t);
                return null;
            }
            entries.append(gpa, t) catch {
                destroy(t);
                return null;
            };
            held_bytes += t.bytes;
            disk_hits += 1;
            std.debug.print("GPU_OUTER_PLAN_CLASS store_hit class={x} bytes={} load_ns={}\n", .{ key[0..8], t.bytes, timer.read() });
            return t;
        }
        fn destroy(t: *Template) void {
            gpa.free(t.seed_vars);
            gpa.free(t.constants);
            gpa.free(t.tasks);
            gpa.free(t.indices);
            gpa.free(t.level_ends);
            gpa.destroy(t);
        }
        fn loadImpl(dir: []const u8, key: [32]u8) !*Template {
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const file = try std.fs.cwd().openFile(try pathFor(&buffer, dir, key), .{});
            defer file.close();
            var header: [HEADER]u8 = undefined;
            if (try file.readAll(&header) != HEADER) return error.ClassStoreTruncated;
            if (!std.mem.eql(u8, header[0..8], MAGIC) or std.mem.readInt(u32, header[8..12], .little) != 2) return error.ClassStoreFormat;
            if (!std.mem.eql(u8, header[16..48], &key)) return error.ClassStoreKey;
            const own = try codeIdentity();
            if (!std.mem.eql(u8, header[48..80], &own)) return error.ClassStoreCodeIdentity;
            const identity = header[80..112].*;
            const n_vars = std.mem.readInt(u32, header[112..116], .little);
            var f: [6]u64 = undefined;
            for (&f, 0..) |*v, i| v.* = std.mem.readInt(u64, header[120 + 8 * i ..][0..8], .little);
            const n_constants: usize = @intCast(f[0]);
            const n_origins: usize = @intCast(f[1]);
            const limit_items: u64 = 1 << 32;
            for (f[2..]) |v| if (v > limit_items) return error.ClassStoreFormat;
            const t = try gpa.create(Template);
            errdefer gpa.destroy(t);
            const seed_vars = try gpa.alloc(u32, @intCast(f[2]));
            errdefer gpa.free(seed_vars);
            if (n_constants > seed_vars.len) return error.ClassStoreFormat;
            const constants = try gpa.alloc([4]u32, n_constants);
            errdefer gpa.free(constants);
            const tasks = try gpa.alloc(Task, @intCast(f[3]));
            errdefer gpa.free(tasks);
            const indices = try gpa.alloc(u32, @intCast(f[4]));
            errdefer gpa.free(indices);
            const level_ends = try gpa.alloc(usize, @intCast(f[5]));
            errdefer gpa.free(level_ends);
            inline for (.{ std.mem.sliceAsBytes(seed_vars), std.mem.sliceAsBytes(constants), std.mem.sliceAsBytes(tasks), std.mem.sliceAsBytes(indices), std.mem.sliceAsBytes(level_ends) }) |bytes| {
                if (try file.readAll(bytes) != bytes.len) return error.ClassStoreTruncated;
            }
            var extra: [1]u8 = undefined;
            if (try file.read(&extra) != 0) return error.ClassStoreFormat;
            const recomputed = try @import("schedule_identity.zig").digest(gpa, .{ std.mem.sliceAsBytes(tasks), std.mem.sliceAsBytes(indices), std.mem.sliceAsBytes(level_ends) });
            if (!std.mem.eql(u8, &recomputed, &identity)) return error.ClassStoreIdentity;
            const bytes = tasks.len * @sizeOf(Task) + indices.len * 4 + level_ends.len * @sizeOf(usize) + seed_vars.len * 4 + constants.len * 16;
            t.* = .{ .key = key, .n_vars = n_vars, .n_constants = n_constants, .n_origins = n_origins, .seed_vars = seed_vars, .constants = constants, .tasks = tasks, .indices = indices, .level_ends = level_ends, .identity = identity, .bytes = bytes, .persisted = true, .capability_checked = false };
            return t;
        }
        /// Service boot: loads every class template in the store (in parallel,
        /// up to the in-memory byte limit) so a cold service's first request
        /// already hits memory. Each file passes the same checks as a lazy load.
        pub fn preloadAll() !struct { loaded: usize, ns: u64 } {
            const dir_path = directory() orelse return .{ .loaded = 0, .ns = 0 };
            if (mode() == .off) return .{ .loaded = 0, .ns = 0 };
            var timer = try std.time.Timer.start();
            var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
                error.FileNotFound => return .{ .loaded = 0, .ns = 0 },
                else => return err,
            };
            defer dir.close();
            var keys: std.ArrayListUnmanaged([32]u8) = .empty;
            defer keys.deinit(gpa);
            var it = dir.iterate();
            while (try it.next()) |entry| {
                if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".rv64-class") or entry.name.len != 64 + ".rv64-class".len) continue;
                var key: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&key, entry.name[0..64]) catch continue;
                try keys.append(gpa, key);
            }
            _ = try codeIdentity();
            const Worker = struct {
                fn run(list: []const [32]u8, next: *std.atomic.Value(usize), loaded: *std.atomic.Value(usize)) void {
                    while (true) {
                        const i = next.fetchAdd(1, .monotonic);
                        if (i >= list.len) return;
                        if (load(list[i]) != null) _ = loaded.fetchAdd(1, .monotonic);
                    }
                }
            };
            var next = std.atomic.Value(usize).init(0);
            var loaded = std.atomic.Value(usize).init(0);
            var threads: [8]std.Thread = undefined;
            var spawned: usize = 0;
            while (spawned < @min(threads.len, keys.items.len)) : (spawned += 1) {
                threads[spawned] = std.Thread.spawn(.{}, Worker.run, .{ keys.items, &next, &loaded }) catch break;
            }
            Worker.run(keys.items, &next, &loaded);
            for (threads[0..spawned]) |t| t.join();
            return .{ .loaded = loaded.load(.monotonic), .ns = timer.read() };
        }
        /// Writes every template not yet on disk. Called between requests by the
        /// resident service (off the request wall). Returns bytes written.
        pub fn persistPending() !u64 {
            const dir = directory() orelse return 0;
            try std.fs.cwd().makePath(dir);
            const own = try codeIdentity();
            var written: u64 = 0;
            mutex.lock();
            defer mutex.unlock();
            for (entries.items) |t| {
                if (t.persisted) continue;
                var buffer: [std.fs.max_path_bytes]u8 = undefined;
                const final = try pathFor(&buffer, dir, t.key);
                var tmp_buffer: [std.fs.max_path_bytes]u8 = undefined;
                // Unique, exclusive temp name: two services sharing one store
                // (same driver hash) can never interleave writes into one file.
                var suffix: [8]u8 = undefined;
                std.crypto.random.bytes(&suffix);
                const tmp = try std.fmt.bufPrint(&tmp_buffer, "{s}.{s}.tmp", .{ final, std.fmt.bytesToHex(suffix, .lower) });
                errdefer std.fs.cwd().deleteFile(tmp) catch {};
                {
                    const file = try std.fs.cwd().createFile(tmp, .{ .exclusive = true });
                    defer file.close();
                    var header = std.mem.zeroes([HEADER]u8);
                    @memcpy(header[0..8], MAGIC);
                    std.mem.writeInt(u32, header[8..12], 2, .little);
                    @memcpy(header[16..48], &t.key);
                    @memcpy(header[48..80], &own);
                    @memcpy(header[80..112], &t.identity);
                    std.mem.writeInt(u32, header[112..116], t.n_vars, .little);
                    const f = [6]u64{ t.n_constants, t.n_origins, t.seed_vars.len, t.tasks.len, t.indices.len, t.level_ends.len };
                    for (f, 0..) |v, i| std.mem.writeInt(u64, header[120 + 8 * i ..][0..8], v, .little);
                    try file.writeAll(&header);
                    try file.writeAll(std.mem.sliceAsBytes(t.seed_vars));
                    try file.writeAll(std.mem.sliceAsBytes(t.constants));
                    try file.writeAll(std.mem.sliceAsBytes(t.tasks));
                    try file.writeAll(std.mem.sliceAsBytes(t.indices));
                    try file.writeAll(std.mem.sliceAsBytes(t.level_ends));
                    written += HEADER + t.bytes;
                }
                try std.fs.cwd().rename(tmp, final);
                t.persisted = true;
                disk_stores += 1;
            }
            return written;
        }
    };
    fn originCount(ctx: *const Circuit.builder.Context(Q)) usize {
        return if (ctx.witness_metadata) |m| m.origins.items.len else 0;
    }
    /// Same order as witness_plan.buildImpl: constants, then seed origins.
    fn seedsFor(a: std.mem.Allocator, t: *const Template, ctx: *const Circuit.builder.Context(Q)) ![]Seed {
        if (ctx.circuit.n_vars != t.n_vars or ctx.constants.count() != t.n_constants or originCount(ctx) != t.n_origins) return error.PlanClassShapeMismatch;
        const seeds = try a.alloc(Seed, t.seed_vars.len);
        errdefer a.free(seeds);
        var i: usize = 0;
        for (ctx.constants.keys(), ctx.constants.values()) |key, variable| {
            if (i >= seeds.len or t.seed_vars[i] != variable.idx) return error.PlanClassSeedLayout;
            seeds[i] = .{ .out = variable.idx, .value = Circuit.builder.ivalue.limbs(Circuit.builder.context.constantFromKey(key)) };
            i += 1;
        }
        for (ctx.witness_metadata.?.origins.items) |origin| if (origin.kind == .seed) {
            if (i >= seeds.len or t.seed_vars[i] != origin.out) return error.PlanClassSeedLayout;
            seeds[i] = .{ .out = origin.out, .value = Circuit.builder.ivalue.limbs(origin.value) };
            i += 1;
        };
        if (i != seeds.len) return error.PlanClassSeedLayout;
        return seeds;
    }
    fn insert(key: [32]u8, p: *const Prepared, ctx: *const Circuit.builder.Context(Q)) void {
        insertImpl(key, p, ctx) catch |err| std.debug.print("GPU_OUTER_PLAN_CLASS insert_error={s}\n", .{@errorName(err)});
    }
    fn insertImpl(key: [32]u8, p: *const Prepared, ctx: *const Circuit.builder.Context(Q)) !void {
        const n_constants = ctx.constants.count();
        if (n_constants > p.seeds.len) return error.PlanClassSeedLayout;
        const bytes = p.tasks.len * @sizeOf(Task) + p.indices.len * 4 + p.plan.level_ends.len * @sizeOf(usize) + p.seeds.len * 4 + n_constants * 16;
        mutex.lock();
        defer mutex.unlock();
        for (entries.items) |t| if (std.mem.eql(u8, &t.key, &key)) return;
        if (held_bytes + bytes > limit()) return;
        const t = try gpa.create(Template);
        errdefer gpa.destroy(t);
        const seed_vars = try gpa.alloc(u32, p.seeds.len);
        errdefer gpa.free(seed_vars);
        for (seed_vars, p.seeds) |*out, seed| out.* = seed.out;
        const constants = try gpa.alloc([4]u32, n_constants);
        errdefer gpa.free(constants);
        for (constants, p.seeds[0..n_constants]) |*out, seed| out.* = seed.value;
        const tasks = try gpa.dupe(Task, p.tasks);
        errdefer gpa.free(tasks);
        const indices = try gpa.dupe(u32, p.indices);
        errdefer gpa.free(indices);
        const level_ends = try gpa.dupe(usize, p.plan.level_ends);
        errdefer gpa.free(level_ends);
        t.* = .{ .key = key, .n_vars = ctx.circuit.n_vars, .n_constants = n_constants, .n_origins = originCount(ctx), .seed_vars = seed_vars, .constants = constants, .tasks = tasks, .indices = indices, .level_ends = level_ends, .identity = p.identity, .bytes = bytes };
        try entries.append(gpa, t);
        held_bytes += bytes;
    }
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    reference: ?[*]const Q,
    count: usize,
    plan: Schedule.Plan,
    tasks: []Task,
    indices: []u32,
    seeds: []Seed,
    identity: [32]u8,
    check_reference: bool = false,
    seed: Launch,
    level: Launch,
    timing_api: Events.Api,
    narrow_plan: ?Runs.Plan = null,
    narrow_run: ?LaunchRun = null,
    chain_run: ?LaunchChain = null,
    /// tasks/indices/plan.level_ends are owned by a ClassCache template.
    borrowed: bool = false,
    /// Class plans (folds: a template exists or will) keep their static words
    /// in the device immutable cache; a one-shot plan (a leaf: its own class)
    /// uploads them into request leases so it never evicts class entries.
    reusable: bool = true,
    pub fn init(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib) !Prepared {
        // M6 hint-tape (HT1): a seed tape replaces the graph for this class.
        if (Dev.seed_tape) |tape| return initFromTape(a, library, tape);
        const cache_mode = ClassCache.mode();
        const hint = if (cache_mode == .off) null else @import("stwo_circuit_cpu_integration").om31.device_prove.class_hint;
        var template = if (hint) |class_key| ClassCache.find(class_key) else null;
        if (template) |t| if (cache_mode == .on) {
            if (initFromCheckedTemplate(a, ctx, library, t)) |prepared| return prepared else |err| {
                // In-process templates keep the old fail-closed contract; a
                // persisted one degrades to a fresh build of this class.
                if (!t.persisted) return err;
                ClassCache.reject(t, err);
                template = null;
            }
        };
        var fresh = try initFull(a, ctx, library);
        errdefer fresh.deinit();
        if (template) |t| {
            // check mode: the template must equal the freshly built plan.
            if (!std.mem.eql(u8, std.mem.sliceAsBytes(t.tasks), std.mem.sliceAsBytes(fresh.tasks)) or !std.mem.eql(u32, t.indices, fresh.indices) or !std.mem.eql(usize, t.level_ends, fresh.plan.level_ends) or !std.mem.eql(u8, &t.identity, &fresh.identity)) return error.PlanClassMismatch;
            const seeds = try ClassCache.seedsFor(a, t, ctx);
            defer a.free(seeds);
            if (!std.mem.eql(u8, std.mem.sliceAsBytes(seeds), std.mem.sliceAsBytes(fresh.seeds))) return error.PlanClassMismatch;
            ClassCache.mutex.lock();
            ClassCache.checked += 1;
            ClassCache.mutex.unlock();
            std.debug.print("GPU_OUTER_PLAN_CLASS check_ok class={x}\n", .{t.key[0..8]});
        } else if (hint) |class_key| {
            ClassCache.insert(class_key, &fresh, ctx);
            ClassCache.mutex.lock();
            ClassCache.misses += 1;
            ClassCache.mutex.unlock();
        }
        return fresh;
    }
    fn initFromCheckedTemplate(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib, t: *ClassCache.Template) !Prepared {
        ClassCache.mutex.lock();
        const checked = t.capability_checked;
        ClassCache.mutex.unlock();
        if (!checked) {
            // Disk-loaded template: re-check every task kind against THIS library once.
            const capabilities = if (library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities")) |query| query() else 0xfff;
            for (t.tasks) |task| if (task.kind >= 32 or capabilities & (@as(u32, 1) << @intCast(task.kind)) == 0) return error.UnsupportedCircuitAssignmentHint;
            ClassCache.mutex.lock();
            t.capability_checked = true;
            ClassCache.mutex.unlock();
        }
        return initFromTemplate(a, ctx, library, t);
    }
    /// HT1: every topology byte (tasks, levels, seed variables, constants)
    /// comes from the class template; the tape supplies only the seed-origin
    /// values, in variable order. Any template doubt is a refusal (the caller
    /// then builds the ordinary graph), never a substitution.
    fn initFromTape(a: std.mem.Allocator, library: *std.DynLib, tape: *Dev.SeedTape) !Prepared {
        var timer = try std.time.Timer.start();
        const refuse = struct {
            fn f(reason: []const u8) error{SeedTapeClassMiss} {
                ClassCache.mutex.lock();
                ClassCache.tape_refusals += 1;
                ClassCache.mutex.unlock();
                std.debug.print("GPU_OUTER_SEED_TAPE refused={s}\n", .{reason});
                return error.SeedTapeClassMiss;
            }
        }.f;
        if (ClassCache.mode() != .on) return refuse("class_cache_mode");
        const class_key = Dev.class_hint orelse return refuse("no_class_hint");
        const t = ClassCache.find(class_key) orelse return refuse("no_template");
        ClassCache.mutex.lock();
        const stable = t.constants_stable and !t.rejected;
        const checked = t.capability_checked;
        ClassCache.mutex.unlock();
        if (!stable or t.constants.len != t.n_constants) return refuse("constants_unstable");
        if (t.n_constants + tape.values.len != t.seed_vars.len) {
            std.debug.print("GPU_OUTER_SEED_TAPE length_mismatch class={x} tape={} template_seed_origins={}\n", .{ t.key[0..8], tape.values.len, t.seed_vars.len - t.n_constants });
            return refuse("length");
        }
        if (!checked) {
            const capabilities = if (library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities")) |query| query() else 0xfff;
            for (t.tasks) |task| if (task.kind >= 32 or capabilities & (@as(u32, 1) << @intCast(task.kind)) == 0) return error.UnsupportedCircuitAssignmentHint;
            ClassCache.mutex.lock();
            t.capability_checked = true;
            ClassCache.mutex.unlock();
        }
        const seeds = try a.alloc(Seed, t.seed_vars.len);
        errdefer a.free(seeds);
        for (seeds[0..t.n_constants], t.seed_vars[0..t.n_constants], t.constants) |*out, variable, value| out.* = .{ .out = variable, .value = value };
        for (seeds[t.n_constants..], t.seed_vars[t.n_constants..], tape.values) |*out, variable, value| out.* = .{ .out = variable, .value = value };
        const seeds_ns = timer.lap();
        const prepared = try fromTemplateSeeds(a, library, t, seeds, null);
        tape.n_vars = t.n_vars;
        tape.consumed = true;
        ClassCache.mutex.lock();
        ClassCache.tape_hits += 1;
        ClassCache.mutex.unlock();
        std.debug.print("GPU_OUTER_ASSIGNMENT_PLAN seed_tape=true class={x} seeds_ns={} total_ns={} seeds={} task_bytes={} levels={}\n", .{ t.key[0..8], seeds_ns, timer.read(), seeds.len, t.tasks.len * @sizeOf(Task), t.level_ends.len });
        return prepared;
    }
    fn initFromTemplate(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib, t: *ClassCache.Template) !Prepared {
        var timer = try std.time.Timer.start();
        const seeds = try ClassCache.seedsFor(a, t, ctx);
        errdefer a.free(seeds);
        // HT1 premise check on every full-graph hit: the class constants are
        // the template's. A disagreement only disables the tape for the class.
        if (t.constants.len == t.n_constants) for (seeds[0..t.n_constants], t.constants) |seed, value| {
            if (!std.mem.eql(u32, &seed.value, &value)) {
                ClassCache.mutex.lock();
                t.constants_stable = false;
                ClassCache.mutex.unlock();
                std.debug.print("GPU_OUTER_SEED_TAPE constants_unstable class={x} var={}\n", .{ t.key[0..8], seed.out });
                break;
            }
        };
        const seeds_ns = timer.read();
        const prepared = try fromTemplateSeeds(a, library, t, seeds, if (ctx.trace_only) null else ctx.values().ptr);
        std.debug.print("GPU_OUTER_ASSIGNMENT_PLAN class_cache_hit=true class={x} seeds_ns={} task_bytes={} levels={}\n", .{ t.key[0..8], seeds_ns, t.tasks.len * @sizeOf(Task), t.level_ends.len });
        return prepared;
    }
    /// Takes ownership of `seeds` on success.
    fn fromTemplateSeeds(a: std.mem.Allocator, library: *std.DynLib, t: *const ClassCache.Template, seeds: []Seed, reference: ?[*]const Q) !Prepared {
        const seed = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
        const level = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
        var grouping = try Grouping.init(a, library, t.level_ends, t.tasks.len);
        errdefer if (grouping.plan) |*value| value.deinit();
        ClassCache.mutex.lock();
        ClassCache.hits += 1;
        ClassCache.mutex.unlock();
        return .{ .allocator = a, .reference = reference, .count = t.n_vars, .plan = .{ .allocator = a, .tasks = &.{}, .seeds = &.{}, .level_ends = t.level_ends }, .tasks = t.tasks, .indices = t.indices, .seeds = seeds, .identity = t.identity, .seed = seed, .level = level, .timing_api = try Events.Api.load(library), .narrow_plan = grouping.plan, .narrow_run = grouping.narrow, .chain_run = grouping.chain, .borrowed = true };
    }
    fn initFull(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), library: *std.DynLib) !Prepared {
        const seed = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
        const level = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
        var timer = try std.time.Timer.start();
        var metrics: Schedule.BuildMetrics = .{};
        var plan = try Schedule.buildProfiled(a, ctx, &metrics);
        errdefer plan.deinit();
        const plan_ns = timer.lap();
        var grouping = try Grouping.init(a, library, plan.level_ends, plan.tasks.len);
        errdefer if (grouping.plan) |*value| value.deinit();
        const narrow_plan = grouping.plan;
        const enabled = grouping.narrow_enabled or grouping.chain_enabled;
        const level_stats = if (narrow_plan) |value| value.stats else try Runs.inspect(plan.level_ends, plan.tasks.len);
        const run_plan_ns = timer.lap();
        std.debug.print("GPU_OUTER_ASSIGNMENT_LEVELS enabled={} cta_threads={} max_run_levels={} levels={} nonempty={} empty={} width_1_32={} width_33_64={} width_65_128={} width_129_256={} width_gt256={} max_width={} selected_narrow_runs={} selected_narrow_levels={} run_plan_ns={} chain={}\n", .{ enabled, Runs.threads, Runs.max_levels, level_stats.levels, level_stats.nonempty, level_stats.empty, level_stats.width_1_32, level_stats.width_33_64, level_stats.width_65_128, level_stats.width_129_256, level_stats.width_gt256, level_stats.max_width, if (narrow_plan) |value| value.narrow_runs else 0, if (narrow_plan) |value| value.narrow_levels else 0, run_plan_ns, grouping.chain_enabled });

        const tasks = try a.alloc(Task, plan.tasks.len);
        errdefer a.free(tasks);
        var indices: std.ArrayList(u32) = .empty;
        defer indices.deinit(a);
        var permutation_count: usize = 0;
        var max_permutation_inputs: usize = 0;
        var permutation_pair_work: u64 = 0;
        const capabilities = if (library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities")) |query| query() else 0xfff;
        if (ctx.circuit.permutation.ends.items.len == 0) {
            // Production graphs have no CSR permutation records. Keep every
            // output at its original plan ordinal without a second task copy.
            _ = try Pack.fill(ctx, plan.tasks, tasks, capabilities);
        } else {
            for (plan.tasks, tasks) |task, *out| {
                var ibuf: [6]u32 = undefined;
                var obuf: [4]u32 = undefined;
                const in = Schedule.inputs(ctx, task, &ibuf);
                const outputs = Schedule.outputs(ctx, task, &obuf);
                out.* = .{ .kind = @intFromEnum(task.kind), .out = outputs[0] };
                if (task.kind == .permutation) {
                    permutation_count += 1;
                    max_permutation_inputs = @max(max_permutation_inputs, in.len);
                    const count: u64 = @intCast(in.len);
                    permutation_pair_work = permutation_pair_work +| count *| count;
                    out.args[0] = std.math.cast(u32, indices.items.len) orelse return error.WitnessPlanTooLarge;
                    out.args[1] = std.math.cast(u32, in.len) orelse return error.WitnessPlanTooLarge;
                    try indices.appendSlice(a, in);
                    try indices.appendSlice(a, outputs);
                } else {
                    @memcpy(out.args[0..in.len], in);
                    if (task.kind == .hint) out.kind = switch (ctx.witness_metadata.?.origins.items[task.index].kind) {
                        .seed => return error.InvalidWitnessOrigin,
                        .inverse => 8,
                        .divide => 9,
                        .pointwise_inverse_or_zero => 10,
                        .pointwise_lsb => 11,
                        .byte => 12,
                        .byte_complement => 13,
                        .is_nonzero => 14,
                        .zero => 15,
                    };
                    if (task.kind == .hint) {
                        const hint = ctx.witness_metadata.?.origins.items[task.index];
                        if (hint.kind == .byte or hint.kind == .byte_complement) out.args[1] = hint.b;
                    }
                }
            }
            for (tasks) |task| if (capabilities & (@as(u32, 1) << @intCast(task.kind)) == 0) return error.UnsupportedCircuitAssignmentHint;
        }
        const task_pack_ns = timer.lap();
        if (std.posix.getenv("STWO_RV64_OUTER_ASSIGNMENT_CENSUS") != null) levelKindCensus(tasks, plan.level_ends);
        const seeds = try a.alloc(Seed, plan.seeds.len);
        errdefer a.free(seeds);
        for (plan.seeds, seeds) |input, *out| out.* = .{ .out = input.variable, .value = Circuit.builder.ivalue.limbs(input.value) };
        const seed_pack_ns = timer.lap();
        // This cache identity binds every generation byte. Chunking changes
        // only the private immutable-cache key, never the proof transcript.
        const identity = try @import("schedule_identity.zig").digest(a, .{ std.mem.sliceAsBytes(tasks), std.mem.sliceAsBytes(indices.items), std.mem.sliceAsBytes(plan.level_ends) });
        const hash_ns = timer.lap();
        std.debug.print("GPU_OUTER_ASSIGNMENT_PLAN plan_ns={} producer_alloc_zero_ns={} seeds_ns={} tasks_ns={} level_alloc_zero_ns={} dependency_walk_ns={} ready_tasks={} dfs_roots={} ordering_ns={} task_pack_ns={} seed_pack_ns={} hash_ns={} task_bytes={} index_bytes={} levels={} permutation_count={} max_permutation_inputs={} permutation_pair_work={}\n", .{ plan_ns, metrics.producer_init_ns, metrics.seeds_ns, metrics.tasks_ns, metrics.level_init_ns, metrics.walk_ns, metrics.ready_tasks, metrics.dfs_roots, metrics.ordering_ns, task_pack_ns, seed_pack_ns, hash_ns, tasks.len * @sizeOf(Task), indices.items.len * 4, plan.level_ends.len, permutation_count, max_permutation_inputs, permutation_pair_work });
        return .{ .allocator = a, .reference = if (ctx.trace_only) null else ctx.values().ptr, .count = ctx.circuit.n_vars, .plan = plan, .tasks = tasks, .indices = try indices.toOwnedSlice(a), .seeds = seeds, .identity = identity, .seed = seed, .level = level, .timing_api = try Events.Api.load(library), .narrow_plan = narrow_plan, .narrow_run = grouping.narrow, .chain_run = grouping.chain, .reusable = reusableClassPlan() };
    }
    /// Re-resolve kernel entry points against the adopting device's library.
    /// Plan/pack/seed/identity bytes are library independent. The same mapped
    /// image (identical entry points) needs no capability re-check.
    /// Diagnostic (STWO_RV64_OUTER_ASSIGNMENT_CENSUS=1): dependency levels by
    /// width class and by their most expensive task kind, to attribute the
    /// per-level latency of the device DAG. Host only; never changes a plan.
    fn levelKindCensus(tasks: []const Task, level_ends: []const usize) void {
        const classes = [_][]const u8{ "inverse", "permutation", "blake_g", "mul", "other" };
        var levels = [_]u64{0} ** 5;
        var level_tasks = [_]u64{0} ** 5;
        var wide_levels: u64 = 0;
        var wide_tasks: u64 = 0;
        var width1: u64 = 0;
        var begin: usize = 0;
        for (level_ends) |end| {
            defer begin = end;
            const width = end - begin;
            if (width == 0) continue;
            if (width > 2048) {
                wide_levels += 1;
                wide_tasks += width;
                continue;
            }
            width1 += @intFromBool(width == 1);
            var class: usize = 4;
            for (tasks[begin..end]) |t| {
                const c: usize = switch (t.kind) {
                    8, 9, 10 => 0,
                    7 => 1,
                    6 => 2,
                    2, 3 => 3,
                    else => 4,
                };
                class = @min(class, c);
            }
            levels[class] += 1;
            level_tasks[class] += width;
        }
        std.debug.print("GPU_OUTER_ASSIGNMENT_KINDS wide_levels={} wide_tasks={} narrow_width1={}", .{ wide_levels, wide_tasks, width1 });
        for (classes, levels, level_tasks) |name, l, t| std.debug.print(" {s}_levels={} {s}_tasks={}", .{ name, l, name, t });
        std.debug.print("\n", .{});
    }
    fn reusableClassPlan() bool {
        if (std.posix.getenv("STWO_RV64_OUTER_ASSIGNMENT_LEAF_IMMUTABLE")) |value| if (std.mem.eql(u8, value, "1")) return true;
        return @import("stwo_circuit_cpu_integration").om31.device_prove.class_hint != null;
    }
    pub fn rebind(self: *Prepared, library: *std.DynLib) !void {
        const seed = library.lookup(Launch, "stwo_circuit_assignment_seed_on") orelse return error.MissingCircuitAssignmentKernel;
        const level = library.lookup(Launch, "stwo_circuit_assignment_level_on") orelse return error.MissingCircuitAssignmentKernel;
        if (seed == self.seed and level == self.level) return;
        const capabilities = if (library.lookup(*const fn () callconv(.c) u32, "stwo_circuit_assignment_capabilities")) |query| query() else 0xfff;
        for (self.tasks) |task| if (capabilities & (@as(u32, 1) << @intCast(task.kind)) == 0) return error.UnsupportedCircuitAssignmentHint;
        const narrow_run = library.lookup(LaunchRun, "stwo_circuit_assignment_narrow_run_on");
        const chain_run = library.lookup(LaunchChain, "stwo_circuit_assignment_chain_run_on");
        if (self.narrow_plan) |plan| for (plan.runs) |run| switch (run.kind) {
            .narrow => if (narrow_run == null) return error.MissingCircuitAssignmentNarrowRunKernel,
            .chain => if (chain_run == null) return error.MissingCircuitAssignmentChainKernel,
            .ordinary => {},
        };
        self.timing_api = try Events.Api.load(library);
        self.seed = seed;
        self.level = level;
        self.narrow_run = narrow_run;
        self.chain_run = chain_run;
    }
    pub fn deinit(self: *Prepared) void {
        if (self.narrow_plan) |*value| value.deinit();
        if (self.borrowed) {
            self.allocator.free(self.seeds);
            self.* = undefined;
            return;
        }
        self.plan.deinit();
        self.allocator.free(self.tasks);
        self.allocator.free(self.indices);
        self.allocator.free(self.seeds);
        self.* = undefined;
    }
    fn key(self: *const Prepared, fixed: [32]u8, kind: u32) [8]u32 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(&fixed);
        hash.update(&self.identity);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, kind, .little);
        hash.update(&bytes);
        const digest = hash.finalResult();
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        return words;
    }
    pub fn generate(self: *const Prepared, owner: anytype, ctx: *SC.Context) !N.Lease {
        const service = owner.backend.service;
        var total_timer = try std.time.Timer.start();
        var timer = try std.time.Timer.start();
        var recorder = try Recorder.init(&self.timing_api);
        defer recorder.deinit();
        var stream: ?*anyopaque = null;
        if (owner.backend.api.lane_stream(ctx.native_context, 1, &stream) != 0 or stream == null) return error.InvalidLane;
        const lane = stream.?;
        var values = try ctx.allocate(self.count * 4, 0);
        errdefer ctx.release(&values) catch {};
        var status = try ctx.allocate(1, 0);
        defer ctx.release(&status) catch {};
        var seed_lease = try ctx.allocate(self.seeds.len * 5, 0);
        defer ctx.release(&seed_lease) catch {};
        const alloc_ns = timer.lap();
        try ctx.upload(try ctx.borrow(seed_lease), @as([*]const u32, @ptrCast(self.seeds.ptr))[0 .. self.seeds.len * 5]);
        try ctx.upload(try ctx.borrow(status), &.{0});
        var job: Job = .{ .values = values.words.?, .records = seed_lease.words.?, .indices = null, .status = @ptrCast(status.words.?), .value_count = @intCast(self.count), .record_count = @intCast(self.seeds.len), .index_count = 0, .first = 0, .count = @intCast(self.seeds.len) };
        try ctx.join();
        const seed_upload_ns = timer.lap();
        try recorder.mark(.seed, false, lane);
        if (self.seed(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
        try recorder.mark(.seed, true, lane);
        const seed_enqueue_ns = timer.lap();
        const task_words = @as([*]const u32, @ptrCast(self.tasks.ptr))[0 .. self.tasks.len * 8];
        var one_shot: [3]?N.Lease = .{ null, null, null };
        defer for (&one_shot) |*lease| if (lease.*) |*l| ctx.release(l) catch {};
        const Static = struct {
            fn words(prepared: *const Prepared, c: *SC.Context, svc: anytype, slot: *?N.Lease, fixed: [32]u8, kind: u32, data: []const u32) !N.Lease {
                if (prepared.reusable) return svc.immutableWords(c.native_context, c.scope, prepared.key(fixed, kind), data);
                slot.* = try c.allocate(data.len, 0);
                try c.upload(try c.borrow(slot.*.?), data);
                return slot.*.?;
            }
        };
        const tasks = try Static.words(self, ctx, service, &one_shot[0], owner.initial_scope.fixed, 0, task_words);
        const indices: ?N.Lease = if (self.indices.len == 0) null else try Static.words(self, ctx, service, &one_shot[1], owner.initial_scope.fixed, 1, self.indices);
        job.records = tasks.words.?;
        job.record_count = @intCast(self.tasks.len);
        if (indices) |lease| {
            job.indices = lease.words.?;
            job.index_count = @intCast(self.indices.len);
        }
        // Chain runs read the plan's absolute level ends from the device.
        var chain_ends: ?N.Lease = null;
        if (self.narrow_plan) |plan| for (plan.runs) |run| if (run.kind == .chain) {
            chain_ends = try Static.words(self, ctx, service, &one_shot[2], owner.initial_scope.fixed, 2, plan.ends);
            break;
        };
        try ctx.join();
        const static_ingress_ns = timer.lap();
        try recorder.mark(.levels, false, lane);
        var launches: usize = 1;
        var ordinary_level_calls: usize = 0;
        var narrow_run_calls: usize = 0;
        var chain_run_calls: usize = 0;
        if (self.narrow_plan) |plan| {
            for (plan.runs) |run| {
                job.first = run.first_task;
                job.count = run.task_count;
                const status_code = switch (run.kind) {
                    .narrow => blk: {
                        const function = self.narrow_run orelse return error.MissingCircuitAssignmentNarrowRunKernel;
                        narrow_run_calls += 1;
                        break :blk function(ctx.native_context, 1, &job, plan.ends[run.first_level..].ptr, run.level_count);
                    },
                    .chain => blk: {
                        const function = self.chain_run orelse return error.MissingCircuitAssignmentChainKernel;
                        const ends = chain_ends orelse return error.MissingCircuitAssignmentChainKernel;
                        chain_run_calls += 1;
                        break :blk function(ctx.native_context, 1, &job, ends.words.?, run.first_level, run.level_count);
                    },
                    .ordinary => blk: {
                        ordinary_level_calls += 1;
                        break :blk self.level(ctx.native_context, 1, &job);
                    },
                };
                if (status_code != 0) return error.CudaCircuitAssignmentFailed;
                launches += 1;
            }
        } else {
            var begin: usize = 0;
            for (self.plan.level_ends) |end| {
                if (end != begin) {
                    job.first = @intCast(begin);
                    job.count = @intCast(end - begin);
                    if (self.level(ctx.native_context, 1, &job) != 0) return error.CudaCircuitAssignmentFailed;
                    launches += 1;
                    ordinary_level_calls += 1;
                }
                begin = end;
            }
        }
        try recorder.mark(.levels, true, lane);
        const levels_enqueue_ns = timer.lap();
        // Numeric kernels use lane1 while the copy API uses stream0. A join
        // must precede status D2H; joining after enqueue alone can read old0.
        try ctx.join();
        const levels_join_ns = timer.lap();
        var flag: [1]u32 = undefined;
        try ctx.download(try ctx.borrow(status), &flag);
        try ctx.join();
        if (flag[0] != 0) return error.InvalidCircuitDeviceAssignment;
        const status_ns = timer.lap();
        if (self.check_reference) {
            const observed = try self.allocator.alloc(u32, self.count * 4);
            defer self.allocator.free(observed);
            try ctx.download(try ctx.borrow(values), observed);
            try ctx.join();
            const expected = @as([*]const u32, @ptrCast(self.reference orelse return error.CircuitAssignmentReferenceUnavailable))[0 .. self.count * 4];
            if (!std.mem.eql(u32, observed, expected)) return error.CircuitDeviceAssignmentMismatch;
        }
        const reference_readback_ns = timer.lap();
        // Event spans include enqueue starvation; they are not sums of
        // individual kernel durations. Nsight supplies the latter.
        std.debug.print("GPU_OUTER_ASSIGNMENT_TIMING total_ns={} alloc_ns={} seed_upload_ns={} seed_enqueue_ns={} static_ingress_ns={} levels_enqueue_ns={} levels_join_ns={} status_ns={} reference_readback_ns={} seed_stream_ms={d:.3} levels_stream_ms={d:.3} launches={} native_level_calls={} ordinary_level_calls={} narrow_run_calls={} chain_run_calls={}\n", .{ total_timer.read(), alloc_ns, seed_upload_ns, seed_enqueue_ns, static_ingress_ns, levels_enqueue_ns, levels_join_ns, status_ns, reference_readback_ns, try recorder.milliseconds(.seed), try recorder.milliseconds(.levels), launches, launches - 1, ordinary_level_calls, narrow_run_calls, chain_run_calls });
        std.debug.print("GPU_OUTER_ASSIGNMENT variables={} seed_words={} static_words={} levels={} full_assignment_upload_words=0\n", .{ self.count, self.seeds.len * 5, task_words.len + self.indices.len, self.plan.level_ends.len });
        return values;
    }
};

test "production trace factory refuses partial generation capability masks" {
    for ([_]u32{ 0, 0xfff, 0x7fff, 0xfffe }) |mask| try std.testing.expectError(error.UnsupportedCircuitAssignmentHint, requireProductionMask(mask));
    try requireProductionMask(0xffff);
    try requireProductionMask(0x1ffff);
}
