//! Install-only recursion class construction. The legacy producer builds
//! authorities from the actual input once; its proof/witness values are never
//! request inputs. NodeClasses.retainTemplate owns the immutable products and
//! erases dynamic seeds, public outputs and channel checkpoints. This cold
//! construction cost is included in service init, not a warm performance win.
const std = @import("std");
const Packed = @import("jobs/outer_packed_class.zig");
const CPU = @import("stwo_riscv_cpu_integration");
const Outer = @import("outer_job_factory.zig");
const G = @import("jobs/gpu_native.zig");
const O = @import("jobs/ops.zig");
const D = @import("jobs/driver_dag.zig");
const OD = @import("jobs/outer_device.zig");
const Seed = @import("jobs/outer_seed_device.zig");
const CP = @import("jobs/outer_class_plan.zig");
const St = @import("jobs/outer_staged.zig");
const Job = @import("jobs/outer_job.zig");
const TF = @import("jobs/truth_factory.zig");
const S2 = @import("jobs/native_device_stage2.zig");
const api = @import("jobs/api.zig");
const Fixed = @import("jobs/outer_fixed_job.zig");
const W = @import("jobs/worker.zig");
const RC = @import("jobs/recursion_classes.zig");

extern "c" fn setenv([*:0]const u8, [*:0]const u8, c_int) c_int;
extern "c" fn unsetenv([*:0]const u8) c_int;

const Env = struct {
    a: std.mem.Allocator,
    saved: std.ArrayListUnmanaged(struct { name: [:0]const u8, value: ?[:0]u8 }) = .empty,
    fn put(self: *Env, name: [:0]const u8, value: [:0]const u8) !void {
        const old = if (std.posix.getenv(name)) |v| try self.a.dupeZ(u8, v) else null;
        errdefer if (old) |v| self.a.free(v);
        try self.saved.append(self.a, .{ .name = name, .value = old });
        if (setenv(name, value, 1) != 0) return error.GpuNativeInstallEnvironment;
    }
    fn deinit(self: *Env) void {
        var i = self.saved.items.len;
        while (i != 0) {
            i -= 1;
            const v = self.saved.items[i];
            if (v.value) |old| {
                _ = setenv(v.name, old, 1);
                self.a.free(old);
            } else _ = unsetenv(v.name);
        }
        self.saved.deinit(self.a);
    }
};

pub const Leaf = RC.Leaf;

pub const Owner = struct {
    a: std.mem.Allocator,
    shared: Outer.Shared,
    library: []const u8 = &.{},
    manifest: []const u8 = &.{},
    spool: []const u8 = &.{},
    blocks: std.AutoHashMapUnmanaged(u64, Block) = .empty,
    classes: std.AutoHashMapUnmanaged(G.ClassKey, *Outer.NodeClasses.Entry) = .empty,
    twiddle_owner: std.AutoHashMapUnmanaged(G.ClassKey, G.ClassKey) = .empty,
    const Block = struct { nodes: []*Outer.NodeClasses.Entry, stage_one: []u8, leaves: []Leaf = &.{}, coefficient_counts: [][]u32 = &.{}, leaf_keys: []G.ClassKey = &.{}, native_count: u32 = 0 };

    pub fn init(a: std.mem.Allocator, libs: *O.Libraries, library: []const u8, manifest_path: []const u8, spool: []const u8) !*Owner {
        const self = try a.create(Owner);
        errdefer a.destroy(self);
        var env = try installEnvironment(a);
        defer env.deinit();
        const fs_path = std.posix.getenv("STWO_RV64_M8_OUTER_FS_LIBRARY") orelse return error.MissingOuterFsLibrary;
        self.* = .{ .a = a, .shared = try Outer.Shared.init(&libs.base, &libs.addon, fs_path) };
        errdefer self.deinitContents();
        self.library = try a.dupe(u8, library);
        self.spool = try a.dupe(u8, spool);
        self.manifest = try std.fs.cwd().readFileAlloc(a, manifest_path, 1 << 20);
        return self;
    }

    fn installEnvironment(a: std.mem.Allocator) !Env {
        var env = Env{ .a = a };
        errdefer env.deinit();
        try env.put("STWO_RV64_M8_GN_INSTALL", "1");
        // The legacy native PCS path publishes its readback images to the
        // install recorder. The feeder/native hybrid deliberately does not.
        try env.put("STWO_RV64_M8_JOBS", "0");
        try env.put("STWO_RV64_M8_NATIVE_JOBS", "0");
        try env.put("STWO_RV64_M8_GN_NODE", "check");
        try env.put("STWO_RV64_M8_OUTER_JOBS", "1");
        try env.put("STWO_RV64_M8_OUTER_DEVICE_CHECKS", "1");
        try env.put("STWO_RV64_M8_OUTER_DEVICE_ENCODE", "check");
        try env.put("STWO_RV64_M8_OUTER_CLASS_PLAN", "1");
        // Sample prefill is a witness-dependent host tape. The class template
        // must use the ordinary device assignment path instead.
        try env.put("STWO_RV64_BLAKE_SAMPLE_PREFILL", "0");
        // Cold class construction needs no resident MAIN across the shared
        // challenge barrier. Authenticated replay frees that overlap first.
        try env.put("STWO_RV64_GPU_REPLAY_RETAIN_PER_DEVICE", "0");
        return env;
    }

    /// Quiescent setup only: construct this block's immutable recursion
    /// authorities with the existing recorder before registering request jobs.
    pub fn prepare(self: *Owner, block: u64) !void {
        if (self.blocks.contains(block)) return;
        const a = self.a;
        const library = self.library;
        const spool = self.spool;
        const raw = self.manifest;
        var env = try installEnvironment(a);
        defer env.deinit();
        var previous = self.classes.valueIterator();
        while (previous.next()) |entry| {
            entry.*.resources_warmed = false;
            entry.*.node.require_warm = false;
            entry.*.graphs = @splat(null);
        }
        const number = std.json.Value{ .integer = std.math.cast(i64, block) orelse return error.InvalidResidentBatchManifest };
        var sub = try std.json.parseFromSlice(std.json.Value, a, raw, .{ .allocate = .alloc_always });
        defer sub.deinit();
        if (sub.value != .object) return error.InvalidResidentBatchManifest;
        const order = sub.value.object.get("execution_order") orelse return error.InvalidResidentBatchManifest;
        if (order != .array) return error.InvalidResidentBatchManifest;
        for (order.array.items) |value| {
            if (value == .integer and value.integer == number.integer) break;
        } else return error.MissingResidentBatchBlock;
        const ar = sub.arena.allocator();
        var one = std.array_list.Managed(std.json.Value).init(ar);
        try one.append(number);
        try sub.value.object.put("execution_order", .{ .array = one });
        try sub.value.object.put("repeat", .{ .integer = 1 });
        try sub.value.object.put("warm_order", .{ .array = std.array_list.Managed(std.json.Value).init(ar) });
        try sub.value.object.put("recursion_mode", .{ .string = "ready_candidate" });
        try sub.value.object.put("recursion_device_fixed_candidate", .{ .bool = true });
        const path = try std.fmt.allocPrint(a, "{s}/install-classes/{d}/manifest.json", .{ spool, block });
        defer a.free(path);
        try std.fs.cwd().makePath(std.fs.path.dirname(path).?);
        const text = try std.json.Stringify.valueAlloc(a, sub.value, .{});
        defer a.free(text);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = text });
        const output = try std.fmt.allocPrint(a, "{s}/install-classes/{d}/warm", .{ spool, block });
        defer a.free(output);
        Outer.NodeClasses.beginInstall();
        var timer = try std.time.Timer.start();
        try @import("resident_batch.zig").runCombined(a, library, path, output);
        const nodes = try Outer.NodeClasses.installedNodes(a);
        errdefer a.free(nodes);
        if (nodes.len == 0) return error.GpuNativeNoRecursionClasses;
        const packed_ingress = try Packed.ingressEnabled(std.posix.getenv(Packed.env_select));
        for (nodes) |entry| {
            if (!entry.owns_template) return error.GpuNativeBorrowedRecursionTemplate;
            const fresh = try self.classes.getOrPut(a, entry.class_key);
            if (!fresh.found_existing) {
                fresh.value_ptr.* = entry;
                entry.shared = &self.shared;
                entry.runtime_symbols = .{ .kernels = &self.shared.kernels, .whole = self.shared.whole(), .encode = self.shared.encode, .oods = self.shared.oods, .compressed = self.shared.compressed };
                entry.graphs = @splat(null);
                if (packed_ingress) {
                    const before = entry.staged.image.words[@intFromEnum(St.Region.twiddles)];
                    try entry.staged.shareTwiddleTower();
                    std.debug.print("GPU_M9_SHARED_TWIDDLE_TOWER class={s} before_words={d} after_words={d}\n", .{ std.fmt.bytesToHex(entry.class_key[0..6], .lower), before, entry.staged.image.words[@intFromEnum(St.Region.twiddles)] });
                }
                // All legacy jobs are drained. Drop its address-signature
                // plan before building the service's immutable WholePlan.
                if (entry.staged.statics.class_plan) |p| {
                    const slot: *CP.Slot = @ptrCast(@alignCast(p));
                    slot.deinit();
                }
                var job = try Job.OuterNodeJob.initWhole(entry.staged, &self.shared.kernels, self.shared.whole());
                job.deinit();
                if (packed_ingress) {
                    try Outer.NodeClasses.pack(entry);
                    const compressed = entry.compressed.?;
                    std.debug.print("GPU_M9_PACKED_CLASS class={s} logical_words={d} resident_words={d} class_words={d} fixed_words={d} twiddle_words={d} channels={d}\n", .{ std.fmt.bytesToHex(entry.class_key[0..6], .lower), compressed.outputWords(), compressed.words.len, compressed.class_words, compressed.fixed_words, entry.staged.image.words[@intFromEnum(St.Region.twiddles)], compressed.channel_count });
                }
            }
        }
        const stage_one = try std.fmt.allocPrint(a, "{s}/trial-0/{d}/proof/stage-one.bin", .{ output, block });
        errdefer a.free(stage_one);
        try self.blocks.put(a, block, .{ .nodes = nodes, .stage_one = stage_one });
        std.debug.print("GPU_M8_GN_RECURSION install_block={d} nodes={d} classes={d} construction_ns={d} witness_reused=0\n", .{ block, nodes.len, self.classes.count(), timer.read() });
        var classes = self.classes.valueIterator();
        while (classes.next()) |item| {
            item.*.graphs = @splat(null);
            const key = item.*.staged.twiddleRegionKey();
            const found = try self.twiddle_owner.getOrPut(a, key);
            if (!found.found_existing) found.value_ptr.* = item.*.class_key;
        }
    }

    fn deinitContents(self: *Owner) void {
        self.a.free(self.library);
        self.a.free(self.manifest);
        self.a.free(self.spool);
        var it = self.blocks.valueIterator();
        while (it.next()) |b| {
            self.a.free(b.nodes);
            self.a.free(b.stage_one);
            self.a.free(b.leaves);
            self.a.free(b.leaf_keys);
            for (b.coefficient_counts) |counts| self.a.free(counts);
            self.a.free(b.coefficient_counts);
        }
        self.blocks.deinit(self.a);
        self.classes.deinit(self.a);
        self.twiddle_owner.deinit(self.a);
        Outer.NodeClasses.releaseInstalled();
        self.shared.deinit();
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        self.deinitContents();
        a.destroy(self);
    }
    pub fn interface(self: *Owner) RC.Classes {
        const Hooks = struct {
            fn of(raw: *anyopaque) *Owner {
                return @ptrCast(@alignCast(raw));
            }
            fn destroy(raw: *anyopaque) void {
                of(raw).deinit();
            }
            fn prepare(raw: *anyopaque, block: u64) anyerror!void {
                return of(raw).prepare(block);
            }
            fn register(raw: *anyopaque, block: u64, registry: *OD.Recursion, native: []const G.ClassKey, stage2: *S2.Factory, truths: []const TF.Request, factory: *TF.Factory, inventory: *const CPU.rv64_gkr_execution.Inventory) anyerror!void {
                return of(raw).register(block, registry, native, stage2, truths, factory, inventory);
            }
            fn relayout(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
                return of(raw).relayout(cache);
            }
            fn warm(raw: *anyopaque, workers: []const *W.Worker) anyerror!void {
                return of(raw).warm(workers);
            }
            fn leaf(raw: *anyopaque, block: u64, index: usize) anyerror!Leaf {
                return of(raw).leaf(block, index);
            }
            fn coefficients(raw: *anyopaque, block: u64, index: usize) anyerror![]const u32 {
                return of(raw).coefficients(block, index);
            }
            fn identity(raw: *anyopaque, block: u64, index: usize) anyerror![32]u8 {
                return (try of(raw).nodeClass(block, index)).staged.statics.identity;
            }
            fn pinned(raw: *anyopaque, block: u64) anyerror!usize {
                return of(raw).requestPinnedWords(block);
            }
            const vtable = RC.Classes.VTable{ .deinit = @This().destroy, .prepare = @This().prepare, .register = @This().register, .relayout = @This().relayout, .warm = @This().warm, .leaf = @This().leaf, .coefficients = @This().coefficients, .identity = @This().identity, .pinned = @This().pinned };
        };
        return .{ .ctx = self, .vtable = &Hooks.vtable };
    }

    pub fn leaf(self: *const Owner, block: u64, index: usize) !Leaf {
        const b = self.blocks.get(block) orelse return error.GpuNativeBlockNotWarmed;
        if (index >= b.leaves.len) return error.GpuNativeRecursionInstallTopology;
        return b.leaves[index];
    }
    pub fn coefficients(self: *const Owner, block: u64, index: usize) ![]const u32 {
        const b = self.blocks.get(block) orelse return error.GpuNativeBlockNotWarmed;
        if (index >= b.coefficient_counts.len) return error.GpuNativeRecursionInstallTopology;
        return b.coefficient_counts[index];
    }
    pub fn nodeClass(self: *const Owner, block: u64, index: usize) !*const Outer.NodeClasses.Entry {
        const b = self.blocks.get(block) orelse return error.GpuNativeBlockNotWarmed;
        if (index >= b.nodes.len) return error.GpuNativeRecursionInstallTopology;
        return b.nodes[index];
    }

    /// The slab uses the maximum capacity of a physical class over all
    /// installed blocks. Place each leaf suffix against that final capacity,
    /// so a shorter tape in another block cannot shift the parent's image.
    pub fn relayout(self: *Owner, cache: *G.ClassCache) !void {
        var it = self.blocks.valueIterator();
        while (it.next()) |b| {
            for (b.leaves, b.leaf_keys) |*value, key| {
                const entry = try cache.get(key);
                const region = 1 + (std.math.divCeil(usize, entry.max_encoded_bytes, 4) catch unreachable);
                if (region <= value.suffixWords()) return error.GnNodeChildRegion;
                value.wire_words = @intCast(region - value.suffixWords());
            }
            var topo = try D.Topology.carry(self.a, b.native_count, @intCast(b.leaves.len - b.native_count), 4);
            defer topo.deinit();
            for (topo.nodes, b.nodes) |node, entry| {
                var regions: [Seed.max_children]u32 = undefined;
                var n: usize = 0;
                if (node.children.len == 0) {
                    const index = if (node.segments.len == 1) node.segments[0] else b.native_count + node.truths[0];
                    regions[0] = try b.leaves[index].regionWords();
                    n = 1;
                } else for (node.children) |child| {
                    const info = try cache.get(b.nodes[child].class_key);
                    regions[n] = @intCast(1 + (std.math.divCeil(usize, info.max_encoded_bytes, 4) catch unreachable));
                    n += 1;
                }
                const old_words = entry.program.len;
                try entry.programFor(regions[0..n]);
                if (entry.program.len != old_words) return error.GpuNativeRecursionProgramShapeChanged;
            }
        }
    }

    pub fn requestPinnedWords(self: *const Owner, block: u64) !usize {
        const b = self.blocks.get(block) orelse return error.GpuNativeBlockNotWarmed;
        var total: usize = 0;
        for (b.nodes) |entry| {
            var job = try Job.OuterNodeJob.initWhole(entry.staged, &self.shared.kernels, self.shared.whole());
            defer job.deinit();
            job.require_warm = true;
            total += job.footprint().pinned_words + entry.program.len;
        }
        return total;
    }

    /// FIXED coefficients, class images, twiddles and encoder/seed programs
    /// become persistent on each worker. Only the immutable FIXED commitment
    /// executes; no warm proof assignment or output is used as a request input.
    pub fn warm(self: *Owner, workers: []const *W.Worker) !void {
        var it = self.classes.valueIterator();
        while (it.next()) |item| {
            const entry = item.*;
            entry.resources_warmed = false;
            entry.node.require_warm = false;
            if (entry.program.len == 0) return error.GpuNativeRecursionInstallTopology;
            for (workers, 0..) |worker, device| {
                var warm_job = try Warm.init(self, entry, @intCast(device));
                defer warm_job.deinit();
                var done = struct {
                    event: std.Thread.ResetEvent = .{},
                    result: anyerror!void = {},
                    fn call(raw: *anyopaque, c: api.Completion) void {
                        const me: *@This() = @ptrCast(@alignCast(raw));
                        me.result = c.result;
                        me.event.set();
                    }
                }{};
                try worker.submit(api.Job.from(Warm, &warm_job), .{ .ctx = &done, .done = @TypeOf(done).call });
                done.event.wait();
                try done.result;
                std.debug.print("GPU_M8_GN_RECURSION warm_class={s} device={d} fixed_root_equal=1\n", .{ std.fmt.bytesToHex(entry.class_key[0..6], .lower), device });
            }
            entry.resources_warmed = true;
            entry.node.require_warm = true;
        }
    }

    /// Called after the native and truth builders, before ClassCache.warm.
    /// The topology and child capacities are class data; no proof value is
    /// borrowed from the install request.
    pub fn register(self: *Owner, block: u64, registry: *OD.Recursion, native: []const G.ClassKey, stage2: *S2.Factory, truths: []const TF.Request, truth_factory: *TF.Factory, inventory: *const CPU.rv64_gkr_execution.Inventory) !void {
        const b = self.blocks.getPtr(block) orelse return error.GpuNativeBlockNotWarmed;
        registry.selectScope(block);
        const leaf_keys = try self.a.alloc(G.ClassKey, native.len + truths.len);
        errdefer self.a.free(leaf_keys);
        @memcpy(leaf_keys[0..native.len], native);
        for (truths, leaf_keys[native.len..]) |truth, *key| key.* = truth.class;
        // Polynomial lengths affect the circuit's class. Retain ONLY those
        // lengths; discard the independently framed warm proof values here.
        const raw = try std.fs.cwd().readFileAlloc(self.a, b.stage_one, CPU.rv64_gkr_manifest_wire.MAX_BYTES);
        defer self.a.free(raw);
        var manifest = try CPU.rv64_gkr_manifest_wire.decode(self.a, inventory.execution_identity, inventory.workers, raw);
        defer manifest.deinit();
        const counts = try self.a.alloc([]u32, native.len);
        var counted: usize = 0;
        errdefer {
            for (counts[0..counted]) |c| self.a.free(c);
            self.a.free(counts);
        }
        for (counts, manifest.stages[0..native.len]) |*out, stage| {
            var values: std.ArrayListUnmanaged(u32) = .empty;
            errdefer values.deinit(self.a);
            const local = stage.local orelse return error.WideCpuLocalRequired;
            for (local.proof.sumcheck_proofs) |sumcheck| for (sumcheck.round_polys) |poly| {
                const n = poly.coeffsSlice().len;
                if (n > 4) return error.GpuNativeRecursionPolynomialShape;
                try values.append(self.a, @intCast(n));
            };
            out.* = try values.toOwnedSlice(self.a);
            counted += 1;
        }
        var topo = try D.Topology.carry(self.a, @intCast(native.len), @intCast(truths.len), 4);
        defer topo.deinit();
        if (topo.nodes.len != b.nodes.len) return error.GpuNativeRecursionInstallTopology;
        const leaves = try self.a.alloc(Leaf, native.len + truths.len);
        errdefer self.a.free(leaves);
        const keys = try self.a.alloc(G.ClassKey, b.nodes.len);
        defer self.a.free(keys);
        const bounds = try self.a.alloc(u32, b.nodes.len);
        defer self.a.free(bounds);
        for (topo.nodes, b.nodes, 0..) |node, entry, ordinal| {
            var child_keys: [Seed.max_children]G.ClassKey = undefined;
            var regions: [Seed.max_children]u32 = undefined;
            var n: usize = 0;
            const is_leaf = node.children.len == 0;
            if (is_leaf != entry.leaf) return error.GpuNativeRecursionInstallTopology;
            if (is_leaf) {
                if (node.segments.len + node.truths.len != 1) return error.GpuNativeRecursionInstallTopology;
                const index = if (node.segments.len == 1) node.segments[0] else native.len + node.truths[0];
                var cursor: usize = 0;
                const shape = try Seed.Shape.parse(self.a, entry.shapes[0], &cursor);
                defer self.a.free(shape.trees);
                const wire_bytes = if (index < native.len) blk: {
                    child_keys[0] = native[index];
                    const pool = stage2.classes.get(S2.framingKey(native[index])) orelse return error.GpuNativeClassNotWarmed;
                    break :blk pool.instances.items[0].program.max_encoded_bytes;
                } else blk: {
                    const t = index - native.len;
                    child_keys[0] = truths[t].class;
                    break :blk truth_factory.classes.get(truths[t].class).?.class.encode.max_encoded_bytes;
                };
                leaves[index] = .{ .wire_words = @intCast(1 + (std.math.divCeil(usize, wire_bytes, 4) catch unreachable)), .image_words = @intCast((try Seed.Layout.of(shape)).words), .tail_seeds = entry.tail, .output_words = @intCast(entry.staged.expected.len) };
                regions[0] = try leaves[index].regionWords();
                n = 1;
            } else {
                for (node.children) |child| {
                    if (n == Seed.max_children or child >= ordinal) return error.GpuNativeRecursionInstallTopology;
                    child_keys[n] = keys[child];
                    regions[n] = bounds[child];
                    n += 1;
                }
            }
            try entry.programFor(regions[0..n]);
            keys[ordinal] = entry.class_key;
            bounds[ordinal] = @intCast(1 + (std.math.divCeil(usize, entry.max_encoded_bytes, 4) catch unreachable));
            // Build the actual encoded-node footprint at placeholder targets.
            // No device call or request witness is involved.
            const dummy = api.DeviceBuffer{ .ptr = @ptrFromInt(64), .words = bounds[ordinal] };
            const made = try entry.node.make(entry.node.ctx, self.a, .{ .region = dummy, .pcs_status = dummy, .encode_status = dummy, .oods_status = dummy });
            defer made.destroy(made.ctx);
            var fp = made.job.footprint();
            fp.device_words += std.mem.alignForward(usize, @as(usize, entry.program[Seed.P.scratch_words]) + 8, 64);
            for (regions[0..n]) |words| fp.device_words += std.mem.alignForward(usize, words, 64);
            var held: u64 = entry.desc.len + entry.oods_program.len + entry.program.len;
            if (entry.compressed) |compressed| {
                held += compressed.words.len;
                if (std.mem.eql(u8, &(self.twiddle_owner.get(entry.staged.twiddleRegionKey()).?), &entry.class_key)) held += entry.staged.image.words[@intFromEnum(St.Region.twiddles)];
            } else {
                held += entry.staged.image.words[@intFromEnum(St.Region.class)] + entry.staged.image.words[@intFromEnum(St.Region.twiddles)];
                if (entry.staged.statics.fixed_plan) |fixed| held += fixed.coefficient_words;
            }
            const devices: [G.max_devices]u64 = @splat(held);
            const kind: G.ProofKind = if (is_leaf) .leaf else if (ordinal == topo.root) .root else .fold;
            // driver_dag's ready order runs every native Stage2 before any
            // recursion node. InFlight also checks this phase requirement
            // against its actual DAG, before any request job is made.
            try registry.register(.{ .kind = kind, .ordinal = @intCast(ordinal) }, child_keys[0..n], entry.class_key, .{ .plan = @ptrCast(@constCast(entry.staged.statics)), .encode_descriptor = entry.desc, .max_encoded_bytes = entry.max_encoded_bytes, .held_words = devices, .arena_peak_words = fp.device_words, .phase_b = true, .node = &entry.node, .extra_checks = if (entry.compressed != null) &.{.class_unpack} else &.{} });
        }
        self.a.free(b.leaves);
        b.leaves = leaves;
        self.a.free(b.leaf_keys);
        b.leaf_keys = leaf_keys;
        b.native_count = @intCast(native.len);
        for (b.coefficient_counts) |c| self.a.free(c);
        self.a.free(b.coefficient_counts);
        b.coefficient_counts = counts;
    }
};

const Warm = struct {
    entry: *Outer.NodeClasses.Entry,
    made: OD.Made,
    fixed: Fixed.FixedJob,
    pub fn init(owner: *Owner, entry: *Outer.NodeClasses.Entry, device: u32) !Warm {
        const plan = if (entry.staged.statics.fixed_plan) |*p| p else return error.OuterJobWholeStagingMissing;
        const tw = try entry.staged.statics.table(plan.eval_log);
        var fixed = try Fixed.FixedJob.init(.{ .plan = plan, .raw = entry.staged.fixed_raw, .sorted_logs = entry.staged.statics.fixed_sorted_logs, .twiddles = tw.twiddles, .itwiddles = tw.itwiddles }, &owner.shared.kernels);
        if (entry.compressed == null) fixed.handoff = .{ .key = entry.staged.fixedRegionKey(), .words = @intCast(plan.coefficient_words) };
        const dummy = api.DeviceBuffer{ .ptr = @ptrFromInt(64), .words = 1 + (std.math.divCeil(usize, entry.max_encoded_bytes, 4) catch unreachable) };
        const made = try entry.node.make(entry.node.ctx, owner.a, .{ .device = device, .region = dummy, .pcs_status = dummy, .encode_status = dummy, .oods_status = dummy });
        return .{ .entry = entry, .made = made, .fixed = fixed };
    }
    pub fn deinit(self: *Warm) void {
        self.made.destroy(self.made.ctx);
    }
    pub fn classKey(self: *Warm) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("rv64/m8/native-recursion/install/v1");
        hash.update(&self.entry.class_key);
        return hash.finalResult();
    }
    pub fn footprint(self: *Warm) api.Footprint {
        var fp = self.fixed.footprint();
        const inner = self.made.job.footprint();
        fp.device_words += inner.staged_words;
        fp.staged_words += inner.staged_words;
        fp.pinned_words += inner.pinned_words + self.entry.program.len;
        return fp;
    }
    pub fn stage(self: *Warm, s: *api.Stager) !void {
        try self.fixed.stage(s);
        try self.made.job.vtable.stage(self.made.job.ctx, s);
        const program = try s.persistent(self.entry.node.prog_key, self.entry.program.len);
        if (program.fresh) try s.upload(program.buffer, self.entry.program);
    }
    pub fn enqueue(self: *Warm, e: *api.Enqueue) !void {
        return self.fixed.enqueue(e);
    }
    pub fn finish(self: *Warm, view: api.SlabView) !void {
        try self.fixed.finish(view);
        const root = self.fixed.root orelse return error.GpuNativeRecursionFixedCold;
        if (!std.mem.eql(u8, &root, &self.entry.staged.fixed_root)) return error.GpuNativeRecursionFixedRootMismatch;
    }
    pub fn abort(_: *Warm) void {}
};

test "class setup owns the replay barrier policy and restores the caller environment" {
    const a = std.testing.allocator;
    const name = "STWO_RV64_GPU_REPLAY_RETAIN_PER_DEVICE";
    const before = std.process.getEnvVarOwned(a, name) catch |err| if (err == error.EnvironmentVariableNotFound) null else return err;
    defer if (before) |value| a.free(value);
    {
        var env = try Owner.installEnvironment(a);
        defer env.deinit();
        try std.testing.expectEqualStrings("0", std.posix.getenv(name).?);
    }
    const after = std.process.getEnvVarOwned(a, name) catch |err| if (err == error.EnvironmentVariableNotFound) null else return err;
    defer if (after) |value| a.free(value);
    try std.testing.expectEqualDeep(before, after);
}
