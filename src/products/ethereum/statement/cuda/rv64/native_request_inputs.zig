//! Install-time request authority and truth classes for the GPU-native path.
//! Native class setup is shared with native_class_build.Inventory; truth
//! declarations, FIXED bindings and execution admission reuse the receiver's
//! existing builders. No proof or expected root is borrowed from a golden run.
const std = @import("std");
const ProductCPU = @import("ethereum_cpu_component");
const CPU = @import("stwo_riscv_cpu_integration");
const core = @import("stwo_core");
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const NCB = @import("jobs/native_class_build.zig");
const B = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.driver_bind;
const RC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.recursion_classes;
const LF = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_leaf_wire;
const LB = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_leaf_build;
const LW = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_leaf_warm;
const Publication = @import("native_publication.zig");
const Bounds = CPU.rv64_gkr_source_bounds;
const S2 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage2;
const Channel = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.channel;
const TF = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.truth_factory;
const TJ = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.truth_job;
const K = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.truth_class;
const Seed = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_stage1;
const Plan = ProductCPU.rv64_ethereum_plan;
const Keys = ProductCPU.rv64_ethereum_keys.Owner;
const FixedSet = CPU.rv64_gkr_fixed_authority_set.Set;
const Execution = CPU.rv64_gkr_execution;
const WP = CPU.rv64_gkr_worker_protocol;
const Front = @import("ethereum_frontend_component").rv64_air;
const M = core.fields.m31.M31;

pub const Options = struct {
    uniform: bool = false,
    one_per_family: bool = false,
    coalesce: bool = false,
    max_log: u32 = 18,
    pub fn fromResources(v: std.json.Value) !Options {
        if (v != .object) return error.GpuNativeManifestResources;
        var out = Options{};
        inline for (.{ .{ "keccak_uniform_throughput", "uniform" }, .{ "one_truth_per_family", "one_per_family" }, .{ "coalesce_truth_families", "coalesce" } }) |pair| {
            if (v.object.get(pair[0])) |value| {
                if (value != .bool) return error.GpuNativeManifestResources;
                @field(out, pair[1]) = value.bool;
            }
        }
        if (v.object.get("keccak_max_log")) |value| {
            if (value != .integer) return error.GpuNativeManifestResources;
            out.max_log = std.math.cast(u32, value.integer) orelse return error.GpuNativeManifestResources;
        }
        return out;
    }
};

pub const Block = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    keys: ?Keys = null,
    fixed: ?FixedSet = null,
    inventory: ?Execution.Inventory = null,
    native_inputs: []S2.RequestInputs = &.{},
    truths: []TF.Request = &.{},
    bounds: ?*Bounds.Report = null,
    fn deinit(self: *Block) void {
        if (self.bounds) |value| value.deinit();
        if (self.inventory) |*i| i.deinit();
        if (self.fixed) |*f| f.deinit();
        if (self.keys) |*k| k.deinit();
        self.arena.deinit();
        self.a.destroy(self);
    }
};

pub const Binding = struct {
    a: std.mem.Allocator,
    native: *NCB.Builder,
    binding: *B.Binding,
    base: *std.DynLib,
    options: Options,
    recursion_classes: RC.Classes,
    profile: CPU.rv64_om31_security_candidate.Profile,
    blocks: std.AutoHashMapUnmanaged(u64, *Block) = .empty,
    mutex: std.Thread.Mutex = .{},
    requests: std.AutoHashMapUnmanaged(u64, *Live) = .empty,
    const Live = struct {
        arena: std.heap.ArenaAllocator,
        block: *Block,
        stage2: S2.Factory.Request = undefined,
        captured: bool = false,
        output: ?[43]u8 = null,
    };
    pub fn hooks(self: *Binding) B.InputsHooks {
        return .{ .ctx = self, .begin = begin, .planned = planned, .captured = captured, .ended = ended, .pinned = pinned, .installed = installed, .warm = warm, .publish = publish };
    }
    fn of(raw: *anyopaque) *Binding {
        return @ptrCast(@alignCast(raw));
    }
    fn publish(raw: *anyopaque, ctx: *const G.RequestContext, p: G.Publication) anyerror!void {
        const self = of(raw);
        const live = self.requests.get(ctx.request) orelse return error.GpuNativeRequestNotBegun;
        if (!live.captured) return error.GpuNativeCaptureNotFinished;
        const b = live.block;
        const inv = self.native.inventories.get(p.block) orelse return error.GpuNativeInventoryMissing;
        try Publication.write(self.a, .{ .native = inv, .truths = b.keys.?.truths, .inventory = &b.inventory.?, .native_inputs = b.native_inputs, .truth_inputs = b.truths, .recursion = self.recursion_classes, .bounds = b.bounds.?, .profile = self.profile, .keccak_uniform_throughput = self.options.uniform }, ctx, p, live.output orelse return error.GpuNativeCaptureNotFinished);
    }
    fn installed(raw: *anyopaque) anyerror!void {
        const self = of(raw);
        var it = self.blocks.valueIterator();
        while (it.next()) |b| {
            for (b.*.native_inputs) |input| if (input.leaf_program) |p| for (self.binding.registry.workers) |worker| try LW.warm(p, worker);
            for (b.*.truths) |truth| if (truth.leaf_program) |p| for (self.binding.registry.workers) |worker| try LW.warm(p, worker);
        }
        try self.recursion_classes.warm(self.binding.registry.workers);
    }
    fn warm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        const self = of(raw);
        try self.recursion_classes.relayout(cache);
        var it = self.blocks.iterator();
        while (it.next()) |kv| {
            const number = kv.key_ptr.*;
            const b = kv.value_ptr.*;
            const a = b.arena.allocator();
            const inv = self.native.inventories.get(number) orelse return error.GpuNativeInventoryMissing;
            const rec = for (self.native.blocks.items) |record| {
                if (record.block == number) break record;
            } else return error.GpuNativeInventoryMissing;
            for (b.native_inputs, rec.keys, 0..) |*input, key, i| {
                const c = try self.binding.registry.class(key);
                var fr = self.native.class(key).?.framing.?;
                // Stage 2 is a phase-A job while other segments' MAIN is
                // resident. Its actual request footprint must participate
                // in admission, alongside Stage 1's declared peak.
                var probe = S2.Stage2Job{ .a = self.a, .sym = self.binding.stage2.sym, .ctx = undefined, .class = &fr, .segment = @intCast(i), .device = 0, .seal_device = 0, .constants = undefined, .inputs = input.* };
                const peak = probe.footprint().device_words + Channel.state_words;
                // This is the quiescent warm hook, before the cache seals;
                // request-side get() intentionally exposes a const entry.
                const entry = cache.map.get(key) orelse return error.GpuNativeClassNotWarmed;
                entry.arena_peak_words = @max(entry.arena_peak_words, peak);
                const framing_entry = cache.map.get(S2.framingKey(key)) orelse return error.GpuNativeClassNotWarmed;
                framing_entry.arena_peak_words = @max(framing_entry.arena_peak_words, peak);
                std.debug.print("GPU_M8_GN_STAGE2_BUDGET block={d} segment={d} arena_peak_words={d}\n", .{ number, i, peak });
                const zero_claims = try a.alloc(core.fields.om31.OM31, fr.claim_count);
                @memset(zero_claims, core.fields.om31.OM31.zero());
                const words = try CPU.rv64_om31_cpu_leaf.expectedWords(a, inv.setup(i), inv.requests[i], b.inventory.?.first_ids[i], b.inventory.?.workers[i], @splat(0), @splat(0), @splat(0), zero_claims);
                const leaf = try self.recursion_classes.leaf(number, i);
                const program = try a.create(LF.Program);
                program.* = try LB.cpu(a, .{ .wire_words = leaf.wire_words, .image_words = leaf.image_words, .tail_seeds = leaf.tail_seeds }, c.spec.gkr, &c.section, &fr.program, try self.recursion_classes.coefficients(number, i), words, fr.claim_count);
                input.leaf_program = program;
                try cacheLeaf(cache, program);
            }
            for (b.truths, 0..) |*truth, i| {
                const leaf = try self.recursion_classes.leaf(number, rec.keys.len + i);
                const c = self.binding.truth.?.classes.get(truth.class).?.class;
                const expected = b.inventory.?.workers[rec.keys.len + i];
                const program = try a.create(LF.Program);
                program.* = try LB.truth(a, .{ .wire_words = leaf.wire_words, .image_words = leaf.image_words, .tail_seeds = leaf.tail_seeds }, &c.encode, expected.ordinal, truth.first_id, truth.calls, expected.statement, c.claim_count);
                truth.leaf_program = program;
                try cacheLeaf(cache, program);
            }
        }
    }
    fn cacheLeaf(cache: *G.ClassCache, program: *LF.Program) !void {
        const Builder = struct {
            fn build(raw: *anyopaque, _: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
                const p: *LF.Program = @ptrCast(@alignCast(raw));
                return .{ .key = key, .plan = p, .destroy = noDestroy, .held_words = @splat(std.mem.alignForward(usize, p.words.len, 64)) };
            }
            fn noDestroy(_: *anyopaque) void {}
        };
        _ = try cache.warm(program.key(), .{ .ctx = program, .build = Builder.build });
    }
    fn pinned(raw: *anyopaque) anyerror!usize {
        const self = of(raw);
        var max: usize = 0;
        for (self.native.blocks.items) |record| {
            const b = self.blocks.get(record.block) orelse return error.GpuNativeInventoryMissing;
            var words: usize = 1 << 18; // seal framing and batch metadata bound
            for (record.keys, b.native_inputs) |key, inputs| {
                const cl = try self.binding.registry.class(key);
                words += cl.requestPinnedWords();
                const framing = self.native.class(key).?.framing.?;
                words += S2.requestPinnedWords(&framing, inputs);
            }
            const factory = if (self.binding.truth) |*f| f else return error.GpuNativeTruthFactoryMissing;
            for (b.truths) |t| {
                const c = factory.classes.get(t.class).?.class;
                words += TJ.stage1Footprint(c, t.calls, 0).pinned_words;
                words += TJ.stage2RequestFootprint(c, t.calls, @intCast(c.pcs.outputWords()), @intCast(c.pcs.ingressWords())).pinned_words;
            }
            words += try self.recursion_classes.requestPinnedWords(record.block);
            max = @max(max, words);
        }
        return max;
    }
    fn begin(raw: *anyopaque, block: u64, request: u64, _: u64) anyerror!void {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.requests.contains(request)) return error.GpuNativeRequestAlreadyBegun;
        const b = self.blocks.get(block) orelse return error.GpuNativeBlockNotWarmed;
        self.binding.recursion.selectScope(block);
        const live = try self.a.create(Live);
        errdefer self.a.destroy(live);
        live.* = .{ .arena = std.heap.ArenaAllocator.init(self.a), .block = b };
        errdefer live.arena.deinit();
        const truth = if (self.binding.truth) |*f| f else return error.GpuNativeTruthFactoryMissing;
        try truth.begin(request, b.truths);
        errdefer truth.end(request) catch {};
        try self.requests.put(self.a, request, live);
    }
    fn planned(raw: *anyopaque, ctx: *const G.RequestContext) anyerror!void {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        const live = self.requests.get(ctx.request) orelse return error.GpuNativeRequestNotBegun;
        const b = live.block;
        const a = live.arena.allocator();
        const inv = &b.inventory.?;
        const count = b.native_inputs.len;
        if (ctx.truth_devices.len != b.truths.len) return error.GpuNativeTruthShape;
        const roster = try a.alloc(S2.RosterEntry, inv.workers.len);
        const flat = try a.alloc(S2.FlatEntry, inv.workers.len);
        for (inv.workers, roster, flat, 0..) |w, *r, *f, i| {
            const segment: ?u32 = if (i < count) @intCast(i) else null;
            const truth: ?u32 = if (i >= count) @intCast(i - count) else null;
            const device = if (truth) |t| ctx.truth_devices[t] else 0;
            r.* = .{ .family = if (w.chain) |c| c.family else 0, .rung = if (w.chain) |c| c.rung else 0, .vkhash = if (w.chain) |c| c.vkhash else w.fixed, .stmt = w.statement, .s_in = if (w.chain) |c| c.s_in else @splat(0), .s_out = if (w.chain) |c| c.s_out else @splat(0), .segment = segment, .truth = truth, .truth_device = device };
            f.* = .{ .kind = @intFromEnum(w.kind), .relations = @as(u32, @intFromBool(w.global_relations.ram)) | (@as(u32, @intFromBool(w.global_relations.kio)) << 1) | (@as(u32, @intFromBool(w.global_relations.wire)) << 2), .mass = .{ w.mass.ram, w.mass.kio, w.mass.wire }, .ordinal = w.ordinal, .statement = w.statement, .fixed = w.fixed, .segment = segment, .truth = truth, .truth_device = device, .local_instances = if (w.local_instances) |instances| @intCast(instances.len) else null };
        }
        live.stage2 = .{ .roster = roster, .execution = inv.execution_identity, .inputs = b.native_inputs, .flat = flat };
        try self.binding.stage2.beginRequest(ctx.request, &live.stage2);
    }
    fn captured(raw: *anyopaque, ctx: *const G.RequestContext, ce: G.CaptureEnd) anyerror!void {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        const live = self.requests.get(ctx.request) orelse return error.GpuNativeRequestNotBegun;
        if (live.captured) return error.GpuNativeCaptureEndTwice;
        const current: *const ProductCPU.rv64_ethereum_capture.Owner = @ptrCast(@alignCast(ce.owner));
        const block_inv = self.native.inventories.get(ctx.block) orelse return error.GpuNativeInventoryMissing;
        live.output = try ProductCPU.rv64_ethereum_terminal.require(block_inv.image, block_inv.requests[block_inv.requests.len - 1].base.cpu, current.advice.terminal);
        const a = live.arena.allocator();
        const values = try a.dupe(TF.Request, live.block.truths);
        for (values, live.block.keys.?.truths) |*value, truth| value.compact = try K.packCompact(a, truth, &current.advice);
        const truth = if (self.binding.truth) |*f| f else return error.GpuNativeTruthFactoryMissing;
        try truth.setCaptured(ctx.request, values);
        live.captured = true;
    }
    fn ended(raw: *anyopaque, request: u64) void {
        const self = of(raw);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.requests.fetchRemove(request)) |entry| {
            entry.value.arena.deinit();
            self.a.destroy(entry.value);
        }
    }
    pub fn deinit(self: *Binding) void {
        var requests = self.requests.valueIterator();
        while (requests.next()) |r| {
            r.*.arena.deinit();
            self.a.destroy(r.*);
        }
        self.requests.deinit(self.a);
        var it = self.blocks.valueIterator();
        while (it.next()) |b| b.*.deinit();
        self.blocks.deinit(self.a);
    }
    pub fn shape(raw: ?*anyopaque, wb: G.WarmBlock, native_keys: []const G.ClassKey) anyerror!G.RecursionShape {
        const self: *Binding = @ptrCast(@alignCast(raw.?));
        const b = try self.prepare(wb, native_keys);
        return .{ .truths = @intCast(b.truths.len), .fold_arity = 4 };
    }
    fn prepare(self: *Binding, wb: G.WarmBlock, native_keys: []const G.ClassKey) !*Block {
        if (self.blocks.get(wb.block)) |known| return known;
        const inv = self.native.inventories.get(wb.block) orelse return error.GpuNativeInventoryMissing;
        if (native_keys.len != inv.count()) return error.GpuNativeCaptureSegmentCountChanged;
        const warm_owner: *const ProductCPU.rv64_ethereum_capture.Owner = @ptrCast(@alignCast(wb.capture.owner));
        const config: *const ProductCPU.rv64_ethereum_request.Config = @ptrCast(@alignCast(wb.capture.config));
        const program: *const CPU.rv64_program.Program = @ptrCast(@alignCast(wb.capture.program));
        const b = try self.a.create(Block);
        b.* = .{ .a = self.a, .arena = std.heap.ArenaAllocator.init(self.a) };
        errdefer b.deinit();
        const a = b.arena.allocator();
        const strict = (try CPU.rv64_native_policy.current()).strictRoster();
        const canonical = false;
        const decls = try Plan.truthsWithOptions(a, warm_owner, .{ .v3 = config.execution_profile == .ethereum_services_v3, .uniform_throughput = self.options.uniform, .one_per_family = self.options.one_per_family, .coalesce_families = self.options.coalesce, .split_families = Plan.truthSplitEnabled(), .rung_bound = strict or canonical }, self.options.max_log);
        if (strict or canonical) {
            const classes = try a.alloc(Plan.CanonClass, decls.len);
            try Plan.canonicalTruths(decls, CPU.rv64_native_rungs, classes);
        }
        b.keys = try Keys.initWithSuiteAndCaches(self.a, inv.image, &.{}, decls, true, CPU.rv64_pcs_suite.Suite.experimentalFold4(), .{});
        const cpus = try a.alloc(*const NCB.Setup, inv.count());
        for (cpus, 0..) |*out, i| out.* = inv.setup(i);
        b.fixed = try FixedSet.init(self.a, &inv.fixed_cache, cpus, b.keys.?.truths, inv.config);
        const expected = try ProductCPU.rv64_ethereum_receiver.expectedFromRequests(inv.image, program.identity, inv.requests, config.max_steps, config.batch_steps, true);
        b.inventory = try Execution.Inventory.initWithAuthority(self.a, cpus, b.keys.?.truths, inv.requests, expected, inv.config, &b.fixed.?);
        const cpu_declarations = try a.alloc(CPU.rv64_gkr_bundle_wire.CpuDeclaration, cpus.len);
        for (cpu_declarations, cpus) |*declaration, setup| declaration.* = .{ .geometry = setup.materials.geometry, .bridges = setup.bridges };
        const truth_declarations = try a.alloc(CPU.rv64_gkr_bundle_wire.TruthDeclaration, b.keys.?.truths.len);
        for (truth_declarations, b.keys.?.truths) |*declaration, truth| declaration.* = CPU.rv64_gkr_bundle_wire.TruthDeclaration.from(truth);
        const bounds = try a.create(Bounds.Report);
        bounds.* = try Bounds.derive(a, program.log_size, cpu_declarations, truth_declarations, inv.requests);
        b.bounds = bounds;
        b.native_inputs = try a.alloc(S2.RequestInputs, inv.count());
        const rec = for (self.native.blocks.items) |r| {
            if (r.block == wb.block) break r;
        } else return error.GpuNativeInventoryMissing;
        for (b.native_inputs, inv.requests, 0..) |*out, request, i| out.* = .{
            .oods_diagnostic = false,
            .initial_tuples = try boundaryTuples(a, request.base.memory.initial, true),
            .terminal_tuples = try boundaryTuples(a, request.base.memory.terminal, false),
            .public = rec.public_inputs[i],
        };
        const factory = if (self.binding.truth) |*f| f else return error.GpuNativeTruthFactoryMissing;
        var added: std.ArrayListUnmanaged(G.ClassKey) = .empty;
        try added.ensureTotalCapacity(a, b.keys.?.truths.len);
        errdefer for (added.items) |key| if (factory.classes.fetchRemove(key)) |entry| {
            entry.value.class.deinit();
            self.a.destroy(entry.value.class);
        };
        b.truths = try a.alloc(TF.Request, b.keys.?.truths.len);
        for (b.keys.?.truths, b.truths, 0..) |truth, *out, i| {
            const ordinal = inv.count() + i;
            const authority = b.fixed.?.at(ordinal);
            const worker = b.inventory.?.workers[ordinal];
            const key = try K.classKey(truth, inv.config, authority.root());
            if (!factory.classes.contains(key)) {
                var scheme = try WP.Prover.init(self.a, inv.config);
                defer scheme.deinit(self.a);
                scheme.setCompactPolynomialStorage(1);
                var ch = authority.begin(inv.config, worker);
                try authority.append(self.a, truth.key(), worker.fixed, &scheme, &ch);
                const columns = scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
                const fixed = try a.alloc(K.FixedColumn, columns.len);
                for (fixed, columns) |*d, c| {
                    const words = c.coefficients();
                    d.* = .{ .log_size = c.logSize(), .words = @as([*]const u32, @ptrCast(words.ptr))[0..words.len] };
                }
                const class = try K.build(self.a, .{ .truth = truth, .config = inv.config, .fixed = fixed, .fixed_root = authority.root(), .psym = self.native.env.psym, .wide_framing = self.native.env.wide });
                errdefer {
                    class.deinit();
                    self.a.destroy(class);
                }
                try K.bindLaunches(class, self.a, self.base);
                try factory.addClass(class, 0);
                added.appendAssumeCapacity(key);
            }
            out.* = .{ .class = key, .calls = truth.count(), .first_id = truth.first(), .compact = &.{}, .seed = Seed.seedOf(authority.begin(inv.config, worker)) };
            const class = factory.classes.get(key).?.class;
            std.debug.print("GPU_M8_GN_TRUTH class={s} family={s} log={} calls={} first={} main_words={} inter_words={} comp_words={} compact_per_call={}\n", .{ std.fmt.bytesToHex(key[0..6], .lower), @tagName(truth), class.log, truth.count(), truth.first(), class.mainEvalWords(), class.inter_plan.coefficient_cells, class.composition.coefficientWords(), class.compact_words_per_call });
        }
        try self.recursion_classes.register(wb.block, &self.binding.recursion, native_keys, &self.binding.stage2, b.truths, factory, &b.inventory.?);
        for (native_keys, 0..) |key, i| {
            const suffix = try self.recursion_classes.leaf(wb.block, i);
            const pool = self.binding.stage2.classes.get(S2.framingKey(key)) orelse return error.GpuNativeClassNotWarmed;
            for (pool.instances.items) |framing| {
                if (framing.program.pcs_words != suffix.image_words) return error.GpuNativeLeafImageShape;
                const diagnostic_words = if (b.native_inputs[i].oods_diagnostic) S2.oodsDiagnosticWords(framing) else 0;
                framing.leaf_suffix_words = @max(framing.leaf_suffix_words, suffix.suffixWords() + diagnostic_words);
            }
        }
        for (b.truths, 0..) |truth, i| {
            const suffix = try self.recursion_classes.leaf(wb.block, native_keys.len + i);
            const entry = factory.classes.getPtr(truth.class).?;
            if (entry.class.pcs.outputWords() != suffix.image_words) return error.GpuNativeLeafImageShape;
            entry.max_encoded_bytes = @max(entry.max_encoded_bytes, entry.class.encode.max_encoded_bytes + 4 * suffix.suffixWords());
        }
        try self.blocks.put(self.a, wb.block, b);
        std.debug.print("GPU_M8_GN_INPUTS installed block={d} native={d} truths={d}\n", .{ wb.block, inv.count(), b.truths.len });
        return b;
    }
};

fn boundaryTuples(a: std.mem.Allocator, cells: []const Front.memory.closed_ram.types.Cell, initial: bool) ![]u32 {
    const out = try a.alloc(u32, try std.math.mul(usize, cells.len, 14));
    for (cells, 0..) |_, i| {
        const row = Front.memory.load_store_v2.native.boundaryRow(cells, i);
        const tuple = Front.memory.closed_ram.equations.ramTuple(M, if (initial) .initial else .terminal, &row, false);
        for (tuple, out[14 * i ..][0..14]) |m, *word| word.* = m.v;
    }
    return out;
}
