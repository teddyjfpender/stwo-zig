//! `combined-serve` entry under STWO_RV64_M8_GPU_NATIVE=1 (driver): the GE
//! direct capture as the service's CaptureSource, the real device factories,
//! and the GPU-native service (driver_serve.zig).
//!
//! The capture is the request path's only CPU compute (H1) and it streams:
//! the ordered owner's per-segment readiness hook (`Capture.Ready.call` +
//! `.native_segment`) hands each finished segment to Stream.Feed, which packs
//! it through the native factory into pinned ring chunks and seals it, so
//! that segment's Stage1 stages and enqueues while the capture continues.
//! Per block, the request config, expected image and capture program are
//! built ONCE at explicit setup (immutable inputs of subsequent captures).
//!
//! Requests use the GPU-native driver. Installation still constructs legacy
//! authorities/classes through Host.installRecursion and the class builder;
//! their construction cost and ownership are separate from served requests.
//!
//! Factories: driver_bind.Binding (S1 Registry + S2 Factory into
//! native_device.Native, truth_factory as the two-stage truths, outer_device
//! for nodes). The install sequence binds capture shape, request inputs,
//! recursion shape and node ops before Service.install warms classes and
//! reserves resources. Missing registrations fail explicitly; no served
//! request falls back to legacy proving.
const std = @import("std");
const Packed = @import("outer_packed_class.zig");
const CPU = @import("stwo_riscv_cpu_integration");
const engine = @import("stwo_prover_engine");
const G = @import("gpu_native.zig");
const O = @import("ops.zig");
const W = @import("worker.zig");
const R = @import("driver_request.zig");
const S = @import("driver_serve.zig");
const C = @import("../m8_capture_stream.zig");
const mod = @import("mod.zig");
const B = @import("driver_bind.zig");
const NCB = @import("native_class_build.zig");
const NGl = @import("native_global.zig");
const NP = @import("native_pcs.zig");
const Sources = @import("../gkr_sources.zig");
const CaptureBinding = @import("../native_capture_bind.zig");
const RequestInputs = @import("../native_request_inputs.zig");

const Request = CPU.rv64_ethereum_request;
const Image = CPU.rv64_expected_image;
const Program = CPU.rv64_program.Program;
const Metadata = CPU.rv64_program_metadata;
const Direct = CPU.rv64_ethereum_direct;
const Capture = CPU.rv64_ethereum_capture;
const CaptureOptions = CPU.rv64_ethereum_capture_options.Options;
const Plan = CPU.rv64_ethereum_plan;

// Hook parameter types, taken from the GE Ready contract itself.
const CallFn = @typeInfo(@FieldType(Capture.Ready, "call")).pointer.child;
const Native = @typeInfo(@typeInfo(CallFn).@"fn".params[2].type.?).pointer.child;
const Events = @typeInfo(CallFn).@"fn".params[3].type.?;
const SegmentFn = @typeInfo(@typeInfo(@FieldType(Capture.Ready, "native_segment")).optional.child).pointer.child;
const Shard = @typeInfo(SegmentFn).@"fn".params[3].type.?;

const ManifestBlock = struct { request: []const u8, jobs: []const u8 = "-", prefix_count: u32 = 0, expected_cpu_segments: usize = 0 };
const Manifest = struct {
    schema: []const u8,
    profile: []const u8 = "d2_native_b4_q54_p20_fold4",
    blocks: std.json.ArrayHashMap(ManifestBlock),
    execution_order: []const u64,
    resources: std.json.Value,
};

/// Worker stack of the capture work pool (the legacy receiver budget's
/// WORKER_STACK_BYTES, 1 MiB).
const pool_stack_bytes: usize = 1 << 20;

pub const Source = struct {
    a: std.mem.Allocator,
    blocks: []Block,
    metadata: Metadata.Cache,
    options: CaptureOptions,
    /// Service constants of the native class builder (manifest).
    profile: CPU.rv64_om31_security_candidate.Profile,
    gkr_bytes: usize,
    fixed_setup_bytes: usize,
    inputs_options: RequestInputs.Options = .{},
    /// One capture work pool per in-flight request (TLS-bound on its capture
    /// thread) plus one for install-time warm captures.
    pools: [3]*engine.work_pool.WorkPool,
    pool_busy: [2]bool = .{ false, false },
    mutex: std.Thread.Mutex = .{},

    const Block = struct {
        number: u64,
        config: std.json.Parsed(Request.Config),
        image: ?Image.Owner = null,
        program: ?Program = null,
        warm: ?Capture.Owner = null,
    };

    pub fn init(a: std.mem.Allocator, manifest_path: []const u8) !*Source {
        const raw = try std.fs.cwd().readFileAlloc(a, manifest_path, 1 << 20);
        defer a.free(raw);
        var parsed = try std.json.parseFromSlice(Manifest, a, raw, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        const m = parsed.value;
        if (!std.mem.eql(u8, m.schema, "rv64-ethereum-basket-inputs/v1") or m.execution_order.len == 0) return error.InvalidResidentBatchManifest;
        var options = CaptureOptions{};
        if (m.resources == .object) if (m.resources.object.get("capture_options")) |v| {
            const o = try std.json.parseFromValue(CaptureOptions, a, v, .{ .ignore_unknown_fields = true });
            defer o.deinit();
            options = o.value;
        };
        try options.validate();
        const self = try a.create(Source);
        errdefer a.destroy(self);
        self.* = .{ .a = a, .blocks = &.{}, .metadata = try Metadata.Cache.init(a, 64 << 20), .options = options, .pools = undefined, .profile = try CPU.rv64_om31_security_candidate.Profile.parse(m.profile), .gkr_bytes = resourceUsize(m.resources, "gkr_bytes") orelse return error.GpuNativeManifestNoGkrBytes, .fixed_setup_bytes = resourceUsize(m.resources, "fixed_setup_bytes") orelse (4 << 30) };
        errdefer self.metadata.deinit();
        self.inputs_options = try RequestInputs.Options.fromResources(m.resources);
        var unique: std.ArrayListUnmanaged(u64) = .empty;
        defer unique.deinit(a);
        for (m.execution_order) |b| if (std.mem.indexOfScalar(u64, unique.items, b) == null) try unique.append(a, b);
        const blocks = try a.alloc(Block, unique.items.len);
        var made: usize = 0;
        errdefer {
            for (blocks[0..made]) |*b| freeBlock(b);
            a.free(blocks);
        }
        var workers: usize = 1;
        for (unique.items, blocks) |number, *b| {
            var name: [24]u8 = undefined;
            const item = m.blocks.map.get(try std.fmt.bufPrint(&name, "{d}", .{number})) orelse return error.MissingResidentBatchBlock;
            // GPU-native requests are complete direct executions.
            if (item.prefix_count != 0 or !std.mem.eql(u8, item.jobs, "-")) return error.CombinedRequiresCompleteDirectExecution;
            const text = try std.fs.cwd().readFileAlloc(a, item.request, 16384);
            defer a.free(text);
            // alloc_always: the config's strings (elf/input/output paths) must
            // not borrow `text`, which is freed below while the block (and its
            // warm and per-request captures) keeps the config.
            var config = try std.json.parseFromSlice(Request.Config, a, text, .{ .allocate = .alloc_always });
            errdefer config.deinit();
            // The capture writes its artifacts under output_directory (the
            // legacy resident path creates it before its first request).
            if (config.value.output_directory.len != 0) try std.fs.cwd().makePath(config.value.output_directory);
            workers = @max(workers, try Request.effectiveWorkers(config.value));
            b.* = .{ .number = number, .config = config };
            made += 1;
        }
        self.blocks = blocks;
        var pools_made: usize = 0;
        errdefer for (self.pools[0..pools_made]) |p| {
            p.deinit();
            a.destroy(p);
        };
        for (&self.pools) |*p| {
            p.* = try a.create(engine.work_pool.WorkPool);
            p.*.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = pool_stack_bytes, .backing_allocator = a }) catch |err| {
                a.destroy(p.*);
                return err;
            };
            pools_made += 1;
        }
        return self;
    }
    fn freeBlock(b: *Block) void {
        if (b.warm) |*w| w.deinit();
        if (b.program) |*program| program.deinit();
        if (b.image) |*image| image.deinit();
        b.config.deinit();
    }
    pub fn deinit(self: *Source) void {
        for (self.blocks) |*b| freeBlock(b);
        self.a.free(self.blocks);
        for (self.pools) |p| {
            p.deinit();
            self.a.destroy(p);
        }
        self.metadata.deinit();
        self.a.destroy(self);
    }
    pub fn blockNumbers(self: *const Source, a: std.mem.Allocator) ![]u64 {
        const out = try a.alloc(u64, self.blocks.len);
        for (self.blocks, out) |b, *o| o.* = b.number;
        return out;
    }
    fn find(self: *Source, number: u64) !*Block {
        for (self.blocks) |*b| if (b.number == number) return b;
        return error.MissingResidentBatchBlock;
    }

    pub fn source(self: *Source) S.CaptureSource {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable = S.CaptureSource.VTable{ .warm = warm, .release_warm = releaseWarm, .start = start, .join = join };
    fn of(raw: *anyopaque) *Source {
        return @ptrCast(@alignCast(raw));
    }

    /// Run one capture of `b` on the calling thread (`ready` = streaming hook).
    fn captureBlock(self: *Source, b: *Block, ready: ?Capture.Ready) !Capture.Owner {
        var stats: Direct.Stats = .{};
        const started = Direct.Started.startWithAuthority(self.a, b.config.value, 0, self.options.execution_workers, null) catch |err| {
            std.debug.print("GPU_M8_GN_BIND capture_stage=start block={d} error={s}\n", .{ b.number, @errorName(err) });
            return err;
        };
        defer started.deinit(&stats);
        started.ready = ready;
        return started.capture(&b.image.?, &b.program.?, self.options.max_inflight_packets, &stats) catch |err| {
            std.debug.print("GPU_M8_GN_BIND capture_stage=capture block={d} error={s}\n", .{ b.number, @errorName(err) });
            return err;
        };
    }
    fn endOf(b: *Block, owner: *const Capture.Owner) G.CaptureEnd {
        return .{ .segments = @intCast(owner.native.items.len), .owner = owner, .image = &b.image.?, .program = &b.program.?, .config = &b.config.value };
    }

    fn warm(raw: *anyopaque, number: u64) anyerror!G.CaptureEnd {
        const self = of(raw);
        const b = try self.find(number);
        if (b.image == null) {
            var image = try Image.Owner.init(self.a, b.config.value);
            errdefer image.deinit();
            var program = try Program.initCaptureWithAuthorityAndMetadataCache(self.a, &image.authority, &self.metadata);
            errdefer program.deinit();
            if (Plan.CpuLayout.forGkrProfile(b.config.value.execution_profile).compact_decode) try program.makeCompact();
            b.image = image;
            b.program = program;
        }
        if (b.warm) |*w| w.deinit();
        b.warm = null;
        var binding = try engine.work_pool.ScopedPoolBinding.init(self.pools[2]);
        defer binding.deinit();
        b.warm = self.captureBlock(b, null) catch |err| {
            std.debug.print("GPU_M8_GN_BIND warm_capture_failed block={d} error={s}\n", .{ number, @errorName(err) });
            return err;
        };
        std.debug.print("GPU_M8_GN_BIND warm_capture block={d} segments={d}\n", .{ number, b.warm.?.native.items.len });
        return endOf(b, &b.warm.?);
    }
    fn releaseWarm(raw: *anyopaque, number: u64) void {
        // CaptureBinding's install inventory borrows boundary RAM and setup
        // views. Source owns the warm capture until service teardown.
        _ = raw;
        _ = number;
    }

    /// One request's capture thread and its streaming hook state.
    const Run = struct {
        src: *Source,
        block: *Block,
        stream: *C.Stream,
        feed: C.Feed,
        pool: usize,
        owner: ?Capture.Owner = null,
        thread: std.Thread = undefined,
        /// Events of the segment `call` just reported (consumed by the
        /// `native_segment` that follows it on the same thread).
        events: ?Events = null,
        events_index: usize = 0,

        fn readyCall(ctx: *anyopaque, index: usize, _: *const Native, events: Events, _: u64) void {
            const run: *Run = @ptrCast(@alignCast(ctx));
            run.events = events;
            run.events_index = index;
        }
        fn readySegment(ctx: *anyopaque, index: usize, native: *const Native, shard: Shard, at_ns: u64) void {
            const run: *Run = @ptrCast(@alignCast(ctx));
            if (run.events == null or run.events_index != index) {
                run.feed.abort(error.GpuNativeCaptureEventsMissing);
                return;
            }
            const events = run.events.?;
            var shard_copy = shard;
            // Errors already failed the stream (every unreleased Stage1 and
            // the end gate fail closed); the capture runs to its end.
            run.feed.segment(.{ .segment = @intCast(index), .native = native, .events = @ptrCast(&events), .shard = @ptrCast(&shard_copy), .at_ns = at_ns }) catch {};
            run.events = null;
        }
        fn readyCancel(ctx: *anyopaque) void {
            const run: *Run = @ptrCast(@alignCast(ctx));
            run.feed.abort(error.GpuNativeCaptureCancelled);
        }
        fn main(run: *Run) void {
            const src = run.src;
            var binding = engine.work_pool.ScopedPoolBinding.init(src.pools[run.pool]) catch |err| return run.feed.finish(err);
            defer binding.deinit();
            const ready = Capture.Ready{ .context = run, .call = readyCall, .native_segment = readySegment, .cancel = readyCancel, .seal_native = true };
            run.owner = src.captureBlock(run.block, ready) catch |err| return run.feed.finish(err);
            run.feed.end(endOf(run.block, &run.owner.?)) catch {};
            run.feed.finish(null);
        }
    };

    fn start(raw: *anyopaque, number: u64, stream: *C.Stream) anyerror!*anyopaque {
        const self = of(raw);
        const b = try self.find(number);
        if (b.image == null or b.program == null or b.warm == null) return error.GpuNativeBlockNotWarmed;
        const pool: usize = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (&self.pool_busy, 0..) |*busy, i| if (!busy.*) {
                busy.* = true;
                break :blk i;
            };
            return error.GpuNativePipelineFull;
        };
        errdefer self.freePool(pool);
        const run = try self.a.create(Run);
        errdefer self.a.destroy(run);
        run.* = .{ .src = self, .block = b, .stream = stream, .feed = stream.feed(), .pool = pool };
        run.thread = try std.Thread.spawn(.{}, Run.main, .{run});
        return run;
    }
    fn freePool(self: *Source, pool: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.pool_busy[pool] = false;
    }
    fn join(raw: *anyopaque, handle: *anyopaque) void {
        const self = of(raw);
        const run: *Run = @ptrCast(@alignCast(handle));
        run.thread.join();
        if (run.owner) |*o| o.deinit();
        self.freePool(run.pool);
        self.a.destroy(run);
    }
};

fn resourceUsize(resources: std.json.Value, name: []const u8) ?usize {
    if (resources != .object) return null;
    const v = resources.object.get(name) orelse return null;
    return switch (v) {
        .integer => |i| if (i < 0) null else @intCast(i),
        else => null,
    };
}

fn envUnsigned(name: []const u8, default: u64) !u64 {
    const v = std.posix.getenv(name) orelse return default;
    return std.fmt.parseUnsigned(u64, v, 10) catch error.InvalidM8GpuNativeEnvironment;
}

/// Request slab per GPU and parity [default bound, not a measurement: the
/// D2 golden 24628607 request publishes ~38 MB of proof bytes over both GPUs,
/// M sizes from artifact-fingerprints.json].
const default_slab_bytes: u64 = 64 << 20;
/// Pinned capture ring: 32 buffers x 4 MiB [default; one 2^20-row segment
/// fits, capture_words per class bounds it at plan time].
const default_ring_buffers: u64 = 32;
const default_ring_bytes: u64 = 4 << 20;
/// Batch pinned pool per GPU for Stage1 GKR metadata (n-stage1: small per job).
const default_batch_pinned_bytes: u64 = 1 << 20;

/// `Host`: rv64/m8_class_build_composition.zig, handed in by the combined
/// entry (it reads the legacy composition Context, which the sync lint keeps
/// out of rv64/jobs/ imports).
pub fn serve(a: std.mem.Allocator, library: []const u8, manifest_path: []const u8, spool: []const u8, comptime Host: type) !void {
    var timer = try std.time.Timer.start();
    const addon = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingJobsAddon;
    var libs = try O.Libraries.open(library, addon);
    defer libs.close();
    const peer = try O.Peer.open(&libs.addon);
    const config = try mod.Config.fromEnv();
    // Own the recursion builder before workers. Actual class construction
    // occurs in initial setup or the explicit new-block setup transaction.
    const recursion_classes = try Host.installRecursion(a, &libs, library, manifest_path, spool);
    defer recursion_classes.deinit();
    // [M component] truth-reuse-1 preserves all seven real-block truth
    // proofs with a lower scratch high-water. This is the promoted policy.
    const reuse = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_REUSE", 1);
    if (reuse > 1) return error.InvalidM8GpuNativeEnvironment;
    var workers: [G.max_devices]*W.Worker = undefined;
    var made: usize = 0;
    defer for (workers[0..made]) |w| w.destroy();
    if (config.device_count > G.max_devices) return error.GpuNativeTooManyDevices;
    for (config.devices[0..config.device_count]) |d| {
        // WarmJob uploads FIXED coefficients at install. Lazy slots allocate
        // nothing initially; allow the class's actual upload footprint.
        workers[made] = try W.Worker.create(a, &libs.ops, .{ .device = d, .arena_words = 1 << 16, .pinned_slot_words = (8 << 30) / 4, .pinned_lazy = true, .plan_from_env = false, .reuse_frees = reuse == 1 });
        made += 1;
    }
    const source = try Source.init(a, manifest_path);
    defer source.deinit();
    const blocks = try source.blockNumbers(a);
    defer a.free(blocks);
    // The real device factories (gn-bind: driver_bind.zig).
    const Chain = CPU.rv64_gkr_chain;
    const identity: [32]u8 = Chain.versionIdentity(try Chain.version()) catch |err| blk: {
        std.debug.print("GPU_M8_GN_BIND identity=none error={s} (flat native policy: no chain IV)\n", .{@errorName(err)});
        break :blk @splat(0);
    };
    var fallback_state = Fallbacks{ .truths = @intCast(try envUnsigned("STWO_RV64_M8_GPU_NATIVE_TRUTHS", 5)) };
    const binding = try B.Binding.init(a, &libs, workers[0..made], .{ .identity = identity }, fallback_state.hooks());
    defer binding.deinit();
    // gn-shape: the install-time native class builder (shape + class_of_block).
    var catalogue = try Sources.Catalogue.init(a);
    defer catalogue.deinit();
    var gcatalogue = NGl.Catalogue.init(a, &libs.base);
    defer gcatalogue.deinit();
    var gmutex = std.Thread.Mutex{};
    const host = try Host.HostArtifacts.init(a);
    defer host.deinit(a);
    const Version = *const fn () callconv(.c) u32;
    const wide = if (libs.base.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false;
    var builder = NCB.Builder{
        .a = a,
        .env = .{ .a = a, .catalogue = &catalogue, .gcatalogue = &gcatalogue, .gmutex = &gmutex, .psym = try NP.Symbols.load(&libs.addon), .composition = Host.of(&host.context), .wide = wide, .config = CPU.rv64_om31_security_candidate.configFor(source.profile), .byte_cap = source.gkr_bytes },
        .registry = &binding.registry,
        .factory = &binding.stage2,
        .framing_instances = @import("native_device_stage2.zig").Factory.instances_per_device * made,
        .fixed_setup_bytes = source.fixed_setup_bytes,
    };
    defer builder.deinit();
    var capture_binding = CaptureBinding.Binding.init(a, &builder, &binding.registry);
    defer capture_binding.deinit();
    // lint:install-begin — bind the install-time pinned ROM allocator.
    capture_binding.roms.pinned = .{ .alloc = libs.ops.wait.host_alloc, .free = libs.ops.wait.host_free };
    // lint:install-end
    var request_inputs = RequestInputs.Binding{ .a = a, .native = &builder, .binding = binding, .base = &libs.base, .options = source.inputs_options, .recursion_classes = recursion_classes, .profile = source.profile };
    defer request_inputs.deinit();
    binding.fallback.ctx = &request_inputs;
    binding.fallback.recursion_shape = RequestInputs.Binding.shape;
    binding.bindShape(capture_binding.shapeHooks());
    binding.bindCapture(capture_binding.captureHooks());
    binding.bindInputs(request_inputs.hooks());
    binding.bindNodeOps(&libs, peer);
    {
        var text: std.Io.Writer.Allocating = .init(a);
        defer text.deinit();
        try binding.report(&text.writer);
        std.debug.print("GPU_M8_GN_BIND binding={s}\n", .{text.written()});
    }
    // 28 GiB qualified cap per 5090 (rv64_combined_ethereum_main default);
    // the driver plans against min(cap, measured free memory) per GPU.
    var caps: [G.max_devices]u64 = @splat((28 << 30) / 4);
    const rc = R.Config{
        .capacity_words = caps[0..made],
        .max_segments = 64,
        .exchange_partials = (try Chain.version()) != .flat,
        .pool_current = libs.base.lookup(*const fn (*anyopaque, *usize, *usize) callconv(.c) c_int, "stwo_exec_context_pool_current"),
        .fixed_pool = if (std.posix.getenv("STWO_RV64_DEVICE_ARENA")) |v| !std.mem.eql(u8, v, "0") else true,
        .prewarm_resources = try Packed.ingressEnabled(std.posix.getenv(Packed.env_select)),
        .slab_words = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_SLAB_BYTES", default_slab_bytes) / 4,
        .batch_pinned_words = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_BATCH_PINNED_BYTES", default_batch_pinned_bytes) / 4,
    };
    const ring = S.RingConfig{ .buffers = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_RING_BUFFERS", default_ring_buffers), .words = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_RING_BYTES", default_ring_bytes) / 4 };
    // Admit the manifest once, install its first scheduled block, then use
    // the measured quiescent setup boundary for later allowed blocks.
    const svc = S.Service.install(a, &libs.ops, &peer, workers[0..made], binding.nativeFactory(), binding.recursionFactory(), source.source(), blocks[0..1], rc, ring) catch |err| {
        std.debug.print("GPU_M8_GN_BIND install_failed error={s}\n", .{@errorName(err)});
        binding.reportStage1();
        return err;
    };
    binding.reportStage1();
    svc.setup_hook = .{ .ctx = binding, .prepare = B.Binding.prepareSetup };
    svc.hooks = .{ .ctx = binding, .publishing = publishing, .ended = ended };
    defer svc.deinit();
    try S.serveSpool(svc, spool, timer.read());
}

fn publishing(raw: *anyopaque, topology: *const @import("driver_dag.zig").Topology) void {
    const binding: *B.Binding = @ptrCast(@alignCast(raw));
    binding.topology = topology;
}
fn ended(raw: *anyopaque, request: u64, generation: u64) void {
    const binding: *B.Binding = @ptrCast(@alignCast(raw));
    binding.endRequest(request, generation);
}

/// Fallback hooks for factory entries no stream has landed (see the header).
const Fallbacks = struct {
    truths: u32,
    fn hooks(self: *Fallbacks) B.Fallback {
        return .{ .ctx = self, .native_shape = nativeShape, .recursion_shape = recursionShape };
    }
    /// Rows per native segment of the warm capture: 1 << the segment's CPU
    /// log (Prepared.geometry().cpu_log). Registers no class: the install
    /// then refuses at class_of until the native class builder lands.
    fn nativeShape(_: ?*anyopaque, a: std.mem.Allocator, wb: G.WarmBlock) anyerror![]u64 {
        const owner: *const Capture.Owner = @ptrCast(@alignCast(wb.capture.owner));
        const rows = try a.alloc(u64, owner.native.items.len);
        errdefer a.free(rows);
        for (owner.native.items, rows) |n, *r| r.* = @as(u64, 1) << @intCast((try n.geometry()).cpu_log);
        std.debug.print("GPU_M8_GN_BIND fallback=native_shape block={d} segments={d}\n", .{ wb.block, rows.len });
        return rows;
    }
    fn recursionShape(raw: ?*anyopaque, wb: G.WarmBlock, keys: []const G.ClassKey) anyerror!G.RecursionShape {
        const self: *Fallbacks = @ptrCast(@alignCast(raw.?));
        std.debug.print("GPU_M8_GN_BIND fallback=recursion_shape block={d} segments={d} truths={d} fold_arity=4\n", .{ wb.block, keys.len, self.truths });
        return .{ .truths = self.truths, .fold_arity = 4 };
    }
};
