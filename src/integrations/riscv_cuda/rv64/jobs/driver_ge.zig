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
//! built ONCE at install (they are immutable inputs of every capture).
//!
//! The legacy pipeline (gkr_main, coordinator, admission, owner callbacks)
//! is not instantiated on this path.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const engine = @import("stwo_prover_engine");
const G = @import("gpu_native.zig");
const O = @import("ops.zig");
const W = @import("worker.zig");
const R = @import("driver_request.zig");
const S = @import("driver_serve.zig");
const C = @import("../m8_capture_stream.zig");
const mod = @import("mod.zig");
const ND = @import("native_device.zig");
const OD = @import("outer_device.zig");

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
    /// One capture work pool per in-flight request (TLS-bound on its capture
    /// thread) plus one for install-time warm captures.
    pools: [3]*engine.work_pool.WorkPool,
    pool_busy: [2]bool = .{ false, false },
    mutex: std.Thread.Mutex = .{},

    const Block = struct {
        number: u64,
        config: std.json.Parsed(Request.Config),
        image: Image.Owner,
        program: Program,
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
        self.* = .{ .a = a, .blocks = &.{}, .metadata = try Metadata.Cache.init(a, 64 << 20), .options = options, .pools = undefined };
        errdefer self.metadata.deinit();
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
            var config = try std.json.parseFromSlice(Request.Config, a, text, .{});
            errdefer config.deinit();
            var image = try Image.Owner.init(a, config.value);
            errdefer image.deinit();
            var program = try Program.initCaptureWithAuthorityAndMetadataCache(a, &image.authority, &self.metadata);
            errdefer program.deinit();
            // The capture's AUIPC/JAL FUNCTION facts depend on the decode layout.
            if (Plan.CpuLayout.forGkrProfile(config.value.execution_profile).compact_decode) try program.makeCompact();
            workers = @max(workers, try Request.effectiveWorkers(config.value));
            b.* = .{ .number = number, .config = config, .image = image, .program = program };
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
        b.program.deinit();
        b.image.deinit();
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
        const started = try Direct.Started.startWithAuthority(self.a, b.config.value, 0, self.options.execution_workers, null);
        defer started.deinit(&stats);
        started.ready = ready;
        return started.capture(&b.image, &b.program, self.options.max_inflight_packets, &stats);
    }
    fn endOf(b: *Block, owner: *const Capture.Owner) G.CaptureEnd {
        return .{ .segments = @intCast(owner.native.items.len), .owner = owner, .image = &b.image, .program = &b.program, .config = &b.config.value };
    }

    fn warm(raw: *anyopaque, number: u64) anyerror!G.CaptureEnd {
        const self = of(raw);
        const b = try self.find(number);
        if (b.warm) |*w| w.deinit();
        b.warm = null;
        var binding = try engine.work_pool.ScopedPoolBinding.init(self.pools[2]);
        defer binding.deinit();
        b.warm = try self.captureBlock(b, null);
        return endOf(b, &b.warm.?);
    }
    fn releaseWarm(raw: *anyopaque, number: u64) void {
        const self = of(raw);
        const b = self.find(number) catch return;
        if (b.warm) |*w| w.deinit();
        b.warm = null;
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
                run.stream.fail();
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
            run.stream.fail();
        }
        fn main(run: *Run) void {
            const src = run.src;
            var binding = engine.work_pool.ScopedPoolBinding.init(src.pools[run.pool]) catch |err| return run.feed.finish(err);
            defer binding.deinit();
            const ready = Capture.Ready{ .context = run, .call = readyCall, .native_segment = readySegment, .cancel = readyCancel };
            run.owner = src.captureBlock(run.block, ready) catch |err| return run.feed.finish(err);
            run.feed.end(endOf(run.block, &run.owner.?)) catch {};
            run.feed.finish(null);
        }
    };

    fn start(raw: *anyopaque, number: u64, stream: *C.Stream) anyerror!*anyopaque {
        const self = of(raw);
        const b = try self.find(number);
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

pub fn serve(a: std.mem.Allocator, library: []const u8, manifest_path: []const u8, spool: []const u8) !void {
    var timer = try std.time.Timer.start();
    const addon = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingJobsAddon;
    var libs = try O.Libraries.open(library, addon);
    defer libs.close();
    const peer = try O.Peer.open(&libs.addon);
    const config = try mod.Config.fromEnv();
    var workers: [G.max_devices]*W.Worker = undefined;
    var made: usize = 0;
    defer for (workers[0..made]) |w| w.destroy();
    if (config.device_count > G.max_devices) return error.GpuNativeTooManyDevices;
    for (config.devices[0..config.device_count]) |d| {
        workers[made] = try W.Worker.create(a, &libs.ops, .{ .device = d, .arena_words = 1 << 16, .pinned_slot_words = 1 << 12, .pinned_lazy = true, .plan_from_env = false });
        made += 1;
    }
    const source = try Source.init(a, manifest_path);
    defer source.deinit();
    const blocks = try source.blockNumbers(a);
    defer a.free(blocks);
    // The real device factories (sibling pieces bind their stage hooks here).
    var native = ND.Native{};
    var recursion = OD.Recursion{ .a = a };
    defer recursion.deinit();
    // 28 GiB qualified cap per 5090 (rv64_combined_ethereum_main default);
    // the driver plans against min(cap, measured free memory) per GPU.
    var caps: [G.max_devices]u64 = @splat((28 << 30) / 4);
    const rc = R.Config{
        .capacity_words = caps[0..made],
        .max_segments = 64,
        .slab_words = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_SLAB_BYTES", default_slab_bytes) / 4,
        .batch_pinned_words = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_BATCH_PINNED_BYTES", default_batch_pinned_bytes) / 4,
    };
    const ring = S.RingConfig{ .buffers = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_RING_BUFFERS", default_ring_buffers), .words = try envUnsigned("STWO_RV64_M8_GPU_NATIVE_RING_BYTES", default_ring_bytes) / 4 };
    const svc = try S.Service.install(a, &libs.ops, &peer, workers[0..made], native.factory(), recursion.factory(), source.source(), blocks, rc, ring);
    defer svc.deinit();
    try S.serveSpool(svc, spool, timer.read());
}
