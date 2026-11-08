//! M8 GPU-native install-time class builder: real-block parity harness (pod
//! only, opt-in binary; stream gn-shape, rv64/jobs/native_class_build.zig).
//!
//! 1. Runs the unchanged legacy resident pipeline on one real block (the
//!    gate's manifest) with two byte-neutral pass-through RECORDERS:
//!      * the local-GKR numerical stage: per segment, the legacy Stage-1 class
//!        from exactly the request the hybrid prove() receives
//!        (NCB.stage1FromNumerical: NG.Plan.init / NB.Plan on the legacy
//!        scope, instances, source, FIXED host + MAIN device columns);
//!      * native_stage_two: per segment, the full class (Stage 1 + the
//!        hybrid's Stage-2 framing) from the stage-two CpuWorker + pending
//!        manifest (real local GKR artifact, real shared challenges), then
//!        exactly the legacy CPU stage two (replay restore, complete).
//! 2. Installs the block the GPU-native way, with NO CpuWorker: one warm
//!    capture (GE direct capture, as driver_ge.zig), then the native factory's
//!    shape hook (ND.Native.shape -> NCB.Builder.shape), which builds every
//!    segment class from the capture (setup keys, FIXED authority, request
//!    views) and registers it with the Stage-1 registry and the Stage-2
//!    factory.
//! 3. Compares, per segment, every class field of the install-built class
//!    with the legacy ones (NCB.Fingerprint; per-request fields are listed,
//!    not compared): Stage 1 vs the numerical record, Stage 1 + 2 vs the
//!    stage-two record.
//! 4. GPU: the factory's warm + installed hooks (Stage-1 registry warm, one
//!    WarmJob per class on the job GPU: FIXED commit on device, device root ==
//!    class authority root), Stage-2 factory warm; CUDA-event GPU time per
//!    class WarmJob [M], host wall of every install phase [M].
//! 5. Negatives (each must fail closed with its error).
//! Results: <out>/class-build-parity.json.
//!
//! usage: rv64-m8-class-build-parity <manifest.json> <out-dir>
//! env:   the gate's service environment, plus
//!   STWO_RV64_M8_JOBS_LIBRARY     the jobs addon (required)
//!   STWO_RV64_M8_PARITY_DEVICE    job GPU (default 1; legacy pool: STWO_RV64_GPU_DEVICES=0)
//!   STWO_RV64_M8_JOBS_ARENA_BYTES job arena (default 8 GiB)
//!   STWO_RV64_M8_JOBS_PINNED_BYTES pinned slot (default 1 GiB)
//!   STWO_RV64_M8_GN_SHAPE_LEGACY  1 (default) run the legacy recorder; 0 = install + GPU only
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const engine = @import("stwo_prover_engine");
const Main = CPU.rv64_ethereum_gkr_main;
const Pool = @import("rv64/resident_pool.zig").Pool;
const Router = @import("rv64/resident_router.zig");
const jobs = @import("rv64/jobs/mod.zig");
const W = jobs.worker;
const api = jobs.api;
const G = @import("rv64/jobs/gpu_native.zig");
const NCB = @import("rv64/jobs/native_class_build.zig");
const NCBC = @import("rv64/m8_class_build_composition.zig");
const S1 = @import("rv64/jobs/native_device_stage1.zig");
const S2 = @import("rv64/jobs/native_device_stage2.zig");
const ND = @import("rv64/jobs/native_device.zig");
const NG = @import("rv64/jobs/native_gkr.zig");
const NGl = @import("rv64/jobs/native_global.zig");
const NP = @import("rv64/jobs/native_pcs.zig");
const NE = @import("rv64/jobs/native_encode.zig");
const NC = @import("rv64/jobs/native_commit.zig");
const NComp = @import("rv64/jobs/native_composition.zig");
const Timing = @import("rv64/jobs/job_timing.zig").Timing;
const Sources = @import("rv64/gkr_sources.zig");
const Events = @import("rv64/cuda_events.zig");
const Child = CPU.rv64_gkr_child;
const CW = CPU.rv64_gkr_cpu_worker;
const DP = CPU.rv64_device_pcs;
const Candidate = CPU.rv64_om31_security_candidate;

const Request = CPU.rv64_ethereum_request;
const Image = CPU.rv64_expected_image;
const Program = CPU.rv64_program.Program;
const Metadata = CPU.rv64_program_metadata;
const Direct = CPU.rv64_ethereum_direct;
const Capture = CPU.rv64_ethereum_capture;
const CaptureOptions = CPU.rv64_ethereum_capture_options.Options;
const Plan = CPU.rv64_ethereum_plan;

const Block = struct { request: []const u8, jobs: []const u8 = "-", prefix_count: u32 = 0, expected_cpu_segments: usize };
const Manifest = struct {
    schema: []const u8,
    blocks: std.json.ArrayHashMap(Block),
    execution_order: []const u64,
    resources: std.json.Value,
    profile: []const u8 = "conjectured128_b2_q108_p20_fold4",
    immutable_host_key_bytes: usize = 4 << 30,
    immutable_device_bytes: u64 = 512 << 20,
};

fn env(name: []const u8) ?[]const u8 {
    return std.posix.getenv(name);
}
fn envBytes(name: []const u8, default: usize) !usize {
    const text = env(name) orelse return default;
    return std.fmt.parseUnsigned(usize, text, 10) catch error.InvalidParityEnvironment;
}
fn resourceUsize(resources: std.json.Value, name: []const u8) ?usize {
    if (resources != .object) return null;
    const v = resources.object.get(name) orelse return null;
    return switch (v) {
        .integer => |i| @intCast(i),
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Recorders (pass-through: the legacy bytes are unchanged)
// ---------------------------------------------------------------------------

const NumericalStage = Child.NumericalStage;
const ProveFn = @typeInfo(@FieldType(NumericalStage, "prove")).pointer.child;
const ProveResult = @typeInfo(ProveFn).@"fn".return_type.?;
const NativeStageTwo = @typeInfo(@FieldType(Main.ResidentStages, "native_stage_two")).optional.child;
const StageTwoFn = @typeInfo(@FieldType(NativeStageTwo, "stage_two")).pointer.child;
const StageTwoParams = @typeInfo(StageTwoFn).@"fn".params;

const Recorder = struct {
    a: std.mem.Allocator,
    env: *const NCB.Env,
    inner: *const NumericalStage,
    stage: NumericalStage = undefined,
    mutex: std.Thread.Mutex = .{},
    stage1: std.AutoArrayHashMapUnmanaged(u32, *NCB.Class) = .empty,
    full: std.AutoArrayHashMapUnmanaged(u32, *NCB.Class) = .empty,
    stage1_ns: u64 = 0,
    full_ns: u64 = 0,
    byte_cap: ?usize = null,
    errors: std.ArrayListUnmanaged([]const u8) = .empty,
    var self_ptr: *Recorder = undefined;

    fn init(self: *Recorder) void {
        self.stage = .{ .context = self, .prove = prove, .bind = if (self.inner.bind != null) bind else null, .abort = if (self.inner.abort != null) abort else null, .replay_binding = if (self.inner.replay_binding != null) replay else null };
    }
    fn of(raw: *anyopaque) *Recorder {
        return @ptrCast(@alignCast(raw));
    }
    fn fail(self: *Recorder, what: []const u8, ordinal: u32, err: anyerror) void {
        const text = std.fmt.allocPrint(self.a, "{s} ordinal={d} error={s}", .{ what, ordinal, @errorName(err) }) catch return;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.errors.append(self.a, text) catch {};
        std.debug.print("GPU_M8_GN_SHAPE event=record_failed {s}\n", .{text});
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: NumericalStage.Request) ProveResult {
        const self = of(raw);
        const ordinal: u32 = @intCast(request.scope.ordinal);
        var timer = std.time.Timer.start() catch unreachable;
        if (NCB.stage1FromNumerical(self.env, request)) |cl| {
            const ns = timer.read();
            self.mutex.lock();
            defer self.mutex.unlock();
            self.stage1_ns += ns;
            self.byte_cap = request.byte_cap;
            if (self.stage1.fetchSwapRemove(ordinal)) |old| old.value.deinit();
            self.stage1.put(self.a, ordinal, cl) catch cl.deinit();
        } else |err| self.fail("stage1", ordinal, err);
        return self.inner.prove(self.inner.context, a, request);
    }
    fn bind(_: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) anyerror!Child.DeviceBinding.Owner {
        const self = self_ptr;
        return self.inner.bind.?(self.inner.context, a, request);
    }
    const AbortFn = @typeInfo(@typeInfo(@FieldType(NumericalStage, "abort")).optional.child).pointer.child;
    fn abort(_: *anyopaque, scope: @typeInfo(AbortFn).@"fn".params[1].type.?) void {
        const self = self_ptr;
        self.inner.abort.?(self.inner.context, scope);
    }
    fn replay(_: *anyopaque, a: std.mem.Allocator, request: NumericalStage.Request, owner: *Child.DeviceBinding.Owner) anyerror!void {
        const self = self_ptr;
        return self.inner.replay_binding.?(self.inner.context, a, request, owner);
    }
    fn hook(self: *Recorder) NativeStageTwo {
        return .{ .context = self, .stage_two = stageTwo };
    }
    fn stageTwo(raw: *anyopaque, a: std.mem.Allocator, worker: StageTwoParams[2].type.?, pending: StageTwoParams[3].type.?, index: usize, budget: usize) @typeInfo(StageTwoFn).@"fn".return_type.? {
        const self = of(raw);
        const ordinal: u32 = @intCast(index);
        self.recordFull(worker, pending, ordinal) catch |err| self.fail("full", ordinal, err);
        // Exactly the legacy CPU stage two (coordinator.stageTwo without the hook).
        if (worker.replay) |*owner| try owner.restore(owner.context, worker);
        return worker.complete(a, pending, index, budget);
    }
    fn recordFull(self: *Recorder, worker: *CW.CpuWorker, pending: anytype, ordinal: u32) !void {
        var timer = try std.time.Timer.start();
        const ha = self.a;
        const coefficients = worker.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
        const fixed = try ha.alloc(DP.Column, coefficients.len);
        defer ha.free(fixed);
        // Stage-1 fields of this record come from the stage-1 recorder; the
        // GKR source view here is the stub (the worker's source may be
        // retired after stage one).
        var native = NCB.stubSource(worker.setup, worker.request);
        const got = try NCB.inputsFromWorker(ha, worker, pending, ordinal, fixed, &native);
        defer ha.free(got.main_logs);
        const cl = try NCB.build(self.env, got.inputs);
        const ns = timer.read();
        self.mutex.lock();
        defer self.mutex.unlock();
        self.full_ns += ns;
        if (self.full.fetchSwapRemove(ordinal)) |old| old.value.deinit();
        self.full.put(self.a, ordinal, cl) catch cl.deinit();
    }
};

// ---------------------------------------------------------------------------
// Warm capture (driver_ge.zig Source.captureBlock, inline)
// ---------------------------------------------------------------------------

const Warm = struct {
    a: std.mem.Allocator,
    config: std.json.Parsed(Request.Config),
    image: Image.Owner,
    program: Program,
    metadata: Metadata.Cache,
    owner: Capture.Owner,
    pool: *engine.work_pool.WorkPool,
    capture_ns: u64,

    fn init(a: std.mem.Allocator, request_path: []const u8, resources: std.json.Value) !*Warm {
        var options = CaptureOptions{};
        if (resources == .object) if (resources.object.get("capture_options")) |v| {
            const o = try std.json.parseFromValue(CaptureOptions, a, v, .{ .ignore_unknown_fields = true });
            defer o.deinit();
            options = o.value;
        };
        try options.validate();
        const self = try a.create(Warm);
        errdefer a.destroy(self);
        self.a = a;
        const text = try std.fs.cwd().readFileAlloc(a, request_path, 16384);
        defer a.free(text);
        self.config = try std.json.parseFromSlice(Request.Config, a, text, .{});
        errdefer self.config.deinit();
        self.metadata = try Metadata.Cache.init(a, 64 << 20);
        errdefer self.metadata.deinit();
        self.image = try Image.Owner.init(a, self.config.value);
        errdefer self.image.deinit();
        self.program = try Program.initCaptureWithAuthorityAndMetadataCache(a, &self.image.authority, &self.metadata);
        errdefer self.program.deinit();
        if (Plan.CpuLayout.forGkrProfile(self.config.value.execution_profile).compact_decode) try self.program.makeCompact();
        const workers = try Request.effectiveWorkers(self.config.value);
        self.pool = try a.create(engine.work_pool.WorkPool);
        errdefer a.destroy(self.pool);
        try self.pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1 << 20, .backing_allocator = a });
        errdefer self.pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(self.pool);
        defer binding.deinit();
        var timer = try std.time.Timer.start();
        var stats: Direct.Stats = .{};
        const started = try Direct.Started.startWithAuthority(a, self.config.value, 0, options.execution_workers, null);
        defer started.deinit(&stats);
        self.owner = try started.capture(&self.image, &self.program, options.max_inflight_packets, &stats);
        self.capture_ns = timer.read();
        return self;
    }
    fn end(self: *Warm) G.CaptureEnd {
        return .{ .segments = @intCast(self.owner.native.items.len), .owner = &self.owner, .image = &self.image, .program = &self.program, .config = &self.config.value };
    }
    fn deinit(self: *Warm) void {
        self.owner.deinit();
        self.pool.deinit();
        self.a.destroy(self.pool);
        self.program.deinit();
        self.image.deinit();
        self.metadata.deinit();
        self.config.deinit();
        self.a.destroy(self);
    }
};

// ---------------------------------------------------------------------------
// CUDA-event timed WarmJob (the registry's own warmDevices has no span)
// ---------------------------------------------------------------------------

const Timer = struct {
    events: Events.Api,
    timing: Timing = undefined,
    fn bind(self: *Timer) void {
        self.timing = .{ .ctx = self, .create = tCreate, .record = tRecord, .elapsed = tElapsed, .destroy = tDestroy };
    }
    fn tCreate(raw: ?*anyopaque, out: *?*anyopaque) c_int {
        const self: *Timer = @ptrCast(@alignCast(raw.?));
        return self.events.create(out, 0);
    }
    fn tRecord(raw: ?*anyopaque, ev: *anyopaque, stream: *anyopaque) c_int {
        const self: *Timer = @ptrCast(@alignCast(raw.?));
        return self.events.record(ev, stream);
    }
    fn tElapsed(raw: ?*anyopaque, ms: *f32, b: *anyopaque, e: *anyopaque) c_int {
        const self: *Timer = @ptrCast(@alignCast(raw.?));
        return self.events.elapsed(ms, b, e);
    }
    fn tDestroy(raw: ?*anyopaque, ev: *anyopaque) void {
        const self: *Timer = @ptrCast(@alignCast(raw.?));
        _ = self.events.destroy(ev);
    }
};

const TimedWarm = struct {
    inner: *S1.WarmJob,
    timing: *const Timing,
    span: S1.Span = .{},
    pub fn classKey(self: *TimedWarm) [32]u8 {
        return self.inner.classKey();
    }
    pub fn footprint(self: *TimedWarm) api.Footprint {
        return self.inner.footprint();
    }
    pub fn stage(self: *TimedWarm, s: *api.Stager) !void {
        try self.inner.stage(s);
        try self.span.open(self.timing);
    }
    pub fn enqueue(self: *TimedWarm, e: *api.Enqueue) !void {
        try self.span.mark(self.timing, .begin, e.stream());
        try self.inner.enqueue(e);
        try self.span.mark(self.timing, .end, e.stream());
    }
    pub fn finish(self: *TimedWarm, view: api.SlabView) !void {
        self.span.read(self.timing);
        try self.inner.finish(view);
    }
    pub fn abort(self: *TimedWarm) void {
        self.inner.abort();
    }
};

const Done = struct {
    event: std.Thread.ResetEvent = .{},
    result: anyerror!void = {},
    receipt: api.Receipt = .{},
    fn call(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        self.result = c.result;
        self.receipt = c.receipt;
        self.event.set();
    }
};
fn run(worker: *W.Worker, job: api.Job) !api.Receipt {
    var done = Done{};
    while (true) {
        worker.submit(job, .{ .ctx = &done, .done = Done.call }) catch |err| switch (err) {
            error.WorkerBusy => {
                std.Thread.sleep(20 * std.time.ns_per_us);
                continue;
            },
            else => return err,
        };
        break;
    }
    done.event.wait();
    try done.result;
    return done.receipt;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const SegmentRow = struct {
    ordinal: u32,
    /// RAM boundary claim slots of the class framing (device public_claims).
    initial_claim: ?u32 = null,
    terminal_claim: ?u32 = null,
    class_key: [64]u8,
    rows: u64,
    instances: usize,
    fixed_columns: usize,
    main_columns: usize,
    globals: usize,
    composition_roles: usize,
    patch_entries: usize,
    semantic_words: usize,
    max_encoded_bytes: usize,
    class_fields: usize,
    request_fields: usize,
    stage1_vs_legacy: ?[]const []const u8 = null,
    full_vs_legacy: ?[]const []const u8 = null,
    request_fields_differing: ?[]const []const u8 = null,
    stage1_equal: ?bool = null,
    full_equal: ?bool = null,
};
const ClassRow = struct {
    class_key: [64]u8,
    build_ns: u64,
    setup_ns: u64,
    /// Cold WarmJob on a fresh persistent region (full device FIXED commit +
    /// root copy), CUDA events [M]; then the steady (region already filled).
    cold_gpu_ms: f32,
    cold_host_ns: u64,
    warm_gpu_ms: f32,
    warm_host_ns: u64,
    warm_arena_peak_words: u64,
    held_words: u64,
    main_resident_words: usize,
    arena_peak_words: usize,
};
const Negative = struct { name: []const u8, expected: []const u8, got: []const u8, fired: bool };

fn hex(k: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(k, .lower);
}
fn names(a: std.mem.Allocator, x: *const NCB.Fingerprint, y: *const NCB.Fingerprint) ![]const []const u8 {
    var buf: [256]NCB.Mismatch = undefined;
    const n = try NCB.compare(x, y, &buf);
    const out = try a.alloc([]const u8, @min(n, buf.len));
    for (out, buf[0..out.len]) |*o, m| o.* = m.name;
    return out;
}
fn requestDiffs(a: std.mem.Allocator, x: *const NCB.Fingerprint, y: *const NCB.Fingerprint) ![]const []const u8 {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    for (x.fields.items[0..@min(x.fields.items.len, y.fields.items.len)], y.fields.items[0..@min(x.fields.items.len, y.fields.items.len)]) |p, q| {
        if (p.class or std.mem.eql(u8, &p.digest, &q.digest)) continue;
        try out.append(a, p.name);
    }
    return out.toOwnedSlice(a);
}
fn expectError(a: std.mem.Allocator, list: *std.ArrayListUnmanaged(Negative), name: []const u8, expected: anyerror, result: anytype) !void {
    const got: []const u8 = if (result) |_| "no error" else |err| @errorName(err);
    const fired = std.mem.eql(u8, got, @errorName(expected));
    try list.append(a, .{ .name = name, .expected = @errorName(expected), .got = got, .fired = fired });
    std.debug.print("GPU_M8_GN_SHAPE negative={s} expected={s} got={s} fired={}\n", .{ name, @errorName(expected), got, fired });
}

pub fn main() !void {
    const a = std.heap.page_allocator;
    const argv = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, argv);
    if (argv.len != 3) return error.ExpectedManifestAndOutput;
    const library = env("STWO_RV64_GPU_LIBRARY") orelse return error.ParityRequiresNativeLibrary;
    const addon = env("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.ParityRequiresJobsAddon;
    const out_dir = argv[2];
    try std.fs.cwd().makePath(out_dir);
    const raw = try std.fs.cwd().readFileAlloc(a, argv[1], 1 << 20);
    var parsed = try std.json.parseFromSlice(Manifest, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const manifest = parsed.value;
    const block = manifest.execution_order[0];
    var name_buf: [24]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "{d}", .{block});
    const item = manifest.blocks.map.get(name) orelse return error.MissingResidentBatchBlock;
    const request_path = try std.fs.path.resolve(a, &.{ std.fs.path.dirname(argv[1]) orelse ".", item.request });
    const run_legacy = !std.mem.eql(u8, env("STWO_RV64_M8_GN_SHAPE_LEGACY") orelse "1", "0");

    var libs = try jobs.ops.Libraries.open(library, addon);
    defer libs.close();
    const Version = *const fn () callconv(.c) u32;
    const wide = if (libs.base.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false;
    const profile = try Candidate.Profile.parse(manifest.profile);
    const config = Candidate.configFor(profile);
    const byte_cap = resourceUsize(manifest.resources, "gkr_bytes") orelse return error.ParityRequiresGkrBytes;
    const fixed_setup_bytes = resourceUsize(manifest.resources, "fixed_setup_bytes") orelse (4 << 30);

    // ---- build environment (service constants) ----
    var catalogue = try Sources.Catalogue.init(a);
    defer catalogue.deinit();
    var gcatalogue = NGl.Catalogue.init(a, &libs.base);
    defer gcatalogue.deinit();
    var gmutex = std.Thread.Mutex{};
    const host = try NCBC.HostArtifacts.init(a);
    defer host.deinit(a);
    var build_env = NCB.Env{ .a = a, .catalogue = &catalogue, .gcatalogue = &gcatalogue, .gmutex = &gmutex, .psym = try NP.Symbols.load(&libs.addon), .composition = NCBC.of(&host.context), .wide = wide, .config = config, .byte_cap = byte_cap };

    // ---- 1. legacy run with the recorders ----
    var recorder = Recorder{ .a = a, .env = &build_env, .inner = undefined };
    Recorder.self_ptr = &recorder;
    var legacy_ns: u64 = 0;
    if (run_legacy) {
        var rconfig = try Router.Config.fromEnv(a);
        defer rconfig.deinit(a);
        var recycler = Main.Recycler.init(std.heap.smp_allocator, 1 << 30);
        defer recycler.deinit();
        var session = try Main.ResidentSession.init(recycler.allocator(), manifest.immutable_host_key_bytes);
        defer session.deinit();
        const pool = try Pool.createWithBinding(a, library, rconfig, item.expected_cpu_segments, true);
        defer pool.deinit();
        try pool.stages().requireFullyResident();
        var stages = pool.stages();
        recorder.inner = stages.numerical orelse return error.ParityRequiresNumericalStage;
        recorder.init();
        stages.numerical = &recorder.stage;
        if (stages.native_stage_two != null) return error.ParityNativeStageTwoAlreadySet;
        stages.native_stage_two = recorder.hook();
        const resource_json = try std.json.Stringify.valueAlloc(a, manifest.resources, .{});
        const resources = try std.fs.path.join(a, &.{ out_dir, "resources.json" });
        try std.fs.cwd().writeFile(.{ .sub_path = resources, .data = resource_json });
        const proof = try std.fs.path.join(a, &.{ out_dir, "proof" });
        const parts = [_][]const u8{ "rv64-resident", "--security-profile", manifest.profile, "produce-candidate", request_path, "-", proof, "0", resources };
        var args: [parts.len][:0]u8 = undefined;
        for (parts, &args) |part, *arg| arg.* = try a.dupeZ(u8, part);
        var identity: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("rv64-m8-gn-shape-parity", &identity, .{});
        for (pool.devices, rconfig.caps) |*d, cap| try d.native.beginBlock(identity, .{ .device_bytes = cap, .immutable_bytes = manifest.immutable_device_bytes, .max_scopes = rconfig.scope_limit });
        var timer = try std.time.Timer.start();
        std.debug.print("GPU_M8_GN_SHAPE phase=legacy_start block={}\n", .{block});
        try Main.runWithResidentArgs(&recycler, &args, stages, &session);
        legacy_ns = timer.read();
        for (pool.devices) |*d| try d.native.endBlock(identity);
        std.debug.print("GPU_M8_GN_SHAPE event=legacy_done block={} stage1_records={} full_records={} legacy_ns={}\n", .{ block, recorder.stage1.count(), recorder.full.count(), legacy_ns });
        // Composition artifacts of the resident pool == the host-only table.
        const pc = &pool.devices[0].composition;
        if (pc.artifact_count != host.context.artifact_count) return error.ParityCompositionArtifactsDiffer;
        for (pc.artifacts[0..pc.artifact_count], host.context.artifacts[0..host.context.artifact_count]) |x, y| {
            if (!std.mem.eql(u8, &x.program.identity, &y.program.identity) or !std.mem.eql(u32, x.parameter_slots, y.parameter_slots)) return error.ParityCompositionArtifactsDiffer;
        }
        if (recorder.byte_cap) |cap| if (cap != byte_cap) return error.ParityByteCapDiffers;
    }

    // ---- 2. install: warm capture + the native factory's shape hook ----
    std.debug.print("GPU_M8_GN_SHAPE phase=warm_capture\n", .{});
    const warm = try Warm.init(a, request_path, manifest.resources);
    defer warm.deinit();
    const device = std.fmt.parseUnsigned(u32, env("STWO_RV64_M8_PARITY_DEVICE") orelse "1", 10) catch return error.InvalidParityEnvironment;
    const arena_bytes = try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 8 << 30);
    const worker = try W.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = std.mem.alignBackward(usize, arena_bytes / 4, W.Arena.granule), .pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 1 << 30) / 4 });
    defer worker.destroy();
    const gsym = try NG.Symbols.load(&libs.base);
    const s1sym = try S1.Symbols.load(&libs.base, &libs.addon, &gsym);
    const s2sym = S2.Symbols{ .encode = try NE.Symbols.load(&libs.addon), .seal = try S2.SealSymbols.load(&libs.addon), .commit = try NC.Symbols.load(&libs.base), .pcs = build_env.psym, .composition = try NComp.Symbols.load(&libs.base, &libs.addon), .global = try NGl.Symbols.load(&libs.base) };
    var timer_api = Timer{ .events = try Events.Api.load(&libs.base) };
    timer_api.bind();
    var registry = S1.Registry.init(a);
    defer registry.deinit();
    const workers = [_]*W.Worker{worker};
    registry.sym = &s1sym;
    registry.timing = &timer_api.timing;
    registry.workers = &workers;
    registry.devices = 1;
    var factory = S2.Factory{ .a = a, .sym = &s2sym, .identity = @splat(0) };
    defer factory.deinit();
    // Production pool size: instances_per_device x 2 GPUs.
    const framing_instances = std.fmt.parseUnsigned(usize, env("STWO_RV64_M8_GN_SHAPE_FRAMING_INSTANCES") orelse "4", 10) catch return error.InvalidParityEnvironment;
    var builder = NCB.Builder{ .a = a, .env = build_env, .registry = &registry, .factory = &factory, .framing_instances = framing_instances, .fixed_setup_bytes = fixed_setup_bytes };
    defer builder.deinit();
    var native = ND.Native{ .stage1_hooks = registry.hooks(), .stage2_hooks = factory.hooks(), .shape_hooks = builder.hooks() };
    const nf = native.factory();
    var timer = try std.time.Timer.start();
    const wb = G.WarmBlock{ .block = block, .capture = warm.end() };
    const rows = try nf.vtable.shape.?(nf.ctx, a, wb);
    defer a.free(rows);
    const shape_ns = timer.lap();
    std.debug.print("GPU_M8_GN_SHAPE event=shape block={} segments={} classes={} shape_ns={} inventory_ns={} classes_ns={} threads={}\n", .{ block, rows.len, builder.classes.count(), shape_ns, builder.blocks.items[0].inventory_ns, builder.blocks.items[0].classes_ns, builder.blocks.items[0].threads });
    if (rows.len != item.expected_cpu_segments) return error.ParitySegmentCountDiffers;
    const rec = builder.blocks.items[0];

    // ---- 3. field-by-field comparison with the legacy classes ----
    var segs: std.ArrayListUnmanaged(SegmentRow) = .empty;
    var all_stage1 = true;
    var all_full = true;
    for (rec.keys, rec.rows, 0..) |key, r, i| {
        const cl = builder.class(key) orelse return error.ParityClassMissing;
        var fp = try NCB.Fingerprint.of(a, cl);
        defer fp.deinit();
        var class_fields: usize = 0;
        for (fp.fields.items) |f| class_fields += @intFromBool(f.class);
        var patches: usize = 0;
        for (cl.global_patches) |p| patches += p.shared.len() + p.semantic.len() + p.public.len();
        patches += cl.comp_patches.shared.len() + cl.comp_patches.semantic.len() + cl.comp_patches.public.len();
        // classOf through the factory vtable (block-qualified and not).
        const k1 = try nf.vtable.class_of_block.?(nf.ctx, block, @intCast(i), r);
        if (!std.mem.eql(u8, &k1, &key)) return error.ParityClassOfDiffers;
        var row = SegmentRow{ .ordinal = @intCast(i), .class_key = hex(key), .rows = r, .instances = cl.instances.len, .fixed_columns = cl.fixed_shapes.len, .main_columns = cl.main_shapes.len, .globals = cl.gplans.items.len, .composition_roles = cl.comp_plan.?.roles.len, .patch_entries = patches, .semantic_words = cl.semantic_words, .max_encoded_bytes = cl.program.?.max_encoded_bytes, .class_fields = class_fields, .request_fields = fp.fields.items.len - class_fields, .initial_claim = cl.initial_claim, .terminal_claim = cl.terminal_claim };
        if (run_legacy) {
            if (recorder.stage1.get(@intCast(i))) |legacy| {
                legacy.capture_words = cl.capture_words;
                var lf = try NCB.Fingerprint.ofStage1(a, legacy);
                defer lf.deinit();
                row.stage1_vs_legacy = try names(a, &fp, &lf);
                row.stage1_equal = row.stage1_vs_legacy.?.len == 0;
            } else row.stage1_equal = false;
            if (recorder.full.get(@intCast(i))) |legacy| {
                var lf = try NCB.Fingerprint.of(a, legacy);
                defer lf.deinit();
                // Stage-1 rows of the full record use the stub source: compare
                // its Stage-2 fields + every Stage-1 field the stub does not touch.
                row.full_vs_legacy = try names(a, &fp, &lf);
                row.full_equal = row.full_vs_legacy.?.len == 0;
                row.request_fields_differing = try requestDiffs(a, &fp, &lf);
                if (!std.mem.eql(u8, &legacy.key, &key)) row.full_equal = false;
            } else row.full_equal = false;
            all_stage1 = all_stage1 and row.stage1_equal.?;
            all_full = all_full and row.full_equal.?;
        }
        std.debug.print("GPU_M8_GN_SHAPE segment={} rows={} key={s} stage1_equal={?} full_equal={?} globals={} roles={} patches={}\n", .{ i, r, &row.class_key, row.stage1_equal, row.full_equal, row.globals, row.composition_roles, patches });
        try segs.append(a, row);
    }

    // ---- 4. GPU install through the factory hooks ----
    var cache = G.ClassCache.init(a);
    defer cache.deinit();
    timer.reset();
    try nf.vtable.warm(nf.ctx, &cache);
    try factory.warm(&cache);
    const warm_ns = timer.lap();
    var installed = G.Installed{ .devices = 1 };
    try nf.vtable.installed.?(nf.ctx, &cache, &installed);
    const installed_ns = timer.lap();
    cache.seal();
    std.debug.print("GPU_M8_GN_SHAPE event=installed classes={} cache_entries={} warm_ns={} installed_ns={}\n", .{ builder.classes.count(), cache.count(), warm_ns, installed_ns });
    // Every Stage-2 pool instance owns its mutable Stage-2 state (Stage2Job
    // stage/enqueue write per-job state into the INTER CommitPlan, the
    // composition Plan, the PcsJob and the global plans).
    var framing_exclusive = true;
    var framing_pool_sizes: std.ArrayListUnmanaged(usize) = .empty;
    for (builder.classes.values()) |cl| {
        const pool = factory.classes.get(NCB.Class.framingKey(cl.key)) orelse return error.ParityFramingPoolMissing;
        const insts = pool.instances.items;
        try framing_pool_sizes.append(a, insts.len);
        if (insts.len != framing_instances) framing_exclusive = false;
        for (insts, 0..) |x, i| for (insts[i + 1 ..]) |y| {
            if (x.pcs == y.pcs or x.inter == y.inter or x.composition == y.composition or x.slots.ptr == y.slots.ptr) framing_exclusive = false;
            for (x.slots, y.slots) |sx, sy| if (sx.global) |gx| if (gx.plan == sy.global.?.plan) {
                framing_exclusive = false;
            };
        };
    }
    std.debug.print("GPU_M8_GN_SHAPE event=framing_pool instances={} exclusive={}\n", .{ framing_instances, framing_exclusive });
    // Per class, one CUDA-event-timed WarmJob (the region is already fresh:
    // the measurement is the root copy; a second, cold measurement on a
    // fresh persistent key is the full FIXED commit).
    var classes: std.ArrayListUnmanaged(ClassRow) = .empty;
    for (builder.classes.values()) |cl| {
        const s1c = try registry.class(cl.key);
        const entry = try cache.get(cl.key);
        // Cold: the same spec under a fresh persistent key (true root).
        var cold_spec = cl.spec();
        cold_spec.key[31] ^= 0x3c;
        const cold_class = try S1.Class.init(a, cold_spec);
        defer cold_class.deinit();
        var cold_job = S1.WarmJob{ .a = a, .class = cold_class, .sym = &s1sym };
        try cold_job.init();
        defer cold_job.deinit();
        var cold = TimedWarm{ .inner = &cold_job, .timing = &timer_api.timing };
        var ct = try std.time.Timer.start();
        _ = try run(worker, api.Job.from(TimedWarm, &cold));
        const cold_host_ns = ct.read();
        cold.span.close(&timer_api.timing);
        var job = S1.WarmJob{ .a = a, .class = s1c, .sym = &s1sym };
        try job.init();
        defer job.deinit();
        var timed = TimedWarm{ .inner = &job, .timing = &timer_api.timing };
        var t = try std.time.Timer.start();
        const receipt = try run(worker, api.Job.from(TimedWarm, &timed));
        const host_ns = t.read();
        timed.span.close(&timer_api.timing);
        try classes.append(a, .{ .class_key = hex(cl.key), .build_ns = cl.build_ns, .setup_ns = cl.setup_ns, .cold_gpu_ms = cold.span.gpu_ms, .cold_host_ns = cold_host_ns, .warm_gpu_ms = timed.span.gpu_ms, .warm_host_ns = host_ns, .warm_arena_peak_words = receipt.arena_peak_words, .held_words = entry.held_words[0], .main_resident_words = entry.main_resident_words, .arena_peak_words = entry.arena_peak_words });
    }

    // ---- 5. negatives (fail closed) ----
    var negs: std.ArrayListUnmanaged(Negative) = .empty;
    var miss_wall_ns: u64 = 0;
    {
        // a. device FIXED root vs a tampered class authority root (GPU).
        const cl = builder.classes.values()[0];
        var spec = cl.spec();
        spec.key[0] ^= 0x5a; // a fresh persistent region: the full device FIXED commit runs
        spec.fixed_root[0] ^= 1;
        const bad = try S1.Class.init(a, spec);
        defer bad.deinit();
        var job = S1.WarmJob{ .a = a, .class = bad, .sym = &s1sym };
        try job.init();
        defer job.deinit();
        var timed = TimedWarm{ .inner = &job, .timing = &timer_api.timing };
        const r = run(worker, api.Job.from(TimedWarm, &timed));
        timed.span.close(&timer_api.timing);
        try expectError(a, &negs, "warm_fixed_root_tampered", error.NativeStage1FixedRootMismatch, r);
        // b. registering a sealed registry (request path).
        try expectError(a, &negs, "register_after_seal", error.GpuNativeClassBuildOnRequestPath, registry.register(cl.spec(), NCB.rowsToken(cl.key)));
        // c. class_of of an unknown block / wrong rows.
        try expectError(a, &negs, "class_of_unknown_block", error.GpuNativeClassNotWarmed, nf.vtable.class_of_block.?(nf.ctx, block + 1, 0, rows[0]));
        try expectError(a, &negs, "class_of_wrong_rows", error.GpuNativeClassNotWarmed, nf.vtable.class_of_block.?(nf.ctx, block, 0, rows[0] + 1));
        // d. a framing whose patch table writes outside its target.
        var fr = cl.framing.?;
        var bad_dst = [_]u32{@intCast(cl.comp_plan.?.table.len)};
        var bad_idx = [_]u32{0};
        fr.comp_patches.public = .{ .dst = &bad_dst, .index = &bad_idx };
        fr.key[0] ^= 0xa5;
        try expectError(a, &negs, "framing_patch_out_of_bounds", error.NativeStage2PatchTable, factory.register(&fr));
        // e. the fingerprint sees a one-word FIXED change and a byte-cap change.
        const saved = cl.fixed_storage[0];
        cl.fixed_storage[0] ^= 1;
        var fx = try NCB.Fingerprint.ofStage1(a, cl);
        cl.fixed_storage[0] = saved;
        var f0 = try NCB.Fingerprint.ofStage1(a, cl);
        var mm: [8]NCB.Mismatch = undefined;
        const nfix = try NCB.compare(&fx, &f0, &mm);
        fx.deinit();
        f0.deinit();
        try expectError(a, &negs, "fingerprint_fixed_word", error.GnShapeFieldMismatch, if (nfix == 1 and std.mem.eql(u8, mm[0].name, "s1.fixed_host")) @as(anyerror!void, error.GnShapeFieldMismatch) else @as(anyerror!void, {}));
        // f. a new block after the cache sealed: the miss path builds (and
        //    receipts) instead of failing closed; the block's classes are
        //    already known, so nothing new is registered.
        var t = try std.time.Timer.start();
        const miss = builder.missBlock(.{ .block = block + 1, .capture = warm.end() });
        const miss_ns = t.read();
        const got: []const u8 = if (miss) |_| "ok" else |err| @errorName(err);
        try negs.append(a, .{ .name = "class_miss_new_block_builds", .expected = "ok", .got = got, .fired = if (miss) |m| m.miss else |_| false });
        std.debug.print("GPU_M8_GN_SHAPE event=miss_block result={s} misses={} miss_ns={}\n", .{ got, builder.misses, miss_ns });
        miss_wall_ns = miss_ns;
        const k_miss = try nf.vtable.class_of_block.?(nf.ctx, block + 1, 0, rows[0]);
        try expectError(a, &negs, "miss_block_class_equals_warm", error.GnShapeFieldMismatch, if (std.mem.eql(u8, &k_miss, &rec.keys[0])) @as(anyerror!void, error.GnShapeFieldMismatch) else @as(anyerror!void, {}));
        // g. the row-only class_of is ambiguous now that two blocks share every
        //    (segment, rows) with equal classes: equal -> resolves.
        const k_any = nf.vtable.class_of(nf.ctx, 0, rows[0]);
        try negs.append(a, .{ .name = "class_of_rows_only_two_equal_blocks", .expected = "ok", .got = if (k_any) |_| "ok" else |err| @errorName(err), .fired = if (k_any) |k| std.mem.eql(u8, &k, &rec.keys[0]) else |_| false });
    }
    // ---- 6. a genuinely new block after install: the class-miss path ----
    const MissRow = struct { block: u64, segments: usize, new_classes: u32, wall_ns: u64, capture_ns: u64, classes_ns: u64, register_and_warm_ns: u64, resolved: bool, registry_has_all: bool, cache_has_all: bool };
    var miss_row: ?MissRow = null;
    if (env("STWO_RV64_M8_GN_SHAPE_MISS_REQUEST")) |miss_request| {
        const miss_block = std.fmt.parseUnsigned(u64, env("STWO_RV64_M8_GN_SHAPE_MISS_BLOCK") orelse "0", 10) catch return error.InvalidParityEnvironment;
        builder.miss_cache = &cache;
        builder.miss_devices = 1;
        const warm2 = try Warm.init(a, miss_request, manifest.resources);
        defer warm2.deinit();
        var mt = try std.time.Timer.start();
        const before = builder.classes.count();
        const mrows = try nf.vtable.shape.?(nf.ctx, a, .{ .block = miss_block, .capture = warm2.end() });
        defer a.free(mrows);
        const wall = mt.read();
        const mrec = builder.blocks.items[builder.blocks.items.len - 1];
        var resolved = true;
        var reg_all = true;
        var cache_all = true;
        for (mrec.keys, mrows, 0..) |k, r, i| {
            const kk = nf.vtable.class_of_block.?(nf.ctx, miss_block, @intCast(i), r) catch {
                resolved = false;
                continue;
            };
            resolved = resolved and std.mem.eql(u8, &kk, &k);
            _ = registry.class(k) catch {
                reg_all = false;
            };
            _ = cache.get(k) catch {
                cache_all = false;
            };
            _ = cache.get(NCB.Class.framingKey(k)) catch {
                cache_all = false;
            };
        }
        miss_row = .{ .block = miss_block, .segments = mrows.len, .new_classes = @intCast(builder.classes.count() - before), .wall_ns = wall, .capture_ns = warm2.capture_ns, .classes_ns = mrec.classes_ns, .register_and_warm_ns = mrec.register_ns, .resolved = resolved, .registry_has_all = reg_all, .cache_has_all = cache_all };
        std.debug.print("GPU_M8_GN_SHAPE event=miss_new_block block={} segments={} new_classes={} wall_ns={} register_and_warm_ns={} resolved={} registry_has_all={} cache_has_all={} misses={}\n", .{ miss_block, mrows.len, miss_row.?.new_classes, wall, mrec.register_ns, resolved, reg_all, cache_all, builder.misses });
        try negs.append(a, .{ .name = "class_miss_new_block_warmed_on_device", .expected = "ok", .got = if (resolved and reg_all and cache_all and mrec.miss) "ok" else "incomplete", .fired = resolved and reg_all and cache_all and mrec.miss and miss_row.?.new_classes != 0 });
    }
    var negatives_all = true;
    for (negs.items) |n| negatives_all = negatives_all and n.fired;

    var text: std.Io.Writer.Allocating = .init(a);
    defer text.deinit();
    try std.json.Stringify.value(.{
        .schema = "rv64-m8-gn-shape-parity/v1",
        .block = block,
        .job_device = device,
        .profile = manifest.profile,
        .byte_cap = byte_cap,
        .wide_framing = wide,
        .legacy_ran = run_legacy,
        .legacy_wall_ns = legacy_ns,
        .legacy_record_errors = recorder.errors.items,
        .legacy_stage1_record_ns = recorder.stage1_ns,
        .legacy_full_record_ns = recorder.full_ns,
        .warm_capture_ns = warm.capture_ns,
        .install_shape_ns = shape_ns,
        .install_inventory_ns = rec.inventory_ns,
        .install_classes_ns = rec.classes_ns,
        .install_build_threads = rec.threads,
        .install_warm_ns = warm_ns,
        .install_installed_ns = installed_ns,
        .miss_block_wall_ns = miss_wall_ns,
        .miss_new_block = miss_row,
        .segments = segs.items,
        .unique_classes = builder.classes.count(),
        .stage1_all_equal = all_stage1,
        .full_all_equal = all_full,
        .classes = classes.items,
        .negatives = negs.items,
        .negatives_all_fired = negatives_all,
        .framing_instances = framing_instances,
        .framing_pool_sizes = framing_pool_sizes.items,
        .framing_instances_exclusive = framing_exclusive,
        .scope = "class fields compared by SHA-256 digest per field (NCB.Fingerprint); per-request fields (GKR prefix + publics, PCS section 15 + scope, patched parameter words) listed only. Times: host wall [M] (std.time.Timer), warm_gpu_ms CUDA events around the WarmJob enqueue [M].",
    }, .{ .whitespace = .indent_1 }, &text.writer);
    const report = try std.fs.path.join(a, &.{ out_dir, "class-build-parity.json" });
    try std.fs.cwd().writeFile(.{ .sub_path = report, .data = text.written() });
    std.debug.print("GPU_M8_GN_SHAPE done block={} stage1_all_equal={} full_all_equal={} negatives_all_fired={} report={s}\n", .{ block, all_stage1, all_full, negatives_all, report });
    if ((run_legacy and !(all_stage1 and all_full)) or !negatives_all or !framing_exclusive) std.process.exit(2);
}
