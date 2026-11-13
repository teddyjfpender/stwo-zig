//! M8 GPU-native TruthJob real-block parity harness (pod only, opt-in binary;
//! recursion stream, piece r-truth).
//!
//! Runs the unchanged legacy resident pipeline on a real block (the gate's
//! manifest) with two byte-neutral pass-through decorators that RECORD the
//! legacy truth inputs and outputs:
//!   * truth_source (truth_device_source.Stage): the truth, its expected
//!     worker, PCS config and compact inputs (prepare), the FIXED columns and
//!     the legacy MAIN root (seal_main), the local/shared challenges, the
//!     INTER root and the claims (generate_interactions);
//!   * native_stage_two (coordinator.NativeStageTwo): the manifest digest of
//!     the request (the CPU stage two runs exactly as legacy: replay restore,
//!     then CpuWorker.complete).
//! Then, post hoc on the job GPU, every truth is proven by the GPU-native
//! TruthJob (jobs/truth_job.zig) from the recorded compact inputs, seed and
//! digest only, and compared with the legacy proof:
//!   stage 1: MAIN root == legacy;
//!   stage 2: FIXED/MAIN/INTER roots, claims, local + shared challenges ==
//!            legacy, every device check accepted, proof bytes == the
//!            pipeline's truth-<t>.bin (byte identity);
//!   negatives (first truth of each kind): each injected fault makes exactly
//!            its check reject.
//! gn-truth (device encode): stage 2 run 0 is `.check` (host assembly AND the
//! device OODS check + device encoder; device bytes == host bytes == legacy,
//! device OODS evaluated/extracted == the host engine's), runs 1.. are
//! `.device` (no host assembly; CUDA-event GPU time of the device OODS +
//! encoder, finish host time); negatives run in `.device` over all six
//! stage-2 verdicts, plus the device faults (oods_sample, oods_composition,
//! encode_capacity, encode_value).
//! Results: <out>/truth-parity.json.
//!
//! usage: rv64-m8-truth-parity <manifest.json> <out-dir>
//! env:   the gate's service environment, plus
//!   STWO_RV64_M8_JOBS_LIBRARY        the jobs addon (with truth_ops.cu; required)
//!   STWO_RV64_M8_PARITY_DEVICE       job GPU (default 1; legacy pool: STWO_RV64_GPU_DEVICES=0)
//!   STWO_RV64_M8_JOBS_ARENA_BYTES    job arena (default 24 GiB)
//!   STWO_RV64_M8_JOBS_PINNED_BYTES   pinned slot (default 1 GiB)
//!   STWO_RV64_M8_TRUTH_NEGATIVES     1 (default) / 0
//!   STWO_RV64_M8_TRUTH_REPEAT        stage-2 timing repeats per truth (default 2: cold + warm)
const std = @import("std");
const ProductCPU = @import("ethereum_cpu_component");
const CPU = @import("stwo_riscv_cpu_integration");
const Main = ProductCPU.rv64_ethereum_gkr_main;
const Pool = @import("rv64/resident_pool.zig").Pool;
const Router = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.resident_router;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const W = jobs.worker;
const api = jobs.api;
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const K = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.truth_class;
const TJ = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.truth_job;
const X = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.truth_challenges;
const Events = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.cuda_events;
const S = CPU.rv64_gkr_truth_device_source;
const WP = CPU.rv64_gkr_worker_protocol;
const DP = CPU.rv64_device_pcs;
const O = DP.O;

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
fn rootWords(root: [32]u8) [8]u32 {
    var w: [8]u32 = undefined;
    for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
    return w;
}
fn digestWords(d: [32]u8) [8]u32 {
    return rootWords(d);
}

// ---------------------------------------------------------------------------
// Recording decorators (pass-through: the legacy bytes are unchanged)
// ---------------------------------------------------------------------------

const Record = struct {
    truth: K.Truth,
    expected: CPU.rv64_gkr_manifest.ExpectedWorker,
    config: K.Config,
    compact: []u32,
    fixed: ?*Fixed = null,
    main_root: ?[32]u8 = null,
    local: ?S.Local = null,
    shared: ?S.Shared = null,
    inter_root: ?[32]u8 = null,
    claims: []O = &.{},
    inner: S.Owner = undefined,
};
const Fixed = struct {
    root: [32]u8,
    columns: []K.FixedColumn,
    words: [][]u32,
};

const SourceDecorator = struct {
    a: std.mem.Allocator,
    inner: S.Stage,
    mutex: std.Thread.Mutex = .{},
    records: std.ArrayListUnmanaged(*Record) = .empty,
    fixed: std.ArrayListUnmanaged(*Fixed) = .empty,
    fn stage(self: *SourceDecorator) S.Stage {
        return .{ .context = self, .prepare = prepare, .retained_upper_bound = if (self.inner.retained_upper_bound != null) retained else null };
    }
    fn retained(raw: *anyopaque, request: S.RetentionRequest) anyerror!S.Retained {
        const self: *SourceDecorator = @ptrCast(@alignCast(raw));
        return self.inner.retained_upper_bound.?(self.inner.context, request);
    }
    fn prepare(raw: *anyopaque, a: std.mem.Allocator, request: S.Prepare) anyerror!S.Owner {
        const self: *SourceDecorator = @ptrCast(@alignCast(raw));
        const inner = try self.inner.prepare(self.inner.context, a, request);
        const rec = try self.a.create(Record);
        rec.* = .{ .truth = request.truth, .expected = request.expected, .config = request.config, .compact = K.packCompact(self.a, request.truth, request.advice) catch |err| blk: {
            std.debug.print("GPU_M8_TRUTH_PARITY event=compact_unsupported ordinal={} error={s}\n", .{ request.expected.ordinal, @errorName(err) });
            break :blk &.{};
        }, .inner = inner };
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.records.append(self.a, rec);
        return .{ .context = rec, .seal_main = sealMain, .generate_interactions = generate, .release = release };
    }
    var self_ptr: ?*SourceDecorator = null;
    fn sealMain(raw: *anyopaque, a: std.mem.Allocator, request: S.Sealed) anyerror!DP.Tree {
        const rec: *Record = @ptrCast(@alignCast(raw));
        const tree = try rec.inner.seal_main(rec.inner.context, a, request);
        rec.main_root = tree.root;
        rec.fixed = try self_ptr.?.fixedOf(request.fixed);
        return tree;
    }
    fn fixedOf(self: *SourceDecorator, tree: DP.Tree) !*Fixed {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.fixed.items) |f| if (std.mem.eql(u8, &f.root, &tree.root)) return f;
        const f = try self.a.create(Fixed);
        f.root = tree.root;
        f.columns = try self.a.alloc(K.FixedColumn, tree.columns.len);
        f.words = try self.a.alloc([]u32, tree.columns.len);
        for (tree.columns, f.columns, f.words) |c, *out, *w| {
            if (c.coefficients.len != @as(usize, 1) << @intCast(c.log_size)) return error.ParityFixedNotHost;
            w.* = try self.a.dupe(u32, @as([*]const u32, @ptrCast(c.coefficients.ptr))[0..c.coefficients.len]);
            out.* = .{ .log_size = c.log_size, .words = w.* };
        }
        try self.fixed.append(self.a, f);
        return f;
    }
    fn generate(raw: *anyopaque, a: std.mem.Allocator, local: S.Local, shared: S.Shared) anyerror!S.Interactions {
        const rec: *Record = @ptrCast(@alignCast(raw));
        const out = try rec.inner.generate_interactions(rec.inner.context, a, local, shared);
        rec.local = local;
        rec.shared = shared;
        rec.inter_root = out.tree.root;
        rec.claims = try self_ptr.?.a.dupe(O, out.claims);
        return out;
    }
    fn release(raw: *anyopaque) void {
        const rec: *Record = @ptrCast(@alignCast(raw));
        rec.inner.release(rec.inner.context);
    }
};

const NativeStageTwo = @typeInfo(@FieldType(Main.ResidentStages, "native_stage_two")).optional.child;
const StageTwoFn = @typeInfo(@FieldType(NativeStageTwo, "stage_two")).pointer.child;
const StageTwoParams = @typeInfo(StageTwoFn).@"fn".params;
const Digest = struct {
    mutex: std.Thread.Mutex = .{},
    value: ?[32]u8 = null,
    conflict: bool = false,
    calls: usize = 0,
    fn hook(self: *Digest) NativeStageTwo {
        return .{ .context = self, .stage_two = stageTwo };
    }
    fn stageTwo(raw: *anyopaque, a: std.mem.Allocator, worker: StageTwoParams[2].type.?, pending: StageTwoParams[3].type.?, index: usize, budget: usize) @typeInfo(StageTwoFn).@"fn".return_type.? {
        const self: *Digest = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        if (self.value) |v| {
            if (!std.mem.eql(u8, &v, &pending.digest)) self.conflict = true;
        } else self.value = pending.digest;
        self.calls += 1;
        self.mutex.unlock();
        // Exactly the legacy CPU stage two (coordinator.stageTwo without the hook).
        if (worker.replay) |*owner| try owner.restore(owner.context, worker);
        return worker.complete(a, pending, index, budget);
    }
};

// ---------------------------------------------------------------------------
// Post-hoc TruthJob runs
// ---------------------------------------------------------------------------

const Done = struct {
    done: bool = false,
    result: anyerror!void = {},
    receipt: api.Receipt = .{},
    fn call(raw: *anyopaque, c: api.Completion) void {
        const d: *@This() = @ptrCast(@alignCast(raw));
        d.receipt = c.receipt;
        d.result = c.result;
        @atomicStore(bool, &d.done, true, .release);
    }
};
fn run(worker: *W.Worker, job: api.Job) !api.Receipt {
    var done = Done{};
    try worker.submit(job, .{ .ctx = &done, .done = Done.call });
    while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
    try done.result;
    return done.receipt;
}

const Row = struct {
    ordinal: u32,
    truth_index: usize,
    family: []const u8,
    kind: []const u8,
    log: u32,
    calls: u32,
    compact_words: usize,
    binding: bool = false,
    seed_resolved: bool = false,
    stage1_root_equal: bool = false,
    stage1_gpu_ms: f32 = -1,
    stage1_wait_ns: u64 = 0,
    stage1_host_waits: u32 = 0,
    stage1_arena_peak_words: u64 = 0,
    stage1_declared_words: usize = 0,
    fixed_root_equal: bool = false,
    main_root_equal: bool = false,
    inter_root_equal: bool = false,
    claims_equal: bool = false,
    local_equal: bool = false,
    shared_equal: bool = false,
    verdicts: [6]u32 = @splat(G.Verdict.unset),
    bytes_equal: bool = false,
    /// gn-truth: device bytes == host bytes and device OODS == host engine (run 0, `.check`).
    device_check_equal: bool = false,
    device_oods_evaluated: [8]u32 = @splat(0),
    host_oods_evaluated: [8]u32 = @splat(0),
    /// Every `.device` run's bytes == legacy truth-<t>.bin.
    device_bytes_equal: bool = false,
    device_runs: u32 = 0,
    device_gpu_ms: [4]f32 = @splat(-1),
    oods_gpu_ms: [4]f32 = @splat(-1),
    finish_ns: [4]u64 = @splat(0),
    oods_nodes: usize = 0,
    oods_levels: usize = 0,
    oods_descriptor_words: usize = 0,
    encode_program_words: usize = 0,
    max_encoded_bytes: usize = 0,
    legacy_bytes: usize = 0,
    job_bytes: usize = 0,
    stage2_gpu_ms: [4]f32 = @splat(-1),
    stage2_stage_ns: [4]u64 = @splat(0),
    stage2_enqueue_ns: [4]u64 = @splat(0),
    stage2_wait_ns: [4]u64 = @splat(0),
    stage2_assemble_ns: u64 = 0,
    stage2_host_waits: u32 = 0,
    stage2_arena_peak_words: u64 = 0,
    stage2_declared_words: usize = 0,
    class_build_ns: u64 = 0,
    negatives: []const NegativeRow = &.{},
    error_name: []const u8 = "",
};
const NegativeRow = struct { fault: []const u8, expected_check: []const u8, fired: bool, word: u32, error_name: []const u8 };

fn sameLocal(a: S.Local, b_kind: X.Kind, felts: []const u32) !bool {
    var values: [X.classic_felts]O = undefined;
    const n: usize = if (b_kind == .classic) X.classic_felts else 1;
    for (0..n) |i| values[i] = try feltOf(felts[8 * i ..][0..8]);
    return switch (a) {
        .classic => |c| b_kind == .classic and std.meta.eql(c, try X.classicFrom(values[0..X.classic_felts])),
        .delegated => |d| b_kind == .delegated and d.eql(values[0]),
    };
}
fn feltOf(w: []const u32) !O {
    var limbs: [8]@import("stwo_core").fields.m31.M31 = undefined;
    for (&limbs, w[0..8]) |*l, x| {
        if (x >= @import("stwo_core").fields.m31.Modulus) return error.NoncanonicalFelt;
        l.* = @import("stwo_core").fields.m31.M31.fromCanonical(x);
    }
    return O.fromM31Array(limbs);
}

/// Host replay of the stage-2 transcript prefix (seed, FIXED root, MAIN root)
/// and the local draw: the seed variant whose draw equals the legacy one.
fn resolveSeed(rec: *const Record, class: *const K.Class) !?struct { seed: [9]u32, binding: bool } {
    const local = rec.local orelse return null;
    const fixed = rec.fixed orelse return null;
    const binding = K.Binding{ .identity = try K.fixedIdentity(fixed.columns, rec.config.fri_config.log_blowup_factor), .root = fixed.root, .profile = WP.candidateProfile(rec.config) };
    for ([_]?K.Binding{ null, binding }) |candidate| {
        const seed = K.seed(rec.config, rec.expected, candidate);
        var ch = WP.Channel.init();
        for (0..8) |i| std.mem.writeInt(u32, ch.inner.digest[i * 4 ..][0..4], seed[i], .little);
        ch.inner.n_draws = seed[8];
        WP.digest(&ch, fixed.root);
        WP.digest(&ch, rec.main_root.?);
        var felts: [X.classic_felts]O = undefined;
        try X.replay(class.localScript(), &ch, null, &felts);
        const equal = switch (local) {
            .classic => |c| std.meta.eql(c, try X.classicFrom(&felts)),
            .delegated => |d| d.eql(felts[0]),
        };
        if (equal) return .{ .seed = seed, .binding = candidate != null };
    }
    return null;
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

    var libs = try jobs.ops.Libraries.open(library, addon);
    defer libs.close();
    const device = std.fmt.parseUnsigned(u32, env("STWO_RV64_M8_PARITY_DEVICE") orelse "1", 10) catch return error.InvalidParityEnvironment;
    const arena_bytes = try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 24 << 30);
    const worker = try W.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = std.mem.alignBackward(usize, arena_bytes / 4, W.Arena.granule), .pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 1 << 30) / 4 });
    defer worker.destroy();
    std.debug.print("GPU_M8_TRUTH_PARITY phase=worker_ready device={}\n", .{device});
    const sym = try TJ.Symbols.load(&libs.base, &libs.addon);
    const events = try Events.Api.load(&libs.base);
    const Version = *const fn () callconv(.c) u32;
    const wide = if (libs.base.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false;

    // ---- legacy run with the recording decorators ----
    var config = try Router.Config.fromEnv(a);
    defer config.deinit(a);
    var recycler = Main.Recycler.init(std.heap.smp_allocator, 1 << 30);
    defer recycler.deinit();
    var session = try Main.ResidentSession.init(recycler.allocator(), manifest.immutable_host_key_bytes);
    defer session.deinit();
    const pool = try Pool.createWithBinding(a, library, config, item.expected_cpu_segments, true);
    defer pool.deinit();
    try pool.stages().requireFullyResident();
    std.debug.print("GPU_M8_TRUTH_PARITY phase=pool_ready\n", .{});
    var stages = pool.stages();
    var source = SourceDecorator{ .a = a, .inner = stages.truth_source orelse return error.ParityRequiresTruthSource };
    SourceDecorator.self_ptr = &source;
    stages.truth_source = source.stage();
    var digest = Digest{};
    if (stages.native_stage_two != null) return error.ParityNativeStageTwoAlreadySet;
    stages.native_stage_two = digest.hook();

    const resource_json = try std.json.Stringify.valueAlloc(a, manifest.resources, .{});
    const resources = try std.fs.path.join(a, &.{ out_dir, "resources.json" });
    try std.fs.cwd().writeFile(.{ .sub_path = resources, .data = resource_json });
    const request = try std.fs.path.resolve(a, &.{ std.fs.path.dirname(argv[1]) orelse ".", item.request });
    const proof = try std.fs.path.join(a, &.{ out_dir, "proof" });
    const parts = [_][]const u8{ "rv64-resident", "--security-profile", manifest.profile, "produce-candidate", request, "-", proof, "0", resources };
    var args: [parts.len][:0]u8 = undefined;
    for (parts, &args) |part, *arg| arg.* = try a.dupeZ(u8, part);
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64-m8-truth-parity", &identity, .{});
    for (pool.devices, config.caps) |*d, cap| try d.native.beginBlock(identity, .{ .device_bytes = cap, .immutable_bytes = manifest.immutable_device_bytes, .max_scopes = config.scope_limit });
    var timer = try std.time.Timer.start();
    std.debug.print("GPU_M8_TRUTH_PARITY phase=legacy_start\n", .{});
    try Main.runWithResidentArgs(&recycler, &args, stages, &session);
    const legacy_ns = timer.read();
    for (pool.devices) |*d| try d.native.endBlock(identity);
    const manifest_digest = digest.value orelse return error.ParityDigestNotObserved;
    if (digest.conflict) return error.ParityDigestConflict;
    std.debug.print("GPU_M8_TRUTH_PARITY event=legacy_done block={} truths={} digest_calls={} legacy_ns={}\n", .{ block, source.records.items.len, digest.calls, legacy_ns });

    // ---- post-hoc TruthJob runs ----
    const repeat = std.fmt.parseUnsigned(usize, "2", 10) catch return error.InvalidParityEnvironment;
    const negatives = !std.mem.eql(u8, "1", "0");
    var classes: std.ArrayListUnmanaged(*K.Class) = .empty;
    var rows: std.ArrayListUnmanaged(Row) = .empty;
    var negative_done = [2]bool{ false, false };
    std.mem.sort(*Record, source.records.items, {}, struct {
        fn less(_: void, x: *Record, y: *Record) bool {
            return x.expected.ordinal < y.expected.ordinal;
        }
    }.less);
    for (source.records.items) |rec| {
        const truth_index = rec.expected.ordinal - @as(u32, @intCast(item.expected_cpu_segments));
        var row = Row{ .ordinal = rec.expected.ordinal, .truth_index = truth_index, .family = @tagName(std.meta.activeTag(rec.truth)), .kind = "", .log = K.truthLog(rec.truth) catch 0, .calls = rec.truth.count(), .compact_words = rec.compact.len };
        proveOne(a, worker, &sym, &events, wide, &libs.base, rec, manifest_digest, proof, &classes, &row, repeat, negatives, &negative_done) catch |err| {
            row.error_name = @errorName(err);
        };
        std.debug.print("GPU_M8_TRUTH_PARITY ordinal={} family={s} log={} calls={} stage1_root_equal={} fixed={} main={} inter={} claims={} local={} shared={} verdicts={any} bytes_equal={} device_check_equal={} device_bytes_equal={} legacy_bytes={} job_bytes={} stage1_gpu_ms={d:.3} stage2_gpu_ms={any} device_gpu_ms={any} oods_gpu_ms={any} finish_ns={any} assemble_ns={} oods_nodes={} oods_levels={} arena_peak={} declared={} error={s}\n", .{ row.ordinal, row.family, row.log, row.calls, row.stage1_root_equal, row.fixed_root_equal, row.main_root_equal, row.inter_root_equal, row.claims_equal, row.local_equal, row.shared_equal, row.verdicts, row.bytes_equal, row.device_check_equal, row.device_bytes_equal, row.legacy_bytes, row.job_bytes, row.stage1_gpu_ms, row.stage2_gpu_ms, row.device_gpu_ms, row.oods_gpu_ms, row.finish_ns, row.stage2_assemble_ns, row.oods_nodes, row.oods_levels, row.stage2_arena_peak_words, row.stage2_declared_words, row.error_name });
        try rows.append(a, row);
    }
    var all = rows.items.len != 0;
    var negatives_all = true;
    for (rows.items) |r| {
        all = all and r.error_name.len == 0 and r.seed_resolved and r.stage1_root_equal and r.fixed_root_equal and r.main_root_equal and r.inter_root_equal and r.claims_equal and r.local_equal and r.shared_equal and r.bytes_equal and r.device_check_equal and r.device_bytes_equal and r.stage2_host_waits == 1 and r.stage1_host_waits == 1;
        for (r.verdicts) |v| all = all and v == G.Verdict.accepted;
        for (r.negatives) |n| negatives_all = negatives_all and n.fired;
    }
    var text: std.Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{ .schema = "rv64-m8-truth-parity/v2", .block = block, .legacy_native_wall_ns = legacy_ns, .job_device = device, .wide_framing = wide, .classes = classes.items.len, .all_equal = all, .negatives_all_fired = negatives_all, .truths = rows.items }, .{ .whitespace = .indent_1 }, &text.writer);
    const report = try std.fs.path.join(a, &.{ out_dir, "truth-parity.json" });
    try std.fs.cwd().writeFile(.{ .sub_path = report, .data = text.written() });
    std.debug.print("GPU_M8_TRUTH_PARITY_DONE block={} truths={} classes={} all_equal={} negatives_all_fired={} report={s}\n", .{ block, rows.items.len, classes.items.len, all, negatives_all, report });
    for (classes.items) |c| {
        c.deinit();
        a.destroy(c);
    }
    if (!all) return error.TruthParityMismatch;
    if (negatives and !negatives_all) return error.TruthNegativeNotFired;
}

fn classFor(a: std.mem.Allocator, rec: *const Record, sym: *const TJ.Symbols, wide: bool, base: *std.DynLib, classes: *std.ArrayListUnmanaged(*K.Class), build_ns: *u64) !*K.Class {
    const fixed = rec.fixed orelse return error.ParityFixedNotRecorded;
    const key = try K.classKey(rec.truth, rec.config, fixed.root);
    for (classes.items) |c| if (std.mem.eql(u8, &c.key, &key)) return c;
    var timer = try std.time.Timer.start();
    // STWO_RV64_M8_TRUTH_CLASS_SKEW (default 1): build the class from the
    // truth under a DIFFERENT span (same class key: classes are span-free),
    // as a service does when a class warmed on one request proves another.
    // Every job below runs with the record's own span, so byte identity
    // checks that nothing request-specific leaks from the class authority.
    const skew = !std.mem.eql(u8, "1", "0");
    const authority = if (skew) K.withSpan(rec.truth, if (rec.truth.count() > 1) rec.truth.count() - 1 else rec.truth.count() + 1, rec.truth.first() + 1) else rec.truth;
    if (!std.mem.eql(u8, &key, &try K.classKey(authority, rec.config, fixed.root))) return error.ParityClassKeyNotSpanFree;
    const class = try K.build(a, .{ .truth = authority, .config = rec.config, .fixed = fixed.columns, .fixed_root = fixed.root, .psym = sym.pcs, .wide_framing = wide });
    errdefer {
        class.deinit();
        a.destroy(class);
    }
    try K.bindLaunches(class, a, base);
    build_ns.* = timer.read();
    try classes.append(a, class);
    return class;
}

fn proveOne(a: std.mem.Allocator, worker: *W.Worker, sym: *const TJ.Symbols, events: *const Events.Api, wide: bool, base: *std.DynLib, rec: *Record, digest: [32]u8, proof_dir: []const u8, classes: *std.ArrayListUnmanaged(*K.Class), row: *Row, repeat: usize, negatives: bool, negative_done: *[2]bool) !void {
    if (rec.compact.len == 0) return error.ParityCompactUnsupported;
    const class = try classFor(a, rec, sym, wide, base, classes, &row.class_build_ns);
    row.kind = @tagName(class.kind);
    const resolved = (try resolveSeed(rec, class)) orelse return error.ParitySeedUnresolved;
    row.seed_resolved = true;
    row.binding = resolved.binding;
    // Stage 1: MAIN root from the compact inputs alone.
    var s1 = TJ.Stage1{ .a = a, .class = class, .sym = sym, .ordinal = rec.expected.ordinal, .calls = rec.truth.count(), .first_id = rec.truth.first(), .compact = rec.compact, .timing = events };
    try s1.init();
    defer s1.deinit();
    row.stage1_declared_words = s1.footprint().device_words;
    const r1 = try run(worker, s1.job());
    row.stage1_gpu_ms = s1.span.gpu_ms;
    row.stage1_wait_ns = r1.wait_ns;
    row.stage1_host_waits = r1.host_waits;
    row.stage1_arena_peak_words = r1.arena_peak_words;
    const legacy_main = rootWords(rec.main_root.?);
    row.stage1_root_equal = std.mem.eql(u32, &s1.root, &legacy_main);
    // Stage 2 (cold, then warm repeats): the whole proof from seed + digest + compact.
    const legacy_bytes = blk: {
        var nb: [64]u8 = undefined;
        const file = try std.fmt.bufPrint(&nb, "truth-{d}.bin", .{row.truth_index});
        const path = try std.fs.path.join(a, &.{ proof_dir, file });
        defer a.free(path);
        break :blk try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
    };
    defer a.free(legacy_bytes);
    row.legacy_bytes = legacy_bytes.len;
    row.oods_nodes = class.oods.nodes;
    row.oods_levels = class.oods.levels;
    row.oods_descriptor_words = class.oods.words.len;
    row.encode_program_words = class.encode.words.len;
    row.max_encoded_bytes = class.encode.max_encoded_bytes;
    var device_all = true;
    for (0..@max(2, @min(repeat, 4))) |k| {
        // Run 0: `.check` (host assembly + device OODS/encoder, compared);
        // runs 1..: `.device` (the GPU-native stage 2: no host assembly).
        const mode: TJ.Encode = if (k == 0) .check else .device;
        var s2 = TJ.Stage2{ .a = a, .class = class, .sym = sym, .ordinal = rec.expected.ordinal, .calls = rec.truth.count(), .first_id = rec.truth.first(), .compact = rec.compact, .seed = resolved.seed, .digest_words = digestWords(digest), .stage1_root_words = s1.root, .timing = events, .encode = mode };
        try s2.init();
        defer s2.deinit();
        row.stage2_declared_words = s2.footprint().device_words;
        const r2 = try run(worker, s2.job());
        row.stage2_gpu_ms[k] = s2.span.gpu_ms;
        row.device_gpu_ms[k] = s2.device_span.gpu_ms;
        row.oods_gpu_ms[k] = s2.oods_span.gpu_ms;
        row.finish_ns[k] = s2.finish_ns;
        row.stage2_stage_ns[k] = r2.stage_ns;
        row.stage2_enqueue_ns[k] = r2.enqueue_ns;
        row.stage2_wait_ns[k] = r2.wait_ns;
        row.stage2_host_waits = r2.host_waits;
        row.stage2_arena_peak_words = @max(row.stage2_arena_peak_words, r2.arena_peak_words);
        if (k == 0) {
            row.stage2_assemble_ns = s2.assemble_ns;
            row.fixed_root_equal = std.mem.eql(u32, s2.roots[0..8], &rootWords(rec.fixed.?.root));
            row.main_root_equal = std.mem.eql(u32, s2.roots[8..16], &legacy_main);
            row.inter_root_equal = std.mem.eql(u32, s2.roots[16..24], &rootWords(rec.inter_root.?));
            var ce = rec.claims.len == class.claim_count;
            if (ce) for (rec.claims, 0..) |cl, i| {
                ce = ce and std.mem.eql(u32, &X.words(cl), s2.claims[8 * i ..][0..8]);
            };
            row.claims_equal = ce;
            row.local_equal = try sameLocal(rec.local.?, class.kind, &s2.local_felts);
            var sf: [X.shared_felts]O = undefined;
            for (&sf, 0..) |*v, i| v.* = try feltOf(s2.shared_felts[8 * i ..][0..8]);
            row.shared_equal = std.meta.eql(rec.shared.?, try X.sharedFrom(&sf));
            row.verdicts = s2.verdict_words;
            row.job_bytes = s2.bytes.len;
            row.bytes_equal = std.mem.eql(u8, s2.bytes, legacy_bytes);
            row.device_check_equal = s2.device_equal;
            @memcpy(&row.device_oods_evaluated, s2.oods_diag[0..8]);
            @memcpy(&row.host_oods_evaluated, s2.host_oods[0..8]);
            if (!row.bytes_equal or !s2.device_equal) {
                var nb: [64]u8 = undefined;
                for ([_]struct { name: []const u8, bytes: []const u8 }{ .{ .name = "job", .bytes = s2.bytes }, .{ .name = "device", .bytes = s2.device_bytes } }) |x| {
                    const file = try std.fmt.bufPrint(&nb, "{s}-truth-{d}.bin", .{ x.name, row.truth_index });
                    const path = try std.fs.path.join(a, &.{ proof_dir, "..", file });
                    defer a.free(path);
                    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = x.bytes });
                }
            }
        } else {
            device_all = device_all and std.mem.eql(u8, s2.device_bytes, legacy_bytes);
            for (s2.verdict_words) |w| device_all = device_all and w == G.Verdict.accepted;
            row.device_runs += 1;
        }
        if (s2.bytes.len != 0) a.free(s2.bytes);
        if (s2.out_claims.len != 0) a.free(s2.out_claims);
        if (s2.device_bytes.len != 0) a.free(s2.device_bytes);
    }
    row.device_bytes_equal = device_all and row.device_runs != 0;
    // Negatives: once per kind, each fault must fire exactly its check.
    const kind_index: usize = @intFromEnum(class.kind);
    if (!negatives or negative_done[kind_index]) return;
    negative_done[kind_index] = true;
    // Slots: verdict_names order (truth_status, root_match, channel_order,
    // pcs_status, truth_oods, encode_bounds). `also`: a word that may fire
    // too because the fault invalidates the statement itself (a corrupted
    // gather makes the composition use wrong parameters: the OODS check
    // then legitimately rejects as well).
    const cases = [_]struct { fault: TJ.Fault, check: []const u8, slot: usize, also: ?usize = null }{
        .{ .fault = .parameter_program, .check = "truth_status", .slot = 0, .also = 4 },
        .{ .fault = .absent_claim, .check = "truth_status", .slot = 0 },
        .{ .fault = .class_root, .check = "root_match", .slot = 1 },
        .{ .fault = .stage1_root, .check = "root_match", .slot = 1 },
        .{ .fault = .channel_cursor, .check = "channel_order", .slot = 2 },
        .{ .fault = .pcs_header, .check = "pcs_status", .slot = 3 },
        .{ .fault = .oods_sample, .check = "truth_oods", .slot = 4 },
        .{ .fault = .oods_composition, .check = "truth_oods", .slot = 4 },
        .{ .fault = .encode_capacity, .check = "encode_bounds", .slot = 5 },
        .{ .fault = .encode_value, .check = "encode_bounds", .slot = 5 },
    };
    var out: std.ArrayListUnmanaged(NegativeRow) = .empty;
    for (cases) |case| {
        if (case.fault == .absent_claim and class.kind == .delegated and class.zero_count == 0) continue;
        var s2 = TJ.Stage2{ .a = a, .class = class, .sym = sym, .ordinal = rec.expected.ordinal, .calls = rec.truth.count(), .first_id = rec.truth.first(), .compact = rec.compact, .seed = resolved.seed, .digest_words = digestWords(digest), .stage1_root_words = s1.root, .fault = case.fault, .assemble_on_finish = false, .encode = .device };
        try s2.init();
        defer s2.deinit();
        defer if (s2.device_bytes.len != 0) a.free(s2.device_bytes);
        var neg = NegativeRow{ .fault = @tagName(case.fault), .expected_check = case.check, .fired = false, .word = 0, .error_name = "" };
        if (run(worker, s2.job())) |_| {
            neg.error_name = "AcceptedUnderFault";
        } else |err| {
            neg.error_name = @errorName(err);
            neg.word = s2.verdict_words[case.slot];
            // Exactly the expected word rejects (plus `also`); every other check accepts.
            var only = err == error.DeviceTruthCheckRejected and neg.word != G.Verdict.accepted and neg.word != G.Verdict.unset;
            for (s2.verdict_words, 0..) |w, i| if (i != case.slot and (case.also == null or i != case.also.?)) {
                only = only and w == G.Verdict.accepted;
            };
            // A rejected encode publishes no bytes (length word 0).
            if (case.slot == 5) only = only and s2.device_bytes.len == 0;
            neg.fired = only;
        }
        std.debug.print("GPU_M8_TRUTH_NEGATIVE ordinal={} fault={s} check={s} fired={} word=0x{x} words={any} error={s}\n", .{ rec.expected.ordinal, neg.fault, neg.expected_check, neg.fired, neg.word, s2.verdict_words, neg.error_name });
        try out.append(a, neg);
    }
    row.negatives = out.items;
}
