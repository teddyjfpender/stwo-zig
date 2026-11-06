//! M8 native-producers real-block parity harness (pod only, opt-in binary).
//!
//! Runs the unchanged legacy resident native pipeline on a real block (the
//! same manifest/request the gate writes) with ONE difference: the pool's
//! local-GKR NumericalStage is wrapped. The wrapper calls the legacy stage,
//! then proves the same segment's local GKR again as an M8 job
//! (jobs/native_gkr.zig GkrJob) on a DeviceWorker on another GPU, reading the
//! legacy MAIN coefficients by device pointer and the host FIXED coefficients
//! through the stager, and compares:
//!   * the job's device child transcript after the relation draws with the
//!     legacy request channel (digest + draws);
//!   * the decoded GKR proof with the legacy proof (every sumcheck round
//!     polynomial, layer mask and output claim).
//! The legacy proof is returned unchanged, so the pipeline (and its proof
//! bytes) is not affected. Results: <out>/native-gkr-parity.json.
//!
//! usage: rv64-m8-native-parity <manifest.json> <out-dir>
//! env:   the gate's service environment (STWO_RV64_GPU_LIBRARY, ...), plus
//!        STWO_RV64_M8_JOBS_LIBRARY (addon), STWO_RV64_M8_PARITY_DEVICE (job
//!        GPU, default 1; the legacy pool should use STWO_RV64_GPU_DEVICES=0),
//!        STWO_RV64_M8_JOBS_ARENA_BYTES, STWO_RV64_M8_JOBS_PINNED_BYTES.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Main = CPU.rv64_ethereum_gkr_main;
const Child = CPU.rv64_gkr_child;
const Pool = @import("rv64/resident_pool.zig").Pool;
const Router = @import("rv64/resident_router.zig");
const jobs = @import("rv64/jobs/mod.zig");
const W = jobs.worker;
const api = jobs.api;
const NG = @import("rv64/jobs/native_gkr.zig");
const Sources = @import("rv64/gkr_sources.zig");

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

const Row = struct {
    ordinal: u32,
    instances: usize,
    columns: usize,
    host_columns: usize,
    cells: usize,
    facts: u64,
    channel_equal: bool,
    proof_equal: bool,
    legacy_ns: u64,
    job_stage_ns: u64,
    job_enqueue_ns: u64,
    job_wait_ns: u64,
    host_waits: u32,
    d2h_bytes: u64,
    arena_peak_words: u64,
    declared_device_words: u64,
    launches: u64,
    error_name: []const u8 = "",
};

const Decorator = struct {
    a: std.mem.Allocator,
    inner: Child.NumericalStage,
    worker: *W.Worker,
    symbols: NG.Symbols,
    catalogue: Sources.Catalogue,
    arena_bytes: usize,
    mutex: std.Thread.Mutex = .{},
    rows: std.ArrayListUnmanaged(Row) = .empty,

    fn stage(self: *Decorator) Child.NumericalStage {
        var out = self.inner;
        out.context = self;
        out.prove = prove;
        // bind/abort/replay keep the legacy owner (they take the inner context).
        out.bind = if (self.inner.bind != null) bind else null;
        out.abort = if (self.inner.abort != null) abortScope else null;
        out.replay_binding = if (self.inner.replay_binding != null) replay else null;
        return out;
    }
    fn bind(raw: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) anyerror!Child.DeviceBinding.Owner {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        return self.inner.bind.?(self.inner.context, a, request);
    }
    fn abortScope(raw: *anyopaque, scope: NG.Scope) void {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        self.inner.abort.?(self.inner.context, scope);
    }
    fn replay(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request, owner: *Child.DeviceBinding.Owner) anyerror!void {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        return self.inner.replay_binding.?(self.inner.context, a, request, owner);
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request) anyerror!NG.Proof {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        const legacy = try self.inner.prove(self.inner.context, a, request);
        const legacy_ns = timer.read();
        // One job at a time on the parity worker (segments run in parallel lanes).
        self.mutex.lock();
        defer self.mutex.unlock();
        const row = self.compare(request, &legacy, legacy_ns) catch |err| Row{ .ordinal = request.scope.ordinal, .instances = request.instances.len, .columns = 0, .host_columns = 0, .cells = 0, .facts = 0, .channel_equal = false, .proof_equal = false, .legacy_ns = legacy_ns, .job_stage_ns = 0, .job_enqueue_ns = 0, .job_wait_ns = 0, .host_waits = 0, .d2h_bytes = 0, .arena_peak_words = 0, .declared_device_words = 0, .launches = 0, .error_name = @errorName(err) };
        std.debug.print("GPU_M8_NATIVE_GKR_PARITY ordinal={} channel_equal={} proof_equal={} legacy_ns={} job_enqueue_ns={} job_wait_ns={} host_waits={} arena_peak_words={} error={s}\n", .{ row.ordinal, row.channel_equal, row.proof_equal, row.legacy_ns, row.job_enqueue_ns, row.job_wait_ns, row.host_waits, row.arena_peak_words, row.error_name });
        try self.rows.append(self.a, row);
        return legacy;
    }
    fn compare(self: *Decorator, request: Child.NumericalStage.Request, legacy: *const NG.Proof, legacy_ns: u64) !Row {
        const a = self.a;
        const native = request.native_source orelse return error.NativeGkrSourceRequired;
        var plan = try NG.Plan.init(a, &self.catalogue, request.scope, request.instances, native, request.native_fixed_columns, request.native_main_columns, self.arena_bytes, 0);
        defer plan.deinit();
        const total = request.native_fixed_columns.len + request.native_main_columns.len;
        const inputs = try a.alloc(NG.Input, total);
        defer a.free(inputs);
        var host_columns: usize = 0;
        var main_host = false;
        for (inputs, 0..) |*input, i| {
            const column = if (i < request.native_fixed_columns.len) request.native_fixed_columns[i] else request.native_main_columns[i - request.native_fixed_columns.len];
            if (column.device) |d| {
                input.* = .{ .device = d.words };
            } else {
                input.* = .{ .host = @as([*]const u32, @ptrCast(column.coefficients.ptr))[0..column.coefficients.len] };
                host_columns += 1;
                main_host = main_host or i >= request.native_fixed_columns.len;
            }
        }
        var job = try NG.GkrJob.init(a, &plan, &self.symbols, inputs);
        defer job.deinit();
        var root: [8]u32 = undefined;
        for (&root, 0..) |*w, i| w.* = std.mem.readInt(u32, request.scope.main[4 * i ..][0..4], .little);
        job.main_root_host = root;
        // FIXED coefficients are class-immutable: keep them warm on the worker,
        // keyed by the FIXED root and their size (only when MAIN is all device).
        if (!main_host and host_columns != 0) {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update("rv64-m8-gkr-host-fixed");
            h.update(&request.scope.fixed);
            h.update(std.mem.asBytes(&plan.host_column_words));
            job.gkr.host_key = h.finalResult();
        }
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
        var done = Done{};
        const footprint = job.footprint();
        try self.worker.submit(api.Job.from(NG.GkrJob, &job), .{ .ctx = &done, .done = Done.call });
        while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
        try done.result;
        const section = &(job.section orelse return error.NativeGkrSectionMissing);
        var channel_equal = section.snapshot.draws == request.channel.inner.n_draws;
        for (section.snapshot.digest, 0..) |w, i| channel_equal = channel_equal and w == std.mem.readInt(u32, request.channel.inner.digest[4 * i ..][0..4], .little);
        var proof = try section.proof(a, &plan);
        defer proof.deinit(a);
        var facts: u64 = 0;
        for (plan.source.items) |item| facts += item.facts;
        const r = done.receipt;
        return .{ .ordinal = request.scope.ordinal, .instances = request.instances.len, .columns = total, .host_columns = host_columns, .cells = plan.source.cells, .facts = facts, .channel_equal = channel_equal, .proof_equal = deepEql(proof, legacy.*), .legacy_ns = legacy_ns, .job_stage_ns = r.stage_ns, .job_enqueue_ns = r.enqueue_ns, .job_wait_ns = r.wait_ns, .host_waits = r.host_waits, .d2h_bytes = r.d2h_bytes, .arena_peak_words = r.arena_peak_words, .declared_device_words = footprint.device_words, .launches = job.gkr.launches };
    }
};

/// Structural equality of proof values. Polynomials compare their logical
/// coefficients (`coeffs[0..len]`); ownership flags are not proof content.
fn deepEql(x: anytype, y: @TypeOf(x)) bool {
    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .pointer => |p| {
            if (p.size != .slice) return deepEql(x.*, y.*);
            if (x.len != y.len) return false;
            for (x, y) |u, v| if (!deepEql(u, v)) return false;
            return true;
        },
        .array => {
            for (x, y) |u, v| if (!deepEql(u, v)) return false;
            return true;
        },
        .@"struct" => |s| {
            if (comptime @hasField(T, "coeffs") and @hasField(T, "len")) {
                if (x.len != y.len or x.len > x.coeffs.len or y.len > y.coeffs.len) return false;
                return deepEql(x.coeffs[0..x.len], y.coeffs[0..y.len]);
            }
            inline for (s.fields) |f| {
                if (comptime std.mem.startsWith(u8, f.name, "owns")) continue;
                if (!deepEql(@field(x, f.name), @field(y, f.name))) return false;
            }
            return true;
        },
        else => return std.meta.eql(x, y),
    }
}

fn env(name: []const u8) ?[]const u8 {
    return std.posix.getenv(name);
}
fn envBytes(name: []const u8, default: usize) !usize {
    const text = env(name) orelse return default;
    return std.fmt.parseUnsigned(usize, text, 10) catch error.InvalidParityEnvironment;
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
    defer a.free(raw);
    var parsed = try std.json.parseFromSlice(Manifest, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const manifest = parsed.value;
    const block = manifest.execution_order[0];
    var name_buf: [24]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "{d}", .{block});
    const item = manifest.blocks.map.get(name) orelse return error.MissingResidentBatchBlock;

    // M8 worker first (its arena is carved before the legacy pool's arena).
    var libs = try jobs.ops.Libraries.open(library, addon);
    defer libs.close();
    const device = std.fmt.parseUnsigned(u32, env("STWO_RV64_M8_PARITY_DEVICE") orelse "1", 10) catch return error.InvalidParityEnvironment;
    const arena_bytes = try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 24 << 30);
    const worker = try W.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = std.mem.alignBackward(usize, arena_bytes / 4, W.Arena.granule), .pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 1 << 30) / 4 });
    defer worker.destroy();

    var config = try Router.Config.fromEnv(a);
    defer config.deinit(a);
    var recycler = Main.Recycler.init(std.heap.smp_allocator, 1 << 30);
    defer recycler.deinit();
    const base = recycler.allocator();
    var session = try Main.ResidentSession.init(base, manifest.immutable_host_key_bytes);
    defer session.deinit();
    const pool = try Pool.createWithBinding(a, library, config, item.expected_cpu_segments, true);
    defer pool.deinit();
    try pool.stages().requireFullyResident();
    var decorator = Decorator{ .a = a, .inner = pool.stages().numerical.?.*, .worker = worker, .symbols = try NG.Symbols.load(&libs.base), .catalogue = try Sources.Catalogue.init(a), .arena_bytes = arena_bytes };
    defer decorator.catalogue.deinit();
    defer decorator.rows.deinit(a);
    const wrapped = decorator.stage();
    var stages = pool.stages();
    stages.numerical = &wrapped;

    const resource_json = try std.json.Stringify.valueAlloc(a, manifest.resources, .{});
    defer a.free(resource_json);
    const resources = try std.fs.path.join(a, &.{ out_dir, "resources.json" });
    defer a.free(resources);
    try std.fs.cwd().writeFile(.{ .sub_path = resources, .data = resource_json });
    const request = try std.fs.path.resolve(a, &.{ std.fs.path.dirname(argv[1]) orelse ".", item.request });
    defer a.free(request);
    const proof = try std.fs.path.join(a, &.{ out_dir, "proof" });
    defer a.free(proof);
    const parts = [_][]const u8{ "rv64-resident", "--security-profile", manifest.profile, "produce-candidate", request, "-", proof, "0", resources };
    var args: [parts.len][:0]u8 = undefined;
    for (parts, &args) |part, *arg| arg.* = try a.dupeZ(u8, part);
    defer for (args) |arg| a.free(arg);
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64-m8-native-parity", &identity, .{});
    for (pool.devices, config.caps) |*d, cap| try d.native.beginBlock(identity, .{ .device_bytes = cap, .immutable_bytes = manifest.immutable_device_bytes, .max_scopes = config.scope_limit });
    var timer = try std.time.Timer.start();
    try Main.runWithResidentArgs(&recycler, &args, stages, &session);
    const wall_ns = timer.read();
    for (pool.devices) |*d| try d.native.endBlock(identity);

    var all = decorator.rows.items.len == item.expected_cpu_segments;
    for (decorator.rows.items) |row| all = all and row.channel_equal and row.proof_equal and row.host_waits == 1 and row.error_name.len == 0;
    var text: std.Io.Writer.Allocating = .init(a);
    defer text.deinit();
    try std.json.Stringify.value(.{ .schema = "rv64-m8-native-gkr-parity/v1", .block = block, .expected_segments = item.expected_cpu_segments, .legacy_native_wall_ns = wall_ns, .job_device = device, .all_equal = all, .segments = decorator.rows.items }, .{ .whitespace = .indent_1 }, &text.writer);
    const report = try std.fs.path.join(a, &.{ out_dir, "native-gkr-parity.json" });
    defer a.free(report);
    try std.fs.cwd().writeFile(.{ .sub_path = report, .data = text.written() });
    std.debug.print("GPU_M8_NATIVE_GKR_PARITY_DONE block={} segments={} all_equal={} report={s}\n", .{ block, decorator.rows.items.len, all, report });
    if (!all) return error.NativeGkrParityMismatch;
}
