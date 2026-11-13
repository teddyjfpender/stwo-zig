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
//!   STWO_RV64_M8_JOBS_LIBRARY       the jobs addon (required)
//!   STWO_RV64_M8_PARITY_DEVICE      job GPU (default 1; the legacy pool should
//!                                   use STWO_RV64_GPU_DEVICES=0)
//!   STWO_RV64_M8_PARITY_SOURCE_DEVICE  legacy GPU the peer copies read (default 0)
//!   STWO_RV64_M8_JOBS_ARENA_BYTES   job arena (default 20 GiB: the legacy global
//!                                   kernels native_global reuses allocate OUTSIDE
//!                                   the arena; 23 GiB failed 10/127 slots on
//!                                   24628607, 20 GiB passes 127/127)
//!   STWO_RV64_M8_JOBS_PINNED_BYTES  pinned slot size (default 1 GiB)
//!   STWO_RV64_M8_PARITY_ONLY        "" (default: GKR/Stage1/binding, global,
//!                                   commits; + composition/PCS when enabled),
//!                                   "composition" (composition only; with
//!                                   DEVICE_CLAIMS=1 also the global decorator,
//!                                   the source of the device claims) or "pcs"
//!   STWO_RV64_M8_PARITY_STAGE1      1 (default) / 0: Stage1 job checks
//!   STWO_RV64_M8_PARITY_BINDING     1 (default) / 0: binding tail in Stage1
//!   STWO_RV64_M8_PARITY_COMPOSITION 0 (default) / 1: composition parity
//!   STWO_RV64_M8_PARITY_DEVICE_CLAIMS 0 (default) / 1: composition claim slots
//!                                   patched from the native_global jobs' claims
//!                                   (Stage2 layout, jobs/native_claims.zig)
//!   STWO_RV64_M8_PARITY_TRUTH       1 (default) / 0: truth compositions too
//!   STWO_RV64_M8_PARITY_PCS         0 (default) / 1: OODS + PCS parity
const std = @import("std");
const ProductCPU = @import("ethereum_cpu_component");
const CPU = @import("stwo_riscv_cpu_integration");
const Main = ProductCPU.rv64_ethereum_gkr_main;
const Child = CPU.rv64_gkr_child;
const Pool = @import("rv64/resident_pool.zig").Pool;
const Router = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.resident_router;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const W = jobs.worker;
const api = jobs.api;
const NG = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_gkr;
const Sources = @import("stwo_riscv_cuda_integration").rv64.execution.source.gkr_sources;
const NGl = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_global;
const NC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_commit;
const NS1 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_stage1;
const NB = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_binding;
const NP = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_pcs;
const A = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.abi;
const NComp = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_composition;
const S2 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_stage2;
const NClaims = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_claims;
const CompRoles = @import("stwo_riscv_cuda_integration").rv64.execution.composition.roles;
const RC = @import("stwo_riscv_cuda_integration").rv64.resident_composition;
const Worker = CPU.rv64_gkr_cpu_worker;
const TruthComposition = CPU.rv64_gkr_truth_device_composition;
const Events = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.cuda_events;
const Trace = @import("stwo_prover_engine").air.component_prover.ForField(O).Trace;
/// Native PCS blowup seen by the trace-commit wrapper (MAIN precedes the GKR).
const native_beta = &@import("rv64/parity/native_common.zig").native_beta;

const DP = CPU.rv64_device_pcs;
const Slab = jobs.slab;
const DG = CPU.rv64_gkr_cpu_worker.DeviceGlobal;
const O = @import("stwo_core").fields.om31.OM31;
const Compare = @import("rv64/parity/native_common.zig").Compare;
const PeerCopy = @import("rv64/parity/native_common.zig").PeerCopy;
const Peer = @import("rv64/parity/native_common.zig").Peer;
const GkrParityJob = @import("rv64/parity/native_gkr.zig").GkrParityJob;
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

const Row = @import("rv64/parity/native_gkr.zig").Row;
const bindingRoots = @import("rv64/parity/native_gkr.zig").bindingRoots;
const bindingTreeWords = @import("rv64/parity/native_gkr.zig").bindingTreeWords;
const BindingCheckJob = @import("rv64/parity/native_gkr.zig").BindingCheckJob;
const BindingOwner = @import("rv64/parity/native_gkr.zig").BindingOwner;
const Stage1ParityJob = @import("rv64/parity/native_gkr.zig").Stage1ParityJob;
const wordsEqual = @import("rv64/parity/native_gkr.zig").wordsEqual;
const Decorator = @import("rv64/parity/native_gkr.zig").Decorator;
const GlobalRow = @import("rv64/parity/native_global_commit.zig").GlobalRow;
const GlobalParityJob = @import("rv64/parity/native_global_commit.zig").GlobalParityJob;
const check = @import("rv64/parity/native_common.zig").check;

const GlobalDecorator = @import("rv64/parity/native_global_commit.zig").GlobalDecorator;
const CommitRow = @import("rv64/parity/native_global_commit.zig").CommitRow;
const CommitParityJob = @import("rv64/parity/native_global_commit.zig").CommitParityJob;
const CommitDecorator = @import("rv64/parity/native_global_commit.zig").CommitDecorator;
const CompositionRow = @import("rv64/parity/native_composition.zig").CompositionRow;
const CompositionParityJob = @import("rv64/parity/native_composition.zig").CompositionParityJob;
const CompositionDecorator = @import("rv64/parity/native_composition.zig").CompositionDecorator;
const Done = @import("rv64/parity/native_common.zig").Done;
const PcsRow = @import("rv64/parity/native_pcs.zig").PcsRow;
const PcsParityJob = @import("rv64/parity/native_pcs.zig").PcsParityJob;
const PcsDecorator = @import("rv64/parity/native_pcs.zig").PcsDecorator;
const deepEql = @import("rv64/parity/native_common.zig").deepEql;
const env = @import("rv64/parity/native_common.zig").env;
const envBytes = @import("rv64/parity/native_common.zig").envBytes;
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
    // 20 GiB: headroom for the legacy global kernels' out-of-arena scratch (see header).
    const arena_bytes = try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 20 << 30);
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
    const peer = Peer{ .copy = libs.addon.lookup(PeerCopy, "stwo_rv64_jobs_native_peer_copy_v1") orelse return error.ParityRequiresPeerCopy, .source_device = std.fmt.parseUnsigned(c_int, env("STWO_RV64_M8_PARITY_SOURCE_DEVICE") orelse "0", 10) catch return error.InvalidParityEnvironment };
    // STWO_RV64_M8_PARITY_ONLY (parsed once): see the header.
    const Only = enum { all, composition, pcs };
    const only_mode = env("STWO_RV64_M8_PARITY_ONLY") orelse "";
    const only: Only = if (only_mode.len == 0) .all else std.meta.stringToEnum(Only, only_mode) orelse return error.InvalidParityEnvironment;
    const only_composition = only == .composition;
    const device_claims = std.mem.eql(u8, env("STWO_RV64_M8_PARITY_DEVICE_CLAIMS") orelse "0", "1");
    var stages = pool.stages();
    var decorator = Decorator{ .a = a, .inner = pool.stages().numerical.?.*, .worker = worker, .symbols = try NG.Symbols.load(&libs.base), .catalogue = try Sources.Catalogue.init(a), .arena_bytes = arena_bytes, .peer = peer, .csym = try NC.Symbols.load(&libs.base) };
    defer decorator.catalogue.deinit();
    defer decorator.rows.deinit(a);
    defer decorator.pending_binding.deinit(a);
    const events_api = try Events.Api.load(&libs.base);
    if (!std.mem.eql(u8, "1", "0") and !std.mem.eql(u8, "1", "0")) {
        decorator.bsym = try NB.Symbols.load(&libs.base);
        decorator.events = &events_api;
    }
    const wrapped = decorator.stage();
    if (only == .all) stages.numerical = &wrapped;
    const compare = libs.addon.lookup(Compare, "stwo_rv64_jobs_native_compare_v1") orelse return error.ParityRequiresCompareKernel;
    var global = GlobalDecorator{ .a = a, .inner = stages.global_interaction orelse return error.ParityRequiresDeviceGlobal, .worker = worker, .symbols = try NGl.Symbols.load(&libs.base), .catalogue = NGl.Catalogue.init(a, &libs.base), .compare = compare, .peer = peer };
    defer global.deinit();
    // The global decorator is also the source of the composition's device claims.
    if (only == .all or (only_composition and device_claims)) stages.global_interaction = global.stage();
    var commits = CommitDecorator{ .a = a, .inner = stages.trace_commit orelse return error.ParityRequiresDeviceTraceCommit, .worker = worker, .symbols = try NC.Symbols.load(&libs.base), .peer = peer };
    defer commits.rows.deinit(a);
    const wrapped_commit = commits.stage();
    if (only == .all) stages.trace_commit = &wrapped_commit;

    var composition = CompositionDecorator{ .a = a, .inner = stages.resident_composition orelse return error.ParityRequiresResidentComposition, .context = &pool.devices[0].composition, .events = &events_api, .worker = worker, .symbols = try NComp.Symbols.load(&libs.base, &libs.addon), .compare = compare, .peer = peer };
    defer composition.rows.deinit(a);
    const wrapped_composition = composition.stage();
    const composition_flag = env("STWO_RV64_M8_PARITY_COMPOSITION") orelse "0";
    const check_composition = only_composition or !std.mem.eql(u8, composition_flag, "0");
    if (check_composition) stages.resident_composition = &wrapped_composition;
    composition.device_claims = device_claims;
    if (only == .all or only_composition) composition.global = &global;
    // Truth/service compositions through the same producer (truth kernel).
    if (check_composition and !std.mem.eql(u8, "1", "0")) {
        composition.truth_inner = stages.truth_composition orelse return error.ParityRequiresTruthComposition;
        stages.truth_composition = composition.truthStage();
    }
    // STWO_RV64_M8_PARITY_PCS=1 (default 0): OODS + enqueue-only PCS at every
    // legacy PCS (CPU segments and truths).
    const check_pcs = std.mem.eql(u8, env("STWO_RV64_M8_PARITY_PCS") orelse "0", "1") or only == .pcs;
    var pcs_mutex: std.Thread.Mutex = .{};
    var pcs_rows: std.ArrayListUnmanaged(PcsRow) = .empty;
    defer pcs_rows.deinit(a);
    const Version = *const fn () callconv(.c) u32;
    const wide = if (libs.base.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false;
    const pcs_sym = try NP.Symbols.load(&libs.addon);
    var cpu_pcs = PcsDecorator{ .a = a, .inner = stages.pcs orelse return error.ParityRequiresDevicePcs, .kind = "cpu", .worker = worker, .sym = pcs_sym, .peer = peer, .events = &events_api, .wide = wide, .mutex = &pcs_mutex, .rows = &pcs_rows };
    var truth_pcs = PcsDecorator{ .a = a, .inner = stages.truth_pcs orelse return error.ParityRequiresTruthPcs, .kind = "truth", .worker = worker, .sym = pcs_sym, .peer = peer, .events = &events_api, .wide = wide, .mutex = &pcs_mutex, .rows = &pcs_rows };
    const wrapped_cpu_pcs = cpu_pcs.stage();
    const wrapped_truth_pcs = truth_pcs.stage();
    if (check_pcs) {
        stages.pcs = &wrapped_cpu_pcs;
        stages.truth_pcs = &wrapped_truth_pcs;
    }

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

    var cpu_rows: usize = 0;
    for (composition.rows.items) |row| cpu_rows += @intFromBool(std.mem.eql(u8, row.kind, "cpu"));
    var composition_all = cpu_rows == item.expected_cpu_segments;
    for (composition.rows.items) |row| {
        composition_all = composition_all and row.through_seam and row.root_equal and row.coefficient_mismatches == 0 and row.status == 0 and row.host_waits == 1 and row.error_name.len == 0;
        // Device claims: every CPU row's buffer is native_global's output and
        // equals the host claims in the Stage2 layout.
        if (device_claims and std.mem.eql(u8, row.kind, "cpu")) composition_all = composition_all and std.mem.eql(u8, row.claims_source, "native_global") and row.claims_match_host and row.device_claims != 0;
    }
    var pcs_all = pcs_rows.items.len >= item.expected_cpu_segments;
    for (pcs_rows.items) |row| pcs_all = pcs_all and row.oods_equal and row.proof_equal and row.channel_equal and row.host_waits == 1 and row.error_name.len == 0;
    if (check_pcs) {
        var ptext: std.Io.Writer.Allocating = .init(a);
        defer ptext.deinit();
        try std.json.Stringify.value(.{ .schema = "rv64-m8-native-pcs-parity/v1", .block = block, .expected_cpu_segments = item.expected_cpu_segments, .legacy_native_wall_ns = wall_ns, .job_device = device, .wide_framing = wide, .pcs_all_equal = pcs_all, .proofs = pcs_rows.items }, .{ .whitespace = .indent_1 }, &ptext.writer);
        const preport = try std.fs.path.join(a, &.{ out_dir, "native-pcs-parity.json" });
        defer a.free(preport);
        try std.fs.cwd().writeFile(.{ .sub_path = preport, .data = ptext.written() });
        std.debug.print("GPU_M8_NATIVE_PCS_PARITY_DONE block={} proofs={} all_equal={} report={s}\n", .{ block, pcs_rows.items.len, pcs_all, preport });
        if (!pcs_all) return error.NativePcsParityMismatch;
        if (only == .pcs) return;
    }
    if (only_composition) {
        var ctext: std.Io.Writer.Allocating = .init(a);
        defer ctext.deinit();
        try std.json.Stringify.value(.{ .schema = "rv64-m8-native-composition-parity/v2", .block = block, .device_claims = device_claims, .arena_bytes = arena_bytes, .expected_segments = item.expected_cpu_segments, .legacy_native_wall_ns = wall_ns, .job_device = device, .composition_all_equal = composition_all, .compositions = composition.rows.items }, .{ .whitespace = .indent_1 }, &ctext.writer);
        const creport = try std.fs.path.join(a, &.{ out_dir, "native-composition-parity.json" });
        defer a.free(creport);
        try std.fs.cwd().writeFile(.{ .sub_path = creport, .data = ctext.written() });
        std.debug.print("GPU_M8_NATIVE_COMPOSITION_PARITY_DONE block={} segments={} all_equal={} report={s}\n", .{ block, composition.rows.items.len, composition_all, creport });
        if (!composition_all) return error.NativeCompositionParityMismatch;
        return;
    }
    var all = decorator.rows.items.len == item.expected_cpu_segments;
    for (decorator.rows.items) |row| all = all and row.channel_equal and row.proof_equal and row.host_waits == 1 and row.error_name.len == 0;
    var stage1_all = decorator.rows.items.len != 0;
    for (decorator.rows.items) |row| stage1_all = stage1_all and row.stage1_fixed_root_equal and row.stage1_main_root_equal and row.stage1_channel_equal and row.stage1_proof_equal and row.stage1_host_waits == 1;
    const binding_checked = decorator.bsym != null;
    var binding_all = decorator.rows.items.len != 0;
    for (decorator.rows.items) |row| binding_all = binding_all and row.binding_checked and row.binding_roots_equal and row.binding_verdict == 0 and row.binding_error.len == 0;
    var global_all = global.rows.items.len != 0;
    for (global.rows.items) |row| global_all = global_all and row.claims_equal and row.verdict == 0 and row.witness_mismatches == 0 and row.host_waits == 1 and row.error_name.len == 0;
    var commit_all = commits.rows.items.len != 0;
    for (commits.rows.items) |row| commit_all = commit_all and row.root_equal and row.host_waits == 1 and row.error_name.len == 0;
    var text: std.Io.Writer.Allocating = .init(a);
    defer text.deinit();
    try std.json.Stringify.value(.{ .schema = "rv64-m8-native-gkr-parity/v1", .block = block, .expected_segments = item.expected_cpu_segments, .legacy_native_wall_ns = wall_ns, .job_device = device, .all_equal = all, .stage1_all_equal = stage1_all, .binding_checked = binding_checked, .binding_all_equal = binding_all, .segments = decorator.rows.items, .global_all_equal = global_all, .global_slots = global.rows.items, .commit_all_equal = commit_all, .commits = commits.rows.items, .composition_checked = check_composition, .composition_all_equal = composition_all, .compositions = composition.rows.items }, .{ .whitespace = .indent_1 }, &text.writer);
    const report = try std.fs.path.join(a, &.{ out_dir, "native-gkr-parity.json" });
    defer a.free(report);
    try std.fs.cwd().writeFile(.{ .sub_path = report, .data = text.written() });
    std.debug.print("GPU_M8_NATIVE_GKR_PARITY_DONE block={} segments={} all_equal={} global_slots={} global_all_equal={} commits={} commit_all_equal={} report={s}\n", .{ block, decorator.rows.items.len, all, global.rows.items.len, global_all, commits.rows.items.len, commit_all, report });
    if (!all) return error.NativeGkrParityMismatch;
    if (!global_all) return error.NativeGlobalParityMismatch;
    if (!commit_all) return error.NativeCommitParityMismatch;
    std.debug.print("GPU_M8_NATIVE_STAGE1_PARITY_DONE segments={} all_equal={}\n", .{ decorator.rows.items.len, stage1_all });
    if (!stage1_all) return error.NativeStage1ParityMismatch;
    if (binding_checked) {
        std.debug.print("GPU_M8_NATIVE_BINDING_PARITY_DONE segments={} all_equal={}\n", .{ decorator.rows.items.len, binding_all });
        if (!binding_all) return error.NativeBindingParityMismatch;
    }
    if (check_composition and !composition_all) return error.NativeCompositionParityMismatch;
}
