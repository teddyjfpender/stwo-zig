//! M8 GPU-native Stage-2 tail real-block parity harness (pod only, opt-in
//! binary; stream native, piece gn-s2).
//!
//! Runs the unchanged legacy resident pipeline on a real block (the gate's
//! manifest) with byte-neutral pass-through decorators that RECORD the legacy
//! Stage-2 inputs and outputs of every native CPU segment:
//!   * resident_composition: the composition coefficient alpha, the roles
//!     (CompRoles.fromItemsWith: parameters, hc rows, geometry) and the items
//!     (for the host OODS check);
//!   * pcs (cpu): the REAL enqueue-only PCS image (native_pcs.PcsJob run on
//!     the job GPU from the legacy PCS request, BEFORE the legacy call, as the
//!     native-parity harness does) + its device OODS field, then the legacy
//!     proof (whose encodePhysical bytes the pipeline writes as cpu-<k>.bin);
//!   * native_stage_two: the pending manifest (digest, shared draws, every
//!     entry's flat-digest fields incl. local receipt digests and marginals).
//! Post hoc, per segment, ONE job on the job GPU runs the Stage-2 tail back to
//! back on device from those recorded inputs only:
//!   seal (flat v1-flat digest script over an exchange replica holding the
//!   recorded MAIN / truth roots, receipt digests and marginals) -> shared
//!   draws -> Check.oods_constraint (native_encode_oods) -> ProofEncoder ->
//!   root_match, and compares every output:
//!   seal digest == pending.digest, shared == pending.shared, oods verdict 0
//!   with [evaluated | extracted] == the host engine's values
//!   (evalCompositionPolynomialAtPoint / extractCompositionOodsEvalWithSplit),
//!   encoder bytes == the pipeline's cpu-<k>.bin (byte identity), pcs_status /
//!   encode_bounds / root_match 0.
//! Negatives (every segment): one fault per run, the named word must reject
//! and every other word must accept. CUDA-event GPU time per tail stage and
//! the host time per step are reported [M]. Results: <out>/gn-s2-parity.json.
//!
//! usage: rv64-m8-gn-s2-parity <manifest.json> <out-dir>
//! env: the gate's service environment (STWO_RV64_GPU_LIBRARY, legacy on
//!   STWO_RV64_GPU_DEVICES=0), plus
//!   STWO_RV64_M8_JOBS_LIBRARY        the jobs addon (with native_encode_oods.cu)
//!   STWO_RV64_M8_PARITY_DEVICE       job GPU (default 1)
//!   STWO_RV64_M8_PARITY_SOURCE_DEVICE legacy GPU the PCS mirror reads (default 0)
//!   STWO_RV64_M8_JOBS_ARENA_BYTES    job arena (default 20 GiB)
//!   STWO_RV64_M8_JOBS_PINNED_BYTES   pinned slot (default 1 GiB)
//!   STWO_RV64_M8_GN_S2_NEGATIVES     1 (default) / 0
//!   STWO_RV64_M8_GN_S2_REPEAT        timed warm repeats per segment (default 3)
const std = @import("std");
const ProductCPU = @import("ethereum_cpu_component");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const Main = ProductCPU.rv64_ethereum_gkr_main;
const Pool = @import("rv64/resident_pool.zig").Pool;
const Router = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.resident_router;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const W = jobs.worker;
const api = jobs.api;
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const NP = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_pcs;
const NE = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_encode;
const NO = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_encode_oods;
const S2D = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage2;
const CompRoles = @import("stwo_riscv_cuda_integration").rv64.execution.composition.roles;
const RC = @import("stwo_riscv_cuda_integration").rv64.resident_composition;
const JG = @import("stwo_riscv_cuda_integration").rv64.execution.composition.joined_codegen;
const Oracle = @import("stwo_riscv_cuda_integration").rv64.execution.composition.sources;
const Events = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.cuda_events;
const Slab = jobs.slab;
const Worker = CPU.rv64_gkr_cpu_worker;
const Components = CPU.rv64_gkr_cpu_components;
const WP = CPU.rv64_gkr_worker_protocol;
const ManifestM = CPU.rv64_gkr_manifest;
const DP = CPU.rv64_device_pcs;
const O = core.fields.om31.OM31;
const M31 = core.fields.m31.M31;
const Point = core.circle.CirclePoint(O);

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

const env = @import("rv64/parity/gn_s2_common.zig").env;
const envBytes = @import("rv64/parity/gn_s2_common.zig").envBytes;
const words8 = @import("rv64/parity/gn_s2_common.zig").words8;
const feltOf = @import("rv64/parity/gn_s2_common.zig").feltOf;
const PeerCopy = @import("rv64/parity/gn_s2_common.zig").PeerCopy;
const Peer = @import("rv64/parity/gn_s2_common.zig").Peer;
const Done = @import("rv64/parity/gn_s2_common.zig").Done;
const run = @import("rv64/parity/gn_s2_common.zig").run;
const Seg = @import("rv64/parity/gn_s2_capture.zig").Seg;
const Recorder = @import("rv64/parity/gn_s2_capture.zig").Recorder;
const CompositionDecorator = @import("rv64/parity/gn_s2_capture.zig").CompositionDecorator;
const PcsCaptureJob = @import("rv64/parity/gn_s2_capture.zig").PcsCaptureJob;
const PcsDecorator = @import("rv64/parity/gn_s2_capture.zig").PcsDecorator;
const NativeStageTwo = @import("rv64/parity/gn_s2_capture.zig").NativeStageTwo;
const StageTwoFn = @import("rv64/parity/gn_s2_capture.zig").StageTwoFn;
const StageTwoParams = @import("rv64/parity/gn_s2_capture.zig").StageTwoParams;
const PendingHook = @import("rv64/parity/gn_s2_capture.zig").PendingHook;
pub const Fault = @import("rv64/parity/gn_s2_tail.zig").Fault;
const T = @import("rv64/parity/gn_s2_tail.zig").T;
const TailJob = @import("rv64/parity/gn_s2_tail.zig").TailJob;
const sealInputs = @import("rv64/parity/gn_s2_tail.zig").sealInputs;
const NegativeRow = @import("rv64/parity/gn_s2_tail.zig").NegativeRow;
const Row = @import("rv64/parity/gn_s2_tail.zig").Row;
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
    const arena_bytes = try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 20 << 30);
    const worker = try W.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = std.mem.alignBackward(usize, arena_bytes / 4, W.Arena.granule), .pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 1 << 30) / 4 });
    defer worker.destroy();
    const events = try Events.Api.load(&libs.base);
    const esym = try NE.Symbols.load(&libs.addon);
    const osym = try NO.Symbols.load(&libs.addon);
    const ssym = try S2D.SealSymbols.load(&libs.addon);
    _ = try ssym.flatFn();
    const peer = Peer{ .copy = libs.addon.lookup(PeerCopy, "stwo_rv64_jobs_native_peer_copy_v1") orelse return error.ParityRequiresPeerCopy, .source_device = std.fmt.parseUnsigned(c_int, env("STWO_RV64_M8_PARITY_SOURCE_DEVICE") orelse "0", 10) catch return error.InvalidParityEnvironment };
    const Version = *const fn () callconv(.c) u32;
    const wide = if (libs.base.lookup(Version, "stwo_rv64_pcs_request_version")) |v| v() >= 3 else false;
    std.debug.print("GPU_M8_GN_S2 phase=worker_ready device={} wide={}\n", .{ device, wide });

    var config = try Router.Config.fromEnv(a);
    defer config.deinit(a);
    var recycler = Main.Recycler.init(std.heap.smp_allocator, 1 << 30);
    defer recycler.deinit();
    var session = try Main.ResidentSession.init(recycler.allocator(), manifest.immutable_host_key_bytes);
    defer session.deinit();
    const pool = try Pool.createWithBinding(a, library, config, item.expected_cpu_segments, true);
    defer pool.deinit();
    try pool.stages().requireFullyResident();
    var stages = pool.stages();
    var rec = Recorder{ .a = a, .context = &pool.devices[0].composition };
    var comp = CompositionDecorator{ .rec = &rec, .inner = stages.resident_composition orelse return error.ParityRequiresResidentComposition };
    const wrapped_comp = comp.stage();
    stages.resident_composition = &wrapped_comp;
    var pcs = PcsDecorator{ .rec = &rec, .inner = stages.pcs orelse return error.ParityRequiresDevicePcs, .worker = worker, .sym = try NP.Symbols.load(&libs.addon), .peer = peer, .events = &events, .wide = wide };
    const wrapped_pcs = pcs.stage();
    stages.pcs = &wrapped_pcs;
    var hook = PendingHook{ .rec = &rec };
    if (stages.native_stage_two != null) return error.ParityNativeStageTwoAlreadySet;
    stages.native_stage_two = hook.hook();

    const resource_json = try std.json.Stringify.valueAlloc(a, manifest.resources, .{});
    const resources = try std.fs.path.join(a, &.{ out_dir, "resources.json" });
    try std.fs.cwd().writeFile(.{ .sub_path = resources, .data = resource_json });
    const request = try std.fs.path.resolve(a, &.{ std.fs.path.dirname(argv[1]) orelse ".", item.request });
    const proof = try std.fs.path.join(a, &.{ out_dir, "proof" });
    const parts = [_][]const u8{ "rv64-resident", "--security-profile", manifest.profile, "produce-candidate", request, "-", proof, "0", resources };
    var args: [parts.len][:0]u8 = undefined;
    for (parts, &args) |part, *arg| arg.* = try a.dupeZ(u8, part);
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64-m8-gn-s2-parity", &identity, .{});
    for (pool.devices, config.caps) |*d, cap| try d.native.beginBlock(identity, .{ .device_bytes = cap, .immutable_bytes = manifest.immutable_device_bytes, .max_scopes = config.scope_limit });
    var timer = try std.time.Timer.start();
    std.debug.print("GPU_M8_GN_S2 phase=legacy_start block={}\n", .{block});
    try Main.runWithResidentArgs(&recycler, &args, stages, &session);
    const legacy_ns = timer.read();
    for (pool.devices) |*d| try d.native.endBlock(identity);
    const digest = rec.pending_digest orelse return error.ParityPendingNotObserved;
    if (rec.digest_conflict) return error.ParityDigestConflict;
    {
        const path = try std.fs.path.join(a, &.{ proof, "stage-one.bin" });
        const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
        if (bytes.len < 40 or !std.mem.eql(u8, bytes[0..8], "RV64MGK1")) return error.ParityStageOneShape;
        @memcpy(&rec.execution, bytes[8..40]);
    }
    const cpu = item.expected_cpu_segments;
    std.debug.print("GPU_M8_GN_S2 event=legacy_done block={} segments={} entries={} legacy_ns={}\n", .{ block, rec.segs.count(), rec.flat.len, legacy_ns });
    const tag = G.Exchange.flagTag(1);
    // Host mirror of the flat seal == the pipeline's manifest digest.
    var flat_ns: u64 = 0;
    const host_flat_equal = blk: {
        timer.reset();
        var si = try sealInputs(a, &rec, cpu, tag, .none);
        flat_ns = timer.read();
        defer si.script.deinit();
        defer a.free(si.replica);
        break :blk switch (si.script.hostDigest(si.replica, tag)) {
            .digest => |d| std.mem.eql(u8, &d, &digest),
            .refuse => false,
        };
    };
    std.debug.print("GPU_M8_GN_S2 event=flat_host digest_equal={} script_ns={}\n", .{ host_flat_equal, flat_ns });
    const repeat = std.fmt.parseUnsigned(usize, "3", 10) catch return error.InvalidParityEnvironment;
    const negatives = !std.mem.eql(u8, "1", "0");
    const constants = S2D.sealConstants(@splat(0), rec.execution, @intCast(rec.flat.len), tag);
    var rows: std.ArrayListUnmanaged(Row) = .empty;
    var ordinals: std.ArrayListUnmanaged(u32) = .empty;
    var it = rec.segs.keyIterator();
    while (it.next()) |k| try ordinals.append(a, k.*);
    std.mem.sort(u32, ordinals.items, {}, std.sort.asc(u32));
    for (ordinals.items) |ordinal| {
        const seg = rec.segs.get(ordinal).?;
        var nodes: usize = 0;
        for (0..if (seg.desc.len != 0) seg.desc[NO.H.roles] else 0) |r| nodes += seg.desc[NO.H.header_words + r * NO.Role.words + NO.Role.n_nodes];
        var row = Row{ .ordinal = ordinal, .roles = seg.roles.specs.len, .nodes = nodes, .samples = if (seg.desc.len != 0) seg.desc[NO.H.samples] else 0, .mask_log = seg.mask_log, .split = seg.split, .oods_replay_equal = seg.oods_replay_equal, .host_accept = seg.host_accept, .mirror_word = seg.mirror_word, .mirror_eval_equal = seg.mirror_eval_equal, .pcs_gpu_ms = seg.pcs_gpu_ms, .host_check_ns = seg.host_check_ns, .class_build_ns = seg.class_build_ns, .flat_script_ns = flat_ns, .error_name = seg.error_name };
        if (row.error_name.len == 0) tailOne(a, worker, &rec, seg, &esym, &osym, &ssym, &events, peer, constants, cpu, tag, digest, proof, repeat, negatives, &row) catch |err| {
            row.error_name = @errorName(err);
        };
        std.debug.print("GPU_M8_GN_S2 ordinal={} roles={} nodes={} words={any} diag={} seal={} shared={} bytes={} legacy_bytes={} device_bytes={} oods_ms={any} encode_ms={any} seal_ms={any} host_check_ns={} class_build_ns={} error={s}\n", .{ row.ordinal, row.roles, row.nodes, row.words, row.diag_equal, row.seal_digest_equal, row.shared_equal, row.bytes_equal, row.legacy_bytes, row.device_bytes, row.oods_gpu_ms, row.encode_gpu_ms, row.seal_shared_gpu_ms, row.host_check_ns, row.class_build_ns, row.error_name });
        try rows.append(a, row);
    }
    var all = rows.items.len == cpu and host_flat_equal;
    var negatives_all = true;
    for (rows.items) |r| {
        all = all and r.error_name.len == 0 and r.oods_replay_equal and r.host_accept and r.mirror_word == G.Verdict.accepted and r.mirror_eval_equal and r.diag_equal and r.seal_digest_equal and r.shared_equal and r.bytes_equal and r.host_waits == 1;
        for (r.words) |w| all = all and w == G.Verdict.accepted;
        for (r.negatives) |n| negatives_all = negatives_all and n.fired;
    }
    var text: std.Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{ .schema = "rv64-m8-gn-s2-parity/v1", .block = block, .legacy_native_wall_ns = legacy_ns, .job_device = device, .wide_framing = wide, .native_version = env("STWO_RV64_NATIVE_VERSION") orelse "", .flat_host_digest_equal = host_flat_equal, .all_equal = all, .negatives_all_fired = negatives_all, .segments = rows.items }, .{ .whitespace = .indent_1 }, &text.writer);
    const report = try std.fs.path.join(a, &.{ out_dir, "gn-s2-parity.json" });
    try std.fs.cwd().writeFile(.{ .sub_path = report, .data = text.written() });
    std.debug.print("GPU_M8_GN_S2_DONE block={} segments={} all_equal={} negatives_all_fired={} report={s}\n", .{ block, rows.items.len, all, negatives_all, report });
    if (!all) return error.GnS2ParityMismatch;
    if (negatives and !negatives_all) return error.GnS2NegativeNotFired;
}

const runTail = @import("rv64/parity/gn_s2_tail.zig").runTail;
const freeTail = @import("rv64/parity/gn_s2_tail.zig").freeTail;
const tailOne = @import("rv64/parity/gn_s2_tail.zig").tailOne;
