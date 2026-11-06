//! M8 outer-job parity fixture (pod only). One trace-only native-OM31 node is
//! proved by the legacy resident controller (outer_source.zig, owner
//! callbacks) and then run through the job runtime (runtime worker +
//! OuterNodeJob prefix). The node is the one rv64/outer_proof_fixture.zig
//! qualifies. Compared word for word:
//!   * MAIN root, INTER root   vs legacy proof commitments[1], [2];
//!   * the 11 claims           vs legacy Produced.claims;
//!   * z, alpha, coefficient and every prefix channel snapshot vs a host
//!     Om31Channel replay of the legacy transcript (prove.begin, FIXED,
//!     MAIN, draw z/alpha, claims, INTER, draw coefficient);
//! across N job runs on one worker (direct, captured, rebound graph), which
//! must all be byte-identical. Prints one OUTER_JOB_PARITY JSON line per run.
//!
//! usage: rv64-m8-outer-job-fixture <base.so> <jobs-addon.so> <outer-fs-ops.so> [runs]
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Service = @import("rv64/pcs_native.zig");
const TC = @import("rv64/trace_commit.zig");
const RC = @import("rv64/resident_composition.zig");
const Legacy = @import("rv64/outer_source.zig");
const Prestage = @import("rv64/outer_job_prestage.zig");
const Ops = @import("rv64/jobs/ops.zig");
const Worker = @import("rv64/jobs/worker.zig");
const api = @import("rv64/jobs/api.zig");
const K = @import("rv64/jobs/outer_kernels.zig");
const Job = @import("rv64/jobs/outer_job.zig");
const Graphs = @import("rv64/jobs/outer_graph_cache.zig");
const N = @import("rv64/jobs/outer_node.zig");
const Plan = @import("rv64/jobs/outer_plan.zig");
const Factory = @import("rv64/outer_job_factory.zig");
const Q = Outer.protocol.Q;
const Raw = core.channel.raw_mod_m31;

fn buildNode(a: std.mem.Allocator) !circuit.builder.Context(Q) {
    // Same production-hint circuit as outer_proof_fixture.zig gpu_trace_hints.
    var ctx = try circuit.builder.Context(Q).initTraceOnly(a, 8);
    errdefer ctx.deinit();
    const expected: [32]u8 = @splat(0x42);
    var outputs: [8]circuit.builder.Var = undefined;
    for (&outputs, 0..) |*out, i| out.* = try ctx.guess(circuit.builder.ivalue.packU32(Q, std.mem.readInt(u32, expected[4 * i ..][0..4], .little)));
    const x = try ctx.guess(Q.fromU32Unchecked(11, 3, 7, 9));
    const y = try ctx.guess(Q.fromU32Unchecked(17, 0, 0, 0));
    const reciprocal = try ctx.inv(y);
    const quotient = try ctx.div(x, y);
    const sum = try ctx.add(reciprocal, quotient);
    const lanes = circuit.builder.simd.Simd.fromPacked(&.{x}, 4);
    _ = try circuit.builder.simd.guessInvOrZero(Q, &ctx, lanes);
    _ = try circuit.builder.simd.guessLsb(Q, &ctx, lanes);
    _ = try ctx.permuteNamed(&.{ sum, x, y }, .sort_by_u_coordinate);
    const B = circuit.builder;
    const raw: u32 = 0xfedcba98;
    const packed_word = try B.wrappers.guessU32(Q, &ctx, B.wrappers.u32Value(Q, raw));
    var octets: [4]B.Var = undefined;
    for (&octets, 0..) |*out, i| {
        const octet: u8 = @truncate(raw >> @intCast(i * 8));
        out.* = try ctx.guessU16(Q.fromU32Unchecked(octet, 0, 0, 0));
        const complement = try ctx.guessU16(Q.fromU32Unchecked(255 - @as(u32, octet), 0, 0, 0));
        try ctx.noteWitnessByte(out.*, packed_word.get(), @intCast(i), false);
        try ctx.noteWitnessByte(complement, packed_word.get(), @intCast(i), true);
        try ctx.eq(try ctx.add(out.*, complement), try ctx.constant(Q.fromU32Unchecked(255, 0, 0, 0)));
    }
    const k = try ctx.constant(Q.fromU32Unchecked(256, 0, 0, 0));
    const low = try ctx.add(octets[0], try ctx.mul(octets[1], k));
    const high = try ctx.add(octets[2], try ctx.mul(octets[3], k));
    const imag = try ctx.constant(Q.fromU32Unchecked(0, 1, 0, 0));
    try ctx.eq(packed_word.get(), try ctx.add(low, try ctx.mul(high, imag)));
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    try circuit.common.finalize.padToTargets(Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    return ctx;
}

const Reference = struct {
    main_root: [32]u8,
    inter_root: [32]u8,
    claims: [Plan.n_components]Outer.protocol.O,
    /// Host channel checkpoints after each prefix step + the challenges.
    steps: [N.prefix_steps]Raw.Om31Checkpoint,
    z: Outer.protocol.O,
    alpha: Outer.protocol.O,
    coefficient: Outer.protocol.O,
};

fn reference(a: std.mem.Allocator, key: *const Outer.prove.Authority, expected: []const Q, produced: *const Outer.prove.Produced) !Reference {
    const pcs = &produced.proof.proof.commitment_scheme_proof;
    var r: Reference = undefined;
    r.main_root = pcs.commitments.items[1];
    r.inter_root = pcs.commitments.items[2];
    r.claims = produced.claims.toArray();
    // Host replay of device_prove.zig proveOwnedDirect's transcript.
    var ch = try Outer.prove.begin(a, key, expected);
    Outer.protocol.MC.mixRoot(&ch, key.fixedRoot());
    Outer.protocol.MC.mixRoot(&ch, r.main_root);
    r.steps[0] = Raw.om31Checkpoint(&ch);
    const zalpha = Outer.prove.draw(&ch);
    r.z = zalpha.z;
    r.alpha = zalpha.alpha;
    r.steps[1] = Raw.om31Checkpoint(&ch);
    ch.mixFelts(&r.claims);
    r.steps[2] = Raw.om31Checkpoint(&ch);
    Outer.protocol.MC.mixRoot(&ch, r.inter_root);
    r.steps[3] = Raw.om31Checkpoint(&ch);
    r.coefficient = ch.drawSecureFelt();
    r.steps[4] = Raw.om31Checkpoint(&ch);
    return r;
}

const Done = struct {
    event: std.Thread.ResetEvent = .{},
    result: anyerror!void = {},
    fn done(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        self.result = c.result;
        self.event.set();
    }
};

/// Ops.Libraries.open, except the raw transcript draw (absent from the frozen
/// a25 base image, and unused by the outer prefix) resolves to a refusing stub.
fn openLibraries(base_path: []const u8, addon_path: []const u8) !Ops.Libraries {
    var base = try std.DynLib.open(base_path);
    errdefer base.close();
    var addon = try std.DynLib.open(addon_path);
    errdefer addon.close();
    const Stub = struct {
        fn draw(_: [*]u32, _: u32, _: u64, _: u64, _: [*]u32, _: [*]u32, _: [*]u32, _: *anyopaque) callconv(.c) c_int {
            return 1;
        }
    };
    var out: Ops.Libraries = .{ .base = base, .addon = addon, .ops = undefined };
    inline for (@typeInfo(Ops.Exec).@"struct".fields) |f| {
        const names = .{ .alloc_u32 = "stwo_exec_context_alloc_u32", .alloc_u32_long = "stwo_exec_context_alloc_u32_long", .free_u32 = "stwo_exec_context_free_u32", .channel_init_on = "stwo_rv64_channel_init_on", .channel_mix_on = "stwo_rv64_channel_mix_on", .channel_draw_on = "stwo_rv64_channel_draw_on", .channel_queries_on = "stwo_rv64_channel_queries_on", .transcript_draw_u32s_on = "stwo_blake2s_transcript_draw_u32s_on", .pow_persistent_on = "stwo_blake2s_pow_persistent_on", .copy_async = "stwo_rv64_jobs_copy_async", .event_record = "stwo_rv64_jobs_event_record", .stream_wait = "stwo_rv64_jobs_stream_wait", .host_fn = "stwo_rv64_jobs_host_fn" };
        const name: [:0]const u8 = @field(names, f.name);
        @field(out.ops.exec, f.name) = out.base.lookup(f.type, name) orelse out.addon.lookup(f.type, name) orelse if (comptime std.mem.eql(u8, f.name, "transcript_draw_u32s_on")) Stub.draw else return error.MissingJobsRuntimeSymbol;
    }
    inline for (@typeInfo(Ops.Wait).@"struct".fields) |f| {
        const names = .{ .context_create = "stwo_exec_context_create_options", .context_destroy = "stwo_exec_context_destroy", .lane_stream = "stwo_exec_context_lane_stream", .stream_create = "stwo_rv64_jobs_stream_create", .stream_destroy = "stwo_rv64_jobs_stream_destroy", .event_create = "stwo_rv64_jobs_event_create", .event_destroy = "stwo_rv64_jobs_event_destroy", .event_sync = "stwo_rv64_jobs_event_wait_host", .host_alloc = "stwo_rv64_jobs_host_alloc", .host_free = "stwo_rv64_jobs_host_free" };
        const name: [:0]const u8 = @field(names, f.name);
        @field(out.ops.wait, f.name) = out.base.lookup(f.type, name) orelse out.addon.lookup(f.type, name) orelse return error.MissingJobsRuntimeSymbol;
    }
    return out;
}

pub fn main() !void {
    const a = std.heap.c_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 4) return error.Usage;
    const runs: usize = if (args.len > 4) try std.fmt.parseInt(usize, args[4], 10) else 4;

    var graph = try buildNode(a);
    defer graph.deinit();
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &graph.circuit);
    defer pp.deinit(a);
    var key = try Outer.prove.Authority.init(a, &pp);
    defer key.deinit();
    const digest: [32]u8 = @splat(0x42);
    var expected: [8]Q = undefined;
    for (&expected, 0..) |*out, i| out.* = circuit.builder.ivalue.packU32(Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little));

    // Legacy resident proof (owner callbacks), the parity reference.
    var legacy_bytes: []u8 = &.{};
    defer a.free(legacy_bytes);
    var legacy_timer = try std.time.Timer.start();
    const ref = blk: {
        var service = try Service.Context.init(args[1], 0, 28 << 30);
        defer service.deinit();
        try service.enableImmutableSetup(2 << 30);
        var commit = try TC.Context.init(&service);
        defer commit.deinit();
        var composition = try RC.Context.initNumerical(a, &service);
        defer composition.deinit();
        var factory = try Legacy.Context.init(a, &service, &commit, &composition);
        defer factory.deinit();
        var produced = try Outer.device_prove.proveFromCircuit(a, &key, &graph, &expected, 0, factory.factory());
        defer produced.deinit();
        legacy_bytes = try Outer.wire.encode(a, key.identity, produced.outputs, produced.claims, &produced.proof.proof);
        break :blk try reference(a, &key, &expected, &produced);
    };
    const legacy_ns = legacy_timer.read();

    var libs = try openLibraries(args[1], args[2]);
    defer libs.close();
    var fs = try std.DynLib.open(args[3]);
    defer fs.close();
    const kernels = try K.Kernels.load(&libs.base, &fs);
    var prestage_timer = try std.time.Timer.start();
    const staged = try Prestage.prestage(a, .{ .key = &key, .graph = &graph, .expected = &expected, .ordinal = 0, .library = &libs.base });
    defer staged.deinit();
    const prestage_ns = prestage_timer.read();
    const worker = try Worker.Worker.create(a, &libs.ops, .{ .device = 0, .arena_words = 5 << 30, .pinned_slot_words = 1 << 27 });
    defer worker.destroy();
    var cache = Graphs.Cache.init(a, try Graphs.Api.load(&libs.addon), Graphs.Policy.fromEnv());
    defer cache.deinit();

    var first: ?[]u32 = null;
    defer if (first) |w| a.free(w);
    var failures: usize = 0;
    for (0..runs) |run| {
        var job = try Job.OuterNodeJob.init(staged, &kernels, true);
        job.graphs = &cache;
        const keep = try a.alloc(u32, job.layout.words);
        defer a.free(keep);
        job.keep_slab = keep;
        const fp = job.footprint();
        std.debug.print("OUTER_JOB_FOOTPRINT device_words={d} staged_words={d} slab_words={d} pinned_words={d} image_words=[{d},{d},{d}]\n", .{ fp.device_words, fp.staged_words, fp.slab_words, fp.pinned_words, staged.image.words[0], staged.image.words[1], staged.image.words[2] });
        var done = Done{};
        var timer = try std.time.Timer.start();
        try worker.submit(job.job(), .{ .ctx = &done, .done = Done.done });
        done.event.wait();
        const wall_ns = timer.read();
        done.result catch |err| {
            std.debug.print("OUTER_JOB_PARITY {{\"run\":{d},\"error\":\"{s}\"}}\n", .{ run, @errorName(err) });
            return err;
        };
        const d = job.decoded orelse return error.OuterJobNotDecoded;
        const ok_roots = std.mem.eql(u8, &d.main_root, &ref.main_root) and std.mem.eql(u8, &d.inter_root, &ref.inter_root);
        var ok_claims = true;
        for (d.claims.toArray(), ref.claims) |x, y| ok_claims = ok_claims and x.eql(y);
        const ok_challenges = d.z.eql(ref.z) and d.alpha.eql(ref.alpha) and d.coefficient.eql(ref.coefficient);
        var ok_snapshots = true;
        const view = api.SlabView{ .words = keep, .layout = &job.layout };
        for (ref.steps, 0..) |cp, step| {
            const w = try Job.OuterNodeJob.snapshotWords(view, @intCast(step));
            for (0..8) |i| ok_snapshots = ok_snapshots and w[i] == std.mem.readInt(u32, cp.digest[4 * i ..][0..4], .little);
            ok_snapshots = ok_snapshots and w[8] == cp.draws and w[10] == 0;
        }
        var ok_repeat = true;
        if (first) |old| ok_repeat = std.mem.eql(u32, old, keep[0..Plan.Section.words]) else first = try a.dupe(u32, keep[0..Plan.Section.words]);
        if (!(ok_roots and ok_claims and ok_challenges and ok_snapshots and ok_repeat)) failures += 1;
        std.debug.print("OUTER_JOB_PARITY {{\"run\":{d},\"graph\":\"{s}\",\"roots\":{},\"claims\":{},\"challenges\":{},\"snapshots\":{},\"repeat_identical\":{},\"host_api_launches\":{d},\"body_launches\":{d},\"graph_kernel_nodes\":{d},\"staged_words\":[{d},{d},{d}],\"host_waits\":{d},\"d2h_bytes\":{d},\"wait_ns\":{d},\"enqueue_ns\":{d},\"wall_ns\":{d},\"legacy_wall_ns\":{d},\"prestage_ns\":{d},\"arena_peak_words\":{d}}}\n", .{ run, @tagName(job.report.outcome), ok_roots, ok_claims, ok_challenges, ok_snapshots, ok_repeat, job.report.launches, job.report.body_launches, job.report.kernel_nodes, job.report.staged_words[0], job.report.staged_words[1], job.report.staged_words[2], job.report.receipt.host_waits, job.report.receipt.d2h_bytes, job.report.receipt.wait_ns, job.report.receipt.enqueue_ns, wall_ns, legacy_ns, prestage_ns, job.report.receipt.arena_peak_words });
    }
    if (failures != 0) return error.OuterJobParityMismatch;
    std.debug.print("OUTER_JOB_PARITY_PASS runs={d}\n", .{runs});

    // Whole node through the request-layer adapter (outer_job_factory.zig):
    // prestage -> OuterNodeJob on the worker -> assemble -> wire bytes, which
    // must equal the legacy proof bytes.
    var shared = try Factory.Shared.init(&libs.base, &libs.addon, args[3]);
    defer shared.deinit();
    var prover = Factory.Prover.init(a, &shared, worker);
    defer prover.deinit();
    var whole_failures: usize = 0;
    // Production folds/leaves use a device-precommitted FIXED authority (no host
    // FIXED tree): same identity, same proof. The last run uses one.
    var device_key = try Outer.prove.Authority.initForDeviceProver(a, &pp, key.fixedRoot());
    defer device_key.deinit();
    if (!std.mem.eql(u8, &device_key.identity, &key.identity) or device_key.fixed != null) return error.DeviceFixedAuthorityOracleMismatch;
    for (0..runs + 1) |run| {
        const node_key = if (run == runs) &device_key else &key;
        var timer = try std.time.Timer.start();
        var r: Factory.Report = .{};
        var produced = prover.prove(a, .{ .key = node_key, .graph = &graph, .expected = &expected, .ordinal = 0, .library = &libs.base }, &r) catch |err| {
            std.debug.print("OUTER_JOB_WHOLE {{\"run\":{d},\"error\":\"{s}\"}}\n", .{ run, @errorName(err) });
            return err;
        };
        defer produced.deinit();
        const wall_ns = timer.read();
        const encoded = try Outer.wire.encode(a, key.identity, produced.outputs, produced.claims, &produced.proof.proof);
        defer a.free(encoded);
        const identical = std.mem.eql(u8, encoded, legacy_bytes);
        if (!identical) whole_failures += 1;
        var proof_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &proof_digest, .{});
        std.debug.print("OUTER_JOB_WHOLE {{\"run\":{d},\"device_fixed_authority\":{},\"graph\":\"{s}\",\"proof_bytes_identical\":{},\"proof_bytes\":{d},\"proof_sha256\":\"{s}\",\"host_api_launches\":{d},\"graph_kernel_nodes\":{d},\"host_waits\":{d},\"d2h_bytes\":{d},\"wait_ns\":{d},\"enqueue_ns\":{d},\"prestage_ns\":{d},\"job_ns\":{d},\"assemble_ns\":{d},\"wall_ns\":{d},\"arena_peak_words\":{d}}}\n", .{ run, run == runs, @tagName(r.outcome), identical, encoded.len, std.fmt.bytesToHex(proof_digest, .lower), r.launches, r.kernel_nodes, r.receipt.host_waits, r.receipt.d2h_bytes, r.receipt.wait_ns, r.receipt.enqueue_ns, r.prestage_ns, r.job_ns, r.assemble_ns, wall_ns, r.receipt.arena_peak_words });
    }
    // Concurrent callers on one worker (pipelined: pre-stage of one node
    // overlaps another's GPU work); every proof must still equal legacy.
    const Concurrent = struct {
        prover: *Factory.Prover,
        input: Prestage.Input,
        legacy: []const u8,
        identity: [32]u8,
        ok: bool = false,
        report: Factory.Report = .{},
        fn run(self: *@This()) void {
            const al = std.heap.c_allocator;
            var produced = self.prover.prove(al, self.input, &self.report) catch return;
            defer produced.deinit();
            const encoded = Outer.wire.encode(al, self.identity, produced.outputs, produced.claims, &produced.proof.proof) catch return;
            defer al.free(encoded);
            self.ok = std.mem.eql(u8, encoded, self.legacy);
        }
    };
    var lanes: [3]Concurrent = undefined;
    var threads: [3]std.Thread = undefined;
    var concurrent_timer = try std.time.Timer.start();
    for (&lanes, &threads) |*lane, *thread| {
        lane.* = .{ .prover = &prover, .input = .{ .key = &key, .graph = &graph, .expected = &expected, .ordinal = 0, .library = &libs.base }, .legacy = legacy_bytes, .identity = key.identity };
        thread.* = try std.Thread.spawn(.{}, Concurrent.run, .{lane});
    }
    for (threads) |t| t.join();
    const concurrent_ns = concurrent_timer.read();
    for (lanes, 0..) |lane, i| {
        if (!lane.ok) whole_failures += 1;
        std.debug.print("OUTER_JOB_CONCURRENT {{\"lane\":{d},\"proof_bytes_identical\":{},\"graph\":\"{s}\",\"prestage_ns\":{d},\"job_ns\":{d},\"assemble_ns\":{d},\"wait_ns\":{d}}}\n", .{ i, lane.ok, @tagName(lane.report.outcome), lane.report.prestage_ns, lane.report.job_ns, lane.report.assemble_ns, lane.report.receipt.wait_ns });
    }
    std.debug.print("OUTER_JOB_CONCURRENT_WALL nodes=3 wall_ns={d}\n", .{concurrent_ns});
    var legacy_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(legacy_bytes, &legacy_digest, .{});
    std.debug.print("OUTER_JOB_LEGACY proof_bytes={d} proof_sha256={s}\n", .{ legacy_bytes.len, std.fmt.bytesToHex(legacy_digest, .lower) });
    if (whole_failures != 0) return error.OuterJobWholeProofMismatch;
    std.debug.print("OUTER_JOB_WHOLE_PASS runs={d}\n", .{runs});
}
