//! Full resident numerical controller for the original BLAKE3 execution parent.
//! DeviceProducer is a finite device witness/framework implementation, not a
//! backend fallback hook. This factory alone does not qualify a raw-child route.
const std = @import("std");
const core = @import("stwo_core");
const Twiddles = @import("resident_parent_twiddles_v1.zig");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Program = @import("resident_parent_program_v1.zig");
const PCS = @import("resident_parent_pcs_v1.zig");
const Memory = @import("resident_parent_memory_v1.zig");
const Transcript = @import("resident_parent_transcript_v1.zig");
const Terminal = @import("resident_parent_terminal_v1.zig");
const Pipeline = @import("resident_parent_pipeline_v1.zig");
const Controller = @import("stwo_cairo_cuda_integration").executor.quotient.controller;
const M = core.fields.m31.M31;
pub const Limits = struct { max_device_bytes: usize = 96 << 30, accepted_sms: []const u32 = &.{90} };
pub const HostTiming = struct {
    admission_ns: u64 = 0,
    pcs_plans_ns: u64 = 0,
    terminal_memory_plans_ns: u64 = 0,
    open_transaction_ns: u64 = 0,
    ingress_enqueue_ns: u64 = 0,
    pipeline_enqueue_ns: u64 = 0,
    terminal_read_finish_ns: u64 = 0,
    decode_ns: u64 = 0,
};
pub const Result = struct {
    proof: Terminal.Proof,
    verdict: cuda.runtime.verdict.Verdict,
    device_arena_bytes: usize,
    /// Time through terminal decoding, including cold plans and raw ingress.
    /// Caller must measure the complete call to include deferred teardown;
    /// independent verification is separately reported.
    elapsed_ns: u64,
    /// Host wall intervals include GPU waits where the named boundary waits.
    /// Device stage events remain separately available in verdict.counters.
    host_timing: HostTiming,
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};
/// Plan contract: requirements(a,program,pcs)![]arena.Requirement,
/// bind(a,tx,program,pcs,views)!Bound; Bound.{prime,witness,interactions,composition}.
/// The constructor supplies fixed metadata and raw source bytes only. A concrete
/// production caller must independently compile its routing/key from the same
/// original verifier and verify the returned proof before claiming authority.
pub fn For(comptime DevicePlan: type) type {
    return struct {
        pub const Input = struct {
            program: *const Program.Owned,
            fixed: []const []const M,
            raw_input: []const u8,
            device_plan: *const DevicePlan,
            limits: Limits = .{},
            /// Explicit process-owned CUDA context/modules. Request buffers,
            /// witness state and transcript are still fresh for every proof.
            /// Callers report runtime startup separately from warm requests.
            runtime: ?*cuda.runtime.NativeRuntime = null,
        };
        pub fn prove(a: std.mem.Allocator, input: Input) !Result {
            var phase: []const u8 = "admission";
            errdefer std.debug.print("RESIDENT_PARENT_FAILURE phase={s}\n", .{phase});
            var timer = try std.time.Timer.start();
            var phase_clock = try std.time.Timer.start();
            var host: HostTiming = .{};
            const p = input.program.view();
            try p.validate();
            if (input.raw_input.len == 0 or input.fixed.len != p.trees[0].column_logs.len) return error.InvalidResidentParentInput;
            for (input.fixed, p.trees[0].column_logs) |values, log| {
                if (values.len != @as(usize, 1) << @intCast(log)) return error.InvalidResidentParentInput;
                // Fixed values are admitted immutable key material; their root is
                // checked by the independent original verifier, not re-derived here.
            }
            phase = "pcs_plans";
            host.admission_ns = phase_clock.lap();
            var pcs = try PCS.Plans.init(a, input.program, input.limits.max_device_bytes);
            defer pcs.deinit();
            host.pcs_plans_ns = phase_clock.lap();
            phase = "terminal_plan";
            var terminal = try Terminal.init(a, input.program, &pcs);
            defer terminal.deinit(a);
            phase = "producer_requirements";
            const extra = try input.device_plan.requirements(a, input.program, &pcs);
            defer a.free(extra);
            phase = "memory_plan";
            var memory = try Memory.Plan.init(a, input.program, &pcs, &terminal, input.raw_input.len, extra, input.limits.max_device_bytes);
            defer memory.deinit();
            const device_bytes = try std.math.mul(usize, memory.placement.total_words, 4);
            phase = "open_transaction";
            host.terminal_memory_plans_ns = phase_clock.lap();
            var tx = if (input.runtime) |runtime| blk: {
                if (!runtime.isReady()) return error.InvalidRetainedParentRuntime;
                const sm = try cuda.runtime.device_admission.sm(runtime.planningSession().device);
                if (!cuda.runtime.device_admission.contains(input.limits.accepted_sms, sm)) return error.InvalidDeviceArchitecture;
                var placement = try memory.takePlacement();
                const retained = runtime.beginProof() catch |err| {
                    placement.deinit(a);
                    return err;
                };
                break :blk try cuda.runtime.proof_transaction.ResidentProofTransaction.openPreparedRetained(a, retained, placement);
            } else try cuda.runtime.proof_transaction.ResidentProofTransaction.openPrepared(a, input.limits.accepted_sms, try memory.takePlacement());
            var finished = false;
            host.open_transaction_ns = phase_clock.lap();
            defer if (!finished) tx.abort() catch {};
            const session = tx.proofSession();
            phase = "bind_views";
            var views = try Memory.bind(a, &tx, &pcs, &terminal);
            defer views.deinit();
            // Raw bytes are copied verbatim, with only transport alignment zero
            // padding. No hash, arithmetic witness or execution happens here.
            phase = "raw_fixed_ingress";
            const ingress = try a.alloc(u32, views.raw_input.len);
            defer a.free(ingress);
            @memset(ingress, 0);
            @memcpy(std.mem.sliceAsBytes(ingress)[0..input.raw_input.len], input.raw_input);
            try session.context.uploadSlice(u32, views.raw_input, ingress);
            for (input.fixed, views.sources[0]) |values, dst| try session.context.uploadSlice(u32, dst, @as([*]const u32, @ptrCast(values.ptr))[0..values.len]);
            phase = "gpu_twiddles";
            try Twiddles.generate(session, @max(p.fri_log, p.composition_log), views.twiddles_forward, views.twiddles_inverse);
            phase = "terminal_ingress";
            try session.zeroResidentSlice(u32, .ingress, views.error_flag);
            try session.zeroResidentSlice(u32, .ingress, views.proof.bundle);
            try session.context.uploadSlice(u32, try views.proof.bundle.sub(0, terminal.static_header.len), terminal.static_header);
            phase = "transcript_bind";
            var sink = try Transcript.NativeSink.init(session, input.program, views.transcript);
            try sink.prime();
            phase = "commitment_prime";
            var commitments: [4]PCS.Commit.Bound = undefined;
            for (&commitments, &pcs.commitments, views.commits) |*bound, *plan, buffers| {
                bound.* = try PCS.Commit.Bound.init(plan, buffers);
                try bound.prime(session);
            }
            phase = "producer_bind_prime";
            var producer = try input.device_plan.bind(a, &tx, input.program, &pcs, &views);
            defer producer.deinit(a);
            try producer.prime(session);
            phase = "oods_upload";
            try pcs.oods.upload(session, views.oods);
            phase = "oods_bind";
            var oods = try pcs.oods.bind(a, views.commits);
            defer oods.deinit();
            phase = "quotient_topology";
            var topology = try pcs.takeQuotient();
            var owns_topology = true;
            defer if (owns_topology) topology.deinit();
            var evals: [4]common.Words = undefined;
            for (views.commits, &evals) |tree, *out| out.* = tree.evaluations;
            phase = "quotient_prepare";
            var quotient = try Controller.prepareFromTopology(a, session, &topology, &evals, views.oods.sample_points, views.oods.sampled_values, views.quotient, views.twiddles_forward, p.fri_log, p.identity);
            owns_topology = false;
            defer quotient.deinit();
            phase = "quotient_transform_init";
            try quotient.initializeTransform(session, views.twiddles_inverse);
            phase = "fri_prime";
            try pcs.fri.upload(session, views.fri, views.twiddles_inverse);
            phase = "decommit_prime";
            try pcs.decommit.upload(session, views.decommit);
            phase = "finish_ingress";
            try tx.finishIngress();
            var pipeline = Pipeline.Bound(@TypeOf(producer)){ .transaction = &tx, .program = input.program, .plans = &pcs, .views = &views, .producer = &producer, .sink = &sink, .oods = &oods, .quotient = &quotient, .commitments = &commitments };
            phase = "pipeline_execute";
            host.ingress_enqueue_ns = phase_clock.lap();
            try pipeline.execute();
            try sink.requireComplete();
            host.pipeline_enqueue_ns = phase_clock.lap();
            const words = try a.alloc(u32, terminal.total_words);
            defer a.free(words);
            phase = "terminal_read";
            const verdict = try tx.assembleAndFinish(words, try Memory.id(.terminal_bundle, 0));
            finished = true;
            if (!verdict.isResident()) return error.NonresidentParentProof;
            phase = "terminal_decode";
            host.terminal_read_finish_ns = phase_clock.lap();
            // Optional diagnostic copy of the sole completed terminal read.
            // This performs no additional device observation and is also
            // useful when the sticky device verdict prevents decoding.
            if (std.process.getEnvVarOwned(a, "STWO_RESIDENT_PARENT_TERMINAL")) |path| {
                defer a.free(path);
                try std.fs.cwd().writeFile(.{ .sub_path = path, .data = std.mem.sliceAsBytes(words) });
            } else |err| if (err != error.EnvironmentVariableNotFound) return err;
            errdefer if (words.len > 15) std.debug.print("RESIDENT_PARENT_TERMINAL words={d} sticky_verdict={d}\n", .{ words.len, words[15] });
            const proof = try Terminal.Proof.decode(a, input.program, &pcs, words, .{ .operations = verdict.counters.d2h_proof_operations, .bytes = verdict.counters.d2h_proof_bytes, .runtime_compile_attempts = verdict.aot.aot_misses, .cpu_fallback_attempts = verdict.counters.cpu_fallback_attempts });
            host.decode_ns = phase_clock.lap();
            return .{ .proof = proof, .verdict = verdict, .device_arena_bytes = device_bytes, .elapsed_ns = timer.read(), .host_timing = host };
        }
    };
}
