//! Finite fully resident original-native controller. This assembled path has
//! not yet executed a complete device proof; production entry is fail-closed.
//! Qualification callers must independently run the original Native verifier.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Numerical = @import("resident_parent_pcs_v1.zig");
const Controller = @import("stwo_cairo_cuda_integration").executor.quotient.controller;
const Twiddles = @import("resident_parent_twiddles_v1.zig");
const ClaimPack = @import("resident_native_claim_pack_v1.zig");
pub const production_ready = false;
pub fn requireQualification(qualification_only: bool) !void {
    if (!production_ready and !qualification_only) return error.UnqualifiedResidentNativeController;
}
pub const HostTiming = @import("resident_parent_prover_v1.zig").HostTiming;
pub const Limits = struct {
    max_device_bytes: usize = 96 << 30,
    accepted_sms: []const u32 = &.{90},
    producer: @import("resident_native_producer_v1.zig").Limits = .{},
    composition: @import("resident_native_composition_v1.zig").Limits = .{},
};
pub fn ForCommitments(comptime N: usize) type {
    const Program = @import("resident_native_program_v1.zig").ForCommitments(N);
    const PCS = @import("resident_native_pcs_v1.zig").ForCommitments(N);
    const Memory = @import("resident_native_memory_v1.zig").ForCommitments(N);
    const Terminal = @import("resident_native_terminal_v1.zig").ForCommitments(N);
    const Transcript = @import("resident_native_transcript_v1.zig").ForCommitments(N);
    const Producer = @import("resident_native_producer_v1.zig").ForCommitments(N);
    const Composition = @import("resident_native_composition_v1.zig").ForCommitments(N);
    const Pipeline = @import("resident_native_pipeline_v1.zig").ForCommitments(N);
    return struct {
        pub const Input = struct {
            program: *const Program.Owned,
            /// Original retirement packet followed by raw clock-update records. No
            /// precomputed MAIN, interactions, field challenges or fixed columns.
            raw_input: []const u32,
            limits: Limits = .{},
            runtime: ?*cuda.runtime.NativeRuntime = null,
            qualification_only: bool = false,
        };
        pub const Result = struct {
            proof: Terminal.Proof,
            verdict: cuda.runtime.verdict.Verdict,
            device_arena_bytes: usize,
            elapsed_ns: u64,
            host_timing: HostTiming,
            pub fn deinit(self: *Result, a: std.mem.Allocator) void {
                self.proof.deinit(a);
                self.* = undefined;
            }
        };
        pub fn prove(a: std.mem.Allocator, input: Input) !Result {
            try requireQualification(input.qualification_only);
            var phase: []const u8 = "admission";
            var timer = try std.time.Timer.start();
            var clock = try std.time.Timer.start();
            var host: HostTiming = .{};
            const p = input.program.view();
            errdefer std.debug.print("RESIDENT_NATIVE_FAILURE phase={s} commitments={d} fri_log={d} composition_log={d} split={d}\n", .{ phase, N, p.fri_log, p.composition_log, p.composition_split });
            var transcript = try Transcript.Static.derive(a, input.program);
            defer transcript.deinit();
            host.admission_ns = clock.lap();
            phase = "pcs_plans";
            var pcs = try PCS.Plans.init(a, input.program, input.limits.max_device_bytes);
            defer pcs.deinit();
            host.pcs_plans_ns = clock.lap();
            // CUB scratch sizing queries the selected CUDA runtime. Establish
            // its admitted process context before any producer planning query.
            var owned_runtime: ?cuda.runtime.NativeRuntime = null;
            if (input.runtime == null) owned_runtime = try cuda.runtime.NativeRuntime.openStaticNative(input.limits.accepted_sms, p.code_identity);
            defer if (owned_runtime) |*owner| owner.abort() catch {};
            const runtime = input.runtime orelse &owned_runtime.?;
            if (!runtime.isReady()) return error.InvalidRetainedNativeRuntime;
            if (runtime.planningSession().execution_kind != .static_native or
                !std.mem.eql(u8, &runtime.planningSession().static_code_identity, &p.code_identity))
                return error.InvalidRetainedNativeRuntime;
            const admitted_sm = try cuda.runtime.device_admission.sm(runtime.planningSession().device);
            if (!cuda.runtime.device_admission.contains(input.limits.accepted_sms, admitted_sm)) return error.InvalidDeviceArchitecture;
            phase = "producer_plans";
            const producer_plan = try Producer.Plan.init(input.program, input.limits.producer);
            if (input.raw_input.len != producer_plan.raw_words) return error.InvalidResidentNativeInput;
            var composition_plan = try Composition.Plan.init(a, input.program, input.limits.composition);
            defer composition_plan.deinit();
            var terminal = try Terminal.init(a, input.program, &pcs);
            defer terminal.deinit(a);
            const transcript_extra = try transcript.requirements(a);
            defer a.free(transcript_extra);
            var extra: std.ArrayList(cuda.runtime.arena.Requirement) = .empty;
            defer extra.deinit(a);
            try extra.appendSlice(a, &producer_plan.requirements);
            try extra.appendSlice(a, &composition_plan.requirements);
            try extra.appendSlice(a, transcript_extra);
            phase = "memory_plan";
            var memory = try Memory.Plan.init(a, input.program, &pcs, &terminal, transcript.count, try std.math.mul(usize, input.raw_input.len, 4), extra.items, input.limits.max_device_bytes);
            defer memory.deinit();
            const device_bytes = try std.math.mul(usize, memory.placement.total_words, 4);
            host.terminal_memory_plans_ns = clock.lap();
            phase = "open_transaction";
            var tx = blk: {
                var placement = try memory.takePlacement();
                const retained = runtime.beginProof() catch |err| {
                    placement.deinit(a);
                    return err;
                };
                break :blk try cuda.runtime.proof_transaction.ResidentProofTransaction.openPreparedRetained(a, retained, placement);
            };
            var finished = false;
            defer if (!finished) tx.abort() catch {};
            host.open_transaction_ns = clock.lap();
            const session = tx.proofSession();
            phase = "bind";
            var views = try Memory.bind(a, &tx, input.program, &pcs, &terminal, memory.raw_words);
            defer views.deinit();
            phase = "ingress";
            phase = "ingress_raw";
            if (input.raw_input.len != 0) try session.context.uploadSlice(u32, views.raw_input, input.raw_input);
            phase = "ingress_error_flag";
            try session.zeroResidentSlice(u32, .ingress, views.error_flag);
            phase = "ingress_terminal_zero";
            try session.zeroResidentSlice(u32, .ingress, views.proof.bundle);
            phase = "ingress_table_zero";
            for (views.table_counters) |table| try session.zeroResidentSlice(u32, .ingress, table);
            phase = "ingress_terminal_header";
            try session.context.uploadSlice(u32, try views.proof.bundle.sub(0, terminal.static_header.len), terminal.static_header);
            phase = "twiddles";
            std.debug.print("RESIDENT_NATIVE_GEOMETRY composition={d} fri={d} split={d}\n", .{ p.composition_log, p.fri_log, p.composition_split });
            phase = "ingress_twiddles";
            try Twiddles.generate(session, @max(p.fri_log, p.composition_log), views.twiddles_forward, views.twiddles_inverse);
            phase = "transcript_bind";
            phase = "ingress_transcript_bind";
            const bindings = try transcript.bind(&tx, views.transcript.state, views.transcript.static_words, views.relations, views.error_flag);
            phase = "ingress_transcript_init";
            var sink = try Transcript.NativeSink.init(session, input.program, &transcript, bindings);
            phase = "transcript_prime";
            phase = "ingress_transcript_prime";
            try sink.prime();
            phase = "claim_pack_prime";
            phase = "ingress_claim_bind";
            var pack = try ClaimPack.Bound.init(transcript.claims, try sink.claimBindings());
            phase = "ingress_claim_prime";
            try pack.prime(session);
            phase = "commitments_prime";
            phase = "ingress_commit_prime";
            var commitments: [N]Numerical.Commit.Bound = undefined;
            for (&commitments, &pcs.commitments, views.commits) |*bound, *plan, buffers| {
                bound.* = try Numerical.Commit.Bound.init(plan, buffers);
                try bound.prime(session);
            }
            phase = "producer_prime";
            phase = "ingress_producer_bind";
            var producer = try Producer.Bound.init(&producer_plan, &tx);
            phase = "ingress_producer_prime";
            try producer.prime(session);
            phase = "composition_prime";
            phase = "ingress_composition_bind";
            var composition = try Composition.Bound.init(&composition_plan, &tx);
            phase = "ingress_composition_prime";
            try composition.prime(session);
            phase = "oods_upload";
            phase = "ingress_oods_upload";
            try pcs.oods.upload(session, views.oods);
            phase = "ingress_oods_bind";
            var oods = try pcs.oods.bindTrees(a, &views.commits);
            defer oods.deinit();
            phase = "ingress_quotient_plan";
            var topology = try pcs.takeQuotient();
            var owns_topology = true;
            defer if (owns_topology) topology.deinit();
            var evals: [N]common.Words = undefined;
            for (views.commits, &evals) |tree, *out| out.* = tree.evaluations;
            phase = "ingress_quotient_prepare";
            var quotient = try Controller.prepareFromTopology(a, session, &topology, &evals, views.oods.sample_points, views.oods.sampled_values, views.quotient, views.twiddles_forward, p.fri_log, p.identity);
            owns_topology = false;
            defer quotient.deinit();
            phase = "ingress_quotient_transform";
            try @import("resident_native_quotient_v1.zig").initialize(&quotient, session, views.twiddles_inverse);
            phase = "ingress_fri_upload";
            try pcs.fri.upload(session, views.fri, views.twiddles_inverse);
            var logs: [N]common.Words = undefined;
            for (views.commits, &logs) |tree, *out| out.* = tree.column_logs;
            phase = "ingress_decommit_upload";
            try pcs.decommit.uploadForTrees(session, &logs);
            phase = "ingress_finish";
            try tx.finishIngress();
            host.ingress_enqueue_ns = clock.lap();
            phase = "pipeline";
            var pipeline = Pipeline{ .transaction = &tx, .program = input.program, .plans = &pcs, .views = &views, .producer = &producer, .composition = &composition, .sink = &sink, .claim_pack = &pack, .oods = &oods, .quotient = &quotient, .commitments = &commitments };
            try pipeline.execute();
            try sink.requireComplete();
            host.pipeline_enqueue_ns = clock.lap();
            const words = try a.alloc(u32, terminal.total_words);
            defer a.free(words);
            phase = "terminal_read";
            const verdict = try tx.assembleAndFinish(words, try @import("resident_native_memory_v1.zig").id(.terminal_bundle, 0));
            finished = true;
            if (!verdict.isResident()) return error.NonresidentNativeProof;
            host.terminal_read_finish_ns = clock.lap();
            phase = "terminal_decode";
            // Diagnostics reuse the sole terminal read; they never introduce a
            // numerical readback or turn an unverified artifact into a receipt.
            if (std.process.getEnvVarOwned(a, "STWO_RESIDENT_NATIVE_TERMINAL")) |path| {
                defer a.free(path);
                var file = try std.fs.cwd().createFile(path, .{});
                defer file.close();
                try file.writeAll(std.mem.sliceAsBytes(words));
            } else |err| switch (err) {
                error.EnvironmentVariableNotFound => {},
                else => return err,
            }
            if (words[15] != 0) std.debug.print("RESIDENT_NATIVE_TERMINAL_REJECT status={d} device_bytes={d} d2h_operations={d}\n", .{ words[15], device_bytes, verdict.counters.d2h_proof_operations });
            const proof = try Terminal.Proof.decode(a, input.program, &pcs, words, .{ .operations = verdict.counters.d2h_proof_operations, .bytes = verdict.counters.d2h_proof_bytes, .runtime_compile_attempts = verdict.aot.aot_misses, .cpu_fallback_attempts = verdict.counters.cpu_fallback_attempts });
            host.decode_ns = clock.lap();
            return .{ .proof = proof, .verdict = verdict, .device_arena_bytes = device_bytes, .elapsed_ns = timer.read(), .host_timing = host };
        }
    };
}
