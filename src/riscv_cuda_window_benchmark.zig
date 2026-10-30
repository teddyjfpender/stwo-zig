//! Actual V7 proof benchmark with GPU DEEP and original CPU Blake3/AIR/FRI.
//! Never enables the unfinished resident RISC-V CUDA product.
const std = @import("std");
const X = @import("integrations/riscv_cuda/hybrid_quotient_executor_v1.zig");
const Composition = @import("integrations/riscv_cuda/hybrid_framework_composition_v1.zig");
const Interaction = @import("integrations/riscv_cuda/hybrid_framework_interaction_v1.zig");
const Original = @import("frontends/riscv/prover/tests/block_v7_real_window_v2_benchmark.zig");
const Complete = @import("frontends/riscv/recursion/block_v7_real_window_root_test_v2.zig");
const INTERACTION_COHORTS = @import("frontends/riscv/recursion/blake3_native_parent_artifact.zig").CLAIM_COUNT;
fn SinkFor(comptime Call: type) type {
    return struct {
        file: std.fs.File,
        fn record(context: *anyopaque, call: Call) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, call, .{});
            defer std.testing.allocator.free(bytes);
            try self.file.writeAll(bytes);
            try self.file.writeAll("\n");
        }
    };
}
const Sink = SinkFor(X.Call);
const CompositionSink = SinkFor(Composition.Call);
const InteractionSink = SinkFor(Interaction.Call);
fn number(comptime T: type, name: [:0]const u8, fallback: T) !T {
    return if (std.posix.getenv(name)) |value| std.fmt.parseInt(T, value, 10) else fallback;
}
fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidCudaCoverageReport;
    return value.object.get(name) orelse error.InvalidCudaCoverageReport;
}
fn count(value: std.json.Value) !usize {
    if (value != .integer or value.integer < 0) return error.InvalidCudaCoverageReport;
    return std.math.cast(usize, value.integer) orelse error.InvalidCudaCoverageReport;
}
fn requireCoverage(calls: usize, originals_only: bool) !void {
    const a = std.testing.allocator;
    const path = if (originals_only)
        try std.fs.path.join(a, &.{ std.posix.getenv("STWO_REAL_WINDOW_V2_OUTPUT") orelse return error.MissingBenchmarkOutput, "report.json" })
    else
        try a.dupe(u8, std.posix.getenv("STWO_V7_WINDOW_REPORT") orelse return error.MissingCudaCoverageReport);
    defer a.free(path);
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 4 << 20);
    defer a.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    defer parsed.deinit();
    const expected = if (originals_only)
        try count(try field(try field(parsed.value, "artifacts"), "proof_count"))
    else
        try std.math.add(usize, try count(try field(try field(parsed.value, "source"), "original_proofs")), try count(try field(parsed.value, "recursive_proof_count")));
    if (calls != expected) return error.CudaProofCoverageMismatch;
}
fn save(dir: std.fs.Dir, owner: *const X.Owner, completed: bool, originals_only: bool, cpu_reference: bool, context_startup_ns: u64) !void {
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, .{
        .schema = "stwo-v7-cuda-deep-v1",
        .complete_helper_succeeded = completed,
        .proof_scope = if (originals_only) "declared_window_original_proofs" else "declared_window_recursive_root",
        .gpu_selected = !cpu_reference,
        .gpu_stages = if (cpu_reference) "none" else if (owner.stats.expansion_kernel_launches != 0) "coefficient_expansion,deep_numerator_and_combine" else "deep_numerator_and_combine",
        .cpu_stages = if (cpu_reference) "all" else "execution,witness,composition,tiny_coefficient_expansion,blake3,transcript,fri,verification",
        .context_startup_ns = context_startup_ns,
        .resident_proof = false,
        .fallback_allowed = false,
        .device = owner.device,
        .platform = owner.platform,
        .static_module_identity = owner.module_identity,
        .limits = owner.limits,
        .stats = owner.stats,
    }, .{ .whitespace = .indent_2 });
    defer std.testing.allocator.free(bytes);
    try dir.writeFile(.{ .sub_path = "cuda-deep-receipt.json", .data = bytes });
}
fn saveComposition(dir: std.fs.Dir, owner: *const Composition.Owner, completed: bool, context_startup_ns: u64) !void {
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, .{
        .schema = "stwo-v7-cuda-framework-composition-v1",
        .complete_helper_succeeded = completed,
        .scope = "recursive_parent_composition",
        .gpu_stages = "framework_row_evaluation",
        .cpu_stages = "source_materialization,polynomial_extension,blake3,transcript,fri,verification",
        .context_startup_ns = context_startup_ns,
        .resident_proof = false,
        .fallback_allowed = false,
        .device = owner.device,
        .platform = owner.platform,
        .static_module_identity = owner.module_identity,
        .limits = owner.limits,
        .stats = owner.stats,
    }, .{ .whitespace = .indent_2 });
    defer std.testing.allocator.free(bytes);
    try dir.writeFile(.{ .sub_path = "cuda-composition-receipt.json", .data = bytes });
}
fn requireCompositionCoverage(calls: usize) !void {
    const path = std.posix.getenv("STWO_V7_WINDOW_REPORT") orelse return error.MissingCudaCoverageReport;
    const a = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(a, path, 4 << 20);
    defer a.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    defer parsed.deinit();
    const expected = try count(try field(parsed.value, "recursive_proof_count"));
    if (expected == 0 or calls != expected) return error.CudaCompositionCoverageMismatch;
}
fn saveInteraction(dir: std.fs.Dir, owner: *const Interaction.Owner, completed: bool, context_startup_ns: u64) !void {
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, .{
        .schema = "stwo-v7-cuda-framework-interaction-v1",
        .complete_helper_succeeded = completed,
        .scope = "recursive_parent_interactions",
        .cohorts_per_parent = INTERACTION_COHORTS,
        .gpu_stages = "fractions,prefix_scan,mean_and_claims",
        .cpu_stages = "input_projection,blake3,transcript,fri,verification",
        .context_startup_ns = context_startup_ns,
        .resident_proof = false,
        .fallback_allowed = false,
        .device = owner.device,
        .platform = owner.platform,
        .static_module_identity = owner.module_identity,
        .limits = owner.limits,
        .stats = owner.stats,
    }, .{ .whitespace = .indent_2 });
    defer std.testing.allocator.free(bytes);
    try dir.writeFile(.{ .sub_path = "cuda-interaction-receipt.json", .data = bytes });
}
test "actual CUDA DEEP V7 canonical window and optional complete recursive root" {
    const path = std.posix.getenv("STWO_RISCV_CUDA_REPORT_DIR") orelse return error.MissingCudaReportDirectory;
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const cap_mib = try number(usize, "STWO_RISCV_CUDA_DEVICE_MIB", 16384);
    if (cap_mib == 0 or cap_mib > 196608) return error.InvalidCudaQuotientPolicy;
    const sm = try number(u32, "STWO_RISCV_CUDA_SM", 90);
    const device = try number(u32, "STWO_RISCV_CUDA_DEVICE", 0);
    var startup = try std.time.Timer.start();
    var owner = try X.Owner.open(device, sm, .{ .plan = .{ .max_device_bytes = try std.math.mul(usize, cap_mib, 1 << 20) } });
    defer owner.deinit() catch @panic("CUDA context teardown failed");
    const context_startup_ns = startup.read();
    var sink = Sink{ .file = try dir.createFile("cuda-deep-calls.jsonl", .{}) };
    defer sink.file.close();
    owner.observer = .{ .context = &sink, .record = Sink.record };
    const originals_only = (try number(u1, "STWO_RISCV_CUDA_ORIGINALS_ONLY", 0)) == 1;
    // An explicit reference mode gives paired CPU/GPU experiments the same
    // executable, compiler flags and context startup. It is never a fallback.
    const cpu_reference = (try number(u1, "STWO_RISCV_CUDA_CPU_REFERENCE", 0)) == 1;
    const parent_composition = (try number(u1, "STWO_RISCV_CUDA_PARENT_COMPOSITION", 0)) == 1;
    const parent_interactions = (try number(u1, "STWO_RISCV_CUDA_PARENT_INTERACTIONS", 0)) == 1;
    if ((parent_composition or parent_interactions) and (cpu_reference or originals_only)) return error.InvalidCudaCompositionSelection;
    var composition_owner: ?Composition.Owner = null;
    defer if (composition_owner) |*selected_owner| selected_owner.deinit() catch @panic("CUDA composition context teardown failed");
    var composition_sink: ?CompositionSink = null;
    defer if (composition_sink) |*selected_sink| selected_sink.file.close();
    var composition_startup_ns: u64 = 0;
    if (parent_composition) {
        startup.reset();
        composition_owner = try Composition.Owner.open(device, sm, .{
            .max_device_bytes = try std.math.mul(usize, cap_mib, 1 << 20),
            .max_host_scratch_bytes = 8 << 30,
        });
        composition_startup_ns = startup.read();
        composition_sink = .{ .file = try dir.createFile("cuda-composition-calls.jsonl", .{}) };
        composition_owner.?.observer = .{ .context = &composition_sink.?, .record = CompositionSink.record };
    }
    var interaction_owner: ?Interaction.Owner = null;
    defer if (interaction_owner) |*selected_owner| selected_owner.deinit() catch @panic("CUDA interaction context teardown failed");
    var interaction_sink: ?InteractionSink = null;
    defer if (interaction_sink) |*selected_sink| selected_sink.file.close();
    var interaction_startup_ns: u64 = 0;
    if (parent_interactions) {
        startup.reset();
        interaction_owner = try Interaction.Owner.open(device, sm, .{ .max_device_bytes = try std.math.mul(usize, cap_mib, 1 << 20) });
        interaction_startup_ns = startup.read();
        interaction_sink = .{ .file = try dir.createFile("cuda-interaction-calls.jsonl", .{}) };
        interaction_owner.?.observer = .{ .context = &interaction_sink.?, .record = InteractionSink.record };
    }
    var completed = false;
    defer save(dir, &owner, completed, originals_only, cpu_reference, context_startup_ns) catch @panic("CUDA receipt write failed");
    defer if (composition_owner) |*selected_owner| saveComposition(dir, selected_owner, completed, composition_startup_ns) catch @panic("CUDA composition receipt write failed");
    defer if (interaction_owner) |*selected_owner| saveInteraction(dir, selected_owner, completed, interaction_startup_ns) catch @panic("CUDA interaction receipt write failed");
    const executor = owner.executor();
    var composition_executor = if (composition_owner) |*selected_owner| selected_owner.executor() else null;
    var interaction_executor = if (interaction_owner) |*selected_owner| selected_owner.executor() else null;
    const selected = if (cpu_reference) null else &executor;
    if (originals_only) try Original.runWithExecutor(selected) else try Complete.runWithAllExecutors(selected, if (composition_executor) |*selected_executor| selected_executor else null, if (interaction_executor) |*selected_executor| selected_executor else null);
    if (owner.poisoned or (cpu_reference and (owner.stats.calls != 0 or owner.stats.kernel_launches != 0)))
        return error.CudaNumericalPathUnused;
    if (!cpu_reference) {
        if (owner.stats.calls == 0 or owner.stats.kernel_launches != 2 * owner.stats.calls + owner.stats.expansion_kernel_launches)
            return error.CudaNumericalPathUnused;
        try requireCoverage(owner.stats.calls, originals_only);
    }
    if (composition_owner) |*selected_owner| {
        if (selected_owner.poisoned or selected_owner.bound or selected_owner.stats.calls == 0 or selected_owner.stats.kernel_launches < selected_owner.stats.calls)
            return error.CudaCompositionPathUnused;
        try requireCompositionCoverage(selected_owner.stats.calls);
    }
    if (interaction_owner) |*selected_owner| {
        if (selected_owner.poisoned or selected_owner.active or selected_owner.stats.calls == 0 or
            selected_owner.stats.calls % INTERACTION_COHORTS != 0 or selected_owner.stats.kernel_launches != 4 * selected_owner.stats.calls)
            return error.CudaInteractionPathUnused;
        try requireCompositionCoverage(selected_owner.stats.calls / INTERACTION_COHORTS);
    }
    completed = true;
}
