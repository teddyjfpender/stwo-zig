const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Protocol = @import("frontends/riscv/recursion/blake3_execution_parent_protocol.zig");
const Storage = @import("frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const Projection = @import("frontends/riscv/recursion/air/blake3_row_columns.zig");
const Fixed = @import("frontends/riscv/recursion/blake3_parent_fixed_key_v1.zig");
const Program = @import("integrations/riscv_cuda/resident_parent_program_v1.zig");
const Padding = @import("integrations/riscv_cuda/resident_parent_padding_v1.zig");
const Prover = @import("integrations/riscv_cuda/resident_parent_prover_v1.zig");
const Artifact = @import("frontends/riscv/recursion/blake3_native_parent_artifact.zig");
const Verifier = @import("frontends/riscv/recursion/blake3_native_parent_verifier.zig");
test "actual fully resident original25 parent padding numerical proof fresh verifies" {
    const a = std.testing.allocator;
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    const context = (try Program.fixtureAdmission()).key.context;
    // Cold independent key construction is deliberately before the proof call.
    const canonical = if (std.process.getEnvVarOwned(a, "STWO_RESIDENT_PADDING_CANONICAL")) |value| blk: {
        defer a.free(value);
        if (!std.mem.eql(u8, value, "1")) return error.InvalidCanonicalProfileOption;
        break :blk true;
    } else |err| if (err == error.EnvironmentVariableNotFound) false else return err;
    const key = try Fixed.ForBackend(Cpu).derive(a, fixed, context, if (canonical) .csp_q70_pow26 else .diagnostic_q8_pow0);
    std.debug.print("RESIDENT_PADDING_PROFILE queries={d} pow_bits={d}\n", .{ key.config.fri_config.n_queries, key.config.pow_bits });
    const admitted = try Protocol.Admission.init(key, try key.identity());
    const program = try Program.Owned.derive(a, admitted, .{});
    defer program.deinit();
    var plan = try Padding.Plan.init(a, program);
    defer plan.deinit();
    var columns: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
    defer {
        for (columns.items) |c| a.free(c.values);
        columns.deinit(a);
    }
    inline for (Storage.Airs, 0..) |Air, i| try Projection.projectFixed(Air, a, fixed[i], key.log_sizes[i], &columns);
    for ([_]@import("frontends/riscv/air/lookups/tables/schema.zig").Kind{ .bitwise, .range_check_8_8 }) |kind| try Projection.tablePreprocessed(a, kind, &columns);
    const inputs = try a.alloc([]const core.fields.m31.M31, columns.items.len);
    defer a.free(inputs);
    for (columns.items, inputs) |c, *out| out.* = c.values;
    const retained_mode = if (std.process.getEnvVarOwned(a, "STWO_RESIDENT_PADDING_RETAINED")) |value| blk: {
        defer a.free(value);
        if (!std.mem.eql(u8, value, "1")) return error.InvalidRetainedProfileOption;
        break :blk true;
    } else |err| if (err == error.EnvironmentVariableNotFound) false else return err;
    var open_clock = try std.time.Timer.start();
    var runtime: ?@import("stwo_cuda_backend").runtime.NativeRuntime = if (retained_mode) try @import("stwo_cuda_backend").runtime.NativeRuntime.open(&.{90}) else null;
    defer if (runtime) |*r| r.abort() catch {};
    if (runtime != null) std.debug.print("RESIDENT_PADDING_RUNTIME open_ns={d}\n", .{open_clock.read()});
    for (0..@as(usize, if (retained_mode) 2 else 1)) |iteration| {
        std.debug.print("RESIDENT_PADDING_REQUEST iteration={d} retained={}\n", .{ iteration, retained_mode });
        var result = try Prover.For(Padding.Plan).prove(a, .{ .program = program, .device_plan = &plan, .fixed = inputs, .raw_input = &.{0}, .runtime = if (runtime) |*r| r else null });
        // Ownership moves to the unchanged original verifier. The GPU transaction
        // has already been destroyed, leaving only the single terminal proof.
        var artifact = Artifact.Owned.init(a, result.proof.stark, admitted.expected_id, result.proof.claims);
        if (std.process.getEnvVarOwned(a, "STWO_RESIDENT_PADDING_ARTIFACT")) |path| {
            defer a.free(path);
            const encoded = try @import("frontends/riscv/recursion/blake3_native_parent_codec.zig").encode(a, &artifact, &admitted);
            defer a.free(encoded);
            const artifact_path = if (retained_mode) try std.fmt.allocPrint(a, "{s}.{d}", .{ path, iteration }) else try a.dupe(u8, path);
            defer a.free(artifact_path);
            try std.fs.cwd().writeFile(.{ .sub_path = artifact_path, .data = encoded });
            std.debug.print("RESIDENT_PADDING_ARTIFACT bytes={d} elapsed_ns={d} path={s}\n", .{ encoded.len, result.elapsed_ns, path });
        } else |err| if (err != error.EnvironmentVariableNotFound) return err;
        var verified = try Verifier.verify(&artifact, &admitted);
        defer verified.deinit();
        try std.testing.expect(result.verdict.isResident());
        const counters = result.verdict.counters;
        inline for (std.meta.fields(Prover.HostTiming)) |field| std.debug.print("RESIDENT_PADDING_HOST name={s} ns={d}\n", .{ field.name, @field(result.host_timing, field.name) });
        std.debug.print("RESIDENT_PADDING_TRANSFER d2h_operations={d} d2h_bytes={d} h2d_bytes={d} cpu_fallback_attempts={d} aot_misses={d}\n", .{ counters.d2h_proof_operations, counters.d2h_proof_bytes, counters.h2d_bytes, counters.cpu_fallback_attempts, result.verdict.aot.aot_misses });
        for (@import("stwo_cuda_backend").runtime.telemetry.all_stages) |stage| {
            const measured = counters.stages[stage.index()];
            std.debug.print("RESIDENT_PADDING_STAGE name={s} device_ns={d} kernels={d} h2d_bytes={d} d2h_bytes={d}\n", .{ @tagName(stage), measured.device_elapsed_ns, measured.kernel_launches, measured.h2d_bytes, measured.d2h_proof_bytes });
        }
        std.debug.print("RESIDENT_PADDING verified=true child_receipt=false device_bytes={d} elapsed_ns={d}\n", .{ result.device_arena_bytes, result.elapsed_ns });
    }
}
