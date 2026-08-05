//! End-to-end Native frontend proof through the CuMetal CUDA provider.

const std = @import("std");
const stwo = @import("stwo_under_test");

const integration = stwo.integrations.native_cuda.wide_fibonacci;

test "Native proof executes on the provider-bound CuMetal runtime" {
    const allocator = std.testing.allocator;
    const protocol = integration.request.Protocol{
        .pow_bits = 10,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
        .lifting_log_size = null,
    };
    const request = integration.request.Request{
        .statement = .{
            .log_n_rows = 5,
            .sequence_len = 8,
        },
        .protocol = protocol,
    };
    var runtime = integration.CuMetalRuntime.open(&.{80}) catch |err| {
        std.debug.print("CuMetal runtime admission failed: {s}\n", .{@errorName(err)});
        diagnoseAdmission();
        return err;
    };
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};
    const driver = integration.CuMetalDriver{ .allocator = allocator };
    var output = driver.runRetained(&runtime, request) catch |err| {
        std.debug.print("CuMetal Native proof failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer output.deinit(allocator);
    try std.testing.expect(output.verdict.isResident());
    try std.testing.expect(output.verdict.aot.isStrict());
    try std.testing.expectEqual(
        @as(u64, 0),
        output.verdict.counters.cpu_fallback_attempts,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        output.verdict.counters.cpu_fallbacks_completed,
    );

    var proof = try integration.proof_decode.decodeProof(
        allocator,
        output.bundle,
    );
    var proof_live = true;
    defer if (proof_live) proof.deinit(allocator);
    var fri_config = try stwo.core.fri.FriConfig.init(0, 1, 3);
    fri_config.fold_step = 1;
    const pcs_config = stwo.core.pcs.PcsConfig{
        .pow_bits = protocol.pow_bits,
        .fri_config = fri_config,
        .lifting_log_size = null,
    };
    proof_live = false;
    try stwo.examples.wide_fibonacci.verify(
        allocator,
        pcs_config,
        .{
            .log_n_rows = request.statement.log_n_rows,
            .sequence_len = request.statement.sequence_len,
        },
        proof,
    );
    try runtime.close();
    runtime_live = false;
}

fn diagnoseAdmission() void {
    const cuda = stwo.backends.cuda;
    const api = cuda.abi.runtime;
    var count: u32 = 0;
    var current: u32 = 0;
    var major: u32 = 0;
    var minor: u32 = 0;
    report("device snapshot", api.stwo_cuda_device_snapshot(
        &count,
        &current,
        &major,
        &minor,
    ));
    var platform = cuda.abi.types.PlatformSnapshot{};
    report("platform snapshot", api.stwo_cuda_platform_snapshot(&platform));
    var identity = [_]u8{0} ** 32;
    report("build identity", api.stwo_static_cuda_module_build_identity(&identity));
    var context: ?*anyopaque = null;
    const context_status = api.stwo_exec_context_create(&context);
    report("execution context", context_status);
    if (context_status != 0 or context == null) return;
    defer report("context cleanup", api.stwo_exec_context_destroy(context.?));

    var stream: ?*anyopaque = null;
    report("context stream", api.stwo_exec_context_stream(context.?, &stream));
    var device: c_int = -1;
    report("context device", api.stwo_exec_context_device(context.?, &device));
    var lanes: u32 = 0;
    report("context lanes", api.stwo_exec_context_lane_count(context.?, &lanes));
    var loader: ?*anyopaque = null;
    const loader_status = cuda.abi.aot.stwo_native_aot_loader_create(
        context.?,
        &loader,
    );
    report("AOT loader", loader_status);
    if (loader_status == 0 and loader != null) {
        report("AOT loader cleanup", cuda.abi.aot.stwo_native_aot_loader_destroy(
            loader.?,
        ));
    }
}

fn report(component: []const u8, status: c_int) void {
    std.debug.print("CuMetal admission {s}: status={d}\n", .{ component, status });
}
