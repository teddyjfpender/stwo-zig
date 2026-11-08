//! Runtime backend dispatch into the shared Native proving transaction.

const std = @import("std");
const capabilities = @import("aggregate_capabilities");
const builtin = @import("builtin");
const stwo = @import("stwo");
const runner = @import("native_proof_runner");
const product_identity = @import("native_product_identity");
const cli = @import("cli.zig");

pub const Execution = struct {
    warmups: usize,
    samples: usize,
    profiled: bool,
    proof_temporary: ?[]const u8,
    proof_report_path: ?[]const u8,
};

pub fn run(
    allocator: std.mem.Allocator,
    request: cli.Run,
    execution: Execution,
) ![]u8 {
    const args = nativeArgs(request, execution);
    return switch (request.backend) {
        .cpu => runner.run(
            stwo.examples.wide_fibonacci.CpuProverEngine,
            .cpu_native,
            allocator,
            args,
        ),
        .metal_hybrid => {
            if (comptime builtin.os.tag != .macos or !capabilities.metal_enabled)
                return error.MetalBackendUnavailable;
            return runner.run(
                stwo.backends.metal.MetalProverEngine,
                .metal_hybrid,
                allocator,
                args,
            );
        },
    };
}

fn nativeArgs(request: cli.Run, execution: Execution) runner.config.Args {
    var result = runner.config.Args{
        .product_identity = product_identity.value(),
        .example = switch (request.workload) {
            .wide_fibonacci => .wide_fibonacci,
            .xor => .xor,
            .plonk => .plonk,
            .state_machine => .state_machine,
            .blake => .blake,
            .poseidon => .poseidon,
        },
        .protocol = switch (request.protocol) {
            .secure => .secure,
            .functional => .functional,
            .smoke => .smoke,
        },
        .warmups = execution.warmups,
        .samples = execution.samples,
        .profiled = execution.profiled,
        .proof_artifact_out = execution.proof_temporary,
        .proof_artifact_report_path = execution.proof_report_path,
        .blake2_backend = switch (request.blake2_backend) {
            .auto => .auto,
            .scalar => .scalar,
            .simd => .simd,
        },
        .resource_profile = switch (request.resource_profile) {
            .standard => .standard,
            .large => .large,
            .extreme => .extreme,
        },
        .metal_runtime = .{
            .mode = switch (request.metal_runtime.mode) {
                .source_jit => .source_jit,
                .authenticated_aot => .authenticated_aot,
            },
            .aot_bundle = request.metal_runtime.aot_bundle,
            .manifest_sha256 = request.metal_runtime.manifest_sha256,
        },
    };
    switch (request.workload) {
        .wide_fibonacci => |value| result.wide_fibonacci = .{
            .log_n_rows = value.log_n_rows,
            .sequence_len = value.sequence_len,
        },
        .xor => |value| result.xor = .{
            .log_size = value.log_size,
            .log_step = value.log_step,
            .offset = value.offset,
        },
        .plonk => |value| result.plonk = .{ .log_n_rows = value.log_n_rows },
        .state_machine => |value| result.state_machine = .{
            .log_n_rows = value.log_n_rows,
            .initial_x = value.initial_x,
            .initial_y = value.initial_y,
        },
        .blake => |value| result.blake = .{
            .log_n_rows = value.log_n_rows,
            .n_rounds = value.n_rounds,
        },
        .poseidon => |value| result.poseidon = .{
            .log_n_instances = value.log_n_instances,
        },
    }
    return result;
}

test "native dispatch: CLI workload mapping preserves parameters" {
    const args = nativeArgs(.{
        .backend = .cpu,
        .protocol = .secure,
        .workload = .{ .wide_fibonacci = .{ .log_n_rows = 17, .sequence_len = 31 } },
        .blake2_backend = .simd,
        .metal_runtime = .{},
        .resource_profile = .large,
    }, .{
        .warmups = 2,
        .samples = 7,
        .profiled = true,
        .proof_temporary = "/tmp/proof.tmp",
        .proof_report_path = "proof.json",
    });
    try std.testing.expectEqual(runner.config.Example.wide_fibonacci, args.example);
    try std.testing.expectEqual(runner.config.Protocol.secure, args.protocol);
    try std.testing.expectEqual(@as(u32, 17), args.wide_fibonacci.log_n_rows);
    try std.testing.expectEqual(@as(u32, 31), args.wide_fibonacci.sequence_len);
    try std.testing.expectEqual(runner.config.ResourceProfile.large, args.resource_profile);
    try std.testing.expectEqualStrings("proof.json", args.proof_artifact_report_path.?);
}

test "native dispatch: extreme resource profile reaches the native runner" {
    const args = nativeArgs(.{
        .backend = .cpu,
        .protocol = .secure,
        .workload = .{ .wide_fibonacci = .{ .log_n_rows = 22, .sequence_len = 100 } },
        .blake2_backend = .auto,
        .metal_runtime = .{},
        .resource_profile = .extreme,
    }, .{
        .warmups = 0,
        .samples = 1,
        .profiled = false,
        .proof_temporary = null,
        .proof_report_path = null,
    });

    try std.testing.expectEqual(runner.config.ResourceProfile.extreme, args.resource_profile);
}

test "native dispatch: security profiles map by meaning, not enum ordinal" {
    const workload: cli.Workload = .{ .plonk = .{ .log_n_rows = 8 } };
    const execution = Execution{
        .warmups = 0,
        .samples = 1,
        .profiled = false,
        .proof_temporary = null,
        .proof_report_path = null,
    };
    inline for (.{
        .{ cli.Protocol.secure, runner.config.Protocol.secure },
        .{ cli.Protocol.functional, runner.config.Protocol.functional },
        .{ cli.Protocol.smoke, runner.config.Protocol.smoke },
    }) |pair| {
        const args = nativeArgs(.{
            .backend = .cpu,
            .protocol = pair[0],
            .workload = workload,
            .blake2_backend = .auto,
            .metal_runtime = .{},
            .resource_profile = .standard,
        }, execution);
        try std.testing.expectEqual(pair[1], args.protocol);
    }
}
