const std = @import("std");
const hooks = @import("rv64_pipeline_hooks");
const pipeline = @import("opstack_cpu_component").Pipeline;
const ProductHooks = @import("stwo_riscv_rv64_pipeline").ProductHooks;

test "hooks contract: OP hooks satisfy the pipeline contract" {
    try std.testing.expect(comptime ProductHooks.violation(hooks) == null);
    try std.testing.expectEqual(@as(usize, 32 * 1024 * 1024 - 4), hooks.MAX_INPUT_BYTES);
    try std.testing.expectEqual(@as(usize, 0), hooks.service_families.len);
}

test "hooks contract: only the v3 services profile is admitted in S1" {
    try std.testing.expect(hooks.admitsProfile(.ethereum_services_v3));
    try std.testing.expect(!hooks.admitsProfile(.ethereum_services_v1));
    try std.testing.expect(!hooks.admitsProfile(.ethereum_services_v2));
}

test "hooks contract: a non-admitted profile fails request admission before any file read" {
    const fixture = @import("opstack_frontend_component").guest_abi.Symbols{ .input_start = 0x800000, .input_end = 0xc00000, .halt_flag = 0xc00000, .output_len = 0xc00004, .output_data = 0xc00008, .output_end = 0x1000000, .stack_bottom = 0x1000000, .stack_top = 0x2000000, .heap_start = 0x2100000, .heap_end = 0x2200000 };
    const config = pipeline.request.Config{ .elf = "/nonexistent/guest.elf", .input = "/nonexistent/input.bin", .elf_sha256 = "", .input_sha256 = "", .expected_output = "", .symbols = fixture, .output_directory = "", .terminal_pc = 0, .execution_profile = .ethereum_services_v2 };
    try std.testing.expectError(error.UnsupportedGuestExecutionProfile, pipeline.request.validateBudget(config));
    var admitted = config;
    admitted.execution_profile = .ethereum_services_v3;
    try pipeline.request.validateBudget(admitted);
}
