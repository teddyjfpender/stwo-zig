//! Hook contract behaviour that does not need a proof: profile admission
//! happens before any ELF, input or capture work, and the hook label never
//! changes request identity.
const std = @import("std");
const H = @import("rv64_pipeline_hooks");
const Request = @import("../request.zig");
const fixture = @import("execution_fixture.zig");

fn config(profile: @import("stwo_riscv_rv64").execution.execution_profile.Profile) Request.Config {
    return .{ .elf = "/nonexistent/guest.elf", .input = "/nonexistent/input.bin", .elf_sha256 = "", .input_sha256 = "", .expected_output = "", .symbols = fixture.symbols, .output_directory = "", .terminal_pc = 0, .execution_profile = profile };
}

test "hooks: non-admitted profile is rejected before any file is read" {
    try std.testing.expect(!H.admitsProfile(.ethereum_services_v1));
    try std.testing.expectError(error.UnsupportedGuestExecutionProfile, Request.validateBudget(config(.ethereum_services_v1)));
    // The same request with an admitted profile passes admission and only then
    // fails on the missing ELF, proving the order.
    try Request.validateBudget(config(.ethereum_services_v2));
    try std.testing.expectError(error.FileNotFound, Request.Request.init(std.testing.allocator, config(.ethereum_services_v2)));
}

test "hooks: empty service families keep the base roster" {
    try std.testing.expectEqual(@as(usize, 0), H.service_families.len);
}

test "hooks: input window bounds follow MAX_INPUT_BYTES" {
    try std.testing.expectEqual(@as(?u64, 4 * 1024 * 1024), H.inputWindow(fixture.symbols));
    var oversized = fixture.symbols;
    oversized.input_end = oversized.input_start + 2 * (H.MAX_INPUT_BYTES + 4);
    try std.testing.expectEqual(@as(?u64, null), H.inputWindow(oversized));
}
