//! Lifecycle and publication boundary for the focused RISC-V CPU product.
//!
//! The generic body lives in `src/products/riscv_shared/app.zig`; this file is
//! the CPU binding of it. It is the single place where the focused CPU product
//! chooses its prover engine and its adapter backend tag.

const std = @import("std");
const shared = @import("riscv_shared_app");

const Deps = struct {
    pub const stwo = @import("stwo_riscv_cpu");
    pub const adapter = @import("riscv_adapter");
    pub const cli = @import("cli.zig");
    pub const registry = @import("registry.zig");
    pub const output_transaction = @import("output_transaction");
    pub const Engine = stwo.integrations.riscv_cpu.CpuProverEngine;
    pub const backend: adapter.Backend = .cpu;
};

const app = shared.App(Deps);

pub const main = app.main;

test "focused verifier rejects non-RISC-V artifacts" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "artifact.json", .data = "{}" });
    const path = try temporary.dir.realpathAlloc(std.testing.allocator, "artifact.json");
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.UnsupportedArtifactKind, app.verifyArtifact(
        std.testing.allocator,
        .{
            .artifact = path,
            .elf_path = "guest.elf",
            .protocol = .functional,
            .expected_statement_digest = [_]u8{0} ** 32,
        },
    ));
}
