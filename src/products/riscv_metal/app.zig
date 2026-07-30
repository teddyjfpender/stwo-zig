//! Lifecycle and publication boundary for the focused RISC-V Metal product.
//!
//! The generic body lives in `src/products/riscv_shared/app.zig`; this file is
//! the Metal binding of it. It is the single place where the focused Metal
//! product chooses its prover engine and its adapter backend tag, exactly
//! mirroring `src/products/riscv_cpu/app.zig`. Nothing else about the run
//! differs: the output transaction, the atomic publication order, the adapter
//! error mapping and the command dispatch are the shared ones, which is what
//! makes a Metal run comparable with a CPU run.
//!
//! `MetalProverEngine.Channel` is the same type as `CpuProverEngine.Channel`
//! (both instantiate the engine over the Blake2s hasher/channel the RV32IM
//! frontend pins), so the shared adapter's postcard serialization and transcript
//! digest are reached unchanged from here.

const std = @import("std");
const shared = @import("riscv_shared_app");

const Deps = struct {
    pub const stwo = @import("stwo_riscv_metal");
    pub const adapter = @import("riscv_adapter");
    pub const cli = @import("cli.zig");
    pub const registry = @import("registry.zig");
    pub const output_transaction = @import("output_transaction");
    pub const Engine = stwo.integrations.riscv_metal.MetalProverEngine;
    pub const backend: adapter.Backend = .metal;
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

test "this product binds the Metal engine and the metal backend tag" {
    try std.testing.expectEqual(Deps.adapter.Backend.metal, Deps.backend);
    try std.testing.expectEqualStrings("metal", @tagName(Deps.backend));
    try std.testing.expect(Deps.Engine == Deps.stwo.integrations.riscv_metal.MetalProverEngine);
}
