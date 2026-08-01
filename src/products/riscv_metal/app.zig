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
const base_adapter = @import("riscv_adapter");
const shared = @import("riscv_shared_app");
const metal_aot_config = @import("metal_aot_config");

/// Product-local adapter guard. The shared RISC-V shell remains backend-neutral,
/// while every proving or benchmark transaction initializes the Metal engine
/// from the identity-bound core bundle before the adapter can call `warmup`.
/// Verification is deliberately re-exported unchanged because it requires no
/// proving device or Metal runtime.
const AuthenticatedAdapter = struct {
    pub const Backend = base_adapter.Backend;
    pub const Protocol = base_adapter.Protocol;
    pub const Mode = base_adapter.Mode;
    pub const Options = base_adapter.Options;
    pub const PENDING_DIAGNOSTIC = base_adapter.PENDING_DIAGNOSTIC;
    pub const verifyArtifact = base_adapter.verifyArtifact;

    pub fn run(
        comptime Engine: type,
        comptime backend: Backend,
        allocator: std.mem.Allocator,
        elf_path: []const u8,
        input_path: ?[]const u8,
        options: Options,
    ) ![]u8 {
        const before = Engine.runtimeLifecycleSnapshot();
        if (before.initialized) return error.RuntimeAlreadyInitialized;

        const bundle_path = try resolveBundlePath(allocator);
        defer allocator.free(bundle_path);
        try Engine.initializeRuntime(allocator, .{
            .authenticated_aot = .{
                .bundle_path = bundle_path,
                .manifest_sha256 = metal_aot_config.manifest_sha256,
            },
        });
        errdefer Engine.Backend.shutdown() catch {};

        const report = try base_adapter.run(
            Engine,
            backend,
            allocator,
            elf_path,
            input_path,
            options,
        );
        errdefer allocator.free(report);
        try Engine.Backend.shutdown();
        return report;
    }
};

const Deps = struct {
    pub const stwo = @import("stwo_riscv_metal");
    pub const adapter = AuthenticatedAdapter;
    pub const cli = @import("cli.zig");
    pub const registry = @import("registry.zig");
    pub const output_transaction = @import("output_transaction");
    pub const Engine = stwo.integrations.riscv_metal.MetalProverEngine;
    pub const backend: adapter.Backend = .metal;
};

const app = shared.App(Deps);

pub const main = app.main;

fn resolveBundlePath(allocator: std.mem.Allocator) ![]u8 {
    const configured = std.process.getEnvVarOwned(
        allocator,
        "STWO_RISCV_METAL_AOT_BUNDLE",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    if (configured) |path| {
        errdefer allocator.free(path);
        if (path.len == 0 or !std.fs.path.isAbsolute(path))
            return error.InvalidMetalAotBundlePath;
        return path;
    }

    const executable = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(executable);
    const bin_dir = std.fs.path.dirname(executable) orelse
        return error.InvalidExecutablePath;
    return std.fs.path.resolve(
        allocator,
        &.{ bin_dir, "..", metal_aot_config.install_subdir },
    );
}

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
    try std.testing.expect(!std.mem.eql(
        u8,
        &metal_aot_config.manifest_sha256,
        &([_]u8{0} ** 32),
    ));
}
