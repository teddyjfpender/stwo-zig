//! Metal instantiation of the backend-generic compact secp256k1 proof harness.

const std = @import("std");
const MetalBackend = @import("stwo_metal_backend");
const frontend = @import("stwo_riscv_frontend");
const proof_harness = @import("secp256k1_proof_harness");

// The commitment backend changes; the production RISC-V transcript and proof
// type do not. CPU and Metal therefore exercise the same protocol statement.
const Engine = frontend.prover_mod.ProverEngineForBackend(
    MetalBackend.MetalCommitBackend,
);

test "secp256k1 typed ECDSA bundle proves on Metal and independently verifies" {
    const allocator = std.testing.allocator;
    const bundle_path = try std.process.getEnvVarOwned(
        allocator,
        "STWO_RISCV_METAL_AOT_BUNDLE",
    );
    defer allocator.free(bundle_path);

    const lifecycle = Engine.runtimeLifecycleSnapshot();
    var owns_runtime = false;
    if (!lifecycle.initialized) {
        try Engine.initializeRuntime(allocator, .{
            .authenticated_aot = .{
                .bundle_path = bundle_path,
                .manifest_sha256 = try readManifestTrustAnchor(allocator, bundle_path),
            },
        });
        owns_runtime = true;
    }
    defer if (owns_runtime) Engine.Backend.shutdown() catch unreachable;

    const before = try Engine.telemetrySnapshot();
    const timings = try proof_harness.Harness(Engine).run(allocator);
    const delta = (try Engine.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();

    std.debug.print(
        "secp256k1 Metal total: prove={d:.3}ms fresh-verify={d:.3}ms total={d:.3}ms " ++
            "dispatches={d} fallbacks={d}\n",
        .{
            milliseconds(timings.proveProductionNs()),
            milliseconds(timings.verify_ns),
            milliseconds(timings.totalNs()),
            delta.counters.metalDispatchTotal(),
            delta.counters.cpuFallbackTotal(),
        },
    );
}

fn readManifestTrustAnchor(
    allocator: std.mem.Allocator,
    bundle_path: []const u8,
) ![32]u8 {
    var directory = try std.fs.cwd().openDir(bundle_path, .{});
    defer directory.close();
    const encoded = try directory.readFileAlloc(
        allocator,
        "stwo_zig_core.manifest.sha256",
        256,
    );
    defer allocator.free(encoded);
    if (encoded.len < 64) return error.InvalidManifestTrustAnchor;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded[0..64]) catch
        return error.InvalidManifestTrustAnchor;
    return digest;
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}
