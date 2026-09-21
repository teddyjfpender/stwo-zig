const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const Engine = frontend.prover_mod.ProverEngineForBackend(@import("stwo_metal_backend").MetalCommitBackend);

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3 and args.len != 5 and args.len != 7) return error.ExpectedAotBundleAndManifestSha256;
    if (args[2].len != 64) return error.InvalidManifestSha256;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, args[2]);
    try Engine.initializeRuntime(allocator, .{ .authenticated_aot = .{
        .bundle_path = args[1],
        .manifest_sha256 = digest,
    } });
    defer Engine.Backend.shutdown() catch unreachable;
    if (args.len != 3) {
        const before = try Engine.telemetrySnapshot();
        try frontend.testing.ethereum_node_proof_v1.artifactCommand(Engine, allocator, args[3..]);
        if (std.mem.eql(u8, args[3], "produce") or std.mem.eql(u8, args[3], "produce-program")) {
            const delta = (try Engine.telemetrySnapshot()).delta(before);
            try delta.requireMetalDispatch();
            std.debug.print("Metal artifact dispatches={d}, fallbacks={d}\n", .{ delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal() });
        }
        return;
    }
    const before = try Engine.telemetrySnapshot();
    const receipt = try frontend.testing.ethereum_node_proof_v1.exercise(Engine, allocator);
    const delta = (try Engine.telemetrySnapshot()).delta(before);
    try delta.requireMetalDispatch();
    std.debug.print("Ethereum path V1 Metal: 30 nodes, 120 permutations, {d} serialized bytes, sha256={s}, produce={d}ns, fresh-verify={d}ns, forgery rejection passed, dispatches={d}, fallbacks={d} (diagnostic PCS)\n", .{
        receipt.proof_bytes,                 std.fmt.bytesToHex(receipt.proof_sha256, .lower), receipt.produce_ns, receipt.fresh_verify_ns,
        delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal(),
    });
}
