const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const Engine = frontend.prover_mod.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);

pub fn main() !void {
    var allocator = std.heap.DebugAllocator(.{}){};
    defer std.debug.assert(allocator.deinit() == .ok);
    const args = try std.process.argsAlloc(allocator.allocator());
    defer std.process.argsFree(allocator.allocator(), args);
    if (args.len != 1) return frontend.testing.ethereum_node_proof_v1.artifactCommand(Engine, allocator.allocator(), args[1..]);
    const receipt = try frontend.testing.ethereum_node_proof_v1.exercise(Engine, allocator.allocator());
    std.debug.print("Ethereum path V1 CPU: 30 nodes, 120 permutations, {d} serialized bytes, sha256={s}, produce={d}ns, fresh-verify={d}ns, forgery rejection passed (diagnostic PCS)\n", .{
        receipt.proof_bytes, std.fmt.bytesToHex(receipt.proof_sha256, .lower), receipt.produce_ns, receipt.fresh_verify_ns,
    });
}
