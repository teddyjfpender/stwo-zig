//! Explicit real-source physical gate; artifacts persist before fresh reception.
const std = @import("std");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Engine = @import("stwo_prover_engine");
const Topology = @import("topology.zig");
const Proof = @import("proof.zig");
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
const Catalog = @import("../pure_p2_truth_leaf_test.zig");
const LocalCatalog = @import("../truth_local_gkr/leaf_test.zig");
fn key(a: std.mem.Allocator, source: anytype) !Topology.SourceLeaf {
    const V = @TypeOf(source);
    return if (V == CPU.ShapeView) Topology.SourceLeaf.initCpu(a, source) else if (V == Catalog.View) Topology.SourceLeaf.initCatalog(a, source) else if (V == LocalCatalog.View) Topology.SourceLeaf.initLocalCatalog(a, source) else Topology.SourceLeaf.initMiller(a, source);
}
pub fn maybe(a: std.mem.Allocator, kind: []const u8, source: anytype, owner: *const C.PoseidonContext) !void {
    const selected = std.posix.getenv("STWO_OP_R6_PHYSICAL_KIND") orelse return;
    if (!std.mem.eql(u8, selected, kind)) return;
    const out = std.posix.getenv("STWO_OP_R6_OUT") orelse return error.MissingR6ArtifactDirectory;
    try std.fs.cwd().makeDir(out);
    var dir = try std.fs.cwd().openDir(out, .{});
    defer dir.close();
    const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
    var timer = try std.time.Timer.start();
    var producer = try key(a, source);
    defer producer.deinit();
    const key_ns = timer.lap();
    const outputs = try source.expectedOutput(a);
    var recorder = Engine.stage_profile.Recorder.initWithOptions(a, "cpu", "op_r6_actual_source_leaf", .{ .capture_tasks = false, .capture_process_usage = true });
    defer recorder.deinit();
    const proof = try Proof.proveProfiled(a, owner, &producer.authority, &outputs, &recorder);
    defer a.free(proof);
    const prove_ns = timer.lap();
    try write(dir, "leaf.bin", proof);
    var stages = try recorder.snapshot(a);
    defer stages.deinit(a);
    const stages_json = try std.json.Stringify.valueAlloc(a, stages, .{});
    defer a.free(stages_json);
    try write(dir, "stages.json", stages_json);
    var receiver = try key(a, source);
    defer receiver.deinit();
    const receiver_setup_ns = timer.lap();
    try std.testing.expectEqualSlices(u8, &producer.authority.base.identity, &receiver.authority.base.identity);
    try Proof.verify(a, &receiver.authority, &outputs, proof);
    const verify_ns = timer.lap();
    var wrong = outputs;
    wrong[8] = wrong[8].add(C.Q.one());
    try std.testing.expect(std.meta.isError(Proof.verify(a, &receiver.authority, &wrong, proof)));
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(proof, &sha, .{});
    const receipt = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-r6-actual-source-physical-v1", .kind = kind, .bytes = proof.len, .key_ns = key_ns, .prove_ns = prove_ns, .fresh_setup_ns = receiver_setup_ns, .fresh_verify_ns = verify_ns, .sha256 = std.fmt.bytesToHex(sha, .lower), .source_identity = std.fmt.bytesToHex(receiver.authority.base.identity, .lower), .raw = try owner.rawCounts(), .logs = receiver.authority.base.logs, .mul_log = receiver.authority.mul_log, .native_mul_calls = owner.native_mul_calls.items.len, .fresh_source = true, .wrong_output_rejected = true, .complete_execution = false, .production_admission = false }, .{});
    defer a.free(receipt);
    try write(dir, "leaf.json", receipt);
    try std.posix.fsync(dir.fd);
    std.debug.print("OP_R6_ACTUAL_PHYSICAL {s}\n", .{receipt});
}
