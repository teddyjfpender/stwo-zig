//! Explicit bounded physical gate, using receiver-owned source graphs/keys.
//! This fixture proves a group, not a complete OP execution source suite.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Key = @import("../native_omul/authority.zig").Key;
const Proof = @import("../native_omul/proof.zig");
const Topology = @import("../native_omul/topology.zig");
const Cost = @import("cost.zig").Model;
const Profile = @import("../op_profile.zig").Profile;
const Write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
pub fn run(a: std.mem.Allocator, owner: *const C.PoseidonContext, source: *const C.PoseidonContext, profile: Profile, outputs: [9]C.Q, baseline_sources: []const Topology.SourceLeaf, execution: [32]u8, path: []const u8, baseline_root: []const u8) !void {
    try std.fs.cwd().makeDir(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    var timer = try std.time.Timer.start();
    var producer = try Key.init(a, source, profile);
    defer producer.deinit();
    const key_ns = timer.lap();
    try std.testing.expectEqualDeep(try Cost.derive(source), try Cost.fromKey(&producer));
    try std.testing.expectEqualDeep(try Cost.derive(owner), try Cost.fromKey(&producer));
    const identity = producer.base.identity;
    var recorder = engine.stage_profile.Recorder.initWithOptions(a, "cpu", "op_direct_native_group4", .{ .capture_tasks = false, .capture_process_usage = true });
    defer recorder.deinit();
    const bytes = try Proof.proveProfiled(a, owner, &producer, &outputs, &recorder);
    defer a.free(bytes);
    const prove_ns = timer.lap();
    // Persist the expensive result BEFORE independent receiver construction.
    try Write(dir, "group.bin", bytes);
    var stages = try recorder.snapshot(a);
    defer stages.deinit(a);
    const stages_json = try std.json.Stringify.valueAlloc(a, stages, .{});
    defer a.free(stages_json);
    try Write(dir, "stages.json", stages_json);
    @import("../native_omul/verifier_key.zig").retireProverData(&producer);
    var receiver = try Key.init(a, source, profile);
    defer receiver.deinit();
    const fresh_key_ns = timer.lap();
    try std.testing.expectEqualSlices(u8, &identity, &receiver.base.identity);
    try Proof.verify(a, &receiver, &outputs, bytes);
    var wrong = outputs;
    wrong[8] = wrong[8].add(C.Q.one());
    if (Proof.verify(a, &receiver, &wrong, bytes)) |_| return error.NativeGroupAcceptedWrongOutput else |_| {}
    const corrupt = try a.dupe(u8, bytes);
    defer a.free(corrupt);
    corrupt[corrupt.len / 2] ^= 1;
    if (Proof.verify(a, &receiver, &outputs, corrupt)) |_| return error.NativeGroupAcceptedCorruptProof else |_| {}
    const verify_ns = timer.lap();
    @import("../native_omul/verifier_key.zig").retireProverData(&receiver);
    // Independently reconstruct the old seven-node source topology. Its
    // retained physical root must validate under THAT authority and then fail
    // under the direct group's same-profile, same-public-root authority.
    var baseline = try Topology.Topology.initForVerification(a, profile, execution, baseline_sources);
    defer baseline.deinit();
    const baseline_key_ns = timer.lap();
    const control = try std.fs.cwd().readFileAlloc(a, baseline_root, 2 << 20);
    defer a.free(control);
    try Proof.verify(a, baseline.key(), &outputs, control);
    if (Proof.verify(a, &receiver, &outputs, control)) |_| return error.NativeGroupAcceptedWrongSourceProof else |_| {}
    var baseline_models: [7]Cost = undefined;
    if (baseline_sources.len != 4 or baseline.owned.items.len != 3) return error.NativeGroupBaselineTopology;
    for (baseline_sources, baseline_models[0..4]) |*leaf, *model| model.* = try Cost.fromKey(try leaf.key());
    for (baseline.owned.items, baseline_models[4..]) |key, *model| model.* = try Cost.fromKey(key);
    var total: u64 = 0;
    for (baseline_models) |model| total = try std.math.add(u64, total, model.total_cells);
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sha, .{});
    const report = .{
        .schema = "op-direct-native-group4-physical-v1",
        .scope = "four_native_verifiers_directly_proved_pending_fixture_not_OP_block_admission",
        .security_label = "128-bit security target under documented assumptions",
        .security_qualified = false,
        .production_admission = false,
        .members = 4,
        .recursive_child_proofs_verified = 0,
        .intermediate_fold_proofs = 0,
        .bytes = bytes.len,
        .sha256 = std.fmt.bytesToHex(sha, .lower),
        .source_identity = std.fmt.bytesToHex(identity, .lower),
        .source_key_ns = key_ns,
        .prove_ns = prove_ns,
        .fresh_key_ns = fresh_key_ns,
        .verify_and_negative_ns = verify_ns,
        .baseline_source_key_ns = baseline_key_ns,
        .model = try Cost.fromKey(&receiver),
        .baseline_seven_models = baseline_models,
        .baseline_total_cells = total,
        .same_canonical_root_as_retained_seven_node_proof = true,
        .fresh_source_receiver = true,
        .wrong_output_corruption_and_valid_wrong_source_proof_rejected = true,
        .timings_are_qualification_not_quiet_block_benchmark = true,
    };
    const json = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try Write(dir, "receipt.json", json);
    try std.posix.fsync(dir.fd);
    std.debug.print("OP_DIRECT_NATIVE_GROUP_PHYSICAL {s}\n", .{json});
}
