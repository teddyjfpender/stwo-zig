const std = @import("std");
const Driver = @import("../block_v6_cpu_native_batch_driver_v1.zig");
const Receive = @import("../block_v6_cpu_native_batch_receive_v1.zig");
const Files = @import("../block_v5_artifact_files_v1.zig");

pub fn qualify(a: std.mem.Allocator, source: *@import("../block_v4_cpu_runner_source.zig").Source, policy: @import("../block_v5_cpu_driver_admission_v1.zig").InputPolicy, options: Driver.Options, baseline: @import("../block_v5_cpu_driver_v1.zig").Result, baseline_wall_ns: u64) !void {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var timer = try std.time.Timer.start();
    const actual = try Driver.run(a, dir.dir, source, policy, options);
    const wall_ns = timer.lap();
    var expected = baseline.verified;
    expected.exact_recursive_forest = .pending;
    try std.testing.expectEqualDeep(expected, actual.verified.globals);
    try std.testing.expectEqual(baseline.proof_files, actual.base_files);
    try std.testing.expectError(error.FileNotFound, dir.dir.access(@import("../block_v5_cpu_receiver_policy_file_v1.zig").FILE, .{}));
    const limits = Receive.Limits{ .metadata = options.metadata, .store = options.store, .max_proof_bytes = options.forest.max_proof_bytes };
    // Driver's assembly, captures, pool and budget are already destroyed.
    const detached = try Receive.verify(a, dir.dir, source.input, actual.pins, limits);
    const detached_ns = timer.lap();
    try std.testing.expectEqualDeep(actual.verified, detached);
    var wrong = actual.pins;
    wrong.identity.final_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5ReceiverPolicyIdentity, Receive.verify(a, dir.dir, source.input, wrong, limits));
    const raw = try Files.readPinned(a, dir.dir, Receive.PROOF_FILE, actual.pins.proof_bytes, actual.pins.proof_sha256, limits.max_proof_bytes);
    defer a.free(raw);
    const M = @import("stwo_core").fields.m31.M31;
    const first = std.mem.readInt(u32, raw[44..48], .little);
    const second = std.mem.readInt(u32, raw[60..64], .little);
    std.mem.writeInt(u32, raw[44..48], M.fromCanonical(first).add(M.one()).v, .little);
    std.mem.writeInt(u32, raw[60..64], M.fromCanonical(second).sub(M.one()).v, .little);
    var file = try dir.dir.openFile(Receive.PROOF_FILE, .{ .mode = .read_write });
    defer file.close();
    try file.pwriteAll(raw, 0);
    wrong = actual.pins;
    // Rehash transport deliberately: the verifier, not transport integrity,
    // must reject changed claims preserving the aggregate.
    wrong.proof_sha256 = Files.hash(raw);
    try std.testing.expectError(error.OodsNotMatching, Receive.verify(a, dir.dir, source.input, wrong, limits));
    std.debug.print("BLOCK_V6_DRIVER_NEGATIVE changed_identity=rejected cancelling_claims=OodsNotMatching cold_after_owner_destruction=true\n", .{});
    std.debug.print("BLOCK_V6_DRIVER verified=true profile={s} segments={d} baseline_wall_ns={d} wall_ns={d} collection_ns={d} base_ns={d} recursive_ns={d} verification_ns={d} prepare_ns={d} setup_ns={d} prove_ns={d} encode_ns={d} detached_ns={d} charged_peak_bytes={d} base_files={d} base_file_bytes={d} batch_bytes={d} memory_ns={d} caller_ns={d} lookup_ns={d} rom_ns={d} replacement_driver=true standalone_root=false\n", .{ @tagName(options.profile), actual.verified.globals.execution_count, baseline_wall_ns, wall_ns, actual.collection_ns, actual.base_ns, actual.recursive_ns, actual.verification_ns, actual.prepare_ns, actual.setup_ns, actual.prove_ns, actual.encode_ns, detached_ns, actual.peak_bytes, actual.base_files, actual.base_file_bytes, actual.pins.proof_bytes, actual.families.family_ns[1], actual.families.family_ns[0], actual.families.family_ns[3], actual.families.family_ns[2] });
}
