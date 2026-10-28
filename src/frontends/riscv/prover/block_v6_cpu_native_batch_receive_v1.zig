//! Cold, bounded complete-bundle receiver for one V6 native batch.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Global = @import("block_v5_global_receiver_v1.zig");
const Store = @import("block_v5_cpu_bundle_store_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
pub const Metadata = @import("block_v5_cpu_receiver_policy_file_impl_v1.zig").NativeBatch;
pub const PROOF_FILE = "block-v6-native-batch.proof";
pub const Pins = struct {
    identity: Metadata.Identity,
    policy_sha256: [32]u8,
    bundle_sha256: [32]u8,
    proof_sha256: [32]u8,
    proof_bytes: u64,
};
pub const Limits = struct { metadata: Metadata.Limits, store: Store.Limits, max_proof_bytes: usize };
pub fn verify(a: std.mem.Allocator, dir: std.fs.Dir, input: []const u8, pins: Pins, limits: Limits) !Global.VerifiedNativeBatchBundle {
    const metadata = try Metadata.read(a, dir, pins.policy_sha256, pins.identity, limits.metadata);
    defer metadata.deinit();
    const globals = metadata.globals();
    const policies = try @import("block_v5_cpu_bundle_policy_v1.zig").build(a, globals, limits.store);
    defer a.free(policies);
    var files = try Store.readPins(a, dir, pins.bundle_sha256, limits.store);
    defer files.deinit();
    var store = try Store.Store.initReader(a, dir, policies, files.files, pins.identity.config, limits.store);
    defer store.deinit();
    const proof = try Files.readPinned(a, dir, PROOF_FILE, pins.proof_bytes, pins.proof_sha256, limits.max_proof_bytes);
    defer a.free(proof);
    var sources: [4]std.fs.File = undefined;
    var initialized: usize = 0;
    defer for (sources[0..initialized]) |file| file.close();
    for (@import("block_v5_memory_source_writer_v1.zig").filenames, &sources) |name, *file| {
        file.* = try dir.openFile(name, .{});
        initialized += 1;
    }
    const result = try Global.ForBackend(Cpu).verifyCompleteNativeBatch(a, globals, .{ .public_input = input, .endpoint_sources = .{ .initial = .{ .input_words = sources[0], .rw_words = sources[1], .first_touches = sources[2] }, .endpoints = sources[3] }, .memory = store.packedMemoryLoader(), .execution_memory = store.executionMemoryLoader(), .tables = store.tableLoader(), .programs = store.programLoader() }, metadata.recursion(), proof);
    try store.requireConsumed();
    return result;
}
