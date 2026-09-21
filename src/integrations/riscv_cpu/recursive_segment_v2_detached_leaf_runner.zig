//! Canonical detached leaf command: admitted segment inputs produce serialized candidates.
//! Acceptance belongs exclusively to the standalone verifier after this process exits.
const std = @import("std");
const options_mod = @import("recursive_segment_v2_detached_leaf_options.zig");
const CpuOuterEngine = @import("recursive_segment_v2_detached_proof.zig").CpuEngine;
const NativeCpuEngine = @import("recursive_segment_v2_leaf_outer.zig").Engine;
const ProofProfile = options_mod.Profile;

pub fn main() !void {
    try run(void);
}
pub fn runWithMetal(comptime Metal: type) !void {
    try run(Metal);
}

fn run(comptime Metal: type) !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = options_mod.parse(args[1..]) catch |err| {
        std.debug.print("usage: {s} --memory-addresses 1|4|16 --segments-output NEW_DIRECTORY --segment-count 1|2|4|8 --child-N-key PATH --child-N-key-sha256 SHA256 [--proof-profile recursive_q193_v1|development_q3_v1] [--initial-memory-word U32] [--native-backend cpu|metal] [--recursive-backend cpu|metal] [--aot-bundle PATH --aot-manifest-sha256 SHA256 --aot-profile recursive-framework-v1]\n", .{args[0]});
        return err;
    };
    switch (options.native_backend) {
        .cpu => try produceSelectedSegments(options.segment_count, NativeCpuEngine, CpuOuterEngine, allocator, options.address_count, options.initial_memory_word, options.directory, options.child_key_paths, options.child_key_pins, options.proof_profile),
        .metal => {
            if (comptime Metal == void) return error.MetalBackendUnavailable else {
                const Backend = Metal.MetalCommitBackend;
                try Backend.admitHostProving(.witness_generation);
                const bundle = options.aot_bundle.?;
                const manifest = options.aot_manifest.?;
                const selected_aot: Metal.shaders.aot_profile.Profile = if (std.mem.eql(u8, options.aot_profile orelse "recursive-framework-v1", "recursive-framework-v1")) .recursive_framework_v1 else .core_v2;
                if (Backend.runtimeLifecycleSnapshot().initialized) return error.MetalRuntimeAlreadyInitialized;
                var timer = try std.time.Timer.start();
                try Backend.initializeRuntime(allocator, .{ .authenticated_aot = .{
                    .bundle_path = bundle,
                    .manifest_sha256 = manifest,
                    .profile = selected_aot,
                } });
                // The shared native boundary normally shuts down first; this
                // also cleans initialization/proving failure paths.
                defer if (Backend.runtimeLifecycleSnapshot().initialized) {
                    Backend.shutdown() catch unreachable;
                };
                const lifecycle = Backend.runtimeLifecycleSnapshot();
                const identity = lifecycle.identity orelse return error.AuthenticatedMetalRuntimeMissing;
                if (!lifecycle.initialized or identity.origin != .authenticated_core_aot or
                    identity.manifest_sha256 == null or !std.meta.eql(identity.manifest_sha256.?, manifest) or
                    identity.metallib_sha256 == null or identity.metallib_bytes == null or identity.metallib_bytes.? == 0 or
                    !std.meta.eql(identity.source_sha256, selected_aot.sourceDigest()))
                    return error.AuthenticatedMetalRuntimeMismatch;
                std.debug.print(
                    "SEGMENT_V2_NATIVE_METAL_AOT profile={s} manifest_sha256={s} source_sha256={s} metallib_sha256={s} initialization_ns={d}\n",
                    .{ @tagName(selected_aot), std.fmt.bytesToHex(manifest, .lower), std.fmt.bytesToHex(identity.source_sha256, .lower), std.fmt.bytesToHex(identity.metallib_sha256.?, .lower), timer.read() },
                );
                const NativeEngine = @import("stwo_riscv_frontend").recursion.engine.ProverEngineForBackend(Backend);
                if (options.recursive_backend == .metal)
                    try produceSelectedSegments(options.segment_count, NativeEngine, NativeEngine, allocator, options.address_count, options.initial_memory_word, options.directory, options.child_key_paths, options.child_key_pins, options.proof_profile)
                else
                    try produceSelectedSegments(options.segment_count, NativeEngine, CpuOuterEngine, allocator, options.address_count, options.initial_memory_word, options.directory, options.child_key_paths, options.child_key_pins, options.proof_profile);
                try Backend.shutdown();
                if (Backend.runtimeLifecycleSnapshot().initialized) return error.NativeMetalRuntimeNotReleased;
            }
        },
    }
    std.debug.print("SEGMENT_V2_TWO_CHILD_PRODUCER status=unverified_candidates native_backend={s} recursive_backend={s} owners_destroyed=true parent_proof_created=false\n", .{ @tagName(options.native_backend), @tagName(options.recursive_backend) });
}

fn produceSegments(comptime count: usize, comptime NativeEngine: type, comptime OuterEngine: type, allocator: std.mem.Allocator, address_count: usize, initial_memory_word: u32, directory: []const u8, child_key_paths: [8]?[]const u8, child_key_pins: [8]?[]const u8, proof_profile: ProofProfile) !void {
    const pair = @import("recursive_segment_v2_detached_leaf_producer.zig");
    const ingress = @import("recursive_segment_v2_native_ingress.zig");
    const recursion = @import("stwo_riscv_frontend").recursion;
    const command = @import("recursive_segment_v2_detached_command.zig");
    var admitted: [count]?*command.OwnedKeyV1 = @splat(null);
    defer for (admitted) |key| if (key) |owner| owner.deinit();
    for (child_key_paths[0..count], child_key_pins[0..count], 0..) |path, pin_text, index| {
        if (path) |key_path| {
            var pin: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&pin, pin_text.?);
            const bytes = try std.fs.cwd().readFileAlloc(allocator, key_path, command.MAX_KEY_BYTES);
            defer allocator.free(bytes);
            admitted[index] = try command.OwnedKeyV1.admit(allocator, bytes, pin);
        }
    }
    try std.fs.cwd().makeDir(directory);
    var directories: [count][]const u8 = undefined;
    var initialized: usize = 0;
    defer for (directories[0..initialized]) |path| allocator.free(path);
    var keys: [count]?*const @import("recursive_segment_v2_detached_verifier.zig").KeyV1 = @splat(null);
    for (&directories, 0..) |*path, index| {
        path.* = try std.fmt.allocPrint(allocator, "{s}/child-{d}", .{ directory, index });
        initialized += 1;
        keys[index] = if (admitted[index]) |owner| owner.key() else null;
    }
    const receipt = try pair.produceSegmentsWithEngines(count, NativeEngine, OuterEngine, allocator, address_count, .{
        .native_keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
            ingress.digest("recursive-v2-segment-vk"),
            ingress.digest("recursive-v2-parent-vk"),
        ),
        .child_directories = directories,
        .initial_memory_word = initial_memory_word,
        .admitted_outer_keys = keys,
        .proof_profile = proof_profile,
    });
    const bytes = try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    defer allocator.free(bytes);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    var file = try dir.createFile("candidate-receipt.json", .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
}

fn produceSelectedSegments(count: usize, comptime NativeEngine: type, comptime OuterEngine: type, allocator: std.mem.Allocator, address_count: usize, seed: u32, directory: []const u8, paths: [8]?[]const u8, pins: [8]?[]const u8, profile: ProofProfile) !void {
    switch (count) {
        inline 1, 2, 4, 8 => |n| try produceSegments(n, NativeEngine, OuterEngine, allocator, address_count, seed, directory, paths, pins, profile),
        else => return error.InvalidSegmentCount,
    }
}
