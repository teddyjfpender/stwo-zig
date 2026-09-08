//! Lean process runner for the real 39-row SegmentV2 outer proof.
//!
//! The imported gate is also exercised by an exact-name guarded test target.
//! Running it as an executable omits transitive test declarations from code
//! generation, keeping relation-closure and proof debugging iterations short.

const std = @import("std");
const gate = @import("recursive_segment_v2_concrete_outer_proof_test.zig");

const NativeBackend = enum { cpu, metal };

pub fn main() !void {
    try run(void);
}

/// Metal supplies only its backend module; fixture, options, native ingress,
/// fresh CPU verification and complete outer proof remain shared with CPU.
pub fn runWithMetal(comptime Metal: type) !void {
    try run(Metal);
}

fn run(comptime Metal: type) !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 1) {
        try gate.runGate(allocator);
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--check-workload")) {
        try gate.checkSizedWorkload(allocator);
        std.debug.print("SEGMENT_V2_LADDER_EXECUTION status=passed sizes=1,4,16,64 continuation_steps=16\n", .{});
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--check-memory-workload")) {
        try gate.checkMemoryWorkload(allocator);
        std.debug.print("SEGMENT_V2_MEMORY_EXECUTION status=passed\n", .{});
        return;
    }
    var steps: ?usize = null;
    var memory_addresses: ?usize = null;
    var backend: NativeBackend = .cpu;
    var backend_seen = false;
    var aot_bundle: ?[]const u8 = null;
    var aot_manifest: ?[32]u8 = null;
    var at: usize = 1;
    while (at < args.len) : (at += 2) {
        if (at + 1 == args.len) return error.InvalidArguments;
        const key = args[at];
        const value = args[at + 1];
        if (std.mem.eql(u8, key, "--native-steps")) {
            if (steps != null) return error.DuplicateArgument;
            steps = std.fmt.parseInt(usize, value, 10) catch return error.InvalidNativeStepCount;
        } else if (std.mem.eql(u8, key, "--memory-addresses")) {
            if (memory_addresses != null) return error.DuplicateArgument;
            memory_addresses = std.fmt.parseInt(usize, value, 10) catch return error.InvalidMemoryAddressCount;
        } else if (std.mem.eql(u8, key, "--native-backend")) {
            if (backend_seen) return error.DuplicateArgument;
            backend_seen = true;
            backend = std.meta.stringToEnum(NativeBackend, value) orelse return error.InvalidNativeBackend;
        } else if (std.mem.eql(u8, key, "--aot-bundle")) {
            if (aot_bundle != null) return error.DuplicateArgument;
            if (value.len == 0) return error.InvalidArguments;
            aot_bundle = value;
        } else if (std.mem.eql(u8, key, "--aot-manifest-sha256")) {
            if (aot_manifest != null) return error.DuplicateArgument;
            if (value.len != 64) return error.InvalidAotManifestSha256;
            var digest: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&digest, value) catch return error.InvalidAotManifestSha256;
            aot_manifest = digest;
        } else {
            std.debug.print("usage: {s} [--check-workload | --check-memory-workload | (--native-steps 1|4|16|64 | --memory-addresses 1|4|16) [--native-backend cpu|metal] [--aot-bundle PATH --aot-manifest-sha256 SHA256]]\n", .{args[0]});
            return error.InvalidArguments;
        }
    }
    if (memory_addresses) |count| {
        if (steps != null) return error.ConflictingWorkloadArguments;
        switch (count) {
            1, 4, 16 => {},
            else => return error.InvalidMemoryAddressCount,
        }
    }
    const selected_steps = if (memory_addresses != null) gate.memory_native_steps else steps orelse return error.MissingNativeStepCount;
    switch (selected_steps) {
        1, 4, 16, 64 => {},
        else => return error.InvalidNativeStepCount,
    }
    std.debug.print(
        "SEGMENT_V2_LADDER mode=narrow_complete_proof requested_steps={d} native_backend={s} memory_addresses={d}\n",
        .{ selected_steps, @tagName(backend), memory_addresses orelse 0 },
    );
    switch (backend) {
        .cpu => {
            if (aot_bundle != null or aot_manifest != null) return error.UnexpectedAotArguments;
            if (memory_addresses) |count|
                try gate.runMemoryProof(allocator, count)
            else
                try gate.runSizedProof(allocator, selected_steps);
        },
        .metal => {
            if (comptime Metal == void) {
                return error.MetalBackendUnavailable;
            } else {
                const Backend = Metal.MetalCommitBackend;
                const bundle = aot_bundle orelse return error.MissingAotBundle;
                const manifest = aot_manifest orelse return error.MissingAotManifestSha256;
                if (Backend.runtimeLifecycleSnapshot().initialized) return error.MetalRuntimeAlreadyInitialized;
                var timer = try std.time.Timer.start();
                try Backend.initializeRuntime(allocator, .{ .authenticated_aot = .{
                    .bundle_path = bundle,
                    .manifest_sha256 = manifest,
                    .profile = .core_v2,
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
                    !std.meta.eql(identity.source_sha256, Metal.shaders.aot_profile.Profile.core_v2.sourceDigest()))
                    return error.AuthenticatedMetalRuntimeMismatch;
                std.debug.print(
                    "SEGMENT_V2_NATIVE_METAL_AOT profile=core_v2 manifest_sha256={s} source_sha256={s} metallib_sha256={s} initialization_ns={d}\n",
                    .{ std.fmt.bytesToHex(manifest, .lower), std.fmt.bytesToHex(identity.source_sha256, .lower), std.fmt.bytesToHex(identity.metallib_sha256.?, .lower), timer.read() },
                );
                const NativeEngine = @import("stwo_riscv_frontend").recursion.engine.ProverEngineForBackend(Backend);
                if (memory_addresses) |count|
                    try gate.runMemoryProofWithNativeEngine(NativeEngine, allocator, count)
                else
                    try gate.runSizedProofWithNativeEngine(NativeEngine, allocator, selected_steps);
                if (Backend.runtimeLifecycleSnapshot().initialized) return error.NativeMetalRuntimeNotReleased;
            }
        },
    }
    // Native admission, producer/cohort and returned verifier capture owners
    // have all been destroyed before process-level completion.
    std.debug.print("SEGMENT_V2_LADDER status=verified requested_steps={d} native_backend={s} memory_addresses={d} owners_destroyed=true\n", .{ selected_steps, @tagName(backend), memory_addresses orelse 0 });
}
