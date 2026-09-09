//! Lean process runner for the real 39-row SegmentV2 outer proof.
//!
//! The imported gate is also exercised by an exact-name guarded test target.
//! Running it as an executable omits transitive test declarations from code
//! generation, keeping relation-closure and proof debugging iterations short.

const std = @import("std");
const gate = @import("recursive_segment_v2_concrete_outer_proof_test.zig");

const NativeBackend = enum { cpu, metal };
const CpuOuterEngine = @import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_proof.CpuEngine;
const ProofProfile = @import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_proof.Profile;

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
    if (args.len == 2 and std.mem.eql(u8, args[1], "--check-two-segment-workload")) {
        try gate.checkTwoSegmentWorkload(allocator);
        std.debug.print("SEGMENT_V2_TWO_SEGMENT_EXECUTION status=passed\n", .{});
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--check-segment-ladder")) {
        try @import("recursive_segment_v2_two_segment_test_support.zig").checkSegmentLadder(allocator);
        return;
    }
    var native_ingress_profile: ?@import("recursive_segment_v2_leaf_outer_proof_test.zig").NativeProfile = null;
    var proof_profile: ?ProofProfile = null;
    var steps: ?usize = null;
    var memory_addresses: ?usize = null;
    var segment_count: ?usize = null;
    var two_segment_output: ?[]const u8 = null;
    var initial_register7: ?u32 = null;
    var initial_memory_word: ?u32 = null;
    var child_key_paths: [8]?[]const u8 = @splat(null);
    var child_key_pins: [8]?[]const u8 = @splat(null);
    var backend: NativeBackend = .cpu;
    var backend_seen = false;
    var recursive_backend: ?NativeBackend = null;
    var aot_bundle: ?[]const u8 = null;
    var aot_manifest: ?[32]u8 = null;
    var at: usize = 1;
    while (at < args.len) : (at += 2) {
        if (at + 1 == args.len) return error.InvalidArguments;
        const key = args[at];
        const value = args[at + 1];
        if (std.mem.eql(u8, key, "--native-ingress-profile")) {
            if (native_ingress_profile != null) return error.DuplicateArgument;
            native_ingress_profile = std.meta.stringToEnum(@import("recursive_segment_v2_leaf_outer_proof_test.zig").NativeProfile, value) orelse return error.InvalidNativeProfile;
        } else if (std.mem.eql(u8, key, "--proof-profile")) {
            if (proof_profile != null) return error.DuplicateArgument;
            proof_profile = std.meta.stringToEnum(ProofProfile, value) orelse return error.InvalidProofProfile;
        } else if (std.mem.eql(u8, key, "--native-steps")) {
            if (steps != null) return error.DuplicateArgument;
            steps = std.fmt.parseInt(usize, value, 10) catch return error.InvalidNativeStepCount;
        } else if (std.mem.eql(u8, key, "--memory-addresses")) {
            if (memory_addresses != null) return error.DuplicateArgument;
            memory_addresses = std.fmt.parseInt(usize, value, 10) catch return error.InvalidMemoryAddressCount;
        } else if (std.mem.eql(u8, key, "--initial-memory-word")) {
            if (initial_memory_word != null) return error.DuplicateArgument;
            initial_memory_word = std.fmt.parseInt(u32, value, 0) catch return error.InvalidInitialMemoryWord;
        } else if (std.mem.eql(u8, key, "--segment-count")) {
            if (segment_count != null) return error.DuplicateArgument;
            segment_count = std.fmt.parseInt(usize, value, 10) catch return error.InvalidSegmentCount;
            switch (segment_count.?) {
                2, 4, 8 => {},
                else => return error.InvalidSegmentCount,
            }
        } else if (std.mem.startsWith(u8, key, "--child-")) {
            if (key.len < 13 or key[8] < '0' or key[8] > '7') return error.InvalidArguments;
            const index: usize = key[8] - '0';
            if (std.mem.eql(u8, key[9..], "-key")) {
                if (child_key_paths[index] != null or value.len == 0) return error.InvalidArguments;
                child_key_paths[index] = value;
            } else if (std.mem.eql(u8, key[9..], "-key-sha256")) {
                if (child_key_pins[index] != null or value.len != 64) return error.InvalidArguments;
                child_key_pins[index] = value;
            } else return error.InvalidArguments;
        } else if (std.mem.eql(u8, key, "--initial-register7")) {
            if (initial_register7 != null) return error.DuplicateArgument;
            initial_register7 = std.fmt.parseInt(u32, value, 0) catch return error.InvalidInitialRegister7;
        } else if (std.mem.eql(u8, key, "--two-segment-output") or std.mem.eql(u8, key, "--segments-output")) {
            if (two_segment_output != null) return error.DuplicateArgument;
            if (value.len == 0) return error.InvalidArguments;
            two_segment_output = value;
        } else if (std.mem.eql(u8, key, "--native-backend")) {
            if (backend_seen) return error.DuplicateArgument;
            backend_seen = true;
            backend = std.meta.stringToEnum(NativeBackend, value) orelse return error.InvalidNativeBackend;
        } else if (std.mem.eql(u8, key, "--recursive-backend")) {
            if (recursive_backend != null) return error.DuplicateArgument;
            recursive_backend = std.meta.stringToEnum(NativeBackend, value) orelse return error.InvalidRecursiveBackend;
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
            std.debug.print("usage: {s} [--check-workload | --check-memory-workload | --check-two-segment-workload | --check-segment-ladder | (--native-steps 1|4|16|64 | --memory-addresses 1|4|16 [--segments-output NEW_DIRECTORY [--segment-count 2|4|8] [--initial-memory-word U32] [--child-0-key PATH --child-0-key-sha256 SHA256 --child-1-key PATH --child-1-key-sha256 SHA256]]) [--proof-profile development_q3_v1|recursive_q193_v1 (segment output only)] [--native-ingress-profile development_q1|protocol_v1 (memory workload only, no outer proof)] [--initial-register7 U32] [--native-backend cpu|metal] [--recursive-backend cpu|metal (segment output only)] [--aot-bundle PATH --aot-manifest-sha256 SHA256]]\n", .{args[0]});
            return error.InvalidArguments;
        }
    }
    if (native_ingress_profile != null and (memory_addresses == null or two_segment_output != null or initial_register7 != null or steps != null))
        return error.ConflictingNativeProfileArguments;
    if (proof_profile != null and (two_segment_output == null or native_ingress_profile != null)) return error.ProofProfileRequiresSegmentOutput;
    if (recursive_backend != null and two_segment_output == null) return error.RecursiveBackendRequiresSegmentOutput;
    if (recursive_backend == .metal and backend != .metal) return error.RecursiveMetalRequiresNativeMetal;
    const selected_segments = segment_count orelse 2;
    if (two_segment_output == null and (initial_memory_word != null or segment_count != null)) return error.TwoSegmentOutputRequired;
    for (child_key_paths, child_key_pins, 0..) |path, pin, index| {
        if ((path == null) != (pin == null)) return error.MissingDetachedKeyAdmission;
        if (path != null and (two_segment_output == null or index >= selected_segments)) return error.InvalidArguments;
    }
    if (two_segment_output != null and memory_addresses == null) return error.MissingMemoryAddressCount;
    if (memory_addresses) |count| {
        if (steps != null or initial_register7 != null) return error.ConflictingWorkloadArguments;
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
        "SEGMENT_V2_LADDER mode={s} requested_steps={d} native_backend={s} memory_addresses={d} initial_register7={x}\n",
        .{ if (native_ingress_profile != null) "native_ingress_only" else "narrow_complete_proof", selected_steps, @tagName(backend), memory_addresses orelse 0, initial_register7 orelse 0 },
    );
    switch (backend) {
        .cpu => {
            if (aot_bundle != null or aot_manifest != null) return error.UnexpectedAotArguments;
            if (native_ingress_profile) |profile|
                try @import("recursive_segment_v2_two_segment_proof_test_support.zig").checkNativeProfile(@import("stwo_riscv_cpu_integration").recursive_segment_v2_leaf_outer.Engine, allocator, memory_addresses.?, profile)
            else if (two_segment_output) |directory|
                try produceSelectedSegments(selected_segments, @import("stwo_riscv_cpu_integration").recursive_segment_v2_leaf_outer.Engine, CpuOuterEngine, allocator, memory_addresses.?, initial_memory_word orelse 0, directory, child_key_paths, child_key_pins, proof_profile orelse .development_q3_v1)
            else if (memory_addresses) |count|
                try gate.runMemoryProof(allocator, count)
            else
                try gate.runSizedProofWithRegister7(allocator, selected_steps, initial_register7 orelse 0);
        },
        .metal => {
            if (comptime Metal == void) {
                return error.MetalBackendUnavailable;
            } else {
                const Backend = Metal.MetalCommitBackend;
                try Backend.admitHostProving(.witness_generation);
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
                if (native_ingress_profile) |profile| {
                    const before = try Backend.telemetrySnapshot();
                    try @import("recursive_segment_v2_two_segment_proof_test_support.zig").checkNativeProfile(NativeEngine, allocator, memory_addresses.?, profile);
                    const delta = (try Backend.telemetrySnapshot()).delta(before);
                    try delta.requireMetalDispatch();
                    try Backend.shutdown();
                } else if (two_segment_output) |directory| {
                    if (recursive_backend == .metal)
                        try produceSelectedSegments(selected_segments, NativeEngine, NativeEngine, allocator, memory_addresses.?, initial_memory_word orelse 0, directory, child_key_paths, child_key_pins, proof_profile orelse .development_q3_v1)
                    else
                        try produceSelectedSegments(selected_segments, NativeEngine, CpuOuterEngine, allocator, memory_addresses.?, initial_memory_word orelse 0, directory, child_key_paths, child_key_pins, proof_profile orelse .development_q3_v1);
                    try Backend.shutdown();
                } else if (memory_addresses) |count|
                    try gate.runMemoryProofWithNativeEngine(NativeEngine, allocator, count)
                else
                    try gate.runSizedProofWithInitialRegister7(NativeEngine, allocator, selected_steps, initial_register7 orelse 0);
                if (Backend.runtimeLifecycleSnapshot().initialized) return error.NativeMetalRuntimeNotReleased;
            }
        },
    }
    if (native_ingress_profile) |profile| {
        std.debug.print("SEGMENT_V2_NATIVE_INGRESS status=verified profile={s} native_backend={s} owners_destroyed=true outer_proof_created=false\n", .{ @tagName(profile), @tagName(backend) });
        return;
    }
    if (two_segment_output != null) {
        std.debug.print("SEGMENT_V2_TWO_CHILD_PRODUCER status=unverified_candidates native_backend={s} recursive_backend={s} owners_destroyed=true parent_proof_created=false\n", .{ @tagName(backend), @tagName(recursive_backend orelse .cpu) });
        return;
    }
    // Native admission, producer/cohort and returned verifier capture owners
    // have all been destroyed before process-level completion.
    std.debug.print("SEGMENT_V2_LADDER status=verified requested_steps={d} native_backend={s} memory_addresses={d} initial_register7={x} owners_destroyed=true\n", .{ selected_steps, @tagName(backend), memory_addresses orelse 0, initial_register7 orelse 0 });
}

fn produceSegments(comptime count: usize, comptime NativeEngine: type, comptime OuterEngine: type, allocator: std.mem.Allocator, address_count: usize, initial_memory_word: u32, directory: []const u8, child_key_paths: [8]?[]const u8, child_key_pins: [8]?[]const u8, proof_profile: ProofProfile) !void {
    const pair = @import("recursive_segment_v2_two_segment_proof_test_support.zig");
    const ingress = @import("recursive_segment_v2_leaf_outer_proof_test.zig");
    const recursion = @import("stwo_riscv_frontend").recursion;
    const command = @import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_command;
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
    var keys: [count]?*const @import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_verifier.KeyV1 = @splat(null);
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
        inline 2, 4, 8 => |n| try produceSegments(n, NativeEngine, OuterEngine, allocator, address_count, seed, directory, paths, pins, profile),
        else => return error.InvalidSegmentCount,
    }
}
