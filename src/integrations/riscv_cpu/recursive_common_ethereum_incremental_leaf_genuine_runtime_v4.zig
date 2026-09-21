//! Non-semantic runtime policy for the isolated genuine role-0 gate.
//! Worker count and allocator telemetry never enter proof or artifact bytes.

const std = @import("std");

/// The saved-proof development gates admit bytes at one SHA-pinned boundary.
pub fn readPinnedStage101(allocator: std.mem.Allocator, path: []const u8, expected_hex: []const u8) ![]u8 {
    var expected: [32]u8 = undefined;
    if (expected_hex.len != 64) return error.InvalidStage101ReplayDigest;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 512 * 1024 * 1024);
    errdefer allocator.free(bytes);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    if (!std.mem.eql(u8, &expected, &actual)) return error.InvalidStage101ReplayDigest;
    return bytes;
}
const prover_api = @import("stwo_prover_api");
const work_pool = @import("stwo_prover_engine").work_pool;
const runtime_usage =
    @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_usage_v4.zig");

pub const WORKER_COUNT_ENV = "STWO_ROLE0_GENUINE_WORKER_COUNT";
pub const HOST_BYTE_BUDGET_ENV =
    "STWO_ROLE0_GENUINE_HOST_BYTE_BUDGET";
pub const STOP_AFTER_MATERIALIZE_ENV =
    "STWO_ROLE0_GENUINE_STOP_AFTER_MATERIALIZE";
pub const MAXIMUM_WORKER_COUNT: usize = work_pool.MAX_WORKERS;
const EXECUTION_RECEIPT_DOMAIN =
    "stwo-zig/role0-genuine-stage101-execution-receipt/v4\x00";
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const RuntimePhaseV4 = runtime_usage.RuntimePhaseV4;
pub const PhaseUsageReceiptV4 = runtime_usage.PhaseUsageReceiptV4;
pub const PhaseUsageMeasurementV4 = runtime_usage.PhaseUsageMeasurementV4;

/// Custody format shared by native fixture export and cold wrapper replay.
/// Consumers still admit the ELF independently and verify both native proofs.
pub const NativeReplayManifestV1 = struct {
    version: u16 = 1,
    claim_admission: @import("ethereum_incremental_full_leaf_profile_v4.zig").ClaimAdmissionV4,
    native_sha256: [2][32]u8,
    program_sha256: [32]u8,
    global_metadata_sha256: [32]u8,
};

pub const GlobalReplayMetadataV1 = struct {
    version: u16 = 1,
    leaves: [2]@import("stwo_riscv_frontend").recursion.segment_leaf_local_authority_v3.MetadataV3,
};

/// Optional durable fixture export is runtime I/O, not proof admission.
pub fn exportStage101(allocator: std.mem.Allocator, artifacts: []const []const u8) !void {
    const path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ROLE0_GENUINE_STAGE101_EXPORT_DIR",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(path);
    try exportStage101ToDirectory(allocator, path, artifacts);
}

/// Explicit corpus destination used by versioned producer-only development
/// gates. Content-addressed files are never replaced with different bytes.
pub fn exportStage101ToDirectory(allocator: std.mem.Allocator, path: []const u8, artifacts: []const []const u8) !void {
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    for (artifacts, 0..) |bytes, index| {
        var digest: [32]u8 = undefined;
        Sha256.hash(bytes, &digest, .{});
        const name = try std.fmt.allocPrint(allocator, "{x}.bin", .{digest});
        defer allocator.free(name);
        try writeReplayFile(dir, name, bytes);
        std.debug.print(
            "ETHEREUM_INCREMENTAL_ROLE0_STAGE101_EXPORT leaf={d} bytes={d} path={s}/{s}\n",
            .{ index, bytes.len, path, name },
        );
    }
}

/// The whole ELF is independent circuit admission material, retained beside
/// the native pair rather than reconstructed from observed completion words.
pub fn exportProgramElf(path: []const u8, elf_bytes: []const u8) !void {
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try writeReplayFile(dir, "program.elf", elf_bytes);
    var digest: [32]u8 = undefined;
    Sha256.hash(elf_bytes, &digest, .{});
    std.debug.print("ETHEREUM_BASE_BOUND_PROGRAM sha256={x} bytes={d} path={s}/program.elf\n", .{ digest, elf_bytes.len, path });
}

/// Retain the complete replay inputs before destroying the producer. Saving
/// bytes grants no proof authority: these may be the next failing regression.
pub fn exportWrapperReplay(allocator: std.mem.Allocator, native_inputs: []const []const u8, program_elf: []const u8, wrapper: []const u8, global_metadata_json: ?[]const u8) !void {
    const corpus = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_CORPUS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(corpus);
    const digest = try wrapperReplayIdentity(native_inputs, program_elf, wrapper, global_metadata_json);
    const path = try std.fmt.allocPrint(allocator, "{s}/wrapper-replays/{x}", .{ corpus, digest });
    defer allocator.free(path);
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    try writeWrapperReplay(dir, native_inputs, program_elf, wrapper, global_metadata_json);
    std.debug.print("ETHEREUM_ROLE0_WRAPPER_REPLAY path={s} bytes={d} independently_verified=false\n", .{ path, wrapper.len });
}

fn wrapperReplayIdentity(native_inputs: []const []const u8, program_elf: []const u8, wrapper: []const u8, global_metadata_json: ?[]const u8) ![32]u8 {
    if (native_inputs.len != 2) return error.InvalidWrapperReplayLeafCount;
    var hasher = Sha256.init(.{});
    hasher.update(if (global_metadata_json != null) "stwo-zig/ethereum-wrapper-replay/v3\x00" else "stwo-zig/ethereum-wrapper-replay/v2\x00");
    for ([_][]const u8{ native_inputs[0], native_inputs[1], program_elf, wrapper }) |bytes| {
        var digest: [32]u8 = undefined;
        Sha256.hash(bytes, &digest, .{});
        hasher.update(&digest);
    }
    if (global_metadata_json) |bytes| {
        var digest: [32]u8 = undefined;
        Sha256.hash(bytes, &digest, .{});
        hasher.update(&digest);
    }
    return hasher.finalResult();
}

fn writeWrapperReplay(dir: std.fs.Dir, native_inputs: []const []const u8, program_elf: []const u8, wrapper: []const u8, global_metadata_json: ?[]const u8) !void {
    if (native_inputs.len != 2) return error.InvalidWrapperReplayLeafCount;
    // This is custody only. The fresh input boundary authenticates these
    // dynamic values against the native proofs and the selected AIR profile.
    if (global_metadata_json) |bytes| try writeReplayFile(dir, "global-metadata-v1.json", bytes);
    // Publish the wrapper last: its presence means all replay inputs exist.
    const names = [_][]const u8{ "leaf-0.bin", "leaf-1.bin", "program.elf", "wrapper.bin" };
    const artifacts = [_][]const u8{ native_inputs[0], native_inputs[1], program_elf, wrapper };
    for (names, artifacts) |name, bytes| {
        try writeReplayFile(dir, name, bytes);
    }
}

/// Retain the serialized native case and publish its manifest last. This
/// records custody; the proof-development consumer freshly verifies each leaf.
pub fn exportNativeReplayManifest(directory: []const u8, manifest_json: []const u8, global_metadata_json: []const u8) !void {
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    try writeReplayFile(dir, "global-metadata-v1.json", global_metadata_json);
    try writeReplayFile(dir, "native-inputs-v1.json", manifest_json);
}

pub fn writeReplayFile(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    // Repeated exports must preserve an existing regression. Compare in
    // bounded memory; only absent files may be published below.
    if (try replayFileMatches(dir, name, bytes)) return;
    var buffer: [64 * 1024]u8 = undefined;
    var file = try dir.atomicFile(name, .{ .write_buffer = &buffer });
    defer file.deinit();
    try file.file_writer.interface.writeAll(bytes);
    try file.finish();
}

fn replayFileMatches(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !bool {
    const file = dir.openFile(name, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close();
    var buffer: [64 * 1024]u8 = undefined;
    var offset: usize = 0;
    while (true) {
        const count = try file.readAll(&buffer);
        if (count == 0) break;
        if (count > bytes.len - offset or !std.mem.eql(u8, buffer[0..count], bytes[offset..][0..count]))
            return error.WrapperReplayContentMismatch;
        offset += count;
    }
    if (offset != bytes.len) return error.WrapperReplayContentMismatch;
    return true;
}

test "role0 wrapper replay retains bytes after producer destruction" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        const first = try allocator.dupe(u8, "first native proof");
        defer allocator.free(first);
        const second = try allocator.dupe(u8, "second native proof");
        defer allocator.free(second);
        const wrapper = try allocator.dupe(u8, "wrapper bytes awaiting verification");
        defer allocator.free(wrapper);
        try std.testing.expectError(error.InvalidWrapperReplayLeafCount, writeWrapperReplay(tmp.dir, &.{first}, "whole program ELF", wrapper, null));
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile("wrapper.bin"));
        try writeWrapperReplay(tmp.dir, &.{ first, second }, "whole program ELF", wrapper, null);
        try writeWrapperReplay(tmp.dir, &.{ first, second }, "whole program ELF", wrapper, null);
        try std.testing.expectError(error.WrapperReplayContentMismatch, writeWrapperReplay(tmp.dir, &.{ first, "different second proof" }, "whole program ELF", wrapper, null));
        const identity = try wrapperReplayIdentity(&.{ first, second }, "whole program ELF", wrapper, null);
        try std.testing.expect(!std.mem.eql(u8, &identity, &try wrapperReplayIdentity(&.{ first, second }, "different whole ELF", wrapper, null)));
        try std.testing.expect(!std.mem.eql(u8, &identity, &try wrapperReplayIdentity(&.{ first, "different second proof" }, "whole program ELF", wrapper, null)));
        try std.testing.expect(!std.mem.eql(u8, &identity, &try wrapperReplayIdentity(&.{ second, first }, "whole program ELF", wrapper, null)));
    }
    const names = [_][]const u8{ "leaf-0.bin", "leaf-1.bin", "program.elf", "wrapper.bin" };
    const expected = [_][]const u8{ "first native proof", "second native proof", "whole program ELF", "wrapper bytes awaiting verification" };
    for (names, expected) |name, bytes| {
        const retained = try tmp.dir.readFileAlloc(allocator, name, 1024);
        defer allocator.free(retained);
        try std.testing.expectEqualStrings(bytes, retained);
    }
}

test "role0 replay binds retained global metadata without granting proof authority" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const inputs: []const []const u8 = &.{ "first", "second" };
    const metadata = "unverified global metadata";
    const legacy = try wrapperReplayIdentity(inputs, "elf", "wrapper", null);
    const global = try wrapperReplayIdentity(inputs, "elf", "wrapper", metadata);
    const changed = try wrapperReplayIdentity(inputs, "elf", "wrapper", "changed metadata");
    try std.testing.expect(!std.meta.eql(legacy, global));
    try std.testing.expect(!std.meta.eql(global, changed));
    try writeWrapperReplay(tmp.dir, inputs, "elf", "wrapper", metadata);
    try writeWrapperReplay(tmp.dir, inputs, "elf", "wrapper", metadata);
    try std.testing.expectError(error.WrapperReplayContentMismatch, writeWrapperReplay(tmp.dir, inputs, "elf", "wrapper", "changed metadata"));
    const retained = try tmp.dir.readFileAlloc(allocator, "global-metadata-v1.json", 1024);
    defer allocator.free(retained);
    try std.testing.expectEqualStrings(metadata, retained);
}

pub const WorkerPolicyV4 = struct {
    worker_count: usize,
    host_byte_budget: usize,

    pub fn hostDefault(host_byte_budget: usize) !WorkerPolicyV4 {
        const result = WorkerPolicyV4{
            .worker_count = @max(
                1,
                @min(
                    try std.Thread.getCpuCount(),
                    MAXIMUM_WORKER_COUNT,
                ),
            ),
            .host_byte_budget = host_byte_budget,
        };
        try result.validate();
        return result;
    }

    /// Worker count is host-derived by default. The host byte budget is an
    /// explicit caller policy, optionally overridden by a decimal environment
    /// value; no workstation-specific RAM total is embedded here.
    pub fn fromEnvironment(
        allocator: std.mem.Allocator,
        fallback_host_byte_budget: usize,
    ) !WorkerPolicyV4 {
        const encoded = std.process.getEnvVarOwned(
            allocator,
            WORKER_COUNT_ENV,
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (encoded) |value| allocator.free(value);
        const worker_count = if (encoded) |value|
            std.fmt.parseUnsigned(usize, value, 10) catch
                return error.InvalidRole0GenuineWorkerCount
        else
            @max(
                1,
                @min(
                    try std.Thread.getCpuCount(),
                    MAXIMUM_WORKER_COUNT,
                ),
            );
        const encoded_budget = std.process.getEnvVarOwned(
            allocator,
            HOST_BYTE_BUDGET_ENV,
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (encoded_budget) |value| allocator.free(value);
        const host_byte_budget = if (encoded_budget) |value|
            std.fmt.parseUnsigned(usize, value, 10) catch
                return error.InvalidRole0GenuineHostByteBudget
        else
            fallback_host_byte_budget;
        const result = WorkerPolicyV4{
            .worker_count = worker_count,
            .host_byte_budget = host_byte_budget,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: WorkerPolicyV4) !void {
        if (self.worker_count == 0 or
            self.worker_count > MAXIMUM_WORKER_COUNT)
        {
            return error.InvalidRole0GenuineWorkerCount;
        }
        if (self.host_byte_budget == 0 or
            self.host_byte_budget == std.math.maxInt(usize))
        {
            return error.InvalidRole0GenuineHostByteBudget;
        }
    }

    pub fn cpuRequest(
        self: WorkerPolicyV4,
    ) !prover_api.CpuCompositionExecutionRequest {
        try self.validate();
        return .{
            .worker_count = self.worker_count,
            .host_byte_budget = self.host_byte_budget,
            .contention_policy = .strict,
        };
    }
};

/// Test-transaction receipt proving both sequential Stage-101 producers were
/// handed one identical strict, non-null execution request. It is diagnostics,
/// not proof admission, and is excluded from all proof/artifact bytes.
pub const Stage101ExecutionReceiptV4 = struct {
    proof_count: u32,
    worker_count: u32,
    host_byte_budget: u64,
    contention_policy: prover_api.CpuCompositionContentionPolicy,
    identity_sha256: [32]u8,

    pub fn mint(
        request: prover_api.CpuCompositionExecutionRequest,
        proof_count: usize,
    ) !Stage101ExecutionReceiptV4 {
        const result = Stage101ExecutionReceiptV4{
            .proof_count = std.math.cast(u32, proof_count) orelse
                return error.InvalidRole0GenuineExecutionReceipt,
            .worker_count = std.math.cast(u32, request.worker_count) orelse
                return error.InvalidRole0GenuineExecutionReceipt,
            .host_byte_budget = std.math.cast(u64, request.host_byte_budget) orelse
                return error.InvalidRole0GenuineExecutionReceipt,
            .contention_policy = request.contention_policy,
            .identity_sha256 = undefined,
        };
        var sealed = result;
        sealed.identity_sha256 = executionReceiptIdentity(&sealed);
        try sealed.validate();
        return sealed;
    }

    pub fn validate(self: *const Stage101ExecutionReceiptV4) !void {
        if (self.proof_count == 0 or self.worker_count == 0 or
            @as(usize, self.worker_count) > MAXIMUM_WORKER_COUNT or
            self.host_byte_budget == 0 or
            self.contention_policy != .strict or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &executionReceiptIdentity(self),
            ))
        {
            return error.InvalidRole0GenuineExecutionReceipt;
        }
    }
};

pub fn stopAfterMaterialize(allocator: std.mem.Allocator) !bool {
    const encoded = std.process.getEnvVarOwned(
        allocator,
        STOP_AFTER_MATERIALIZE_ENV,
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return false,
        else => return err,
    };
    defer allocator.free(encoded);
    if (std.mem.eql(u8, encoded, "0")) return false;
    if (std.mem.eql(u8, encoded, "1")) return true;
    return error.InvalidRole0GenuineStopPolicy;
}

/// Compatibility alias; the shared prover owns allocation accounting.
pub const TrackedSmpAllocatorV4 = @import("stwo_prover_engine").tracked_smp_allocator.TrackedSmpAllocator;

fn executionReceiptIdentity(
    value: *const Stage101ExecutionReceiptV4,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(EXECUTION_RECEIPT_DOMAIN);
    hashInt(&hash, u32, value.proof_count);
    hashInt(&hash, u32, value.worker_count);
    hashInt(&hash, u64, value.host_byte_budget);
    hashInt(&hash, u8, @intFromEnum(value.contention_policy));
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}
