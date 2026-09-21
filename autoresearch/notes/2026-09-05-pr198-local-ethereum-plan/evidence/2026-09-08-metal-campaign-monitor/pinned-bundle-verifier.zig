//! Independent STWIEF04 bundle verification. Only one decoded proof/capture
//! lives at a time. The shared span and leaf-local authorities own coverage
//! and continuation; a transport digest never substitutes for proof checks.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const span = frontend.recursion.span_statement;
const global = frontend.recursion.segment_leaf_local_authority_v3;
const input = @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const profile = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const fixed_program = @import("ethereum_fixed_program_admission_v1.zig");
const coordinate = @import("recursive_node_artifact_v1.zig").TaskCoordinateV1;
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const usage = @import("stwo_prover_engine").measurement.process_usage;
const Engine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_PROOF_BYTES = 512 * 1024 * 1024;
pub const VERSION: u16 = 1;

pub const LeafV1 = struct {
    metadata: global.MetadataV3,
    proof_bytes: usize,
    proof_sha256: [32]u8,
};

/// Files are named <proof_sha256>.bin beside this manifest. An independently
/// supplied manifest hash pins the intended job, geometry and proof inventory.
pub const ManifestV1 = struct {
    version: u16 = VERSION,
    claim_admission: profile.ClaimAdmissionV4,
    leaves: []const LeafV1,

    /// Structural preflight only. The returned statement becomes verified
    /// solely after every leaf has passed the native verifier below.
    pub fn checkCoverage(self: *const ManifestV1) !span.RootStatement {
        if (self.version != VERSION or self.leaves.len == 0 or self.leaves.len > @import("ethereum_incremental_capture_publication_v4.zig").MAX_SEGMENT_COUNT)
            return error.InvalidEthereumBundleManifest;
        const first = &self.leaves[0].metadata;
        try first.validate();
        const first_span = try span.SpanStatement.fromCanonicalWords(&first.base_statement_words);
        if (first.segment_count != self.leaves.len) return error.IncompleteEthereumBundle;
        for (self.leaves, 0..) |*leaf, index| {
            try leaf.metadata.validate();
            if (leaf.metadata.segment_index != index or leaf.proof_bytes == 0 or
                leaf.proof_bytes > MAX_PROOF_BYTES or std.mem.allEqual(u8, &leaf.proof_sha256, 0))
                return error.InvalidEthereumBundleLeaf;
            if (index != 0) try global.requireAdjacentMetadata(&self.leaves[index - 1].metadata, &leaf.metadata);
        }
        const last = &self.leaves[self.leaves.len - 1].metadata;
        const last_span = try span.SpanStatement.fromCanonicalWords(&last.base_statement_words);
        const begin = first_span.body.executed;
        const end = last_span.body.executed;
        const executed = try span.ExecutedSpan.init(begin.first_segment, @intCast(self.leaves.len), begin.first_cycle, try std.math.sub(u64, last.global_cycle_end, first.global_cycle_start), begin.entry, end.exit, begin.input, end.output);
        return span.RootStatement.init(try span.SpanStatement.init(first_span.job, try span.SlotSpan.init(0, first_span.job.slot_height), .{ .executed = executed }));
    }
};

pub const ReceiptV1 = struct {
    version: u16 = VERSION,
    endpoint: []const u8 = "verified_native_full_leaf_bundle",
    manifest_sha256: [32]u8,
    materialization_sha256: ?[32]u8,
    leaf_count: usize,
    worker_count: usize,
    total_proof_bytes: u64,
    request_ns: u64,
    verify_ns: u64,
    peak_footprint_bytes: ?u64,
    statement: span.StatementWords,
};

pub fn verifyDirectory(allocator: std.mem.Allocator, directory: []const u8, expected_manifest_sha256: [32]u8) !ReceiptV1 {
    return verifyDirectoryAgainstJob(allocator, directory, expected_manifest_sha256, null, try defaultWorkerCount());
}

pub const ExpectedJobV1 = struct {
    job: span.JobContext,
    materialization_sha256: [32]u8,
};

pub fn verifyDirectoryAgainstJob(allocator: std.mem.Allocator, directory: []const u8, expected_manifest_sha256: [32]u8, expected: ?ExpectedJobV1, worker_count: usize) !ReceiptV1 {
    return verifyDirectoryWithProgram(allocator, directory, expected_manifest_sha256, expected, worker_count, null);
}

/// The caller independently admits one immutable program for the whole bundle.
/// Coverage, job and native acceptance use the same path as legacy bundles.
pub fn verifyDirectoryWithProgram(allocator: std.mem.Allocator, directory: []const u8, expected_manifest_sha256: [32]u8, expected: ?ExpectedJobV1, worker_count: usize, program: ?*const fixed_program.OwnedV1) !ReceiptV1 {
    var timer = try std.time.Timer.start();
    const absolute = try artifact_io.resolveAbsolute(allocator, directory);
    defer allocator.free(absolute);
    const manifest_path = try std.fs.path.join(allocator, &.{ absolute, "bundle.json" });
    defer allocator.free(manifest_path);
    const bytes = try artifact_io.readFileBounded(allocator, manifest_path, MAX_MANIFEST_BYTES);
    defer allocator.free(bytes);
    if (!std.meta.eql(hash(bytes), expected_manifest_sha256)) return error.EthereumBundleManifestIdentityMismatch;
    var parsed = try std.json.parseFromSlice(ManifestV1, allocator, bytes, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const manifest = &parsed.value;
    if ((manifest.claim_admission == .fixed_program_narrow_v5) != (program != null))
        return error.EthereumFixedProgramAdmissionRequired;
    const root = try manifest.checkCoverage();
    if (expected) |admitted| {
        try admitted.job.validate();
        if (!std.meta.eql(root.statement.job, admitted.job)) return error.EthereumBundleJobMismatch;
    }
    var scope: @import("ethereum_native_verification_scope_v1.zig").ScopeV1 = undefined;
    try scope.initInPlace(worker_count);
    defer scope.deinit();
    var proof_bytes: u64 = 0;
    var verify_ns: u64 = 0;
    for (manifest.leaves, 0..) |*leaf, index| {
        // This scope releases bytes and the entire verifier capture before
        // opening the next leaf. No producer capability is accepted.
        const basename = try std.fmt.allocPrint(allocator, "{s}.bin", .{std.fmt.bytesToHex(leaf.proof_sha256, .lower)});
        defer allocator.free(basename);
        const path = try std.fs.path.join(allocator, &.{ absolute, basename });
        defer allocator.free(path);
        const proof = try artifact_io.readFileBounded(allocator, path, leaf.proof_bytes);
        defer allocator.free(proof);
        const elapsed = try verifyLeafWithProgram(allocator, proof, leaf, manifest.claim_admission, program);
        verify_ns = try std.math.add(u64, verify_ns, elapsed);
        proof_bytes = try std.math.add(u64, proof_bytes, proof.len);
        std.debug.print("ETHEREUM_BUNDLE_LEAF index={d} count={d} proof_bytes={d} verify_ns={d}\n", .{ index, manifest.leaves.len, proof.len, elapsed });
    }
    const sample = usage.sample() catch null;
    return .{ .manifest_sha256 = expected_manifest_sha256, .materialization_sha256 = if (expected) |admitted| admitted.materialization_sha256 else null, .leaf_count = manifest.leaves.len, .worker_count = scope.workerCount(), .total_proof_bytes = proof_bytes, .request_ns = timer.read(), .verify_ns = verify_ns, .peak_footprint_bytes = if (sample) |value| value.lifetime_peak_physical_footprint_bytes else null, .statement = try root.statement.canonicalWords() };
}

/// Native proof acceptance shared by full bundles and selected-leaf replay.
/// The caller owns the explicit worker scope and the proof bytes; no producer
/// or retained materialization capability enters this verification relation.
pub fn verifyLeaf(allocator: std.mem.Allocator, proof: []const u8, leaf: *const LeafV1, claim_admission: profile.ClaimAdmissionV4) !u64 {
    return verifyLeafWithProgram(allocator, proof, leaf, claim_admission, null);
}

/// The fixed program owner is independent of proof/metadata transport and may
/// be reused across leaves. A descriptor copied from the proof cannot mint it.
pub fn verifyLeafWithProgram(allocator: std.mem.Allocator, proof: []const u8, leaf: *const LeafV1, claim_admission: profile.ClaimAdmissionV4, program: ?*const fixed_program.OwnedV1) !u64 {
    if ((claim_admission == .fixed_program_narrow_v5) != (program != null))
        return error.EthereumFixedProgramAdmissionRequired;
    if (leaf.proof_bytes == 0 or leaf.proof_bytes > MAX_PROOF_BYTES or
        proof.len != leaf.proof_bytes or !std.meta.eql(hash(proof), leaf.proof_sha256))
        return error.EthereumBundleProofIdentityMismatch;
    try leaf.metadata.validate();
    var timer = try std.time.Timer.start();
    var fresh = if (program) |admitted|
        try input.FreshInputV4(Engine).coldOpenWithProgramAdmission(allocator, proof, try coordinate.init(0, leaf.metadata.segment_index), .{}, admitted)
    else
        try input.FreshInputV4(Engine).coldOpen(allocator, proof, try coordinate.init(0, leaf.metadata.segment_index), .{});
    defer fresh.deinit();
    if (try fresh.stage101.profile.claimAdmission() != claim_admission)
        return error.EthereumBundleClaimAdmissionMismatch;
    try fresh.admitGlobalMetadata(&leaf.metadata);
    return timer.read();
}

pub const SelectedLeafReceiptV1 = struct {
    version: u16 = VERSION,
    endpoint: []const u8 = "verified_native_selected_leaf",
    materialization_sha256: [32]u8,
    metadata_file_sha256: [32]u8,
    proof_sha256: [32]u8,
    proof_bytes: usize,
    segment_index: u32,
    segment_count: u32,
    worker_count: usize,
    request_ns: u64,
    verify_ns: u64,
    peak_footprint_bytes: ?u64,
    retained_admission_destroyed_before_proof: bool = true,
};

pub const SelectedFixedProgramReceiptV1 = struct {
    version: u16 = 1,
    endpoint: []const u8 = "verified_native_selected_leaf_fixed_program_v5",
    verification: SelectedLeafReceiptV1,
    program: fixed_program.DescriptorV1,
};

pub fn verifySelectedLeaf(
    allocator: std.mem.Allocator,
    proof_path: []const u8,
    metadata_path: []const u8,
    materialization_path: []const u8,
    expected_materialization_sha256: [32]u8,
    worker_count: usize,
) !SelectedLeafReceiptV1 {
    return (try verifySelectedLeafInternal(false, allocator, proof_path, metadata_path, materialization_path, expected_materialization_sha256, worker_count)).receipt;
}

pub fn verifySelectedLeafWithFixedProgramV5(
    allocator: std.mem.Allocator,
    proof_path: []const u8,
    metadata_path: []const u8,
    materialization_path: []const u8,
    expected_materialization_sha256: [32]u8,
    worker_count: usize,
) !SelectedFixedProgramReceiptV1 {
    const verified = try verifySelectedLeafInternal(true, allocator, proof_path, metadata_path, materialization_path, expected_materialization_sha256, worker_count);
    return .{ .verification = verified.receipt, .program = verified.program.? };
}

fn verifySelectedLeafInternal(
    comptime use_fixed_program: bool,
    allocator: std.mem.Allocator,
    proof_path: []const u8,
    metadata_path: []const u8,
    materialization_path: []const u8,
    expected_materialization_sha256: [32]u8,
    worker_count: usize,
) !struct { receipt: SelectedLeafReceiptV1, program: ?fixed_program.DescriptorV1 } {
    var timer = try std.time.Timer.start();
    var program: ?*fixed_program.OwnedV1 = null;
    defer if (program) |admitted| admitted.deinit();
    const metadata_absolute = try artifact_io.resolveAbsolute(allocator, metadata_path);
    defer allocator.free(metadata_absolute);
    const metadata_bytes = try artifact_io.readFileBounded(allocator, metadata_absolute, 128 * 1024);
    defer allocator.free(metadata_bytes);
    const leaf = blk: {
        var parsed = try std.json.parseFromSlice(LeafV1, allocator, metadata_bytes, .{});
        defer parsed.deinit();
        break :blk parsed.value;
    };
    try leaf.metadata.validate();
    if (leaf.proof_bytes == 0 or leaf.proof_bytes > MAX_PROOF_BYTES) return error.InvalidEthereumBundleLeaf;
    {
        const absolute = try artifact_io.resolveAbsolute(allocator, materialization_path);
        defer allocator.free(absolute);
        var retained = try @import("ethereum_incremental_capture_retained_authority_v4.zig").RetainedAuthorityV4.openWithCampaignGeometryV1(allocator, absolute, .authenticated_v1);
        defer retained.deinit();
        if (!std.meta.eql(retained.materialization_identity.sha256, expected_materialization_sha256))
            return error.EthereumBundleMaterializationIdentityMismatch;
        const index = leaf.metadata.segment_index;
        if (index >= retained.sources.len or !std.meta.eql(leaf.metadata, retained.sources[index].value.metadata))
            return error.EthereumSelectedLeafMetadataMismatch;
        const expected = try span.SpanStatement.fromCanonicalWords(&retained.sources[0].value.metadata.base_statement_words);
        const selected = try span.SpanStatement.fromCanonicalWords(&leaf.metadata.base_statement_words);
        if (!std.meta.eql(selected.job, expected.job)) return error.EthereumBundleJobMismatch;
        if (use_fixed_program) program = try fixed_program.OwnedV1.createFromElf(allocator, retained.elf_bytes, retained.elf_identity.sha256);
    }
    // Every retained source, tape and snapshot admission owner has died before
    // opening the proof. The fixed profile additionally retains its deeply
    // immutable ELF admission; no execution, tape, snapshot or proof owner does.
    var scope: @import("ethereum_native_verification_scope_v1.zig").ScopeV1 = undefined;
    try scope.initInPlace(worker_count);
    defer scope.deinit();
    const absolute_proof = try artifact_io.resolveAbsolute(allocator, proof_path);
    defer allocator.free(absolute_proof);
    const proof = try artifact_io.readFileBounded(allocator, absolute_proof, leaf.proof_bytes);
    defer allocator.free(proof);
    const verify_ns = try verifyLeafWithProgram(allocator, proof, &leaf, if (use_fixed_program) .fixed_program_narrow_v5 else .field_authority_v4, program);
    const sample = usage.sample() catch null;
    return .{ .program = if (program) |admitted| admitted.descriptor() else null, .receipt = .{
        .materialization_sha256 = expected_materialization_sha256,
        .metadata_file_sha256 = hash(metadata_bytes),
        .proof_sha256 = leaf.proof_sha256,
        .proof_bytes = leaf.proof_bytes,
        .segment_index = leaf.metadata.segment_index,
        .segment_count = leaf.metadata.segment_count,
        .worker_count = scope.workerCount(),
        .request_ns = timer.read(),
        .verify_ns = verify_ns,
        .peak_footprint_bytes = if (sample) |value| value.lifetime_peak_physical_footprint_bytes else null,
    } };
}

fn printReceipt(allocator: std.mem.Allocator, receipt: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

pub fn main() !void {
    var timer = try std.time.Timer.start();
    const allocator = std.heap.smp_allocator;
    const raw_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_args);
    const command = try parseWorkers(raw_args);
    const args = command.positional;
    if (args.len == 6 and isSelectedCommand(args[1])) {
        if (args[5].len != 64) return error.ExpectedIndependentMaterializationSha256;
        var source_sha: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&source_sha, args[5]);
        if (std.mem.eql(u8, args[1], "verify-leaf-fixed-program-v5")) {
            var receipt = try verifySelectedLeafWithFixedProgramV5(allocator, args[2], args[3], args[4], source_sha, command.worker_count);
            receipt.verification.request_ns = timer.read();
            try printReceipt(allocator, receipt);
            return;
        }
        var receipt = try verifySelectedLeaf(allocator, args[2], args[3], args[4], source_sha, command.worker_count);
        receipt.request_ns = timer.read();
        try printReceipt(allocator, receipt);
        return;
    }
    if (args.len == 6 and std.mem.eql(u8, args[1], "verify-bundle-fixed-program-v5")) {
        if (args[3].len != 64) return error.ExpectedBundleDirectoryAndIndependentManifestSha256;
        if (args[5].len != 64) return error.ExpectedIndependentMaterializationSha256;
        var manifest_sha: [32]u8 = undefined;
        var source_sha: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&manifest_sha, args[3]);
        _ = try std.fmt.hexToBytes(&source_sha, args[5]);
        var program: *fixed_program.OwnedV1 = undefined;
        const job: ExpectedJobV1 = admitted: {
            const path = try artifact_io.resolveAbsolute(allocator, args[4]);
            defer allocator.free(path);
            var retained = try @import("ethereum_incremental_capture_retained_authority_v4.zig").RetainedAuthorityV4.openWithCampaignGeometryV1(allocator, path, .authenticated_v1);
            defer retained.deinit();
            if (!std.meta.eql(retained.materialization_identity.sha256, source_sha)) return error.EthereumBundleMaterializationIdentityMismatch;
            const statement = try span.SpanStatement.fromCanonicalWords(&retained.sources[0].value.metadata.base_statement_words);
            program = try fixed_program.OwnedV1.createFromElf(allocator, retained.elf_bytes, retained.elf_identity.sha256);
            break :admitted .{ .job = statement.job, .materialization_sha256 = source_sha };
        };
        defer program.deinit();
        var receipt = try verifyDirectoryWithProgram(allocator, args[2], manifest_sha, job, command.worker_count, program);
        receipt.request_ns = timer.read();
        try printReceipt(allocator, receipt);
        return;
    }
    if ((args.len != 3 and args.len != 5) or args[2].len != 64) return error.ExpectedBundleDirectoryAndIndependentManifestSha256;
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, args[2]);
    const job: ?ExpectedJobV1 = if (args.len == 5) admitted: {
        if (args[4].len != 64) return error.ExpectedIndependentMaterializationSha256;
        var source_sha: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&source_sha, args[4]);
        const path = try artifact_io.resolveAbsolute(allocator, args[3]);
        defer allocator.free(path);
        var retained = try @import("ethereum_incremental_capture_retained_authority_v4.zig").RetainedAuthorityV4.openWithCampaignGeometryV1(allocator, path, .authenticated_v1);
        defer retained.deinit();
        if (!std.meta.eql(retained.materialization_identity.sha256, source_sha)) return error.EthereumBundleMaterializationIdentityMismatch;
        const statement = try span.SpanStatement.fromCanonicalWords(&retained.sources[0].value.metadata.base_statement_words);
        break :admitted .{ .job = statement.job, .materialization_sha256 = source_sha };
    } else null;
    var receipt = try verifyDirectoryAgainstJob(allocator, args[1], expected, job, command.worker_count);
    receipt.request_ns = timer.read();
    try printReceipt(allocator, receipt);
}

fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn defaultWorkerCount() !usize {
    return @min(@max(try std.Thread.getCpuCount(), 1), @import("stwo_prover_engine").work_pool.MAX_WORKERS);
}

/// Existing positional forms remain valid. Only an explicit trailing option
/// overrides the reported CPU-count default; proof worker environment is not
/// silently inherited by this standalone endpoint.
fn isSelectedCommand(command: []const u8) bool {
    return std.mem.eql(u8, command, "verify-leaf") or std.mem.eql(u8, command, "verify-leaf-fixed-program-v5");
}

fn parseWorkers(args: []const []const u8) !struct { positional: []const []const u8, worker_count: usize } {
    var positional = args;
    var worker_count = try defaultWorkerCount();
    if (args.len >= 2 and std.mem.eql(u8, args[args.len - 2], "--workers")) {
        worker_count = std.fmt.parseUnsigned(usize, args[args.len - 1], 10) catch return error.InvalidWorkerBudget;
        positional = args[0 .. args.len - 2];
    }
    _ = try @import("stwo_prover_engine").work_pool.WorkerBudget.init(worker_count);
    const selected = positional.len > 1 and isSelectedCommand(positional[1]);
    if (selected) {
        if (positional.len != 6) return error.ExpectedSelectedLeafProofMetadataAndMaterialization;
    } else if (positional.len > 1 and std.mem.eql(u8, positional[1], "verify-bundle-fixed-program-v5")) {
        if (positional.len != 6) return error.ExpectedFixedProgramBundleAndMaterialization;
    } else if (positional.len != 3 and positional.len != 5) return error.ExpectedBundleDirectoryAndIndependentManifestSha256;
    for (positional[1..]) |value| if (std.mem.startsWith(u8, value, "--")) return error.InvalidBundleOption;
    return .{ .positional = positional, .worker_count = worker_count };
}

test "Ethereum native bundle worker option is explicit and bounded" {
    const fixed_bundle = try parseWorkers(&.{ "bundle", "verify-bundle-fixed-program-v5", "directory", "manifest-sha", "materialization", "source-sha", "--workers", "1" });
    try std.testing.expectEqual(@as(usize, 6), fixed_bundle.positional.len);
    try std.testing.expectEqual(@as(usize, 1), fixed_bundle.worker_count);
    try std.testing.expectError(error.ExpectedFixedProgramBundleAndMaterialization, parseWorkers(&.{ "bundle", "verify-bundle-fixed-program-v5", "directory", "sha" }));
    const fixed = try parseWorkers(&.{ "bundle", "verify-leaf-fixed-program-v5", "proof", "leaf.json", "materialization", "sha256", "--workers", "1" });
    try std.testing.expectEqual(@as(usize, 6), fixed.positional.len);
    try std.testing.expectEqual(@as(usize, 1), fixed.worker_count);
    try std.testing.expectError(error.ExpectedSelectedLeafProofMetadataAndMaterialization, parseWorkers(&.{ "bundle", "verify-leaf-fixed-program-v5", "proof", "leaf.json" }));
    // An untrusted proof cannot select a fixed-program authority for itself.
    try std.testing.expectError(error.EthereumFixedProgramAdmissionRequired, verifyLeafWithProgram(std.testing.allocator, &.{}, undefined, .fixed_program_narrow_v5, null));
    const selected = try parseWorkers(&.{ "bundle", "verify-leaf", "proof", "leaf.json", "materialization", "sha256", "--workers", "1" });
    try std.testing.expectEqual(@as(usize, 6), selected.positional.len);
    try std.testing.expectEqual(@as(usize, 1), selected.worker_count);
    try std.testing.expectError(error.ExpectedSelectedLeafProofMetadataAndMaterialization, parseWorkers(&.{ "bundle", "verify-leaf", "proof" }));
    try std.testing.expectError(error.ExpectedSelectedLeafProofMetadataAndMaterialization, parseWorkers(&.{ "bundle", "verify-leaf", "proof", "leaf.json", "materialization", "sha256", "extra" }));
    const legacy = try parseWorkers(&.{ "bundle", "directory", "hash" });
    try std.testing.expectEqual(try defaultWorkerCount(), legacy.worker_count);
    const serial = try parseWorkers(&.{ "bundle", "directory", "hash", "--workers", "1" });
    try std.testing.expectEqual(@as(usize, 1), serial.worker_count);
    try std.testing.expectEqual(@as(usize, 3), serial.positional.len);
    const job = try parseWorkers(&.{ "bundle", "directory", "hash", "materialization", "source-hash", "--workers", "2" });
    try std.testing.expectEqual(@as(usize, 2), job.worker_count);
    try std.testing.expectEqual(@as(usize, 5), job.positional.len);
    try std.testing.expectError(error.InvalidWorkerBudget, parseWorkers(&.{ "bundle", "directory", "hash", "--workers", "0" }));
    try std.testing.expectError(error.InvalidWorkerBudget, parseWorkers(&.{ "bundle", "directory", "hash", "--workers", "33" }));
    try std.testing.expectError(error.InvalidWorkerBudget, parseWorkers(&.{ "bundle", "directory", "hash", "--workers", "x" }));
    try std.testing.expectError(error.ExpectedBundleDirectoryAndIndependentManifestSha256, parseWorkers(&.{ "bundle", "directory", "hash", "--workers" }));
    try std.testing.expectError(error.InvalidBundleOption, parseWorkers(&.{ "bundle", "directory", "hash", "--workers", "2", "--workers", "1" }));
}

test "Ethereum fixed program bundle verifies retained pair and exact coverage" {
    const allocator = std.heap.smp_allocator;
    const directory = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_FIXED_BUNDLE_PAIR_DIR") catch return error.SkipZigTest;
    defer allocator.free(directory);
    const Read = struct {
        fn file(a: std.mem.Allocator, dir: []const u8, basename: []const u8, limit: usize) ![]u8 {
            const path = try std.fs.path.join(a, &.{ dir, basename });
            defer a.free(path);
            return artifact_io.readFileBounded(a, path, limit);
        }
    };
    const pins_bytes = try Read.file(allocator, directory, "native-inputs-v1.json", MAX_MANIFEST_BYTES);
    defer allocator.free(pins_bytes);
    var pinned: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pinned, "97113e1e50f053bf65406eda1c2fd8c28bb68e1bad3b8c54d5440245ec026914");
    try std.testing.expectEqual(pinned, hash(pins_bytes));
    const Pins = struct { claim_admission: profile.ClaimAdmissionV4, native_sha256: [2][32]u8, program_sha256: [32]u8, global_metadata_sha256: [32]u8 };
    var pins = try std.json.parseFromSlice(Pins, allocator, pins_bytes, .{ .ignore_unknown_fields = true });
    defer pins.deinit();
    const metadata_bytes = try Read.file(allocator, directory, "global-metadata-v1.json", MAX_MANIFEST_BYTES);
    defer allocator.free(metadata_bytes);
    try std.testing.expectEqual(pins.value.global_metadata_sha256, hash(metadata_bytes));
    var metadata = try std.json.parseFromSlice(struct { version: u16, leaves: [2]global.MetadataV3 }, allocator, metadata_bytes, .{});
    defer metadata.deinit();
    const elf = try Read.file(allocator, directory, "program.elf", MAX_PROOF_BYTES);
    defer allocator.free(elf);
    const program = try fixed_program.OwnedV1.createFromElf(allocator, elf, pins.value.program_sha256);
    defer program.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const absolute = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(absolute);
    var leaves: [2]LeafV1 = undefined;
    for (&leaves, 0..) |*leaf, index| {
        const basename = try std.fmt.allocPrint(allocator, "{s}.bin", .{std.fmt.bytesToHex(pins.value.native_sha256[index], .lower)});
        defer allocator.free(basename);
        const bytes = try Read.file(allocator, directory, basename, MAX_PROOF_BYTES);
        defer allocator.free(bytes);
        try std.testing.expectEqual(pins.value.native_sha256[index], hash(bytes));
        leaf.* = .{ .metadata = metadata.value.leaves[index], .proof_bytes = bytes.len, .proof_sha256 = pins.value.native_sha256[index] };
        try temp.dir.writeFile(.{ .sub_path = basename, .data = bytes });
    }
    var manifest = ManifestV1{ .claim_admission = pins.value.claim_admission, .leaves = &leaves };
    const root = try manifest.checkCoverage();
    const encoded = try std.json.Stringify.valueAlloc(allocator, manifest, .{});
    defer allocator.free(encoded);
    try temp.dir.writeFile(.{ .sub_path = "bundle.json", .data = encoded });
    // This fixture is pinned by its own saved native-input manifest; it does
    // not claim to carry a retained campaign materialization receipt.
    const receipt = try verifyDirectoryWithProgram(allocator, absolute, hash(encoded), null, 1, program);
    try std.testing.expectEqual(@as(usize, 2), receipt.leaf_count);
    try std.testing.expectEqual(try root.statement.canonicalWords(), receipt.statement);
    try std.testing.expectError(error.EthereumFixedProgramAdmissionRequired, verifyDirectoryAgainstJob(allocator, absolute, hash(encoded), null, 1));
    manifest.leaves = leaves[0..1];
    try std.testing.expectError(error.IncompleteEthereumBundle, manifest.checkCoverage());
    var altered = leaves;
    manifest.leaves = &altered;
    altered[1] = leaves[0];
    try std.testing.expectError(error.InvalidEthereumBundleLeaf, manifest.checkCoverage());
    altered = .{ leaves[1], leaves[0] };
    try std.testing.expectError(error.InvalidEthereumBundleLeaf, manifest.checkCoverage());
    altered = leaves;
    altered[1].metadata.entry.snapshot_id[0] ^= 1;
    try std.testing.expectError(error.MemorySnapshotMismatch, manifest.checkCoverage());
    var changed = root.statement;
    changed.body.executed.entry.pc += 4;
    try std.testing.expectError(error.InitialStateMismatch, span.RootStatement.init(changed));
    changed = root.statement;
    changed.body.executed.exit.pc += 4;
    try std.testing.expectError(error.FinalStateMismatch, span.RootStatement.init(changed));
    changed = root.statement;
    changed.job.complete.total_cycles += 1;
    try std.testing.expectError(error.FinalCycleMismatch, span.RootStatement.init(changed));
}
