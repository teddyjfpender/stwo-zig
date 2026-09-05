//! Retained-authority, fresh one-pass 210-segment capture command.
//!
//! This is an execution/materialization transaction only. It emits no native
//! proof authority. Reopening an unsealed root reexecutes the VM from segment
//! zero and byte-validates its durable segment prefix; there is no serialized
//! runner continuation or execution-prefix shortcut.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const compact_manifest = @import("ethereum_block_leaf_compact_manifest.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const observer_mod = @import("ethereum_incremental_capture_observer_v4.zig");
const options_mod =
    @import("ethereum_incremental_capture_materializer_options_v4.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const retained_mod =
    @import("ethereum_incremental_capture_retained_authority_v4.zig");

pub const command_name = "ethereum-incremental-capture-materialize-v4";
pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;
pub const RECURSIVE_ADMISSIBLE = false;
pub const DURABLE_VM_RESTORE_AVAILABLE = false;

const profile_receipt_basename = "execution-profile-receipt.json";
const compact_manifest_basename = "compact-capture-manifest.json";

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var total_timer = try std.time.Timer.start();
    const parsed = try options_mod.OptionsV4.parse(arguments);
    var options = try parsed.resolve(allocator);
    defer options.deinit(allocator);
    switch (options.root_mode) {
        .create_under_parent => try artifact_io.createDirectoryCreateOnly(
            options.publication_root,
        ),
        .reopen_unsealed => try requireDirectory(options.publication_root),
    }

    var retained = try retained_mod.RetainedAuthorityV4.open(
        allocator,
        options.retained_materialization_result,
    );
    defer retained.deinit();
    const execution = try retained.executionAuthority();
    if (execution.segment_count != publication.CANONICAL_SEGMENT_COUNT)
        return error.CanonicalIncrementalSegmentCountRequired;

    var observer = try observer_mod.ObserverV4.init(
        allocator,
        &retained,
        options.publication_root,
    );
    defer observer.deinit();
    var journal_writer = std.Io.Writer.Allocating.init(allocator);
    defer journal_writer.deinit();
    var stream_timer = try std.time.Timer.start();
    try frontend.diagnostics.segment_manifest.streamObserved(
        allocator,
        retained.elf_bytes,
        retained.input_bytes,
        @intCast(execution.segment_step_budget),
        true,
        .leaf_local,
        &journal_writer.writer,
        &observer,
    );
    const stream_wall_ns = stream_timer.read();
    const generated_journal = journal_writer.written();
    if (!std.mem.eql(u8, generated_journal, retained.journal_bytes))
        return error.RetainedIncrementalJournalMismatch;
    try observer.validateComplete();

    var post_timer = try std.time.Timer.start();
    const materialization_identity = evidence.identity(
        options.retained_materialization_result,
        retained.materialization_bytes,
    );
    const profile_path = try std.fs.path.join(
        allocator,
        &.{ options.publication_root, profile_receipt_basename },
    );
    defer allocator.free(profile_path);
    const profile_bytes = try observer.profiler.encodeReceipt(allocator, .{
        .elf = retained.elfEvidence(),
        .execution_journal = retained.journalEvidence(),
        .materialization_result = materialization_identity,
        .source_request = retained.sourceRequestEvidence(),
    });
    defer allocator.free(profile_bytes);
    try publishOrCompare(allocator, profile_path, profile_bytes, 64 * 1024 * 1024);
    const profile_identity = evidence.identity(profile_path, profile_bytes);

    const executable_sha256 = try artifact_io.executableSha256(allocator);
    const post_execution_authority_wall_ns = post_timer.read();
    const compact_path = try std.fs.path.join(
        allocator,
        &.{ options.publication_root, compact_manifest_basename },
    );
    defer allocator.free(compact_path);
    const compact_bytes = try compact_manifest.encode(allocator, .{
        .artifacts = observer.compact_artifacts.items,
        .elf = retained.elfEvidence(),
        .execution_journal = retained.journalEvidence(),
        .execution_profile_abi_version = frontend.isa.execution_profile
            .ethereum_abi_version,
        .execution_profile_receipt = profile_identity,
        .execution_profile_semantic_sha256 = frontend.isa.execution_profile
            .ethereum_semantic_digest,
        .expected_output = retained.outputEvidence(),
        .input = retained.inputEvidence(),
        .materialization_result = materialization_identity,
        .materializer_executable_sha256 = executable_sha256,
        .program_sha256 = try observer.programIdentity(),
        .segment_step_budget = execution.segment_step_budget,
        .session_sha256 = try execution.sessionIdentity(),
        .source_request = retained.sourceRequestEvidence(),
        .stage_timings = .{
            .capture_wall_ns = observer.capture_wall_ns,
            .encode_wall_ns = observer.encode_wall_ns,
            .observer_wall_ns = observer.observer_wall_ns,
            .pc_attribution_wall_ns = observer.pc_attribution_wall_ns,
            .post_execution_authority_wall_ns = post_execution_authority_wall_ns,
            .publish_wall_ns = observer.publish_wall_ns,
            .stream_observed_wall_ns = stream_wall_ns,
            .pre_manifest_materialization_wall_ns = total_timer.read(),
        },
    });
    defer allocator.free(compact_bytes);
    const retained_compact_bytes = try publishOrAdmitCompact(
        allocator,
        compact_path,
        compact_bytes,
        &observer,
        &retained,
        materialization_identity,
    );
    defer allocator.free(retained_compact_bytes);

    const final_bindings = publication.FinalBindingsV4{
        .compact_manifest = publication.ArtifactIdentityV4.fromBytes(
            retained_compact_bytes,
        ),
        .materialization_result = retained.materialization_identity,
        .source_request = retained.source_request_identity,
        .journal = retained.journal_identity,
        .execution_profile_receipt = publication.ArtifactIdentityV4.fromBytes(
            profile_bytes,
        ),
    };
    var manifest = try observer.owner.?.finalize(final_bindings);
    defer manifest.deinit();
    // STWIMF04 is independently reopened before the companion wire manifest
    // becomes the seal-last publication for the complete replay input.
    try manifest.value.validateAgainst(execution, final_bindings);
    var public_wire_manifest = try observer.public_wire_owner.?.finalize(
        final_bindings,
        manifest.file,
    );
    defer public_wire_manifest.deinit();
    try public_wire_manifest.value.validateAgainst(
        execution,
        final_bindings,
        manifest.file,
    );
}

fn publishOrCompare(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
    max_bytes: usize,
) !void {
    artifact_io.publishCreateOnlyDurable(path, expected) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const retained = try artifact_io.readFileBounded(
                allocator,
                path,
                max_bytes,
            );
            defer allocator.free(retained);
            if (!std.mem.eql(u8, retained, expected))
                return error.IncrementalCaptureResumeArtifactMismatchV4;
        },
        else => return err,
    };
}

/// Timing fields are execution evidence and may differ on a full-VM resume.
/// Existing compact bytes are therefore admitted by their complete canonical
/// parser plus exact semantic authorities/artifact identities, never replaced.
fn publishOrAdmitCompact(
    allocator: std.mem.Allocator,
    path: []const u8,
    freshly_encoded: []const u8,
    observer: *const observer_mod.ObserverV4,
    retained: *const retained_mod.RetainedAuthorityV4,
    materialization: evidence.FileIdentity,
) ![]u8 {
    artifact_io.publishCreateOnlyDurable(path, freshly_encoded) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const bytes = try artifact_io.readFileBounded(
                allocator,
                path,
                compact_manifest.max_manifest_bytes,
            );
            errdefer allocator.free(bytes);
            var parsed = try compact_manifest.parse(allocator, bytes);
            defer parsed.deinit();
            const value = parsed.value;
            if (value.segment_count != publication.CANONICAL_SEGMENT_COUNT or
                value.artifacts.len != observer.compact_artifacts.items.len or
                !identityMatches(value.elf, retained.elfEvidence()) or
                !identityMatches(
                    value.execution_journal,
                    retained.journalEvidence(),
                ) or !identityMatches(
                value.expected_output,
                retained.outputEvidence(),
            ) or !identityMatches(value.input, retained.inputEvidence()) or
                !identityMatches(value.materialization_result, materialization))
            {
                return error.IncrementalCaptureResumeCompactMismatchV4;
            }
            for (value.artifacts, observer.compact_artifacts.items) |
                actual,
                expected,
            | if (!identityMatches(actual.artifact, expected.artifact))
                return error.IncrementalCaptureResumeCompactMismatchV4;
            return bytes;
        },
        else => return err,
    };
    return allocator.dupe(u8, freshly_encoded);
}

fn identityMatches(
    actual: @import("ethereum_block_leaf_contract.zig").Identity,
    expected: evidence.FileIdentity,
) bool {
    const digest = std.fmt.bytesToHex(expected.sha256, .lower);
    return actual.bytes == expected.bytes and
        std.mem.eql(u8, actual.path, expected.path) and
        std.mem.eql(u8, actual.sha256, &digest);
}

fn requireDirectory(path: []const u8) !void {
    var directory = try std.fs.openDirAbsolute(path, .{});
    directory.close();
}
