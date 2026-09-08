//! Explicit single-leaf development admission. Complete campaign seals are
//! neither consumed nor produced. The same native mint and cold reconstruction
//! authenticate the selected retained source, compact tape and public wire.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const io = @import("ethereum_precompile_artifact_io.zig");
const publication = @import("ethereum_incremental_capture_publication_v4.zig");
const wires = @import("ethereum_incremental_public_wire_publication_v4.zig");
const postprocess = @import("ethereum_incremental_capture_postprocess_v4.zig");
const authority = @import("ethereum_incremental_capture_postprocess_authority_v4.zig");
const retained_mod = @import("ethereum_incremental_capture_retained_authority_v4.zig");

pub const VERSION: u16 = 1;
pub const basename = "selected-leaf-admission-v1.json";
pub const SelectionV1 = struct {
    transition: publication.CommittedSegmentV4,
    public_wire: wires.CommittedSegmentV4,
};

pub const AdmissionV1 = struct {
    version: u16,
    scope: enum { selected_leaf },
    execution: publication.ExecutionAuthorityV4,
    metadata: frontend.recursion.segment_leaf_local_authority_v3.MetadataV3,
    materialization: publication.ArtifactIdentityV4,
    source_request: publication.ArtifactIdentityV4,
    journal: publication.ArtifactIdentityV4,
    selection: SelectionV1,

    fn validateAgainst(self: *const AdmissionV1, retained: *const retained_mod.RetainedAuthorityV4, input: *const authority.OwnedMintInputV4) !void {
        try self.execution.validate();
        try self.metadata.validate();
        try self.selection.transition.validate();
        try self.selection.public_wire.validate();
        const native = self.selection.transition.segment;
        const wire = self.selection.public_wire.segment;
        if (self.version != VERSION or !std.meta.eql(self.execution, try retained.executionAuthority()) or
            !std.meta.eql(self.metadata, retained.sources[input.segment_index].value.metadata) or
            !std.meta.eql(self.materialization, retained.materialization_identity) or
            !std.meta.eql(self.source_request, retained.source_request_identity) or
            !std.meta.eql(self.journal, retained.journal_identity) or
            native.segment_index != input.segment_index or native.segment_count != input.segment_count or
            wire.coordinate.segment_index != native.segment_index or wire.coordinate.segment_count != native.segment_count or
            !std.meta.eql(wire.wire_id, input.wire.data.wireId()) or
            !std.meta.eql(native.compact_tape, input.compact_identity) or
            !std.meta.eql(native.source, input.source_identity) or
            !std.meta.eql(native.journal_record_sha256, input.journal_record_sha256) or
            !std.meta.eql(native.segment_public_wire_id, input.wire.data.wireId()) or
            !std.meta.eql(wire.wire_artifact, input.wire_identity) or
            !std.meta.eql(wire.v4_segment_reference, self.selection.transition.reference) or
            !std.meta.eql(wire.source, input.source_identity) or
            !std.meta.eql(wire.journal_record_sha256, input.journal_record_sha256))
            return error.SelectedEthereumLeafAdmissionMismatchV1;
    }
};

pub fn openOrMint(
    allocator: std.mem.Allocator,
    retained: *const retained_mod.RetainedAuthorityV4,
    input: *const authority.OwnedMintInputV4,
    root: []const u8,
    compact_bytes: []const u8,
    wire_bytes: []const u8,
) !SelectionV1 {
    // Prevent accidental reuse of a whole-campaign root as a leaf authority.
    inline for (.{ publication.manifest_basename, wires.manifest_basename }) |name| {
        const path = try std.fs.path.join(allocator, &.{ root, name });
        defer allocator.free(path);
        if (try publication.pathExists(path)) return error.SelectedLeafRootContainsCampaignSeal;
    }
    const path = try std.fs.path.join(allocator, &.{ root, basename });
    defer allocator.free(path);
    if (io.readFileBounded(allocator, path, 128 * 1024)) |bytes| {
        defer allocator.free(bytes);
        var parsed = try std.json.parseFromSlice(AdmissionV1, allocator, bytes, .{});
        defer parsed.deinit();
        try parsed.value.validateAgainst(retained, input);
        // Caller cold-opens every referenced artifact and wire next. Receipt
        // equality alone is never accepted as proof or source verification.
        return parsed.value.selection;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    try std.fs.cwd().makePath(root);
    const execution = try retained.executionAuthority();
    try input.validate(execution);
    if (!std.meta.eql(publication.ArtifactIdentityV4.fromBytes(compact_bytes), input.compact_identity) or
        !std.meta.eql(publication.ArtifactIdentityV4.fromBytes(wire_bytes), input.wire_identity))
        return error.SelectedEthereumLeafAdmissionMismatchV1;
    const entry_words = try input.selectedEntryWordsAlloc(allocator);
    defer allocator.free(entry_words);
    var job = try postprocess.mintSelectedLeafV1(allocator, execution, input.input(), entry_words);
    defer job.deinit();
    const compact_path = try publication.compactTapePathAlloc(allocator, root, input.segment_index);
    defer allocator.free(compact_path);
    try postprocess.publishOrCompare(allocator, compact_path, compact_bytes, compact_bytes.len);
    const wire_path = try wires.wirePathAlloc(allocator, root, input.segment_index);
    defer allocator.free(wire_path);
    try postprocess.publishOrCompare(allocator, wire_path, wire_bytes, wire_bytes.len);
    const result = try postprocess.coldVerifyAndPublish(allocator, root, &job, &input.wire.data, input.publicAuthority(), &retained.sources[input.segment_index].value.metadata);
    const admitted = AdmissionV1{
        .version = VERSION,
        .scope = .selected_leaf,
        .execution = execution,
        .metadata = retained.sources[input.segment_index].value.metadata,
        .materialization = retained.materialization_identity,
        .source_request = retained.source_request_identity,
        .journal = retained.journal_identity,
        .selection = .{ .transition = result.segment, .public_wire = result.public_segment },
    };
    try admitted.validateAgainst(retained, input);
    const bytes = try std.json.Stringify.valueAlloc(allocator, admitted, .{ .whitespace = .indent_2 });
    defer allocator.free(bytes);
    try io.publishCreateOnlyDurable(path, bytes);
    std.debug.print("SELECTED_ETHEREUM_LEAF_ADMISSION_V1 segment={} campaign_segments={} full_campaign_sealed=false\n", .{ input.segment_index, execution.segment_count });
    return admitted.selection;
}
