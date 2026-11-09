//! Manifest entry for repeated leaf batches in one CUDA runtime.
//! A campaign may publish leaves for a later global fold or prove one root
//! per batch. It never silently substitutes a per-batch root for the global
//! root over the complete ordered sequence.

const std = @import("std");

pub const CampaignJob = struct {
    manifest: []const u8,
    root_proof: ?[]const u8 = null,
    root_outputs: ?[]const u8 = null,
    root_packed: ?[]const u8 = null,
    root_mode: []const u8 = "canonical",

    pub fn validate(self: CampaignJob) !void {
        if (self.manifest.len == 0) return error.MissingBatchManifest;
        const integrated = self.root_proof != null;
        if (integrated != (self.root_outputs != null) or integrated != (self.root_packed != null))
            return error.IncompleteRootOutputPaths;
        if (!std.mem.eql(u8, self.root_mode, "canonical") and !std.mem.eql(u8, self.root_mode, "compact"))
            return error.InvalidRootMode;
        if (std.mem.eql(u8, self.root_mode, "compact") and !integrated)
            return error.CompactRootRequiresIntegratedFold;
    }
};

test "rootless campaign batch and complete integrated batch are distinct" {
    try (CampaignJob{ .manifest = "batch.json" }).validate();
    try (CampaignJob{
        .manifest = "batch.json",
        .root_proof = "root.proof",
        .root_outputs = "outputs.json",
        .root_packed = "packed.json",
    }).validate();
    try std.testing.expectError(error.IncompleteRootOutputPaths, (CampaignJob{ .manifest = "batch.json", .root_proof = "root.proof" }).validate());
    try std.testing.expectError(error.CompactRootRequiresIntegratedFold, (CampaignJob{ .manifest = "batch.json", .root_mode = "compact" }).validate());
}

test "rootless campaign JSON from the service has no root fields" {
    const parsed = try std.json.parseFromSlice([]CampaignJob, std.testing.allocator, "[{\"manifest\":\"/tmp/batch.json\"}]", .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.len);
    try parsed.value[0].validate();
    try std.testing.expect(parsed.value[0].root_proof == null);
}
