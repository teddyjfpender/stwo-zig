//! One actual fresh root verification plus exact NEW transcript normalization.
//! Expected public job and trusted setup are independent receiver inputs.
const std = @import("std");
const File = @import("../prover/block_v5_global_expected_public_file_v1.zig");
const Job = @import("block_v5_global_expected_public_job_v1.zig");
const Public = @import("block_v5_global_public_export_policy_v1.zig");
const Fields = @import("block_v5_global_public_fields_v1.zig");
const Bus = @import("block_v5_global_public_export_bus_v1.zig");
const Protocol = @import("block_v5_reusable_global_public_export_protocol_v1.zig");
const Receiver = @import("block_v5_global_public_export_receiver_v1.zig");
const Norm = @import("block_v5_global_public_export_normalizer_v1.zig");
pub const Limits = struct { file: File.Limits = .{}, fields: Fields.Limits = .{}, normalizer: Norm.Limits = .{} };
pub const Fresh = struct {
    equation: Receiver.OpenEquation,
    normalized: Norm.Normalized,
    expected: *File.Owned,
    normalization_source: [32]u8,
    pub const complete_block_authority = false;
    pub const source_authorities_pending = Receiver.OpenEquation.source_authorities_pending;
    pub fn deinit(self: *Fresh) void {
        self.equation.deinit();
        self.normalized.deinit();
        self.expected.deinit();
        self.* = undefined;
    }
    /// Rebuild all exact public fields and routing descriptors. Neither an
    /// altered coordinate nor an altered original statement can reuse capture.
    pub fn validate(self: *const Fresh, a: std.mem.Allocator, original: Public.Policy, key: Protocol.Key, id: [32]u8, schedule: []const Bus.Wire, fields_limits: Fields.Limits) !void {
        if (!std.meta.eql(self.normalization_source, Norm.sourceAuthority())) return error.UntrustedPublicExportNormalizer;
        const policy = try self.expected.bind(original);
        var public = try Public.init(a, policy, fields_limits);
        defer public.deinit();
        const admission = try Protocol.Admission.init(key, id, schedule, .{ .public = &public });
        try self.equation.equation.validate(&admission, id);
        try self.normalized.validate(&admission);
        if (self.equation.equation.public_input_digest == null or !std.meta.eql(self.equation.equation.public_input_digest.?, self.normalized.public_input_digest)) return error.UntrustedPublicExportNormalizer;
    }
};
/// read requires exact expected public bytes, not merely Pin or policy SHA.
/// Original policy owners must be independently restored through their genuine
/// typed admission loaders; this public file cannot fabricate those admissions.
pub fn verify(a: std.mem.Allocator, dir: std.fs.Dir, pin: File.Pin, independently_expected: Job.Expected, original: Public.Policy, bytes: []const u8, key: Protocol.Key, id: [32]u8, schedule: []const Bus.Wire, limits: Limits) !Fresh {
    const owner = try File.read(a, dir, pin, independently_expected, limits.file);
    errdefer owner.deinit();
    const policy = try owner.bind(original);
    var public = try Public.init(a, policy, limits.fields);
    defer public.deinit();
    const admission = try Protocol.Admission.init(key, id, schedule, .{ .public = &public });
    var checked = try Receiver.verifyPrepared(a, bytes, &admission);
    errdefer checked.deinit();
    var normalized = try Norm.normalize(a, &admission, limits.normalizer);
    errdefer normalized.deinit();
    try normalized.rehomeInput(owner.expected().input_words);
    if (checked.equation.public_input_digest == null or !std.meta.eql(checked.equation.public_input_digest.?, normalized.public_input_digest)) return error.UntrustedPublicExportNormalizer;
    return .{ .equation = checked, .normalized = normalized, .expected = owner, .normalization_source = Norm.sourceAuthority() };
}
