//! Actual NEW public-root source adapter. The lazy normalizer is never coerced
//! to legacy H.Child/Source, and only the original fresh CPU receiver admits it.
const std = @import("std");
const core = @import("stwo_core");
const Public = @import("block_v5_global_public_export_policy_v1.zig");
const Protocol = @import("block_v5_reusable_global_public_export_protocol_v1.zig");
const Receiver = @import("block_v5_global_public_owned_receiver_v1.zig");
const Norm = @import("block_v5_global_public_export_normalizer_v1.zig");
const Original = @import("block_v5_heterogeneous_child_frames_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Bus = @import("block_v5_global_public_export_bus_v1.zig");
pub const Source = struct {
    allocator: std.mem.Allocator,
    fresh: *const Receiver.Fresh,
    public: Public.Owner,
    key: Protocol.Key,
    expected_id: [32]u8,
    schedule: []const Bus.Wire,
    terms: []Original.Term,
    fields_limits: @import("block_v5_global_public_fields_v1.zig").Limits,
    pub const complete_source_authority = false;
    pub fn init(a: std.mem.Allocator, fresh: *const Receiver.Fresh, original: Public.Policy, key: Protocol.Key, id: [32]u8, schedule: []const Bus.Wire, limits: @import("block_v5_global_public_fields_v1.zig").Limits) !Source {
        const policy = try fresh.expected.bind(original);
        var public = try Public.init(a, policy, limits);
        errdefer public.deinit();
        const admission = try Protocol.Admission.init(key, id, schedule, .{ .public = &public });
        try fresh.equation.equation.validate(&admission, id);
        try fresh.normalized.validate(&admission);
        if (!std.meta.eql(fresh.normalization_source, Norm.sourceAuthority())) return error.UntrustedPublicExportNormalizer;
        const terms = try a.alloc(Original.Term, schedule.len);
        errdefer a.free(terms);
        for (terms, schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try admission.values.at(wire) };
        return .{ .allocator = a, .fresh = fresh, .public = public, .key = key, .expected_id = id, .schedule = schedule, .terms = terms, .fields_limits = limits };
    }
    pub fn deinit(self: *Source) void {
        self.public.deinit();
        self.allocator.free(self.terms);
        self.* = undefined;
    }
    pub fn authority(self: *const Source) Protocol.Admission {
        return .{ .key = self.key, .expected_id = self.expected_id, .wires = self.schedule, .values = .{ .public = &self.public } };
    }
    pub fn validate(self: *const Source) !void {
        const admitted = self.authority();
        try self.fresh.equation.equation.validate(&admitted, self.expected_id);
        try self.fresh.normalized.validate(&admitted);
        if (!std.meta.eql(self.fresh.normalization_source, Norm.sourceAuthority()) or self.terms.len != self.schedule.len) return error.UntrustedPublicExportNormalizer;
        for (self.terms, self.schedule) |term, wire| {
            if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative != wire.negative or !std.meta.eql(term.coordinates, try admitted.values.at(wire))) return error.UntrustedScopedPublicSource;
        }
    }
    pub fn replayPublic(self: *const Source, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        self.fresh.normalized.replay(recorder);
    }
    pub fn mix(self: *const Source, channel: anytype) !void {
        const admitted = self.authority();
        try admitted.mix(channel);
    }
};
pub const Admission = struct {
    /// Existing generic verifier of the actual parent AIR, with a distinct
    /// independently chosen NEW public-root key/transcript/claim authority.
    pub const open_parent_v5_v2 = true;
    source: *const Source,
    key: Base.Key,
    expected_id: [32]u8,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn init(source: *const Source) Admission {
        return .{ .source = source, .key = .{ .profile = source.key.profile, .config = source.key.config, .context = source.key.context, .log_sizes = source.key.log_sizes, .preprocessed_root = source.key.preprocessed_root }, .expected_id = source.expected_id };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        const expected = init(self.source);
        if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedScopedPublicSource;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        const admitted = self.source.authority();
        try admitted.admitRoot(root);
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        return self.source.fresh.normalized.public_input_digest;
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        try self.source.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const core.fields.qm31.QM31) !void {
        try self.validate();
        const admitted = self.source.authority();
        try admitted.mixClaims(channel, claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        const admitted = self.source.authority();
        try admitted.validateClaimsForRelations(claims, relations);
    }
};
