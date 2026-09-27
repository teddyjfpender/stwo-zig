//! Independently reconstructed fixed-setup policy, NOT a proof admission.
//! Deliberately lacks expected_id, admitRoot, mixClaims and a verified source.
//! A core/live verifier cannot consume this type as successful admission.
const core = @import("stwo_core");
const Bus = @import("block_v5_closed_input_request_forest_bus_v2.zig");
const Public = @import("block_v5_input_request_forest_public_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Protocol = @import("block_v5_closed_input_request_forest_protocol_v2.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
const Span = @import("block_v5_pc_clock_span_v1.zig").Span;
const SourceModule = @import("block_v5_closed_input_request_forest_source_v2.zig");
pub const Source = struct {
    public: *const Bus.Owner,
    terms: []const Term = &.{},
    pub fn validate(self: *const Source) !void {
        try self.public.validate();
        if (self.terms.len != 0) return error.ClosedInputRequestNodeHasNoPublicTerms;
    }
    /// Exact ORIGINAL public absorption recipe, using independent public values.
    /// No proof transcript is run and no main/capture values are supplied.
    pub fn replayPublic(self: *const Source, recorder: anytype) void {
        const R = @import("block_v5_compact_public_replay_v1.zig").ForRecorder(@TypeOf(recorder.*), SourceModule.PUBLIC_CIRCUIT);
        var replay = R{ .recorder = recorder };
        self.mix(&replay) catch |failure| {
            recorder.failure = failure;
            return;
        };
        const first = Bus.nodePrefix(self.public.policy) catch |failure| {
            recorder.failure = failure;
            return;
        };
        if (replay.cursor != first.len + self.public.summary.len) recorder.failure = error.UntrustedInputRequestNodeSource;
    }
    fn mix(self: *const Source, channel: anytype) !void {
        try self.validate();
        const spec = self.public.policy.specs[self.public.policy.index];
        channel.mixU32s(&.{ 0x42354d50, Protocol.VERSION, @intFromEnum(spec.geometry.profile) });
        spec.geometry.config.mixInto(channel);
        channel.mixRoot(spec.expected_id);
        try Public.mix(self.public.policy, channel);
    }
};
pub const Admission = struct {
    pub const fixed_setup_only = true;
    source: *const Source,
    key: Base.Key,
    pc_clock_children: []const Span = &.{},
    pub fn init(source: *const Source) !Admission {
        try source.validate();
        const spec = source.public.policy.specs[source.public.policy.index];
        return .{ .source = source, .key = spec.geometry };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        const spec = self.source.public.policy.specs[self.source.public.policy.index];
        if (!@import("std").meta.eql(self.key, spec.geometry) or self.pc_clock_children.len != 0) return error.UntrustedRecursiveParentShape;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
};
