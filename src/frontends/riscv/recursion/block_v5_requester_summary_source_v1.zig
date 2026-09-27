//! Actual freshly verified requester-only scoped root. This borrows the original
//! root's exact transcript; no host-computed sum or public compensation receipt.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Owner = @import("block_v5_heterogeneous_scoped_owner_v1.zig");
const Scoped = @import("block_v5_heterogeneous_scoped_plan_v1.zig");
const Frames = @import("block_v5_heterogeneous_scoped_source_v1.zig");
const Fresh = @import("block_v5_heterogeneous_scoped_receiver_v1.zig").Fresh;
pub const PUBLIC_CIRCUIT = Frames.PUBLIC_CIRCUIT;
pub const Coordinate = struct { first_cell: u32, word_count: u32 = 4 };
pub const Source = struct {
    owner: *const Owner.Owner,
    fresh: *const Fresh,
    lease: Owner.Borrow,
    /// Borrowed from Fresh, whose lifetime must contain this owner.
    terms: @FieldType(Frames.Source, "terms"),
    pub const complete_block_authority = false;
    pub fn init(owner: *const Owner.Owner, fresh: *const Fresh) !Source {
        var lease = try owner.borrow();
        errdefer lease.deinit();
        const result = Source{ .owner = owner, .fresh = fresh, .lease = lease, .terms = fresh.source.terms };
        try result.validate();
        return result;
    }
    pub fn deinit(self: *Source) void {
        self.lease.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Source) !void {
        if (self.owner.scoped.recipe != .requesters or self.owner.cohorts.recipe != .requesters or self.owner.cohorts.root != .node) return error.NotRequesterSummaryRoot;
        const index = self.owner.cohorts.root.node;
        const authority = try self.owner.node(index);
        try self.fresh.equation.validate(&authority, authority.expected_id);
        try self.fresh.source.validate();
        const expected = try self.owner.source(self.owner.cohorts.root);
        if (!std.meta.eql(expected.seal, self.fresh.source.seal) or !std.meta.eql(expected.ref, self.fresh.source.ref) or self.terms.ptr != self.fresh.source.terms.ptr or self.terms.len != self.fresh.source.terms.len) return error.UntrustedRequesterSummarySource;
        _ = try self.transition();
    }
    pub fn claim(self: *const Source, key: Scoped.Key) !Coordinate {
        var id: ?u32 = null;
        for (self.owner.scoped.requirements, 0..) |requirement, index| if (std.meta.eql(requirement.key, key)) {
            if (id != null or requirement.disposition != .retain) return error.InvalidRequesterSummaryClaim;
            id = @intCast(index);
        };
        const slot = try self.fresh.source.findSlot(id orelse return error.MissingRequesterSummaryClaim);
        return .{ .first_cell = slot.first };
    }
    pub fn transition(self: *const Source) !Coordinate {
        return self.claim(.{ .kind = .transition, .scope = 0, .coordinate = 0 });
    }
    pub fn publicNative(self: *const Source, window: u32) !Coordinate {
        return self.claim(.{ .kind = .public_auth, .scope = window, .coordinate = 32 });
    }
    pub fn publicDigest(self: *const Source, window: u32, byte: u32) !Coordinate {
        if (byte >= 32) return error.InvalidRequesterSummaryClaim;
        return self.claim(.{ .kind = .public_auth, .scope = window, .coordinate = byte });
    }
    pub fn baseSealByte(self: *const Source, byte: u32) !Coordinate {
        if (byte >= 32) return error.InvalidRequesterSummaryClaim;
        return self.claim(.{ .kind = .public_auth, .scope = 0, .coordinate = 33 + byte });
    }
    pub fn cell(self: *const Source, coordinate: u32) ![4]M {
        if (coordinate >= self.fresh.source.cells.len) return error.InvalidRequesterSummaryCoordinate;
        return self.fresh.source.cells[coordinate];
    }
    pub fn replayPublic(self: *const Source, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        self.fresh.source.replayPublic(recorder);
    }
};
pub const Admission = struct {
    pub const open_parent_v5_v2 = true;
    source: *const Source,
    key: @import("blake3_execution_parent_protocol.zig").Key,
    expected_id: [32]u8,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn init(source: *const Source) Admission {
        return .{ .source = source, .key = source.fresh.source.key, .expected_id = source.fresh.source.expected_id };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        const expected = init(self.source);
        if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedRequesterSummarySource;
    }
    fn original(self: *const Admission) Frames.Admission {
        return Frames.Admission.init(&self.source.fresh.source, &.{});
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        const authority = self.original();
        try authority.admitRoot(root);
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        const authority = self.original();
        return authority.publicInputIdentity();
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        const authority = self.original();
        try authority.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
        try self.validate();
        const authority = self.original();
        try authority.mixClaims(channel, claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        const authority = self.original();
        try authority.validateClaimsForRelations(claims, relations);
    }
};
