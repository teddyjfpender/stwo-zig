//! Setup-only ORIGINAL requester transcript and packed public geometry.
//! No Fresh/capture, claims acceptance, received key or proof admission exists.
const std = @import("std");
const core = @import("stwo_core");
const Scoped = @import("block_v5_heterogeneous_scoped_owner_v1.zig");
const Compact = @import("block_v5_heterogeneous_scoped_source_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Span = @import("block_v5_pc_clock_span_v1.zig").Span;
pub const PUBLIC_CIRCUIT = Compact.PUBLIC_CIRCUIT;
pub const Source = struct {
    owner: *const Scoped.Owner,
    lease: Scoped.Borrow,
    /// Arena belongs to the independently constructed immutable Scoped.Owner.
    compact: Compact.Source,
    terms: @FieldType(Compact.Source, "terms"),
    pub const complete_block_authority = false;
    pub fn init(owner: *const Scoped.Owner) !Source {
        var lease = try owner.borrow();
        errdefer lease.deinit();
        if (owner.scoped.recipe != .requesters or owner.cohorts.recipe != .requesters or owner.cohorts.root != .node) return error.NotRequesterSummaryRoot;
        const compact = try owner.source(owner.cohorts.root);
        const source = Source{ .owner = owner, .lease = lease, .compact = compact, .terms = compact.terms };
        try source.validate();
        return source;
    }
    pub fn validate(self: *const Source) !void {
        var lease = try self.owner.borrow();
        defer lease.deinit();
        if (self.owner.scoped.recipe != .requesters or self.owner.cohorts.recipe != .requesters or self.owner.cohorts.root != .node or self.lease.owner != self.owner) return error.NotRequesterSummaryRoot;
        try self.compact.validate();
        const independent = try self.owner.source(self.owner.cohorts.root);
        if (!std.meta.eql(self.compact.key, independent.key) or !std.meta.eql(self.compact.expected_id, independent.expected_id) or !std.meta.eql(self.compact.ref, independent.ref) or !std.meta.eql(self.compact.seal, independent.seal) or
            self.compact.frames.ptr != independent.frames.ptr or self.compact.frames.len != independent.frames.len or
            self.terms.ptr != independent.terms.ptr or self.terms.len != independent.terms.len) return error.UntrustedRequesterSetupSource;
    }
    pub fn replayPublic(self: *const Source, recorder: anytype) void {
        // Same exact operation order and coordinates as Compact.replayPublic.
        // Generic recorder enables the original trusted fixed-only compiler.
        for (self.compact.frames) |frame| {
            const caller = @import("air/blake3_transcript_witness.zig").Caller{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.first };
            switch (frame.operation) {
                .words => |values| recorder.mixPublicWords(caller, values),
                .root => |value| recorder.mixPublicRoot(caller, value),
                .integer => |value| recorder.mixPublicInteger(caller, value),
                .felts => |values| recorder.mixPublicFelts(caller, values),
            }
        }
    }
    pub fn deinit(self: *Source) void {
        // Deliberately do not destroy the borrowed compact Arena facade.
        self.lease.deinit();
        self.* = undefined;
    }
};
pub const Admission = struct {
    pub const fixed_setup_only = true;
    source: *const Source,
    key: Base.Key,
    pc_clock_children: []const Span = &.{},
    pub fn init(source: *const Source) !Admission {
        try source.validate();
        return .{ .source = source, .key = source.compact.key };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        if (self.pc_clock_children.len != 0 or !std.meta.eql(self.key, self.source.compact.key)) return error.UntrustedRequesterSetupSource;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
};
