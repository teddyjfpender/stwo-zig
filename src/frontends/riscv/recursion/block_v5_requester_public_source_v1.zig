//! Genuine public-closed requester root -> original transcript suppliers.
//! Only requester transition remains for the compact memory-root join.
//! No metadata source or unverified token constructs this Fresh owner.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Base = @import("blake3_execution_parent_protocol.zig");
const Receiver = @import("block_v5_requester_public_receiver_v1.zig");
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const Compare = @import("air/block_v5_recursive_statement_compare_v1.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
pub const PUBLIC_CIRCUIT: u32 = 4_300_450;
pub const Limits = struct { max_words: usize = 16 << 20, max_steps: usize = 1 << 20, max_felts: usize = 1 << 20, max_terms: usize = 16 << 20 };
pub const Source = struct {
    a: std.mem.Allocator,
    lease: ?*Budget,
    fresh: *const Receiver.Fresh,
    frame: Frames.Statement,
    transition_first: u32,
    terms: []Term,
    limits: Limits,
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, fresh: *const Receiver.Fresh, limits: Limits) !Source {
        if (limits.max_words == 0 or limits.max_steps == 0 or limits.max_felts == 0 or limits.max_terms == 0) return error.RequesterPublicSourceLimit;
        try fresh.validate();
        const authority = try fresh.authority();
        if (authority.wires.len == 0 or authority.wires.len > limits.max_terms) return error.RequesterPublicSourceLimit;
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const frame = try record(a, &authority, limits);
        errdefer {
            var owned = frame;
            owned.deinit();
        }
        const terms = try a.alloc(Term, authority.wires.len);
        errdefer a.free(terms);
        for (terms, authority.wires) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try authority.values.at(wire) };
        return .{ .a = a, .lease = lease, .fresh = fresh, .frame = frame, .transition_first = try transitionFirst(&frame), .terms = terms, .limits = limits };
    }
    pub fn validate(self: *const Source) !void {
        try self.fresh.validate();
        const authority = try self.fresh.authority();
        if (authority.wires.len != self.terms.len or self.terms.len == 0 or self.terms.len > self.limits.max_terms) return error.RequesterPublicSourceLimit;
        for (self.terms, authority.wires) |term, wire| {
            if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative != wire.negative or !std.meta.eql(term.coordinates, try authority.values.at(wire))) return error.MutatedRequesterPublicSource;
        }
        try requireFrame(&self.frame, self.transition_first, &authority, self.limits);
    }
    pub fn deinit(self: *Source) void {
        const lease = self.lease;
        self.a.free(self.terms);
        self.frame.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
    pub fn requester(self: *const Source) *const @import("block_v5_heterogeneous_scoped_owner_v1.zig").Owner {
        return self.fresh.policy.public.requester;
    }
    pub fn transition(self: *const Source) !struct { first_cell: u32, word_count: u32 = 4 } {
        return .{ .first_cell = self.transition_first };
    }
    pub fn cell(self: *const Source, coordinate: u32) ![4]M {
        if (coordinate >= self.frame.words.len + 4 * self.frame.felts.len) return error.InvalidRequesterPublicCoordinate;
        const value = if (coordinate < self.frame.words.len) self.frame.words[coordinate] else self.frame.felts[(coordinate - self.frame.words.len) / 4].toM31Array()[(coordinate - self.frame.words.len) % 4].v;
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, i| byte.* = M.fromCanonical((value >> @as(u5, @intCast(8 * i))) & 255);
        return bytes;
    }
    pub fn replayPublic(self: *const Source, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        self.frame.recordAt(recorder, self.frame.first, PUBLIC_CIRCUIT) catch |err| {
            recorder.failure = err;
        };
    }
};
fn requireFrame(frame: *const Frames.Statement, transition_first: u32, authority: anytype, limits: Limits) !void {
    try Compare.compareFirst(frame, .{ .max_words = limits.max_words, .max_felts = limits.max_felts, .max_steps = limits.max_steps }, .{ .sealed_offset = 0, .roots_offset = @splat(0) }, authority);
    // Retain the original recording grammar. Bounds and exact operation
    // offsets have been checked before deriving the final public coordinate.
    if (frame.first.len == 0 or frame.first.len > limits.max_steps or frame.felts.len == 0) return error.RequesterPublicSourceLimit;
    if (transition_first != try transitionFirst(frame)) return error.MutatedRequesterPublicSource;
}
fn record(a: std.mem.Allocator, authority: anytype, limits: Limits) !Frames.Statement {
    var builder = Frames.Builder{ .allocator = a, .max_words = limits.max_words, .max_felts = limits.max_felts, .track_root_offsets = false };
    defer builder.deinit();
    try authority.mix(&builder);
    try builder.check();
    if (builder.steps.items.len == 0 or builder.steps.items.len > limits.max_steps or builder.fields.items.len == 0) return error.RequesterPublicSourceLimit;
    const final = builder.steps.items[builder.steps.items.len - 1];
    if (final != .felts or final.felts.first + 1 != builder.fields.items.len or final.felts.len != 1) return error.UntrustedRequesterPublicLayout;
    const words = try builder.data.toOwnedSlice(a);
    errdefer a.free(words);
    const fields = try builder.fields.toOwnedSlice(a);
    errdefer a.free(fields);
    const steps = try builder.steps.toOwnedSlice(a);
    errdefer a.free(steps);
    const claims = try a.alloc(Frames.Step, 0);
    return .{ .allocator = a, .words = words, .felts = fields, .first = steps, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) };
}
fn transitionFirst(frame: *const Frames.Statement) !u32 {
    if (frame.first.len == 0) return error.UntrustedRequesterPublicLayout;
    const final = frame.first[frame.first.len - 1];
    if (final != .felts or final.felts.len != 1 or final.felts.first + 1 != frame.felts.len) return error.UntrustedRequesterPublicLayout;
    return std.math.add(u32, std.math.cast(u32, frame.words.len) orelse return error.RequesterPublicSourceLimit, try std.math.mul(u32, 4, final.felts.first));
}
pub const Admission = struct {
    pub const open_parent_v5_v2 = true;
    source: *const Source,
    key: Base.Key,
    expected_id: [32]u8,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn init(source: *const Source) Admission {
        const key = source.fresh.policy.key;
        return .{ .source = source, .key = .{ .profile = key.profile, .config = key.config, .context = key.context, .log_sizes = key.log_sizes, .preprocessed_root = key.preprocessed_root }, .expected_id = source.fresh.policy.expected_id };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        const original = init(self.source);
        if (!std.meta.eql(self.key, original.key) or !std.meta.eql(self.expected_id, original.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedRequesterPublicSource;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        const authority = try self.source.fresh.authority();
        try authority.admitRoot(root);
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        const authority = try self.source.fresh.authority();
        return authority.publicInputIdentity();
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        const authority = try self.source.fresh.authority();
        try authority.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
        try self.validate();
        const authority = try self.source.fresh.authority();
        try authority.mixClaims(channel, claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        const authority = try self.source.fresh.authority();
        try authority.validateClaimsForRelations(claims, relations);
    }
};

/// Framing oracle only: this does not validate or construct any Fresh/Source.
pub const testing = if (@import("builtin").is_test) struct {
    pub const recordFrame = record;
    pub const transitionCoordinate = transitionFirst;
    pub const checkFrame = requireFrame;
} else struct {};
