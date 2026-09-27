//! Setup-only exact original V20 frame. Expected key must come from independent
//! original preparation inside the family owner; no proof acceptance exists.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Original = @import("block_v5_source_ram_forest_join_source_v1.zig");
const Protocol = @import("block_v5_source_ram_forest_join_protocol_v1.zig");
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const Compare = @import("air/block_v5_recursive_statement_compare_v1.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
pub const PUBLIC_CIRCUIT = Original.PUBLIC_CIRCUIT;
pub const Source = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    original: *const Original.Source,
    key: Protocol.Key,
    independently_expected: [32]u8,
    frame: Frames.Statement,
    terms: []Term,
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, original: *const Original.Source, key: Protocol.Key, independently_expected: [32]u8) !Source {
        try original.validate();
        if (!std.meta.eql(original.fresh.policy.key, key) or !std.meta.eql(original.fresh.policy.expected_id, independently_expected)) return error.UnpairedMemoryRootExpectedSetup;
        const authority = try Protocol.Admission.init(key, independently_expected, &.{}, .{ .public = &original.fresh.public });
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        var builder = Frames.Builder{ .allocator = a, .max_words = original.limits.max_words, .max_felts = 4 };
        defer builder.deinit();
        try authority.mix(&builder);
        try builder.check();
        if (builder.steps.items.len == 0 or builder.steps.items.len > original.limits.max_steps) return error.SourceRamJoinSourceLimit;
        const words = try builder.data.toOwnedSlice(a);
        errdefer a.free(words);
        const felts = try builder.fields.toOwnedSlice(a);
        errdefer a.free(felts);
        const steps = try builder.steps.toOwnedSlice(a);
        errdefer a.free(steps);
        const claims = try a.alloc(Frames.Step, 0);
        errdefer a.free(claims);
        const terms = try a.alloc(Term, 0);
        errdefer a.free(terms);
        const result = Source{ .allocator = a, .lease = lease, .original = original, .key = key, .independently_expected = independently_expected, .frame = .{ .allocator = a, .words = words, .felts = felts, .first = steps, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) }, .terms = terms };
        try result.validate();
        return result;
    }
    pub fn validate(self: *const Source) !void {
        try self.original.validate();
        if (self.terms.len != 0 or !std.meta.eql(self.key, self.original.fresh.policy.key) or !std.meta.eql(self.independently_expected, self.original.fresh.policy.expected_id)) return error.UnpairedMemoryRootExpectedSetup;
        const authority = try Protocol.Admission.init(self.key, self.independently_expected, &.{}, .{ .public = &self.original.fresh.public });
        try Compare.compareFirst(&self.frame, .{ .max_words = self.original.limits.max_words, .max_steps = self.original.limits.max_steps, .max_felts = 4 }, .{ .sealed_offset = 0, .roots_offset = @splat(0) }, authority);
        try Compare.compareFirst(&self.original.frame, .{ .max_words = self.original.limits.max_words, .max_steps = self.original.limits.max_steps, .max_felts = 4 }, .{ .sealed_offset = 0, .roots_offset = @splat(0) }, authority);
    }
    pub fn replayPublic(self: *const Source, recorder: anytype) void {
        self.frame.recordAt(recorder, self.frame.first, PUBLIC_CIRCUIT) catch |failure| {
            recorder.failure = failure;
        };
    }
    pub fn deinit(self: *Source) void {
        const lease = self.lease;
        self.allocator.free(self.terms);
        self.frame.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
pub const Admission = struct {
    pub const fixed_setup_only = true;
    source: *const Source,
    key: Protocol.Key,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn init(source: *const Source) !Admission {
        try source.validate();
        return .{ .source = source, .key = source.key };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        if (self.pc_clock_children.len != 0 or !std.meta.eql(self.key, self.source.key)) return error.UnpairedMemoryRootExpectedSetup;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
};
