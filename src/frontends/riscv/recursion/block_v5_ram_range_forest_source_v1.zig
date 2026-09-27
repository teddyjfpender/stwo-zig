//! Authentic compact RAM/range parent source. Fresh and independent job policy must
//! outlive this source. Only local shard range and merge equations are closed; endpoint and
//! transition/global compensation still require their genuine child verifiers.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Base = @import("blake3_execution_parent_protocol.zig");
const Receiver = @import("block_v5_ram_range_forest_summary_receiver_v1.zig");
const Protocol = @import("block_v5_ram_range_forest_summary_protocol_v1.zig");
const Bus = @import("block_v5_ram_range_forest_bus_v1.zig");
const Norm = @import("block_v5_memory_source_page_forest_normalizer_v1.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
pub const PUBLIC_CIRCUIT: u32 = 4_300_430;
pub const Coordinate = struct { first_cell: u32, word_count: u32 };
pub const Source = struct {
    allocator: std.mem.Allocator,
    owner: ?*Budget,
    fresh: *const Receiver.Fresh,
    terms: []Term,
    normal: Norm.Normalized,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, fresh: *const Receiver.Fresh) !Source {
        try fresh.validate();
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const admission = try fresh.authority();
        const summary = &fresh.public.summary;
        var normal = try Norm.Normalized.initWithWords(a, &admission, &summary.value, 0, &summary.header, fresh.policy.public_limits.normalization);
        errdefer normal.deinit();
        if (fresh.policy.schedule.len != 0) return error.ClosedRamRangeForestHasNoPublicTerms;
        const terms = try a.alloc(Term, 0);
        errdefer a.free(terms);
        for (terms, fresh.policy.schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try admission.values.at(wire) };
        return .{ .allocator = a, .owner = lease, .fresh = fresh, .terms = terms, .normal = normal };
    }
    pub fn deinit(self: *Source) void {
        const lease = self.owner;
        self.allocator.free(self.terms);
        self.normal.deinit();
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
    pub fn validate(self: *const Source) !void {
        try self.fresh.validate();
        const admission = try self.fresh.authority();
        const summary = &self.fresh.public.summary;
        try self.normal.requireWithWords(self.allocator, &admission, &summary.value, 0, &summary.header, self.fresh.policy.public_limits.normalization);
        if (self.terms.len != 0 or self.fresh.policy.schedule.len != 0) return error.UntrustedRamRangeForestNode;
        for (self.terms, self.fresh.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative != wire.negative or !std.meta.eql(term.coordinates, try admission.values.at(wire))) return error.UntrustedRamRangeForestNode;
    }
    pub fn cell(self: *const Source, index: u32) ![4]M {
        return self.normal.cell(index);
    }
    pub fn claimFirst(self: *const Source) u32 {
        return self.normal.claim_first;
    }
    pub fn claim(self: *const Source, index: u32) !Coordinate {
        if (index >= 22) return error.InvalidRamRangeForestCell;
        return .{ .first_cell = try std.math.add(u32, self.claimFirst(), try std.math.mul(u32, 4, index)), .word_count = 4 };
    }
    pub fn transition(self: *const Source) !Coordinate {
        return self.claim(0);
    }
    pub fn predecessor(self: *const Source) !Coordinate {
        return self.claim(1);
    }
    pub fn initial(self: *const Source) !Coordinate {
        return self.claim(2);
    }
    pub fn endpoint(self: *const Source) !Coordinate {
        return self.claim(3);
    }
    pub fn endpointCount(self: *const Source) !Coordinate {
        return self.claim(4);
    }
    pub fn headerFirst(self: *const Source) !u32 {
        return self.normal.word_first orelse error.UntrustedRamRangeForestClaimLayout;
    }
    pub fn replayPublic(self: *const Source, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        self.normal.replay(recorder, PUBLIC_CIRCUIT);
    }
};
pub const Admission = struct {
    pub const open_parent_v5_v2 = true;
    source: *const Source,
    key: Base.Key,
    expected_id: [32]u8,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn init(source: *const Source) Admission {
        const k = source.fresh.policy.key;
        return .{ .source = source, .key = .{ .profile = k.profile, .config = k.config, .context = k.context, .log_sizes = k.log_sizes, .preprocessed_root = k.preprocessed_root }, .expected_id = source.fresh.policy.expected_id };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        const expected = init(self.source);
        if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedRamRangeForestNode;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        const actual = try self.source.fresh.authority();
        try actual.admitRoot(root);
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        const actual = try self.source.fresh.authority();
        return actual.publicInputIdentity();
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        const actual = try self.source.fresh.authority();
        try actual.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
        try self.validate();
        const actual = try self.source.fresh.authority();
        try actual.mixClaims(channel, claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        const actual = try self.source.fresh.authority();
        try actual.validateClaimsForRelations(claims, relations);
    }
};
