//! PUBLIC21 fixed compiler source derived from exact independently admitted
//! public Owner/key/schedule; never from a transported artifact or Fresh.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = @import("block_v5_requester_public_compensation_v1.zig");
const Bus = @import("block_v5_requester_public_bus_v1.zig");
const Protocol = @import("block_v5_requester_public_protocol_v1.zig");
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const Compare = @import("air/block_v5_recursive_statement_compare_v1.zig");
const OriginalSource = @import("block_v5_requester_public_source_v1.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
const Span = @import("block_v5_pc_clock_span_v1.zig").Span;
pub const PUBLIC_CIRCUIT = OriginalSource.PUBLIC_CIRCUIT;
pub const Limits = OriginalSource.Limits;
pub const Source = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    public: *const Public.Owner,
    key: Protocol.Key,
    independently_expected: [32]u8,
    wires: []const Bus.Wire,
    frame: Frames.Statement,
    terms: []Term,
    limits: Limits,
    pub const complete_block_authority = false;
    /// Key/schedule must have been independently derived by the original
    /// PUBLIC21 family compiler. This setup-only object grants no acceptance.
    pub fn init(a: std.mem.Allocator, public: *const Public.Owner, key: Protocol.Key, independently_expected: [32]u8, wires: []const Bus.Wire, limits: Limits) !Source {
        if (limits.max_words == 0 or limits.max_steps == 0 or limits.max_felts == 0 or limits.max_terms == 0 or wires.len == 0 or wires.len > limits.max_terms or wires.len > std.math.maxInt(u32)) return error.RequesterPublicSourceLimit;
        const independently_admitted = try Protocol.Admission.init(key, independently_expected, wires, .{ .public = public });
        const allocation_owner = if (Budget.fromAllocator(a)) |budget| budget.retain() else null;
        errdefer if (allocation_owner) |budget| budget.destroy();
        var builder = Frames.Builder{ .allocator = a, .max_words = limits.max_words, .max_felts = limits.max_felts, .track_root_offsets = false };
        defer builder.deinit();
        try independently_admitted.mix(&builder);
        try builder.check();
        if (builder.steps.items.len == 0 or builder.steps.items.len > limits.max_steps) return error.RequesterPublicSourceLimit;
        const words = try builder.data.toOwnedSlice(a);
        errdefer a.free(words);
        const felts = try builder.fields.toOwnedSlice(a);
        errdefer a.free(felts);
        const steps = try builder.steps.toOwnedSlice(a);
        errdefer a.free(steps);
        const claims = try a.alloc(Frames.Step, 0);
        errdefer a.free(claims);
        const frame = Frames.Statement{ .allocator = a, .words = words, .felts = felts, .first = steps, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) };
        const terms = try a.alloc(Term, wires.len);
        errdefer a.free(terms);
        for (wires, terms) |wire, *term| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try independently_admitted.values.at(wire) };
        const source = Source{ .allocator = a, .allocation_owner = allocation_owner, .public = public, .key = key, .independently_expected = independently_expected, .wires = wires, .frame = frame, .terms = terms, .limits = limits };
        try source.validate();
        return source;
    }
    fn authority(self: *const Source) !Protocol.Admission {
        return Protocol.Admission.init(self.key, self.independently_expected, self.wires, .{ .public = self.public });
    }
    pub fn validate(self: *const Source) !void {
        if (self.limits.max_terms == 0 or self.wires.len == 0 or self.wires.len > self.limits.max_terms or self.wires.len > std.math.maxInt(u32) or self.terms.len != self.wires.len) return error.RequesterPublicSourceLimit;
        const admitted = try self.authority();
        try Compare.compareFirst(&self.frame, .{ .max_words = self.limits.max_words, .max_felts = self.limits.max_felts, .max_steps = self.limits.max_steps }, .{ .sealed_offset = 0, .roots_offset = @splat(0) }, admitted);
        for (self.wires, self.terms) |wire, term| {
            const independent = Term{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try admitted.values.at(wire) };
            if (!std.meta.eql(term, independent)) return error.UntrustedRequesterPublicSetupTerm;
        }
    }
    pub fn replayPublic(self: *const Source, recorder: anytype) void {
        // ONE original source compiler: words occupy the first flattened
        // region, and all felt limbs begin after frame.words. Operation order
        // is unchanged even when the original mix interleaves words/felts.
        self.frame.recordAt(recorder, self.frame.first, PUBLIC_CIRCUIT) catch |failure| {
            recorder.failure = failure;
        };
    }
    pub fn deinit(self: *Source) void {
        const budget = self.allocation_owner;
        self.allocator.free(self.terms);
        self.frame.deinit();
        self.* = undefined;
        if (budget) |owner| owner.destroy();
    }
};
pub const Admission = struct {
    pub const fixed_setup_only = true;
    source: *const Source,
    key: Protocol.Key,
    pc_clock_children: []const Span = &.{},
    pub fn init(source: *const Source) !Admission {
        try source.validate();
        return .{ .source = source, .key = source.key };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        if (self.pc_clock_children.len != 0 or !std.meta.eql(self.key, self.source.key)) return error.UntrustedRequesterPublicSetupTerm;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
};
