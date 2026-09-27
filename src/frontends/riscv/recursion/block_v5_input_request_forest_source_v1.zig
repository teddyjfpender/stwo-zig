//! Genuine compact request node -> exact authenticated public bytes for its
//! next bounded parent. Descendant input/public data is never replayed here.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Receiver = @import("block_v5_input_request_forest_receiver_v1.zig");
const Bus = @import("block_v5_input_request_forest_bus_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
const Recorder = @import("air/blake3_native_recorder.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_300_280;
pub const Coordinate = @import("block_v5_input_request_forest_public_v1.zig").Coordinate;
const Replay = struct {
    recorder: *Recorder.Recorder,
    cursor: u32 = 0,
    fn next(self: *Replay, len: usize) @import("air/blake3_transcript_witness.zig").Caller {
        const first = self.cursor;
        self.cursor = std.math.add(u32, self.cursor, std.math.cast(u32, len) orelse {
            self.recorder.failure = error.InputRequestNodeResourceLimit;
            return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
        }) catch {
            self.recorder.failure = error.InputRequestNodeResourceLimit;
            return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
        };
        return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
    }
    pub fn mixU32s(self: *Replay, words: []const u32) void {
        self.recorder.mixPublicWords(self.next(words.len), words);
    }
    pub fn mixRoot(self: *Replay, root: [32]u8) void {
        self.recorder.mixPublicRoot(self.next(8), root);
    }
    pub fn mixFelts(self: *Replay, values: []const Q) void {
        const count = std.math.mul(usize, values.len, 4) catch {
            self.recorder.failure = error.InputRequestNodeResourceLimit;
            return;
        };
        self.recorder.mixPublicFelts(self.next(count), values);
    }
};
pub const Source = struct {
    allocator: std.mem.Allocator,
    owner: ?*Budget,
    fresh: *const Receiver.Fresh,
    terms: []Term,
    prefix: [32]u32,
    prefix_count: u32,
    cell_count: u32,
    public_input_digest: [32]u8,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn init(a: std.mem.Allocator, fresh: *const Receiver.Fresh) !Source {
        try fresh.validate();
        const admission = try fresh.authority();
        const first = try Bus.nodePrefix(fresh.policy.public);
        const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (lease) |owner| owner.destroy();
        const terms = try a.alloc(Term, fresh.policy.schedule.len);
        errdefer a.free(terms);
        for (terms, fresh.policy.schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try admission.values.at(wire) };
        return .{ .allocator = a, .owner = lease, .fresh = fresh, .terms = terms, .prefix = first.words, .prefix_count = first.len, .cell_count = try std.math.add(u32, first.len, fresh.public.summary.len), .public_input_digest = try admission.publicInputIdentity() };
    }
    pub fn deinit(self: *Source) void {
        const lease = self.owner;
        self.allocator.free(self.terms);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
    pub fn validate(self: *const Source) !void {
        try self.fresh.validate();
        const admission = try self.fresh.authority();
        const first = try Bus.nodePrefix(self.fresh.policy.public);
        if (self.prefix_count != first.len or self.cell_count != try std.math.add(u32, first.len, self.fresh.public.summary.len) or !std.mem.eql(u32, self.prefix[0..self.prefix_count], first.words[0..first.len]) or !std.meta.eql(self.public_input_digest, try admission.publicInputIdentity()) or self.terms.len != self.fresh.policy.schedule.len) return error.UntrustedInputRequestNodeSource;
        for (self.terms, self.fresh.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative != wire.negative or !std.meta.eql(term.coordinates, try admission.values.at(wire))) return error.UntrustedInputRequestNodeSource;
    }
    pub fn cell(self: *const Source, index: u32) ![4]M {
        if (index >= self.cell_count) return error.InvalidInputRequestNodeCell;
        if (index >= self.prefix_count) return self.fresh.public.summary.cell(index - self.prefix_count);
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((self.prefix[index] >> @as(u5, @intCast(8 * part))) & 255);
        return bytes;
    }
    fn lift(self: *const Source, coordinate: Coordinate) !Coordinate {
        return .{ .first_cell = try std.math.add(u32, self.prefix_count, coordinate.first_cell), .word_count = coordinate.word_count };
    }
    pub fn inputRoot(self: *const Source) !Coordinate {
        return self.lift(self.fresh.public.summary.inputRoot());
    }
    pub fn inputLength(self: *const Source) !Coordinate {
        return self.lift(self.fresh.public.summary.inputLength());
    }
    pub fn inputPrefix(self: *const Source) !Coordinate {
        return self.lift(self.fresh.public.summary.inputPrefix());
    }
    pub fn frontier(self: *const Source, ordinal: usize) !Coordinate {
        return self.lift(try self.fresh.public.summary.frontier(ordinal));
    }
    pub fn firstCycle(self: *const Source) !Coordinate {
        return self.lift(self.fresh.public.summary.firstCycle());
    }
    pub fn lastCycle(self: *const Source) !Coordinate {
        return self.lift(self.fresh.public.summary.lastCycle());
    }
    pub fn rangeCoordinates(self: *const Source) !struct { first: u32, count: u32, leaves: u32 } {
        const r = self.fresh.public.summary.rangeCoordinates();
        return .{ .first = try std.math.add(u32, self.prefix_count, r.first), .count = try std.math.add(u32, self.prefix_count, r.count), .leaves = try std.math.add(u32, self.prefix_count, r.leaves) };
    }
    pub fn mix(self: *const Source, channel: anytype) !void {
        const admission = try self.fresh.authority();
        try admission.mix(channel);
    }
    pub fn replayPublic(self: *const Source, recorder: *Recorder.Recorder) void {
        var replay = Replay{ .recorder = recorder };
        self.mix(&replay) catch |failure| {
            recorder.failure = failure;
            return;
        };
        if (replay.cursor != self.cell_count) recorder.failure = error.UntrustedInputRequestNodeSource;
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
        if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedInputRequestNodeSource;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        const admission = try self.source.fresh.authority();
        try admission.admitRoot(root);
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        return self.source.public_input_digest;
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        try self.source.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
        try self.validate();
        const admission = try self.source.fresh.authority();
        try admission.mixClaims(channel, claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        const admission = try self.source.fresh.authority();
        try admission.validateClaimsForRelations(claims, relations);
    }
};
