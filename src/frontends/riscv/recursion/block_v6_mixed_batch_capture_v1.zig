//! Fresh capture of a direct mixed-batch STARK for later recursive reduction.
//! Exact original public frames and wire supplies survive. No native span,
//! aggregate-only scalar, global closure receipt or Ethereum claim is minted.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Bus = @import("block_v6_mixed_direct_public_v1.zig");
const Protocol = @import("block_v6_mixed_direct_protocol_v1.zig");
const Ranges = @import("block_v6_mixed_batch_ranges_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Base = Parent.protocol;
const Frames = @import("block_v5_open_child_frames_v2.zig");
const Universal = @import("air/universal_challenges.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const PUBLIC_CIRCUIT: u32 = 4_200_003;
pub const Limits = struct {
    ranges: Ranges.Limits = .{},
    max_proof_bytes: usize = 128 << 20,
    max_capture_bytes: usize = 4 << 30,
    max_frame_cells: usize = 1 << 20,
    max_terms: usize = 1 << 20,
};

/// All fields are independent caller policy except the untrusted claim values.
/// The selected key must come from the original fixed compiler/registry.
pub const Policy = struct {
    scope: Ranges.Scope,
    whole_roster: []const Bus.Expected,
    counts: []const u32,
    ordinal: u32,
    key: Protocol.Key,
    expected_key: [32]u8,
    wires: []const Bus.Wire,
    values: Bus.Values,
    expected_public_input_identity: [32]u8,

    pub fn admit(self: Policy, a: std.mem.Allocator, limits: Limits) !Selection {
        var plan = try Ranges.create(a, self.scope, self.whole_roster, self.counts, limits.ranges);
        defer plan.deinit();
        if (self.ordinal >= plan.ranges.len) return error.InvalidMixedBatchOrdinal;
        const range = plan.ranges[self.ordinal];
        if (self.wires.len > limits.max_terms or !std.meta.eql(self.key.config, self.scope.profile.config()) or self.key.profile != self.scope.profile)
            return error.UntrustedMixedBatchScope;
        const original = try Protocol.Admission.init(self.key, self.expected_key, self.wires, self.values, self.whole_roster[range.first..][0..range.count]);
        if (!std.meta.eql(range.roster_digest, self.key.roster_digest) or !std.meta.eql(try original.publicInputIdentity(), self.expected_public_input_identity))
            return error.UntrustedMixedBatchProofPin;
        return .{ .range = range, .job_identity = plan.identity, .original = original };
    }
};
pub const Selection = struct { range: Ranges.Range, job_identity: [32]u8, original: Protocol.Admission };

/// Owned normalization of one known original protocol. Its mutation checks
/// reconstruct transcript framing and wire values from the typed original
/// admission. A self-recomputed digest is never used as admission authority.
pub const Source = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    children: []Bus.Child,
    original_key: Protocol.Key,
    expected_id: [32]u8,
    wires: []const Bus.Wire,
    roster: []const Bus.Expected,
    range: Ranges.Range,
    job_identity: [32]u8,
    scope: Ranges.Scope,
    public_input_digest: [32]u8,
    frames: []const Frames.Frame,
    cells: []const [4]M,
    terms: []const Frames.Term,

    pub fn create(a: std.mem.Allocator, policy: Policy, limits: Limits) !*Source {
        const selected = try policy.admit(a, limits);
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        const children = try a.alloc(Bus.Child, selected.original.values.children.len);
        var count: usize = 0;
        errdefer {
            for (children[0..count]) |*child| child.deinit();
            a.free(children);
        }
        for (selected.original.values.children, children) |child, *out| {
            out.* = try child.clone(a);
            count += 1;
        }
        const wires = try temp.dupe(Bus.Wire, policy.wires);
        const roster = try temp.dupe(Bus.Expected, selected.original.roster);
        const admitted = try Protocol.Admission.init(policy.key, policy.expected_key, wires, .{ .children = children }, roster);
        var collector = Collector{ .a = temp, .limit = limits.max_frame_cells };
        try admitted.mix(&collector);
        if (collector.failure) |err| return err;
        const terms = try temp.alloc(Frames.Term, wires.len);
        for (wires, terms) |wire, *term| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .coordinates = try admitted.values.at(wire) };
        const owned_frames = try collector.frames.toOwnedSlice(temp);
        const owned_cells = try collector.cells.toOwnedSlice(temp);
        const self = try a.create(Source);
        self.* = .{ .a = a, .arena = arena, .children = children, .original_key = policy.key, .expected_id = policy.expected_key, .wires = wires, .roster = roster, .range = selected.range, .job_identity = selected.job_identity, .scope = policy.scope, .public_input_digest = policy.expected_public_input_identity, .frames = owned_frames, .cells = owned_cells, .terms = terms };
        return self;
    }
    pub fn original(self: *const Source) !Protocol.Admission {
        return Protocol.Admission.init(self.original_key, self.expected_id, self.wires, .{ .children = self.children }, self.roster);
    }
    pub fn geometry(self: *const Source) Base.Key {
        const k = self.original_key;
        return .{ .profile = k.profile, .config = k.config, .context = k.context, .log_sizes = k.log_sizes, .preprocessed_root = k.preprocessed_root };
    }
    pub fn validate(self: *const Source) !void {
        const admitted = try self.original();
        if (self.range.count != self.roster.len or !std.meta.eql(self.range.roster_digest, self.original_key.roster_digest) or
            !std.meta.eql(self.original_key.config, self.scope.profile.config()) or !std.meta.eql(try admitted.publicInputIdentity(), self.public_input_digest) or self.terms.len != self.wires.len)
            return error.UntrustedMixedBatchFrames;
        var checker = Checker{ .frames = self.frames, .cells = self.cells };
        try admitted.mix(&checker);
        if (checker.failed or checker.next != self.frames.len or checker.offset != self.cells.len) return error.UntrustedMixedBatchFrames;
        for (self.wires, self.terms) |wire, term| {
            const expected = Frames.Term{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .coordinates = try admitted.values.at(wire) };
            if (!std.meta.eql(term, expected)) return error.UntrustedMixedBatchFrames;
        }
    }
    pub fn requirePolicy(self: *const Source, a: std.mem.Allocator, policy: Policy, limits: Limits) !void {
        const selected = try policy.admit(a, limits);
        try self.validate();
        if (!std.meta.eql(self.scope, policy.scope) or !std.meta.eql(self.job_identity, selected.job_identity) or !std.meta.eql(self.range, selected.range) or
            !std.meta.eql(self.original_key, policy.key) or !std.meta.eql(self.expected_id, policy.expected_key) or !std.meta.eql(self.public_input_digest, policy.expected_public_input_identity))
            return error.UntrustedMixedBatchFrames;
    }
    pub fn mix(self: *const Source, channel: anytype) void {
        for (self.frames) |frame| switch (frame.operation) {
            .words => |v| channel.mixU32s(v),
            .root => |v| channel.mixRoot(v),
            .felts => |v| channel.mixFelts(v),
            .integer => |v| channel.mixU64(v),
        };
    }
    pub fn replayPublic(self: *const Source, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        self.replayShape(recorder);
    }
    /// The fixed recorder consumes only operation types, lengths and routing.
    pub fn replayShape(self: *const Source, recorder: anytype) void {
        for (self.frames) |frame| {
            const caller = @import("air/blake3_transcript_witness.zig").Caller{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.first };
            switch (frame.operation) {
                .words => |v| recorder.mixPublicWords(caller, v),
                .root => |v| recorder.mixPublicRoot(caller, v),
                .felts => |v| recorder.mixPublicFelts(caller, v),
                .integer => |v| recorder.mixPublicInteger(caller, v),
            }
        }
    }
    pub fn deinit(self: *Source) void {
        const a = self.a;
        for (self.children) |*child| child.deinit();
        a.free(self.children);
        self.arena.deinit();
        a.destroy(self);
    }
};

/// Reuse only the original public-supply verifier equations and transcript
/// replay. The marker selects these equations; no native leaf adapter, open
/// sum or PC span is synthesized. Future range adjacency is a separate proof.
pub const Admission = struct {
    pub const open_parent_v5_v2 = true;
    source: *const Source,
    key: Base.Key,
    expected_id: [32]u8,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn init(source: *const Source) Admission {
        return .{ .source = source, .key = source.geometry(), .expected_id = source.expected_id };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        if (self.pc_clock_children.len != 0 or !std.meta.eql(self.key, self.source.geometry()) or !std.meta.eql(self.expected_id, self.source.expected_id)) return error.UntrustedMixedBatchFrames;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        if (!std.meta.eql(root, self.key.preprocessed_root)) return error.UntrustedBlake3ParentRoot;
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        return self.source.public_input_digest;
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        self.source.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
        try self.validate();
        const original = try self.source.original();
        try original.mixClaims(channel, claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: Parent.artifact.Claims, relations: Universal.UniversalRelations) !void {
        try self.validate();
        const original = try self.source.original();
        try original.validateClaimsForRelations(claims, relations);
    }
};
pub const Captured = struct {
    budget: *Budget,
    source: *Source,
    verified: @import("blake3_native_parent_verifier.zig").Verified,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Captured) void {
        self.verified.deinit();
        self.source.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    /// Produces original verifier rows, not a proof or complete reduction root.
    /// Caller must expose every frame cell and packed supply term in its parent
    /// public bus, then bind the independent range protocol at that parent.
    /// The capture owner must outlive the returned plan and row construction.
    pub fn plan(self: *const Captured, a: std.mem.Allocator, capacity: u32) !Parent.preparation.Planned {
        const admitted = Admission.init(self.source);
        return Parent.preparation.State.plan(a, &admitted, &self.verified, self.source.expected_id, capacity);
    }
};
pub fn verifyAndCapture(a: std.mem.Allocator, bytes: []const u8, policy: Policy, limits: Limits) !Captured {
    if (bytes.len == 0 or bytes.len > limits.max_proof_bytes or limits.max_capture_bytes == 0) return error.MixedBatchResourceLimit;
    const budget = try Budget.createRetainingParent(a, limits.max_capture_bytes);
    errdefer budget.destroy();
    const bounded = budget.allocator();
    const source = try Source.create(bounded, policy, limits);
    errdefer source.deinit();
    const original = try source.original();
    var decoded = try Parent.codec.decode(bounded, bytes, &original);
    var verified = try Parent.verify(&decoded, &original);
    errdefer verified.deinit();
    const admitted = Admission.init(source);
    try verified.validate(&admitted, policy.expected_key);
    try source.requirePolicy(bounded, policy, limits);
    return .{ .budget = budget, .source = source, .verified = verified };
}

const Collector = struct {
    a: std.mem.Allocator,
    limit: usize,
    frames: std.ArrayList(Frames.Frame) = .empty,
    cells: std.ArrayList([4]M) = .empty,
    failure: ?anyerror = null,
    fn add(self: *Collector, operation: Frames.Operation, words: []const u32) !void {
        if (self.cells.items.len > self.limit or words.len > self.limit - self.cells.items.len or self.cells.items.len > std.math.maxInt(u32)) return error.MixedBatchResourceLimit;
        try self.frames.append(self.a, .{ .first = @intCast(self.cells.items.len), .operation = operation });
        for (words) |word| {
            var cell: [4]M = undefined;
            for (&cell, 0..) |*v, i| v.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
            try self.cells.append(self.a, cell);
        }
    }
    fn reserveCells(self: *Collector, count: usize) bool {
        if (self.failure != null) return false;
        if (self.cells.items.len > self.limit or count > self.limit - self.cells.items.len) {
            self.failure = error.MixedBatchResourceLimit;
            return false;
        }
        return true;
    }
    pub fn mixU32s(self: *Collector, words: []const u32) void {
        if (!self.reserveCells(words.len)) return;
        const owned = self.a.dupe(u32, words) catch |err| {
            self.failure = err;
            return;
        };
        self.add(.{ .words = owned }, owned) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixRoot(self: *Collector, root: [32]u8) void {
        if (self.failure != null) return;
        var words: [8]u32 = undefined;
        for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        self.add(.{ .root = root }, &words) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixFelts(self: *Collector, values: []const Q) void {
        if (self.failure != null) return;
        const count = std.math.mul(usize, values.len, 4) catch {
            self.failure = error.MixedBatchResourceLimit;
            return;
        };
        if (!self.reserveCells(count)) return;
        const owned = self.a.dupe(Q, values) catch |err| {
            self.failure = err;
            return;
        };
        const words = self.a.alloc(u32, count) catch |err| {
            self.failure = err;
            return;
        };
        for (values, 0..) |value, i| for (value.toM31Array(), 0..) |v, j| {
            words[4 * i + j] = v.v;
        };
        self.add(.{ .felts = owned }, words) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixU64(self: *Collector, value: u64) void {
        if (self.failure != null) return;
        self.add(.{ .integer = value }, &.{ @truncate(value), @truncate(value >> 32) }) catch |err| {
            self.failure = err;
        };
    }
};
const Checker = struct {
    frames: []const Frames.Frame,
    cells: []const [4]M,
    next: usize = 0,
    offset: usize = 0,
    failed: bool = false,
    fn operation(self: *Checker, value: Frames.Operation) bool {
        if (self.failed or self.next >= self.frames.len) {
            self.failed = true;
            return false;
        }
        const frame = self.frames[self.next];
        if (frame.first != self.offset or std.meta.activeTag(frame.operation) != std.meta.activeTag(value)) {
            self.failed = true;
            return false;
        }
        const same = switch (value) {
            .words => |v| std.mem.eql(u32, v, frame.operation.words),
            .root => |v| std.meta.eql(v, frame.operation.root),
            .felts => |v| blk: {
                if (v.len != frame.operation.felts.len) break :blk false;
                for (v, frame.operation.felts) |left, right| if (!left.eql(right)) break :blk false;
                break :blk true;
            },
            .integer => |v| v == frame.operation.integer,
        };
        if (!same) {
            self.failed = true;
            return false;
        }
        self.next += 1;
        return true;
    }
    fn word(self: *Checker, value: u32) void {
        if (self.failed or self.offset >= self.cells.len) {
            self.failed = true;
            return;
        }
        for (self.cells[self.offset], 0..) |v, i| {
            if (v.v != ((value >> @as(u5, @intCast(8 * i))) & 255)) self.failed = true;
        }
        self.offset += 1;
    }
    pub fn mixU32s(self: *Checker, values: []const u32) void {
        if (!self.operation(.{ .words = values })) return;
        for (values) |value| self.word(value);
    }
    pub fn mixRoot(self: *Checker, value: [32]u8) void {
        if (!self.operation(.{ .root = value })) return;
        for (0..8) |i| self.word(std.mem.readInt(u32, value[4 * i ..][0..4], .little));
    }
    pub fn mixFelts(self: *Checker, values: []const Q) void {
        if (!self.operation(.{ .felts = values })) return;
        for (values) |value| for (value.toM31Array()) |v| self.word(v.v);
    }
    pub fn mixU64(self: *Checker, value: u64) void {
        if (!self.operation(.{ .integer = value })) return;
        self.word(@truncate(value));
        self.word(@truncate(value >> 32));
    }
};

test "mixed batch original verifier and recursive preparation instantiate" {
    std.mem.doNotOptimizeAway(&verifyAndCapture);
    std.mem.doNotOptimizeAway(&Captured.plan);
}

fn metadataFixture(a: std.mem.Allocator) !*Source {
    // Typed proposals only. No proof, verified capture, or success receipt is fabricated.
    const child = Bus.Child{ .provider = .{ .range16 = .{ .template = @splat(1), .sealed = @splat(2), .plan = @splat(3), .roots = .{ @splat(4), @splat(5) }, .shard = .{ .index = 0, .first_instance = 0, .instance_count = 1, .request_count = 37 }, .sum = Q.one(), .count = 37 } } };
    const roster = [_]Bus.Expected{child.expected()};
    const wires = [_]Bus.Wire{.{ .circuit = 1, .wire = 1, .uses = 1, .child = 0, .source = .{ .provider = .{ .range16 = .sum } }, .coordinate = 0 }};
    const geometry = Base.Key{ .context = .{ .child_key_id = @splat(4), .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(6), @splat(7), @splat(8) }, .transcript_plan_id = @splat(9) }, .log_sizes = @splat(4), .preprocessed_root = @splat(10) };
    const key = try Protocol.Key.fromGeometry(geometry, &wires, &roster);
    const values = Bus.Values{ .children = &.{child} };
    const admitted = try Protocol.Admission.init(key, try key.identity(), &wires, values, &roster);
    return Source.create(a, .{ .scope = .{ .sealed_digest = @splat(2), .profile = .diagnostic_q8_pow0, .public_input_identity = @splat(12) }, .whole_roster = &roster, .counts = &.{1}, .ordinal = 0, .key = key, .expected_key = try key.identity(), .wires = &wires, .values = values, .expected_public_input_identity = try admitted.publicInputIdentity() }, .{});
}
fn metadataAllocation(a: std.mem.Allocator) !void {
    const source = try metadataFixture(a);
    defer source.deinit();
    try source.validate();
}
test "mixed batch owns exact original frames rejects mutation and cleans failed allocations" {
    const source = try metadataFixture(std.testing.allocator);
    defer source.deinit();
    try source.validate();
    var original = core.channel.blake3.Channel{};
    const admission = try source.original();
    try admission.mix(&original);
    var replay = core.channel.blake3.Channel{};
    source.mix(&replay);
    try std.testing.expectEqualDeep(original.digestBytes(), replay.digestBytes());
    const cells = @constCast(source.cells);
    cells[0][0] = cells[0][0].add(M.one());
    try std.testing.expectError(error.UntrustedMixedBatchFrames, source.validate());
    cells[0][0] = cells[0][0].sub(M.one());
    const frames = @constCast(source.frames);
    frames[0].first += 1;
    try std.testing.expectError(error.UntrustedMixedBatchFrames, source.validate());
    frames[0].first -= 1;
    const terms = @constCast(source.terms);
    terms[0].uses += 1;
    try std.testing.expectError(error.UntrustedMixedBatchFrames, source.validate());
    terms[0].uses -= 1;
    const old = source.children[0].provider.range16.sum;
    source.children[0].provider.range16.sum = old.add(Q.one());
    try std.testing.expectError(error.UntrustedMixedBatchFrames, source.validate());
    source.children[0].provider.range16.sum = old;
    try source.validate();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, metadataAllocation, .{});
}
test "mixed batch collector limits before copying and checks each transcript operation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var collector = Collector{ .a = arena.allocator(), .limit = 32 };
    collector.mixU32s(&.{ 1, 0xffffffff });
    collector.mixRoot(@splat(7));
    collector.mixFelts(&.{Q.one()});
    collector.mixU64(0x12345678abcdef);
    try std.testing.expect(collector.failure == null);
    var checker = Checker{ .frames = collector.frames.items, .cells = collector.cells.items };
    checker.mixU32s(&.{ 1, 0xffffffff });
    checker.mixRoot(@splat(7));
    checker.mixFelts(&.{Q.one()});
    checker.mixU64(0x12345678abcdef);
    try std.testing.expect(!checker.failed);
    try std.testing.expectEqual(collector.frames.items.len, checker.next);
    try std.testing.expectEqual(collector.cells.items.len, checker.offset);
    var changed = Checker{ .frames = collector.frames.items, .cells = collector.cells.items };
    changed.mixU64(1);
    try std.testing.expect(changed.failed);
    var bounded = Collector{ .a = arena.allocator(), .limit = 1 };
    bounded.mixFelts(&.{Q.one()});
    try std.testing.expect(bounded.failure != null);
    try std.testing.expect(bounded.failure.? == error.MixedBatchResourceLimit);
    try std.testing.expectEqual(@as(usize, 0), bounded.frames.items.len);
}

pub const testing = if (@import("builtin").is_test) struct {
    pub fn metadataSource(a: std.mem.Allocator) !*Source {
        return metadataFixture(a);
    }
} else struct {};
