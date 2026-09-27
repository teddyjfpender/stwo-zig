//! Immutable original-byte source or compact parent statement. A Source is
//! public policy, never proof authority; Fresh must accompany its verifier use.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Original = @import("block_v5_heterogeneous_child_frames_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Cohorts = @import("block_v5_heterogeneous_scoped_cohorts_v1.zig");
const Span = @import("block_v5_pc_clock_span_v1.zig").Span;
pub const PUBLIC_CIRCUIT: u32 = 4_200_017;
pub const MAX_CELLS: usize = 1 << 20;
pub const Slot = struct { requirement: u32, first: u32 };
pub const Source = struct {
    arena: std.heap.ArenaAllocator,
    ref: Cohorts.Ref,
    routing: [32]u8,
    key: Base.Key,
    expected_id: [32]u8,
    public_input_digest: [32]u8,
    claim_frame: [3]u32,
    frames: []const Original.Frame,
    cells: []const [4]M,
    terms: []const Original.Term,
    slots: []const Slot,
    span: ?@import("block_v5_pc_clock_span_v1.zig").Span,
    span_cell: ?u32,
    seal: [32]u8,
    pub fn deinit(self: *Source) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Source) !void {
        if (self.cells.len == 0 or self.cells.len > MAX_CELLS or self.terms.len == 0) return error.InvalidScopedSource;
        try validateFrames(self.frames, self.cells);
        for (self.slots, 0..) |slot, index| if (slot.first > self.cells.len or self.cells.len - slot.first < 4 or index > 0 and self.slots[index - 1].requirement >= slot.requirement) return error.InvalidScopedSource;
        if (self.ref == .leaf and (self.slots.len != 0 or self.span_cell != null)) return error.InvalidScopedSource;
        if (self.span) |span| try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(span);
        if (self.span_cell) |first| if (self.span == null or first > self.cells.len or self.cells.len - first < 6) return error.InvalidScopedSource;
        for (self.terms) |term| {
            if (term.circuit >= core.fields.m31.Modulus or term.wire >= core.fields.m31.Modulus or term.uses == 0 or term.uses >= core.fields.m31.Modulus) return error.InvalidScopedSource;
            for (term.coordinates) |value| if (value.v >= core.fields.m31.Modulus) return error.NoncanonicalScopedSummary;
        }
        if (!std.meta.eql(self.seal, try self.identity())) return error.MutatedScopedSource;
    }
    pub fn identity(self: *const Source) ![32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355a46, 1, @intFromEnum(std.meta.activeTag(self.ref)), switch (self.ref) {
            .leaf, .node => |index| index,
        } }); // B5ZF
        channel.mixRoot(self.routing);
        channel.mixRoot(try self.key.identity());
        channel.mixRoot(self.expected_id);
        channel.mixRoot(self.public_input_digest);
        channel.mixU32s(&self.claim_frame);
        self.mix(&channel);
        channel.mixU32s(&.{@intFromBool(self.span != null)});
        if (self.span) |span| channel.mixRoot(try span.identity());
        channel.mixU32s(&.{self.span_cell orelse std.math.maxInt(u32)});
        for (self.slots) |slot| channel.mixU32s(&.{ slot.requirement, slot.first });
        for (self.cells) |cell| channel.mixU32s(&.{ cell[0].v, cell[1].v, cell[2].v, cell[3].v });
        for (self.terms) |term| {
            channel.mixU32s(&.{ term.circuit, term.wire, term.uses, @intFromBool(term.negative) });
            channel.mixFelts(&.{Q.fromM31Array(term.coordinates)});
        }
        return channel.digestBytes();
    }
    pub fn findSlot(self: *const Source, requirement: u32) !Slot {
        const at = std.sort.binarySearch(Slot, self.slots, requirement, struct {
            fn order(key: u32, item: Slot) std.math.Order {
                return std.math.order(key, item.requirement);
            }
        }.order) orelse return error.MissingScopedSourceSlot;
        return self.slots[at];
    }
    pub fn mix(self: *const Source, channel: anytype) void {
        for (self.frames) |frame| switch (frame.operation) {
            .words => |v| channel.mixU32s(v),
            .root => |v| channel.mixRoot(v),
            .integer => |v| channel.mixU64(v),
            .felts => |v| channel.mixFelts(v),
        };
    }
    pub fn replayPublic(self: *const Source, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        for (self.frames) |frame| {
            const caller = @import("air/blake3_transcript_witness.zig").Caller{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.first };
            switch (frame.operation) {
                .words => |v| recorder.mixPublicWords(caller, v),
                .root => |v| recorder.mixPublicRoot(caller, v),
                .integer => |v| recorder.mixPublicInteger(caller, v),
                .felts => |v| recorder.mixPublicFelts(caller, v),
            }
        }
    }
};
const Collector = struct {
    a: std.mem.Allocator,
    frames: std.ArrayList(Original.Frame) = .empty,
    cells: std.ArrayList([4]M) = .empty,
    slots: std.ArrayList(Slot) = .empty,
    span_cell: ?u32 = null,
    failure: ?anyerror = null,
    pub fn beginSlot(self: *Collector, requirement: u32) void {
        if (self.failure != null) return;
        self.slots.append(self.a, .{ .requirement = requirement, .first = @intCast(self.cells.items.len) }) catch |err| {
            self.failure = err;
        };
    }
    pub fn beginSpan(self: *Collector) void {
        self.span_cell = @intCast(self.cells.items.len);
    }
    fn add(self: *Collector, operation: Original.Operation, words: []const u32) !void {
        if (words.len > MAX_CELLS -| self.cells.items.len) return error.ScopedSummaryResourceLimit;
        try self.frames.append(self.a, .{ .first = @intCast(self.cells.items.len), .operation = operation });
        for (words) |word_value| {
            var cell: [4]M = undefined;
            for (&cell, 0..) |*byte, i| byte.* = M.fromCanonical((word_value >> @as(u5, @intCast(8 * i))) & 255);
            try self.cells.append(self.a, cell);
        }
    }
    pub fn mixU32s(self: *Collector, words: []const u32) void {
        if (self.failure != null) return;
        const owned = self.a.dupe(u32, words) catch |err| {
            self.failure = err;
            return;
        };
        self.add(.{ .words = owned }, owned) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixRoot(self: *Collector, value: [32]u8) void {
        if (self.failure != null) return;
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word_value, i| word_value.* = std.mem.readInt(u32, value[4 * i ..][0..4], .little);
        self.add(.{ .root = value }, &words) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixU64(self: *Collector, value: u64) void {
        if (self.failure != null) return;
        self.add(.{ .integer = value }, &.{ @truncate(value), @truncate(value >> 32) }) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixFelts(self: *Collector, values: []const Q) void {
        if (self.failure != null) return;
        const owned = self.a.dupe(Q, values) catch |err| {
            self.failure = err;
            return;
        };
        const words = self.a.alloc(u32, values.len * 4) catch |err| {
            self.failure = err;
            return;
        };
        for (values, 0..) |value, i| for (value.toM31Array(), 0..) |limb, part| {
            words[4 * i + part] = limb.v;
        };
        self.add(.{ .felts = owned }, words) catch |err| {
            self.failure = err;
        };
    }
};
pub fn fromLeaf(a: std.mem.Allocator, leaf: *const Original.Child, ordinal: u32, routing: [32]u8) !Source {
    try leaf.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var collector = Collector{ .a = temp };
    leaf.mix(&collector);
    if (collector.failure) |err| return err;
    var result = Source{ .arena = arena, .ref = .{ .leaf = ordinal }, .routing = routing, .key = leaf.key, .expected_id = leaf.expected_id, .public_input_digest = leaf.public_input_digest, .claim_frame = leaf.claim_frame, .frames = try collector.frames.toOwnedSlice(temp), .cells = try collector.cells.toOwnedSlice(temp), .terms = try temp.dupe(Original.Term, leaf.terms), .slots = &.{}, .span = leaf.span, .span_cell = null, .seal = undefined };
    result.seal = try result.identity();
    try result.validate();
    return result;
}
pub fn fromNode(a: std.mem.Allocator, authority: anytype) !Source {
    try authority.validate();
    _ = try nodeWordCount(authority);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var collector = Collector{ .a = temp };
    try authority.mix(&collector);
    if (collector.failure) |err| return err;
    const terms = try temp.alloc(Original.Term, authority.wires.len);
    for (terms, authority.wires) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try authority.values.at(wire) };
    var result = Source{ .arena = arena, .ref = .{ .node = authority.values.index }, .routing = authority.values.routes.digest, .key = .{ .profile = authority.key.profile, .config = authority.key.config, .context = authority.key.context, .log_sizes = authority.key.log_sizes, .preprocessed_root = authority.key.preprocessed_root }, .expected_id = authority.expected_id, .public_input_digest = try authority.publicInputIdentity(), .claim_frame = .{ @TypeOf(authority).CLAIM_TAG, 1, @import("blake3_native_parent_artifact.zig").CLAIM_COUNT }, .frames = try collector.frames.toOwnedSlice(temp), .cells = try collector.cells.toOwnedSlice(temp), .terms = terms, .slots = try collector.slots.toOwnedSlice(temp), .span = authority.values.routes.cohorts.nodes[authority.values.index].span, .span_cell = collector.span_cell, .seal = undefined };
    result.seal = try result.identity();
    try result.validate();
    return result;
}

fn checkWord(cells: []const [4]M, at: usize, value: u32) !void {
    if (at >= cells.len) return error.InvalidScopedSource;
    for (cells[at], 0..) |byte, part| if (byte.v != ((value >> @as(u5, @intCast(8 * part))) & 255)) return error.MutatedScopedSource;
}
fn validateFrames(frames: []const Original.Frame, cells: []const [4]M) !void {
    var at: usize = 0;
    for (frames) |frame| {
        if (frame.first != at) return error.InvalidScopedSource;
        switch (frame.operation) {
            .words => |words| for (words) |value| {
                try checkWord(cells, at, value);
                at += 1;
            },
            .root => |root_value| for (0..8) |part| {
                try checkWord(cells, at, std.mem.readInt(u32, root_value[4 * part ..][0..4], .little));
                at += 1;
            },
            .integer => |value| {
                try checkWord(cells, at, @truncate(value));
                try checkWord(cells, at + 1, @truncate(value >> 32));
                at += 2;
            },
            .felts => |values| for (values) |value| for (value.toM31Array()) |limb| {
                if (limb.v >= core.fields.m31.Modulus) return error.NoncanonicalScopedSummary;
                try checkWord(cells, at, limb.v);
                at += 1;
            },
        }
    }
    if (at != cells.len) return error.InvalidScopedSource;
}
pub const Admission = struct {
    pub const open_parent_v5_v2 = true;
    source: *const Source,
    key: Base.Key,
    expected_id: [32]u8,
    pc_clock_children: []const Span,
    pub fn init(source: *const Source, spans: []const Span) Admission {
        return .{ .source = source, .key = source.key, .expected_id = source.expected_id, .pc_clock_children = spans };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        if (!std.meta.eql(self.key, self.source.key) or !std.meta.eql(self.expected_id, self.source.expected_id)) return error.UntrustedHeterogeneousHierarchySource;
        for (self.pc_clock_children) |span| try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(span);
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
        if (claims.len != @import("blake3_native_parent_artifact.zig").CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
        channel.mixU32s(&self.source.claim_frame);
        channel.mixFelts(claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        const relation = try relations.getExact(.recursion_wire);
        var total = Q.zero();
        for (self.source.terms) |term| {
            const d = try relation.combineBase(&(.{ M.fromCanonical(term.circuit), M.fromCanonical(term.wire) } ++ term.coordinates));
            if (d.isZero()) return error.RecursivePublicDenominatorZero;
            const value = Q.fromBase(M.fromCanonical(term.uses)).mul(try d.inv());
            total = if (term.negative) total.sub(value) else total.add(value);
        }
        for (claims) |claim| total = total.add(claim);
        if (!total.isZero()) return error.InvalidHeterogeneousHierarchyPublicClosure;
    }
};

/// Exact physical transcript words, not a heuristic budget estimate.
pub fn nodeWordCount(authority: anytype) !usize {
    var counter = WordCounter{};
    try authority.mix(&counter);
    if (counter.failure) |err| return err;
    if (counter.words == 0 or counter.words > MAX_CELLS) return error.HeterogeneousHierarchyResourceLimit;
    return counter.words;
}
const WordCounter = struct {
    words: usize = 0,
    failure: ?anyerror = null,
    fn add(self: *WordCounter, count: usize) void {
        if (self.failure != null) return;
        self.words = std.math.add(usize, self.words, count) catch |err| {
            self.failure = err;
            return;
        };
    }
    pub fn mixU32s(self: *WordCounter, words: []const u32) void {
        self.add(words.len);
    }
    pub fn mixRoot(self: *WordCounter, _: [32]u8) void {
        self.add(8);
    }
    pub fn mixU64(self: *WordCounter, _: u64) void {
        self.add(2);
    }
    pub fn mixFelts(self: *WordCounter, values: []const Q) void {
        const count = std.math.mul(usize, values.len, 4) catch |err| {
            self.failure = err;
            return;
        };
        self.add(count);
    }
};
