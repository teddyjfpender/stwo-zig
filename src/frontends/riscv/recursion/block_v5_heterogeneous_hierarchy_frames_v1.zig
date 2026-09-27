//! Exact nested transcript source, including independently routed descendant
//! exports. A Source is public policy; Fresh carries the real verifier equation.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Original = @import("block_v5_heterogeneous_child_frames_v1.zig");
const Topology = @import("block_v5_heterogeneous_hierarchy_plan_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Span = @import("block_v5_pc_clock_span_v1.zig").Span;
pub const PUBLIC_CIRCUIT: u32 = 4_200_014;
pub const MAX_CELLS: usize = 1 << 24;
pub const Export = struct { ordinal: u32, first: u32, count: u32 };
pub const Source = struct {
    arena: std.heap.ArenaAllocator,
    ref: Topology.Ref,
    bounds: Topology.Bounds,
    coverage: [32]u8,
    node_id: ?[32]u8,
    key: Base.Key,
    expected_id: [32]u8,
    public_input_digest: [32]u8,
    claim_frame: [3]u32,
    frames: []const Original.Frame,
    cells: []const [4]M,
    terms: []const Original.Term,
    exports: []const Export,
    span: ?Span,
    span_cell: ?u32,
    seal: [32]u8,
    pub fn deinit(self: *Source) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Source) !void {
        if (self.bounds.count == 0 or self.cells.len == 0 or self.cells.len > MAX_CELLS or self.frames.len == 0 or self.terms.len == 0 or self.terms.len > MAX_CELLS / 4 or self.exports.len != self.bounds.count or self.node_id == null and self.ref == .node) return error.InvalidHeterogeneousHierarchySource;
        if ((self.bounds.schema[@intFromEnum(@import("../prover/block_v5_recursive_coverage_plan_v1.zig").Kind.native_arithmetic)] != 0) != (self.span != null)) return error.InvalidHeterogeneousHierarchySpan;
        if (self.span) |span| try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(span);
        for (self.exports, 0..) |exported, index| if (exported.ordinal != self.bounds.first + index or exported.first > self.cells.len or exported.count > self.cells.len - exported.first or exported.count == 0) return error.InvalidHeterogeneousHierarchyExport;
        if (self.span_cell) |first| if (first > self.cells.len or 6 > self.cells.len - first or self.span == null) return error.InvalidHeterogeneousHierarchySpan;
        var at: usize = 0;
        for (self.frames) |frame| {
            if (frame.first != at) return error.InvalidHeterogeneousHierarchySource;
            switch (frame.operation) {
                .words => |words| for (words) |word| {
                    try self.checkWord(at, word);
                    at += 1;
                },
                .root => |root| for (0..8) |word| {
                    try self.checkWord(at, std.mem.readInt(u32, root[4 * word ..][0..4], .little));
                    at += 1;
                },
                .integer => |value| {
                    try self.checkWord(at, @truncate(value));
                    try self.checkWord(at + 1, @truncate(value >> 32));
                    at += 2;
                },
                .felts => |values| for (values) |value| {
                    for (value.toM31Array()) |word| {
                        if (word.v >= core.fields.m31.Modulus) return error.NoncanonicalHeterogeneousChild;
                        try self.checkWord(at, word.v);
                        at += 1;
                    }
                },
            }
        }
        if (at != self.cells.len or !std.meta.eql(self.seal, try self.identity())) return error.MutatedHeterogeneousHierarchySource;
        for (self.terms) |term| {
            if (term.uses == 0 or term.uses >= core.fields.m31.Modulus) return error.InvalidHeterogeneousHierarchySource;
            for (term.coordinates) |value| if (value.v >= core.fields.m31.Modulus) return error.NoncanonicalHeterogeneousChild;
        }
    }
    fn checkWord(self: *const Source, at: usize, value: u32) !void {
        if (at >= self.cells.len) return error.InvalidHeterogeneousHierarchySource;
        for (self.cells[at], 0..) |part, i| if (part.v != ((value >> @as(u5, @intCast(8 * i))) & 255)) return error.MutatedHeterogeneousHierarchySource;
    }
    pub fn identity(self: *const Source) ![32]u8 {
        var c = core.channel.blake3.Channel{};
        c.mixU32s(&.{ 0x4235484e, 1, @intFromEnum(std.meta.activeTag(self.ref)), switch (self.ref) {
            .leaf, .node => |value| value,
        }, self.bounds.first, self.bounds.count }); // B5HN
        c.mixRoot(self.coverage);
        c.mixRoot(try self.key.identity());
        c.mixRoot(self.expected_id);
        c.mixRoot(self.public_input_digest);
        c.mixU32s(&self.claim_frame);
        c.mixU32s(&self.bounds.schema);
        c.mixU32s(&.{@intFromBool(self.node_id != null)});
        if (self.node_id) |id| c.mixRoot(id);
        c.mixU32s(&.{@intFromBool(self.span != null)});
        if (self.span) |span| c.mixRoot(try span.identity());
        c.mixU32s(&.{self.span_cell orelse std.math.maxInt(u32)});
        self.mix(&c);
        for (self.exports) |exported| c.mixU32s(&.{ exported.ordinal, exported.first, exported.count });
        for (self.cells) |cell| c.mixU32s(&.{ cell[0].v, cell[1].v, cell[2].v, cell[3].v });
        for (self.terms) |term| {
            c.mixU32s(&.{ term.circuit, term.wire, term.uses, @intFromBool(term.negative) });
            c.mixFelts(&.{Q.fromM31Array(term.coordinates)});
        }
        return c.digestBytes();
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
    pub fn exportAt(self: *const Source, ordinal: u32) !Export {
        if (ordinal < self.bounds.first or ordinal - self.bounds.first >= self.exports.len) return error.InvalidHeterogeneousHierarchyExport;
        return self.exports[ordinal - self.bounds.first];
    }
};
pub fn fromLeaf(a: std.mem.Allocator, leaf: *const Original.Child, ordinal: u32, coverage: [32]u8) !Source {
    try leaf.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var collector = Collector{ .a = temp };
    leaf.mix(&collector);
    try collector.check();
    const cells = try collector.cells.toOwnedSlice(temp);
    var schema: [@import("../prover/block_v5_recursive_coverage_plan_v1.zig").KIND_COUNT]u32 = @splat(0);
    schema[@intFromEnum(leaf.physical.kind)] = 1;
    var source = Source{ .arena = arena, .ref = .{ .leaf = ordinal }, .bounds = .{ .first = ordinal, .count = 1, .schema = schema }, .coverage = coverage, .node_id = null, .key = leaf.key, .expected_id = leaf.expected_id, .public_input_digest = leaf.public_input_digest, .claim_frame = leaf.claim_frame, .frames = try collector.frames.toOwnedSlice(temp), .cells = cells, .terms = try temp.dupe(Original.Term, leaf.terms), .exports = try temp.dupe(Export, &.{.{ .ordinal = ordinal, .first = 0, .count = @intCast(cells.len) }}), .span = leaf.span, .span_cell = null, .seal = undefined };
    source.seal = try source.identity();
    try source.validate();
    return source;
}
pub fn fromNode(a: std.mem.Allocator, authority: anytype) !Source {
    try authority.validate();
    _ = try nodeWordCount(authority);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var collector = Collector{ .a = temp };
    try authority.mix(&collector);
    try collector.check();
    const terms = try temp.alloc(Original.Term, authority.wires.len);
    for (authority.wires, terms) |wire, *term| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try authority.values.at(wire) };
    var source = Source{ .arena = arena, .ref = .{ .node = authority.values.index }, .bounds = try authority.values.plan.bounds(.{ .node = authority.values.index }), .coverage = authority.values.plan.expected_coverage, .node_id = try authority.values.plan.nodeIdentity(authority.values.index), .key = .{ .profile = authority.key.profile, .config = authority.key.config, .context = authority.key.context, .log_sizes = authority.key.log_sizes, .preprocessed_root = authority.key.preprocessed_root }, .expected_id = authority.expected_id, .public_input_digest = try authority.publicInputIdentity(), .claim_frame = .{ @TypeOf(authority).CLAIM_TAG, 1, @import("blake3_native_parent_artifact.zig").CLAIM_COUNT }, .frames = try collector.frames.toOwnedSlice(temp), .cells = try collector.cells.toOwnedSlice(temp), .terms = terms, .exports = try collector.exports.toOwnedSlice(temp), .span = try authority.values.plan.span(.{ .node = authority.values.index }), .span_cell = collector.span_cell, .seal = undefined };
    source.seal = try source.identity();
    try source.validate();
    return source;
}
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
const Collector = struct {
    a: std.mem.Allocator,
    frames: std.ArrayList(Original.Frame) = .empty,
    cells: std.ArrayList([4]M) = .empty,
    exports: std.ArrayList(Export) = .empty,
    span_cell: ?u32 = null,
    failure: ?anyerror = null,
    pub fn check(self: *const Collector) !void {
        if (self.failure) |err| return err;
    }
    pub fn beginExport(self: *Collector, ordinal: u32, count: u32) void {
        if (self.failure != null) return;
        self.exports.append(self.a, .{ .ordinal = ordinal, .first = @intCast(self.cells.items.len), .count = count }) catch |err| {
            self.failure = err;
        };
    }
    pub fn beginSpan(self: *Collector) void {
        self.span_cell = @intCast(self.cells.items.len);
    }
    fn add(self: *Collector, operation: Original.Operation, words: []const u32) !void {
        if (words.len > MAX_CELLS -| self.cells.items.len) return error.HeterogeneousHierarchyResourceLimit;
        try self.frames.append(self.a, .{ .first = @intCast(self.cells.items.len), .operation = operation });
        for (words) |word| {
            var cell: [4]M = undefined;
            for (&cell, 0..) |*part, i| part.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
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
    pub fn mixRoot(self: *Collector, root: [32]u8) void {
        if (self.failure != null) return;
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        self.add(.{ .root = root }, &words) catch |err| {
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
        for (values, 0..) |value, i| for (value.toM31Array(), 0..) |word, j| {
            words[4 * i + j] = word.v;
        };
        self.add(.{ .felts = owned }, words) catch |err| {
            self.failure = err;
        };
    }
};
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
