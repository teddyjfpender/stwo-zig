//! Known-protocol child admission normalization for nested open recursion.
//! It preserves every transcript frame and public-wire value. It does not
//! accept caller-created receipts as proof, nor promote open global claims.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const native_protocol = @import("block_v5_reusable_native_parent_protocol_v1.zig");
const native_bus = @import("block_v5_recursive_public_bus_v1.zig");
const capacity_protocol = @import("block_v5_reusable_capacity_parent_protocol_v1.zig");
const capacity_bus = @import("block_v5_capacity_recursive_public_bus_v1.zig");
const span_mod = @import("block_v5_pc_clock_span_v1.zig");
const v1_protocol = @import("block_v5_reusable_open_parent_protocol_v1.zig");
const base = @import("blake3_execution_parent_protocol.zig");
const universal = @import("air/universal_challenges.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_003;
pub const LIMIT: usize = 1 << 20;
pub const Term = struct { circuit: u32, wire: u32, uses: u32, negative: bool = false, coordinates: [4]M };
pub const Operation = union(enum) { words: []const u32, root: [32]u8, felts: []const Q, integer: u64 };
pub const Frame = struct { first: u32, operation: Operation };
pub const Child = struct {
    arena: std.heap.ArenaAllocator,
    key: base.Key,
    expected_id: [32]u8,
    public_input_digest: [32]u8,
    claim_frame: [3]u32,
    frames: []const Frame,
    cells: []const [4]M,
    terms: []const Term,
    span: span_mod.Span,
    native_open_sum: Q,
    seal: [32]u8,
    pub fn deinit(self: *Child) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Child) !void {
        try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(self.span);
        if (self.frames.len == 0 or self.cells.len == 0 or self.cells.len > LIMIT or self.terms.len == 0 or self.terms.len > LIMIT / 4 or
            std.mem.allEqual(u8, &self.expected_id, 0) or std.mem.allEqual(u8, &self.public_input_digest, 0)) return error.InvalidV5OpenChildFrames;
        if (!std.meta.eql(self.seal, try self.identity())) return error.TamperedV5OpenChildFrames;
    }
    fn identity(self: *const Child) ![32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354e46, 2 });
        channel.mixRoot(try self.key.identity()); // geometry, never original domain ID
        channel.mixRoot(self.expected_id);
        channel.mixRoot(self.public_input_digest);
        channel.mixU32s(&self.claim_frame);
        channel.mixRoot(try self.span.identity());
        channel.mixFelts(&.{self.native_open_sum});
        self.mix(&channel);
        for (self.cells) |cell| channel.mixU32s(&.{ cell[0].v, cell[1].v, cell[2].v, cell[3].v });
        for (self.terms) |term| {
            channel.mixU32s(&.{ term.circuit, term.wire, term.uses, @intFromBool(term.negative) });
            channel.mixFelts(&.{Q.fromM31Array(term.coordinates)});
        }
        return channel.digestBytes();
    }
    pub fn mix(self: *const Child, channel: anytype) void {
        for (self.frames) |frame| switch (frame.operation) {
            .words => |v| channel.mixU32s(v),
            .root => |v| channel.mixRoot(v),
            .felts => |v| channel.mixFelts(v),
            .integer => |v| channel.mixU64(v),
        };
    }
    pub fn replayPublic(self: *const Child, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        for (self.frames) |frame| {
            const source = @import("air/blake3_transcript_witness.zig").Caller{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.first };
            switch (frame.operation) {
                .words => |v| recorder.mixPublicWords(source, v),
                .root => |v| recorder.mixPublicRoot(source, v),
                .felts => |v| recorder.mixPublicFelts(source, v),
                .integer => |v| recorder.mixPublicInteger(source, v),
            }
        }
    }
};
pub fn fromNative(a: std.mem.Allocator, admitted: *const @import("../prover/block_v5_native_recursive_admission_v3.zig").Prepared, receipt: @import("../prover/block_v5_native_execution_proof_v3.zig").OpenReceipt, recursive_key: native_protocol.Key, key_id: [32]u8, schedule: []const native_bus.Wire) !Child {
    if (!std.meta.eql(recursive_key.config, admitted.config) or
        !std.meta.eql(recursive_key.context.child_config, admitted.config)) return error.NativeV5RecursiveSecurityMismatch;
    const values = try native_bus.Values.fromNative(a, admitted, receipt);
    const policy = try native_protocol.Admission.init(recursive_key, key_id, schedule, values);
    const span = try span_mod.leaf(admitted.pin, admitted.shape, admitted.sealed.digest, admitted.sealed.execution_instance_count);
    return create(a, policy, span, receipt.open_sum);
}
/// Only the explicit B5CT public policy can select this new child protocol.
/// Normalization records its actual frames and dynamic count supply intact.
pub fn fromCapacity(a: std.mem.Allocator, admitted: *const @import("../prover/block_v5_native_capacity_recursive_admission_v1.zig").Prepared, receipt: @import("../prover/block_v5_native_capacity_proof_v1.zig").OpenReceipt, recursive_key: capacity_protocol.Key, key_id: [32]u8, schedule: []const capacity_bus.Wire) !Child {
    if (!std.meta.eql(recursive_key.config, admitted.config) or
        !std.meta.eql(recursive_key.context.child_config, admitted.config)) return error.CapacityRecursiveSecurityMismatch;
    const values = try capacity_bus.Values.fromCapacity(a, admitted, receipt);
    const policy = try capacity_protocol.Admission.init(recursive_key, key_id, schedule, values);
    const span = try span_mod.leaf(admitted.pin, admitted.shape, admitted.sealed.digest, admitted.sealed.execution_instance_count);
    return create(a, policy, span, receipt.open_sum);
}
pub fn fromOpenV1(a: std.mem.Allocator, policy: v1_protocol.Admission) !Child {
    try policy.validate();
    var open = Q.zero();
    for (policy.values.children) |child| open = open.add(child.admission.values.open_sum);
    return create(a, policy, try policy.values.outputSpan(), open);
}
/// All recursive levels use this same protocol after the first open fold.
/// No legacy admission with an old claim-zero closure is admitted here.
pub fn fromOpenV2(a: std.mem.Allocator, policy: @import("block_v5_reusable_open_parent_protocol_v2.zig").Admission) !Child {
    try policy.validate();
    var open = Q.zero();
    for (policy.values.children) |child| open = open.add(child.native_open_sum);
    return create(a, policy, try policy.values.outputSpan(), open);
}
fn create(a: std.mem.Allocator, policy: anytype, span: span_mod.Span, open: Q) !Child {
    try policy.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var collector = Collector{ .a = temp };
    try policy.mix(&collector);
    if (collector.failure) |err| return err;
    const terms = try temp.alloc(Term, policy.wires.len);
    for (policy.wires, terms) |wire, *term| {
        const coordinates = if (@TypeOf(policy) == native_protocol.Admission or @TypeOf(policy) == capacity_protocol.Admission)
            try policy.values.at(wire.source, wire.coordinate)
        else
            try policy.values.at(wire);
        term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = if (@hasField(@TypeOf(wire), "negative")) wire.negative else false, .coordinates = coordinates };
    }
    var result = Child{ .arena = arena, .key = .{ .profile = policy.key.profile, .config = policy.key.config, .context = policy.key.context, .log_sizes = policy.key.log_sizes, .preprocessed_root = policy.key.preprocessed_root }, .expected_id = policy.expected_id, .public_input_digest = try policy.publicInputIdentity(), .claim_frame = .{ if (@TypeOf(policy) == capacity_protocol.Admission) capacity_protocol.CLAIM_TAG else if (@TypeOf(policy) == native_protocol.Admission) 0x42355243 else 0x42354f43, if (@TypeOf(policy) == @import("block_v5_reusable_open_parent_protocol_v2.zig").Admission) 2 else 1, @import("blake3_native_parent_artifact.zig").CLAIM_COUNT }, .frames = try collector.frames.toOwnedSlice(temp), .cells = try collector.cells.toOwnedSlice(temp), .terms = terms, .span = span, .native_open_sum = open, .seal = undefined };
    result.seal = try result.identity();
    try result.validate();
    return result;
}
const Collector = struct {
    a: std.mem.Allocator,
    frames: std.ArrayList(Frame) = .empty,
    cells: std.ArrayList([4]M) = .empty,
    failure: ?anyerror = null,
    fn add(self: *Collector, operation: Operation, words: []const u32) !void {
        if (words.len > LIMIT -| self.cells.items.len) return error.V5OpenChildFramesTooLarge;
        try self.frames.append(self.a, .{ .first = @intCast(self.cells.items.len), .operation = operation });
        for (words) |word| {
            var value: [4]M = undefined;
            for (&value, 0..) |*v, i| v.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
            try self.cells.append(self.a, value);
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
        for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        self.add(.{ .root = root }, &words) catch |err| {
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
pub const Admission = struct {
    pub const open_parent_v5_v2 = true;
    source: *const Child,
    key: base.Key,
    expected_id: [32]u8,
    pc_clock_children: []const span_mod.Span,
    pub fn init(source: *const Child, pc_clock_children: []const span_mod.Span) Admission {
        return .{ .source = source, .key = source.key, .expected_id = source.expected_id, .pc_clock_children = pc_clock_children };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        if (!std.meta.eql(self.key, self.source.key) or !std.meta.eql(self.expected_id, self.source.expected_id)) return error.UntrustedV5OpenChildFrames;
        if (self.pc_clock_children.len != 0) {
            for (self.pc_clock_children) |span| try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(span);
            _ = try @import("block_v5_open_parent_public_bus_v2.zig").merge(self.pc_clock_children);
        }
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
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: universal.UniversalRelations) !void {
        try self.validate();
        const element = try relations.getExact(.recursion_wire);
        var total = Q.zero();
        for (self.source.terms) |term| {
            const denominator = try element.combineBase(&(.{ M.fromCanonical(term.circuit), M.fromCanonical(term.wire) } ++ term.coordinates));
            if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
            const value = Q.fromBase(M.fromCanonical(term.uses)).mul(try denominator.inv());
            total = if (term.negative) total.sub(value) else total.add(value);
        }
        for (claims) |claim| total = total.add(claim);
        if (!total.isZero()) return error.InvalidV5NestedChildPublicClosure;
    }
};
