//! Exact original two-phase public transcript framing, independently rebuilt.
//! This owner is statement data, not proof authority. Every routed byte is
//! later supplied by the same trusted public bus as the quotient inputs.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Admission = @import("../../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_native_capacity_fused_recursive_capture_v1.zig");
const Fused = @import("../../prover/block_v5_native_capacity_fused_proof_v1.zig");
const Capacity = @import("../../prover/block_v5_native_capacity_protocol_v1.zig");
const Batch = @import("../../prover/block_execution_sidecar_batch_v2.zig");
const Range = @import("../../prover/block_execution_byte_range_v2.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_010;
pub const Span = struct { first: u32, len: u32 };
pub const Step = union(enum) { words: Span, root: u32, integer: u32, felts: Span };
/// Checked exact retained statement/public-vector extent, before allocation.
/// Dynamic array growth is separately charged to the preparation allocator.
pub const Extent = struct {
    words: usize,
    felts: usize,
    first_steps: usize,
    claim_steps: usize,
    public_inputs: usize,
    bytes: usize,
};
pub fn extent(admitted: *const Admission.Prepared) !Extent {
    const projections = admitted.projections.len;
    const accesses = admitted.slots.len;
    const has_access: usize = @intFromBool(accesses != 0);
    var words: usize = try std.math.add(usize, 103, try std.math.mul(usize, 8, has_access));
    for (admitted.projections) |slot_value| {
        const slot_words: usize = switch (slot_value.kind) {
            .program => 8,
            .lookup => 12,
        };
        words = try std.math.add(usize, words, 2 * slot_words + 2);
    }
    words = try std.math.add(usize, words, try std.math.mul(usize, 51, accesses));
    const felts = try std.math.add(usize, projections, try std.math.mul(usize, 2, accesses));
    const first_steps = try std.math.add(usize, try std.math.add(usize, 9, has_access), try std.math.mul(usize, 2, try std.math.add(usize, projections, accesses)));
    const claim_steps = try std.math.add(usize, try std.math.add(usize, 5, try std.math.mul(usize, 4, projections)), try std.math.mul(usize, 33, accesses));
    const public_inputs = try std.math.add(usize, try std.math.add(usize, 8, projections), try std.math.mul(usize, 10, accesses));
    var bytes = try std.math.mul(usize, words, @sizeOf(u32));
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, felts, @sizeOf(Q)));
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, try std.math.add(usize, first_steps, claim_steps), @sizeOf(Step)));
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, public_inputs, @sizeOf(Q)));
    if (bytes > admitted.limits.fused.max_metadata_bytes or try std.math.add(usize, words, try std.math.mul(usize, 4, felts)) >= core.fields.m31.Modulus or public_inputs >= core.fields.m31.Modulus) return error.CapacityFusedRecursiveResourceLimit;
    return .{ .words = words, .felts = felts, .first_steps = first_steps, .claim_steps = claim_steps, .public_inputs = public_inputs, .bytes = bytes };
}
pub const Statement = struct {
    allocator: std.mem.Allocator,
    words: []u32,
    felts: []Q,
    first: []Step,
    claims: []Step,
    sealed_offset: u32,
    roots_offset: [3]u32,
    pub fn init(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture) !Statement {
        return initClaims(a, admitted, capture.metadata.claims, capture.metadata.memory_claims);
    }
    pub fn initClaims(a: std.mem.Allocator, admitted: *const Admission.Prepared, projection_claims: []const Fused.Claim, memory_claims: []const @import("../../prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Claim) !Statement {
        if (projection_claims.len != admitted.projections.len or memory_claims.len != admitted.slots.len) return error.InvalidV5FullFusedClaims;
        const required = try extent(admitted);
        var b = Builder{ .a = a };
        defer b.deinit();
        const index = admitted.native.index;
        const native = admitted.binding;
        try b.words(&.{ Fused.TAG, Fused.VERSION, 1, index, @intCast(admitted.projections.len), @intCast(admitted.slots.len) });
        try b.root(Word.abiId());
        try b.words(&.{ Capacity.TAG, Capacity.VERSION, 1 });
        try b.root(native.template_id);
        try b.root(native.instance_id);
        for (admitted.projections) |slot| try b.slot(slot);
        try b.roster(admitted);
        var root_offsets: [3]u32 = undefined;
        root_offsets[0] = @intCast(b.data.items.len);
        try b.root(native.first_roots[0]);
        root_offsets[1] = @intCast(b.data.items.len);
        try b.root(native.first_roots[1]);
        root_offsets[2] = @intCast(b.data.items.len);
        if (admitted.slots.len != 0) try b.root(admitted.witness_root);
        const first = try b.steps.toOwnedSlice(a);
        errdefer a.free(first);
        // Universal-channel root is outside first/claim phase recipes.
        const sealed_offset: u32 = @intCast(b.data.items.len);
        try b.digestWords(admitted.native.sealed.digest);
        try b.words(&.{ Fused.TAG, Fused.VERSION, 2, index, @intCast(projection_claims.len), @intCast(memory_claims.len) });
        try b.root(native.template_id);
        try b.root(native.instance_id);
        for (admitted.projections, projection_claims) |slot, claim| {
            if (claim.row_count != slot.n_rows) return error.InvalidV5FullFusedClaims;
            try b.slot(slot);
            try b.integer(claim.row_count);
            try b.felts(&.{claim.sum});
        }
        try b.roster(admitted);
        for (admitted.slots, memory_claims) |slot, claim| {
            if (claim.active_count > (@as(u64, 1) << @intCast(slot.log_size))) return error.InvalidV5FullFusedClaims;
            try b.integer(claim.active_count);
            try b.felts(&.{ claim.transition_sum, claim.universal_sum });
            try b.words(&.{ Range.TAG, 2, index, @intFromEnum(slot.family), @intCast(slot.slot) });
            for (claim.range_claims) |sum| for (sum.toM31Array()) |limb| try b.words(&.{limb.toU32()});
        }
        const claims = try b.steps.toOwnedSlice(a);
        errdefer a.free(claims);
        const words = try b.data.toOwnedSlice(a);
        errdefer a.free(words);
        const felts = try b.fields.toOwnedSlice(a);
        errdefer a.free(felts);
        if (words.len != required.words or felts.len != required.felts or first.len != required.first_steps or claims.len != required.claim_steps) return error.InvalidCapacityFusedStatement;
        return .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = claims, .sealed_offset = sealed_offset, .roots_offset = root_offsets };
    }
    pub fn deinit(self: *Statement) void {
        self.allocator.free(self.words);
        self.allocator.free(self.felts);
        self.allocator.free(self.first);
        self.allocator.free(self.claims);
        self.* = undefined;
    }
    pub fn clone(self: *const Statement, a: std.mem.Allocator) !Statement {
        const words = try a.dupe(u32, self.words);
        errdefer a.free(words);
        const felts = try a.dupe(Q, self.felts);
        errdefer a.free(felts);
        const first = try a.dupe(Step, self.first);
        errdefer a.free(first);
        const claims = try a.dupe(Step, self.claims);
        var result = self.*;
        result.allocator = a;
        result.words = words;
        result.felts = felts;
        result.first = first;
        result.claims = claims;
        return result;
    }
    pub fn digest(self: *const Statement, offset: u32) ![32]u8 {
        if (offset > self.words.len or 8 > self.words.len - offset) return error.InvalidCapacityFusedStatement;
        var value: [32]u8 = undefined;
        for (self.words[offset..][0..8], 0..) |word, i| std.mem.writeInt(u32, value[4 * i ..][0..4], word, .little);
        return value;
    }
    /// Canonical native parity oracle; preserves each original mix invocation.
    pub fn replay(self: *const Statement, channel: *core.proof_suites.Blake3.Channel, steps: []const Step) !void {
        for (steps) |step| switch (step) {
            .words => |span| channel.mixU32s(try self.wordSpan(span)),
            .root => |offset| channel.mixRoot(try self.digest(offset)),
            .integer => |offset| channel.mixU64(try self.integerAt(offset)),
            .felts => |span| channel.mixFelts(try self.fieldSpan(span)),
        };
    }
    pub fn record(self: *const Statement, r: *@import("blake3_native_recorder.zig").Recorder, steps: []const Step) !void {
        const fields_base = std.math.cast(u32, self.words.len) orelse return error.InvalidCapacityFusedStatement;
        for (steps) |step| switch (step) {
            .words => |span| r.mixPublicWords(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = span.first }, try self.wordSpan(span)),
            .root => |offset| r.mixPublicRoot(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = offset }, try self.digest(offset)),
            .integer => |offset| r.mixPublicInteger(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = offset }, try self.integerAt(offset)),
            .felts => |span| r.mixPublicFelts(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = try std.math.add(u32, fields_base, try std.math.mul(u32, 4, span.first)) }, try self.fieldSpan(span)),
        };
        try r.check();
    }
    fn wordSpan(self: *const Statement, span: Span) ![]const u32 {
        if (span.first > self.words.len or span.len > self.words.len - span.first) return error.InvalidCapacityFusedStatement;
        return self.words[span.first..][0..span.len];
    }
    fn fieldSpan(self: *const Statement, span: Span) ![]const Q {
        if (span.first > self.felts.len or span.len > self.felts.len - span.first) return error.InvalidCapacityFusedStatement;
        return self.felts[span.first..][0..span.len];
    }
    fn integerAt(self: *const Statement, offset: u32) !u64 {
        if (offset > self.words.len or 2 > self.words.len - offset) return error.InvalidCapacityFusedStatement;
        return @as(u64, self.words[offset]) | (@as(u64, self.words[offset + 1]) << 32);
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    data: std.ArrayList(u32) = .empty,
    fields: std.ArrayList(Q) = .empty,
    steps: std.ArrayList(Step) = .empty,
    fn deinit(self: *Builder) void {
        self.data.deinit(self.a);
        self.fields.deinit(self.a);
        self.steps.deinit(self.a);
    }
    fn words(self: *Builder, values: []const u32) !void {
        const first = std.math.cast(u32, self.data.items.len) orelse return error.InvalidCapacityFusedStatement;
        try self.data.appendSlice(self.a, values);
        try self.steps.append(self.a, .{ .words = .{ .first = first, .len = std.math.cast(u32, values.len) orelse return error.InvalidCapacityFusedStatement } });
    }
    fn digestWords(self: *Builder, value: [32]u8) !void {
        for (0..8) |i| try self.data.append(self.a, std.mem.readInt(u32, value[4 * i ..][0..4], .little));
    }
    fn root(self: *Builder, value: [32]u8) !void {
        const first = std.math.cast(u32, self.data.items.len) orelse return error.InvalidCapacityFusedStatement;
        try self.digestWords(value);
        try self.steps.append(self.a, .{ .root = first });
    }
    fn integer(self: *Builder, value: u64) !void {
        const first = std.math.cast(u32, self.data.items.len) orelse return error.InvalidCapacityFusedStatement;
        try self.data.appendSlice(self.a, &.{ @truncate(value), @truncate(value >> 32) });
        try self.steps.append(self.a, .{ .integer = first });
    }
    fn felts(self: *Builder, values: []const Q) !void {
        for (values) |value| if (!@import("universal_provider_relations.zig").secureIsCanonical(&value)) return error.InvalidV5FullFusedClaims;
        const first = std.math.cast(u32, self.fields.items.len) orelse return error.InvalidCapacityFusedStatement;
        try self.fields.appendSlice(self.a, values);
        try self.steps.append(self.a, .{ .felts = .{ .first = first, .len = std.math.cast(u32, values.len) orelse return error.InvalidCapacityFusedStatement } });
    }
    fn slot(self: *Builder, value: anytype) !void {
        try self.words(&.{ @intFromEnum(std.meta.activeTag(value.kind)), value.degree, value.log_size, value.n_rows, @intCast(value.main_offset), @intCast(value.width), value.register_custody_mode });
        switch (value.kind) {
            .program => |family| try self.words(&.{@intFromEnum(family)}),
            .lookup => |lookup| try self.words(&.{ switch (lookup.source) {
                .opcode => |family| @intFromEnum(family),
                .clock => @import("../../runner/trace.zig").N_FAMILIES,
            }, @intFromEnum(lookup.partition), lookup.entries[0], lookup.entries[1], lookup.entry_count }),
        }
    }
    fn roster(self: *Builder, admitted: *const Admission.Prepared) !void {
        try self.words(&.{ Batch.TAG, 1, admitted.native.index, @intCast(admitted.slots.len) });
        try self.root(admitted.binding.template_id);
        for (admitted.slots) |slot_value| {
            try self.words(&.{ @intFromEnum(slot_value.family), @intCast(slot_value.slot), slot_value.log_size, @intCast(slot_value.main_offset), @intFromEnum(slot_value.frame.clock_frame), slot_value.frame.cycle_count });
            try self.integer(slot_value.frame.global_first_cycle);
        }
    }
};
