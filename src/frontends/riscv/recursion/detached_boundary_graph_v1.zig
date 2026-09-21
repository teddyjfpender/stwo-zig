//! Detached boundary graph operations; shared by the canonical preparation owner.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const recorder = @import("air/composition_graph_recorder.zig");
const S = recorder.Scalar;
const recursion = struct {
    const segment_statement_v2 = @import("segment_statement_v2.zig");
    const span_statement = @import("span_statement.zig");
};
const wire_layout = recursion.segment_statement_v2.fixed_layout;
const span_layout = recursion.span_statement.canonical_layout;
const BASE = wire_layout.base_statement;
const prefix = @import("detached_prefix_preparation_v1.zig");
const Domain = @import("../air/lang/relation.zig").Domain;
const source = @import("segment_leaf_authority_v2.zig");
const framing = @import("poseidon2_channel.zig").canonical_word_sponge;
const poseidon = @import("../air/memory_commitment/mod.zig").poseidon2;
const preimage = @import("../air/statement_v2.zig").authority_preimage;
const rows = @import("segment_transcript_outer_source_v2.zig");

pub const InputSource = union(enum) {
    transcript: prefix.InputCoordinate,
    challenge: struct { domain: Domain, draw: u1, limb: u2, scope: u32 = prefix.BOUNDARY_CHALLENGE_SCOPE },
    end_limb: u1,
    increment_carry,
    increment_low,
    remaining_segments_limb: u1,
    remaining_segments_carry,
    zero_inverse: u2,
    range_bit: struct { input: u32, bit: u5 },
    provider_word: struct { call: u32, word: u5 },
};
pub const InputBinding = struct { node_id: u32, source: InputSource };
/// All32 nodes are base words. The first16 are constrained to the framed
/// sponge state; the remaining16 must be authenticated by Poseidon IO lookup.
pub const ProviderBinding = struct { nodes: [32]u32 };

pub const WordCounter = struct {
    count: usize = 0,
    pub fn scalar(self: *WordCounter, _: anytype) void {
        self.count += 1;
    }
    pub fn boolean(self: *WordCounter, _: anytype) void {
        self.count += 1;
    }
    pub fn u32Value(self: *WordCounter, _: anytype) void {
        self.count += 2;
    }
    pub fn digest(self: *WordCounter, _: anytype) void {
        self.count += 8;
    }
};

pub const NativeCalls = struct {
    calls: []rows.ProviderCall,
    words: [][32]M31,
    at: usize = 0,
    pub fn permute(self: *NativeCalls, input: [16]M31) [16]M31 {
        var output = input;
        poseidon.permute(&output);
        std.debug.assert(self.at < self.calls.len);
        var words: [16]u32 = undefined;
        for (&words, input) |*out, value| out.* = value.toU32();
        self.calls[self.at] = .{ .input = words, .wide = false, .io = true, .narrow_output = null };
        self.words[self.at] = input ++ output;
        self.at += 1;
        return output;
    }
};
pub const NativeSponge = struct {
    state: [16]M31,
    filled: usize = 0,
    calls: *NativeCalls,
    pub fn init(calls: *NativeCalls, domain: u32) NativeSponge {
        return .{ .state = framing.initialState(M31, M31.zero(), M31.fromCanonical(domain)), .calls = calls };
    }
    pub fn scalar(self: *NativeSponge, value: anytype) void {
        framing.absorb(self, M31.fromCanonical(@intCast(value)));
    }
    pub fn boolean(self: *NativeSponge, value: bool) void {
        self.scalar(@intFromBool(value));
    }
    pub fn u32Value(self: *NativeSponge, value: u32) void {
        self.scalar(value & 65535);
        self.scalar(value >> 16);
    }
    pub fn digest(self: *NativeSponge, value: [8]u32) void {
        for (value) |part| self.scalar(part);
    }
    pub fn word(self: *NativeSponge, _: preimage.Source, value: u32) void {
        self.scalar(value);
    }
    pub fn permute(self: *NativeSponge) void {
        self.state = self.calls.permute(self.state);
    }

    pub fn finish(self: *NativeSponge) [8]u32 {
        framing.finish(self, M31.one());
        var result: [8]u32 = undefined;
        for (&result, self.state[0..8]) |*out, value| out.* = value.toU32();
        return result;
    }
};

pub const Inputs = struct {
    allocator: std.mem.Allocator,
    builder: *recorder.Builder,
    values: std.ArrayList(QM31) = .empty,
    bindings: std.ArrayList(InputBinding) = .empty,
    scalars: std.ArrayList(S) = .empty,
    ranges: std.ArrayList(Range) = .empty,
    const Range = struct { input: u32, bits: []const S };
    pub fn deinit(self: *Inputs) void {
        for (self.ranges.items) |range| self.allocator.free(range.bits);
        self.ranges.deinit(self.allocator);
        self.scalars.deinit(self.allocator);
        self.values.deinit(self.allocator);
        self.bindings.deinit(self.allocator);
    }
    pub fn add(self: *Inputs, value: M31, role: InputSource) !S {
        const input = try self.builder.input();
        try self.values.append(self.allocator, QM31.fromBase(value));
        try self.bindings.append(self.allocator, .{ .node_id = input.node_id, .source = role });
        try self.scalars.append(self.allocator, input.value);
        return input.value;
    }
    pub fn addRange(self: *Inputs, index: usize, count: u6) !void {
        for (self.ranges.items) |prior| if (prior.input == index) {
            if (prior.bits.len != count) return error.InvalidBoundaryRange;
            return;
        };
        const bits = try self.allocator.alloc(S, count);
        errdefer self.allocator.free(bits);
        const native = self.values.items[index].toM31Array()[0].toU32();
        if (native >> @as(u5, @intCast(count)) != 0) return error.InvalidBoundaryRange;
        for (bits, 0..) |*bit, bit_index| bit.* = try self.add(M31.fromCanonical((native >> @as(u5, @intCast(bit_index))) & 1), .{ .range_bit = .{ .input = @intCast(index), .bit = @intCast(bit_index) } });
        try self.ranges.append(self.allocator, .{ .input = @intCast(index), .bits = bits });
    }
    pub fn constrainRanges(self: *const Inputs) !void {
        for (self.ranges.items) |range| {
            var value = S.zero();
            for (range.bits, 0..) |bit, index| {
                try self.builder.constrainZero(bit.mul(bit.sub(S.one())));
                value = value.add(bit.mul(base(@as(u32, 1) << @as(u5, @intCast(index)))));
            }
            try self.builder.constrainZero(self.scalars.items[range.input].sub(value));
        }
    }
};

pub fn base(value: u32) S {
    return S.fromBase(M31.fromCanonical(value));
}
pub const U32 = struct {
    limbs: [2]S,
    pub fn value(self: U32) S {
        return self.limbs[0].add(self.limbs[1].mul(base(65536)));
    }
};
pub fn asScalar(value: anytype) S {
    if (@TypeOf(value) == S) return value;
    if (@TypeOf(value) == U32) return value.value();
    return base(@intCast(value));
}
pub fn digestConstants(value: [8]u32) [8]S {
    var result: [8]S = undefined;
    for (&result, value) |*out, word| out.* = base(word);
    return result;
}
pub const GraphCalls = struct {
    builder: *recorder.Builder,
    words: []const [32]S,
    at: usize = 0,
    failure: ?anyerror = null,
    pub fn permute(self: *GraphCalls, input: [16]S) [16]S {
        const words = self.words[self.at];
        self.at += 1;
        for (words[0..16], input) |word, expected| self.builder.constrainZero(word.sub(expected)) catch |err| {
            self.failure = err;
        };
        return words[16..32].*;
    }
};
pub const GraphSponge = struct {
    state: [16]S,
    filled: usize = 0,
    calls: *GraphCalls,
    pub fn init(calls: *GraphCalls, domain: u32) GraphSponge {
        return .{ .state = framing.initialState(S, S.zero(), base(domain)), .calls = calls };
    }
    pub fn scalar(self: *GraphSponge, value: anytype) void {
        framing.absorb(self, asScalar(value));
    }
    pub fn boolean(self: *GraphSponge, value: S) void {
        self.scalar(value);
    }
    pub fn u32Value(self: *GraphSponge, value: U32) void {
        for (value.limbs) |limb| self.scalar(limb);
    }
    pub fn digest(self: *GraphSponge, value: [8]S) void {
        for (value) |part| self.scalar(part);
    }
    pub fn permute(self: *GraphSponge) void {
        self.state = self.calls.permute(self.state);
    }

    pub fn finish(self: *GraphSponge) [8]S {
        framing.finish(self, S.one());
        return self.state[0..8].*;
    }
};
pub const ContextWords = struct {
    words: [source.CONTEXT_WORD_COUNT]S = undefined,
    at: usize = 0,
    pub fn scalar(self: *ContextWords, value: anytype) void {
        self.words[self.at] = asScalar(value);
        self.at += 1;
    }
    pub fn boolean(self: *ContextWords, value: S) void {
        self.scalar(value);
    }
    pub fn u32Value(self: *ContextWords, value: U32) void {
        for (value.limbs) |word| self.scalar(word);
    }
    pub fn digest(self: *ContextWords, value: [8]S) void {
        for (value) |part| self.scalar(part);
    }
};
pub const AuthoritySink = struct {
    sponge: *GraphSponge,
    wire: []const S,
    wire_id: [8]S,
    pub fn word(self: *AuthoritySink, from: preimage.Source, value: u32) void {
        self.sponge.scalar(switch (from) {
            .protocol, .admitted_geometry => base(value),
            .wire_hash_digest => |index| self.wire_id[index],
            .span_scalar => |coordinate| self.wire[
                BASE + switch (coordinate.field) {
                    .initial_pc => span_layout.entry_state_start + span_layout.machine_state_pc_start_offset,
                    .final_pc => span_layout.exit_state_start + span_layout.machine_state_pc_start_offset,
                    .cycle_count => span_layout.executed_cycle_count_start,
                } + @as(usize, coordinate.limb)
            ],
        });
    }
};
