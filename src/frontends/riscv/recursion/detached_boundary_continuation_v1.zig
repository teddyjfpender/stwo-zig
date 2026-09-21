//! Detached boundary continuation operations; shared by the canonical preparation owner.
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
const SectionProfileV1 = @import("detached_section_profile_v1.zig").SectionProfileV1;
const SectionV1 = @import("detached_section_profile_v1.zig").SectionV1;
const graph = @import("detached_boundary_graph_v1.zig");
const Inputs = graph.Inputs;
const U32 = graph.U32;
const base = graph.base;
const GraphCalls = graph.GraphCalls;
const NativeCalls = graph.NativeCalls;
const access_clock = @import("../access_clock.zig");
const memory_profile_mod = @import("detached_memory_profile_v1.zig");
const poseidon = @import("../air/memory_commitment/mod.zig").poseidon2;

pub fn constrainSegmentIndexBound(builder: *recorder.Builder, next: U32, count: U32, remaining: U32, carry: S) !void {
    // Every limb is independently ranged to u16. Both equations are below2^18,
    // so extension-field wrap cannot counterfeit count = index + 1 + remaining.
    try builder.constrainZero(carry.mul(carry.sub(S.one())));
    try builder.constrainZero(next.limbs[0].add(remaining.limbs[0]).sub(count.limbs[0]).sub(carry.mul(base(65536))));
    try builder.constrainZero(next.limbs[1].add(remaining.limbs[1]).add(carry).sub(count.limbs[1]));
}

pub fn testIndexBounds() !void {
    const Case = struct { next: u32, count: u32, remaining: u32, carry: u1, valid: bool };
    const cases = [_]Case{
        .{ .next = 1, .count = 1, .remaining = 0, .carry = 0, .valid = true },
        .{ .next = 65536, .count = 65536, .remaining = 0, .carry = 0, .valid = true },
        .{ .next = 65535, .count = 65536, .remaining = 1, .carry = 1, .valid = true },
        .{ .next = 0xffff_ffff, .count = 0xffff_ffff, .remaining = 0, .carry = 0, .valid = true },
        .{ .next = 2, .count = 1, .remaining = 0xffff_ffff, .carry = 1, .valid = false },
        .{ .next = 65536, .count = 65535, .remaining = 0xffff_ffff, .carry = 0, .valid = false },
        .{ .next = 1, .count = 0, .remaining = 0xffff_ffff, .carry = 1, .valid = false },
    };
    const allocator = std.testing.allocator;
    for (cases) |case| {
        var builder = recorder.Builder.init(allocator);
        defer builder.deinit();
        var inputs = Inputs{ .allocator = allocator, .builder = &builder };
        defer inputs.deinit();
        var integers: [3]U32 = undefined;
        for (&integers, [_]u32{ case.next, case.count, case.remaining }) |*integer, native| {
            for (&integer.limbs, 0..) |*limb, word| limb.* = try inputs.add(M31.fromCanonical((native >> @as(u5, @intCast(16 * word))) & 65535), .{ .remaining_segments_limb = @intCast(word) });
        }
        const carry = try inputs.add(M31.fromCanonical(case.carry), .remaining_segments_carry);
        for (0..6) |word| try inputs.addRange(word, 16);
        try builder.activate();
        try inputs.constrainRanges();
        try constrainSegmentIndexBound(&builder, integers[0], integers[1], integers[2], carry);
        builder.deactivate();
        var circuit = try builder.finish();
        defer circuit.deinit();
        const values = try allocator.alloc(QM31, circuit.nodes.len);
        defer allocator.free(values);
        if (case.valid) try circuit.evaluateInto(inputs.values.items, values) else try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.values.items, values));
    }
}

pub const MemoryCounter = struct {
    count: usize = 0,
    pub fn emptyRoot(_: *MemoryCounter, depth: u32) M31 {
        return M31.fromCanonical(poseidon.DEFAULT_HASHES[depth]);
    }
    pub fn leaf(_: *MemoryCounter, value: M31) M31 {
        return value;
    }
    pub fn pair(self: *MemoryCounter, _: M31, _: M31) M31 {
        self.count += 1;
        return M31.zero();
    }
};
pub const NativeMemoryHasher = struct {
    calls: *NativeCalls,
    pub fn emptyRoot(_: *NativeMemoryHasher, depth: u32) M31 {
        return M31.fromCanonical(poseidon.DEFAULT_HASHES[depth]);
    }
    pub fn leaf(_: *NativeMemoryHasher, value: M31) M31 {
        return value;
    }
    pub fn pair(self: *NativeMemoryHasher, left: M31, right: M31) M31 {
        return self.calls.permute(poseidon.pairState(M31, M31.zero(), left, right))[0];
    }
};
pub const GraphMemoryHasher = struct {
    calls: *GraphCalls,
    pub fn emptyRoot(_: *GraphMemoryHasher, depth: u32) S {
        return base(poseidon.DEFAULT_HASHES[depth]);
    }
    pub fn leaf(_: *GraphMemoryHasher, value: S) S {
        return value;
    }
    pub fn pair(self: *GraphMemoryHasher, left: S, right: S) S {
        return self.calls.permute(poseidon.pairState(S, S.zero(), left, right))[0];
    }
};
pub fn rangedByte(inputs: *const Inputs, word: usize, byte: u1) !S {
    for (inputs.ranges.items) |range| if (range.input == word) {
        if (range.bits.len != 16) return error.InvalidBoundaryRange;
        var value = S.zero();
        for (range.bits[@as(usize, byte) * 8 ..][0..8], 0..) |bit, index| value = value.add(bit.mul(base(@as(u32, 1) << @as(u5, @intCast(index)))));
        return value;
    };
    return error.InvalidBoundaryRange;
}
pub fn recordContinuationRoots(allocator: std.mem.Allocator, calls: *GraphCalls, inputs: *const Inputs, wire: []const S, sections: [4]SectionV1, addresses: [2][]const u32) !void {
    var hasher = GraphMemoryHasher{ .calls = calls };
    for (sections[0..2], addresses, [_]usize{ wire_layout.entry_continuation_root, wire_layout.exit_continuation_root }) |section, fixed_addresses, root_offset| {
        const bytes = try allocator.alloc([4]S, section.count);
        defer allocator.free(bytes);
        for (bytes, fixed_addresses, 0..) |*values, address, index| {
            const at = section.payload_start + index * 4;
            for (0..2) |limb| try calls.builder.constrainZero(wire[at + limb].sub(base((address >> @as(u5, @intCast(16 * limb))) & 65535)));
            for (values, 0..) |*value, byte| value.* = try rangedByte(inputs, at + 2 + byte / 2, @intCast(byte % 2));
            // Canonical sparse words are nonzero; individual bytes still may
            // be zero, and never select a different tree or provider schedule.
            const nonzero = wire[at + 2].add(wire[at + 3]);
            try calls.builder.constrainZero(nonzero.mul(nonzero.inverse()).sub(S.one()));
        }
        var iterator = memory_profile_mod.ByteIterator(S).init(fixed_addresses, bytes);
        const root = recursion.segment_statement_v2.continuationSubtreeRootWithHasher(&iterator, 0, 0, recursion.segment_statement_v2.MAX_RW_ADDRESS_EXCLUSIVE, &hasher);
        if (iterator.current != null) return error.InvalidBoundaryMemoryProfile;
        try calls.builder.constrainZero(root.sub((U32{ .limbs = wire[root_offset..][0..2].* }).value()));
    }
}

pub const ClockBits = [32]S;
pub fn integerBits(inputs: *const Inputs, offset: usize) !ClockBits {
    var result: ClockBits = @splat(S.zero());
    for (0..2) |limb| {
        var found = false;
        for (inputs.ranges.items) |range| if (range.input == offset + limb) {
            if (range.bits.len > 16) return error.InvalidBoundaryRange;
            @memcpy(result[limb * 16 ..][0..range.bits.len], range.bits);
            found = true;
            break;
        };
        if (!found) return error.InvalidBoundaryRange;
    }
    return result;
}
pub fn bitsEqual(left: ClockBits, right: ClockBits) S {
    var equal = S.one();
    for (left, right) |a, b| {
        const difference = a.sub(b);
        equal = equal.mul(S.one().sub(difference.mul(difference)));
    }
    return equal;
}
pub fn bitsLess(left: ClockBits, right: ClockBits) S {
    var less = S.zero();
    // Ascending significance: a different current bit overrides all lower bits.
    for (left, right) |a, b| {
        const difference = a.sub(b);
        less = S.one().sub(a).mul(b).add(S.one().sub(difference.mul(difference)).mul(less));
    }
    return less;
}
pub const ClockPredicate = struct {
    pub fn isZero(_: ClockPredicate, value: ClockBits) S {
        return bitsEqual(value, @splat(S.zero()));
    }
    pub fn hasOrdinal(_: ClockPredicate, value: ClockBits) S {
        comptime std.debug.assert(access_clock.STRIDE == 4);
        return value[0].add(value[1]).sub(value[0].mul(value[1]));
    }
    pub fn bucketPrecedes(_: ClockPredicate, clock: ClockBits, count: ClockBits) S {
        var bucket: ClockBits = @splat(S.zero());
        @memcpy(bucket[0..30], clock[2..32]);
        return bitsLess(bucket, count);
    }
    pub fn both(_: ClockPredicate, a: S, b: S) S {
        return a.mul(b);
    }
    pub fn either(_: ClockPredicate, a: S, b: S) S {
        return a.add(b).sub(a.mul(b));
    }
};

/// Canonical clock rules over the same range-constrained raw-wire words that
/// feed identity hashing and child statement claims. No host-selected matching
/// index or clock value enters the circuit shape.
pub fn recordClockCanonicality(builder: *recorder.Builder, inputs: *const Inputs, sections: [4]SectionV1, end_offset: usize) !void {
    const start = try integerBits(inputs, BASE + span_layout.first_cycle_start);
    const end = try integerBits(inputs, end_offset);
    for (0..32) |register| {
        const entry = try integerBits(inputs, wire_layout.entry_register_clocks + register * 2);
        const exit = try integerBits(inputs, wire_layout.exit_register_clocks + register * 2);
        try builder.constrainZero(access_clock.withinExecutionGeneric(entry, start, true, ClockPredicate{}).sub(S.one()));
        try builder.constrainZero(access_clock.withinExecutionGeneric(exit, end, true, ClockPredicate{}).sub(S.one()));
        try builder.constrainZero(bitsLess(exit, entry));
    }
    for (sections[2..4], [_]ClockBits{ start, end }) |section, cycle| {
        var previous: ?ClockBits = null;
        for (0..section.count) |index| {
            const offset = section.payload_start + index * 4;
            const address = try integerBits(inputs, offset);
            const clock = try integerBits(inputs, offset + 2);
            // Aligned addresses below2^30 are exactly <=MAX_RW-4.
            comptime std.debug.assert(recursion.segment_statement_v2.MAX_RW_ADDRESS_EXCLUSIVE == 1 << 30);
            for ([_]usize{ 0, 1, 30, 31 }) |bit| try builder.constrainZero(address[bit]);
            if (previous) |prior| try builder.constrainZero(bitsLess(prior, address).sub(S.one()));
            try builder.constrainZero(access_clock.withinExecutionGeneric(clock, cycle, false, ClockPredicate{}).sub(S.one()));
            previous = address;
        }
    }
    // Strict ordering above makes every match unique. Every entry must retain
    // one exit address and that address's clock may only advance. This bounded
    // development graph scans the admitted section counts; no dynamic lookup
    // topology is inferred from the witness.
    for (0..sections[2].count) |entry_index| {
        const entry_offset = sections[2].payload_start + entry_index * 4;
        const entry_address = try integerBits(inputs, entry_offset);
        const entry_clock = try integerBits(inputs, entry_offset + 2);
        var matches = S.zero();
        for (0..sections[3].count) |exit_index| {
            const exit_offset = sections[3].payload_start + exit_index * 4;
            const equal = bitsEqual(entry_address, try integerBits(inputs, exit_offset));
            matches = matches.add(equal);
            try builder.constrainZero(equal.mul(bitsLess(try integerBits(inputs, exit_offset + 2), entry_clock)));
        }
        try builder.constrainZero(matches.sub(S.one()));
    }
}

pub fn testClockCanonicality() !void {
    const allocator = std.testing.allocator;
    // Directly exercise the production graph entry, bypassing native canonical
    // decoding so malformed clocks cannot be rejected only by host admission.
    const cases = [_]struct {
        entry_register: u32 = 5,
        exit_register: u32 = 9,
        entry_clock: u32 = 5,
        exit_clock: u32 = 9,
        entry_address: u32 = 4096,
        exit_address: u32 = 4096,
        exit_next_address: u32 = 4100,
        valid: bool = true,
    }{
        .{},                                                              .{ .entry_register = 0, .exit_register = 0 },
        .{ .entry_register = 63, .exit_register = 127 },                  .{ .entry_register = 4, .valid = false },
        .{ .entry_register = 65, .valid = false },                        .{ .entry_register = 9, .exit_register = 5, .valid = false },
        .{ .entry_clock = 0, .valid = false },                            .{ .exit_clock = 128, .valid = false },
        .{ .exit_clock = 5, .entry_clock = 9, .valid = false },           .{ .exit_address = 4104, .exit_next_address = 4108, .valid = false },
        .{ .exit_next_address = 4096, .valid = false },                   .{ .exit_next_address = 4092, .valid = false },
        .{ .entry_address = 4097, .exit_address = 4097, .valid = false }, .{ .entry_address = 1 << 30, .exit_address = 1 << 30, .valid = false },
    };
    const profile = SectionProfileV1{ .counts = .{ 0, 0, 1, 2 } };
    const word_count = recursion.segment_statement_v2.FIXED_CANONICAL_WORDS + 12 + 12;
    const sections = try profile.sections(word_count);
    for (cases) |case| {
        var native: [word_count + 2]u32 = @splat(0);
        native[BASE + span_layout.first_cycle_start] = 16;
        native[word_count] = 32;
        const pairs = [_]struct { at: usize, value: u32 }{
            .{ .at = wire_layout.entry_register_clocks, .value = case.entry_register },
            .{ .at = wire_layout.exit_register_clocks, .value = case.exit_register },
            .{ .at = sections[2].payload_start, .value = case.entry_address },
            .{ .at = sections[3].payload_start, .value = case.exit_address },
            .{ .at = sections[2].payload_start + 2, .value = case.entry_clock },
            .{ .at = sections[3].payload_start + 2, .value = case.exit_clock },
            .{ .at = sections[3].payload_start + 4, .value = case.exit_next_address },
            .{ .at = sections[3].payload_start + 6, .value = 9 },
        };
        for (pairs) |pair| {
            native[pair.at] = pair.value & 65535;
            native[pair.at + 1] = pair.value >> 16;
        }
        var builder = recorder.Builder.init(allocator);
        defer builder.deinit();
        var inputs = Inputs{ .allocator = allocator, .builder = &builder };
        defer inputs.deinit();
        for (native, 0..) |word, index| _ = try inputs.add(M31.fromCanonical(word), .{ .transcript = .{ .kind = .statement, .item = @intCast(index), .limb = 0, .uses = 1 } });
        for ([_]usize{ BASE + span_layout.first_cycle_start, word_count }) |offset| for (0..2) |limb| try inputs.addRange(offset + limb, 16);
        for ([_]usize{ wire_layout.entry_register_clocks, wire_layout.exit_register_clocks }) |offset| for (0..64) |limb| try inputs.addRange(offset + limb, 16);
        for (sections[2..4]) |section| for (0..section.payloadWords()) |word| try inputs.addRange(section.payload_start + word, 16);
        try builder.activate();
        try inputs.constrainRanges();
        try recordClockCanonicality(&builder, &inputs, sections, word_count);
        builder.deactivate();
        var circuit = try builder.finish();
        defer circuit.deinit();
        const values = try allocator.alloc(QM31, circuit.nodes.len);
        defer allocator.free(values);
        if (case.valid) try circuit.evaluateInto(inputs.values.items, values) else try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.values.items, values));
    }
}
