//! Page-wide SOURCE SHA connector, not a SHA digest oracle. Main[0..1728]
//! aliases the ORIGINAL source commitment. Appended256 bytes are the two
//! packed compression boundary captures, committed before the wire draw.
//! Actual packed source/schedule/round/feed-forward AIRs and all their table
//! providers must close this connector's exact64 wire slots. Every capture
//! byte participates in that wire relation: range authority comes from the
//! freshly verified original cores/tables, never from this component alone.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Packed = @import("block_v5_memory_source_packed_sha_v1.zig");
const Original = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const SHA = @import("../air/guest_precompile/sha256_compression.zig");
const Graph = @import("../air/guest_precompile/sha256_compression_graph.zig");
const Rows = @import("../air/guest_precompile/sha256_compression_rows.zig");
pub const SOURCE_MAIN_COUNT: usize = Original.BIT_COUNT;
pub const CAPTURE_MAIN_COUNT: usize = 2 * 128;
pub const MAIN_COUNT = SOURCE_MAIN_COUNT + CAPTURE_MAIN_COUNT;
pub const FIXED_COUNT: usize = 6 + 64 + 64 + 32;
pub const EXPANDED_FIXED_COUNT: usize = FIXED_COUNT + 8;
pub const WIRE_COUNT: usize = 64;
pub const PAIRS = WIRE_COUNT / 2;
pub const INTERACTION_COUNT = 4 * PAIRS;
pub const DIRECT_CONSTRAINT_COUNT = SOURCE_MAIN_COUNT + 2 * 128 + 512 + 256 + 32 + 64 + 32 + 64 + 32;
pub const CONSTRAINT_COUNT = DIRECT_CONSTRAINT_COUNT + PAIRS;
pub const DEGREE: u32 = 3;
pub const EXPANSION_BITS: u32 = 2;
pub const Fixed = [FIXED_COUNT]M;
/// Independently reconstructed full row recipe; null is exact padding.
/// Record rows have active0 and no packed SHA/core requests.
pub fn fixedRow(admitted: *const Source.Admitted, descriptor: ?Raw.Descriptor) !Fixed {
    try admitted.require();
    var out: Fixed = @splat(M.zero());
    const d = descriptor orelse return out;
    const s = switch (d) {
        .sha => |value| value,
        .record => |value| {
            try Original.validateKind(admitted, .{ .record = .{ .stream = value.stream, .ordinal = value.ordinal } });
            return out;
        },
    };
    const count = try Packed.chunkCompressionCount(admitted, s.stream, s.block);
    const length = admitted.byteLength(s.stream);
    const terminal = s.block == length / 64;
    const used: usize = if (terminal) @intCast(length % 64) else 64;
    out[0] = M.one();
    out[1] = M.fromCanonical(@intFromBool(s.block == 0));
    out[2] = M.fromCanonical(@intFromBool(terminal));
    out[3] = M.fromCanonical(@intFromBool(count == 2));
    out[4] = M.fromCanonical(try Raw.firstCall(admitted, s.stream, s.block));
    out[5] = M.fromCanonical(out[4].toU32() + 1);
    for (0..used) |i| out[6 + i] = M.one();
    if (terminal) {
        out[6 + 64 + used] = M.fromCanonical(0x80);
        if (used < 56) for (0..8) |i| {
            out[6 + 64 + 56 + i] = M.fromCanonical(@as(u8, @truncate((length * 8) >> @intCast(56 - 8 * i))));
        };
    }
    for (admitted.digest(s.stream), 0..) |byte, i| out[6 + 128 + i] = M.fromCanonical(byte);
    return out;
}
pub fn expandedFixedRow(admitted: *const Source.Admitted, descriptor: ?Raw.Descriptor) ![EXPANDED_FIXED_COUNT]M {
    const recipe = try fixedRow(admitted, descriptor);
    const length: u64 = if (descriptor) |d| switch (d) {
        .sha => |s| admitted.byteLength(s.stream),
        .record => 0,
    } else 0;
    return Algebra(core.fields.qm31.QM31).expand(recipe, length);
}
/// Native boundary serializer. Captures always follow state/block/output byte
/// order; a missing second block is zero, never an arbitrary unused witness.
pub fn captureInputs(boundaries: []const Packed.Boundary, output: []M) !void {
    if (output.len != CAPTURE_MAIN_COUNT or boundaries.len == 0 or boundaries.len > 2) return error.InvalidSourceShaConnectorCapture;
    @memset(output, M.zero());
    var at: usize = 0;
    for (boundaries) |boundary| {
        for (boundary.state) |word| for (0..4) |i| {
            output[at] = M.fromCanonical(@as(u8, @truncate(word >> @intCast(8 * i))));
            at += 1;
        };
        for (boundary.block) |byte| {
            output[at] = M.fromCanonical(byte);
            at += 1;
        }
        for (boundary.output) |word| for (0..4) |i| {
            output[at] = M.fromCanonical(@as(u8, @truncate(word >> @intCast(8 * i))));
            at += 1;
        };
    }
}
pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Challenge = struct { z: S, powers: [6]S };
        pub const Term = struct { numerator: S, denominator: S };
        fn scalar(value: u32) S {
            if (S == core.fields.packed_qm31.PackedQM31) return S.fromBase(@splat(M.fromCanonical(value).v));
            return S.fromBase(M.fromCanonical(value));
        }
        fn pack(bits: []const S) S {
            var out = S.zero();
            var factor = S.one();
            for (bits) |bit| {
                out = out.add(factor.mul(bit));
                factor = factor.add(factor);
            }
            return out;
        }
        pub const FIXED_VALUES_COUNT = EXPANDED_FIXED_COUNT;
        pub fn expand(fixed: Fixed, length: u64) [FIXED_VALUES_COUNT]M {
            var out: [FIXED_VALUES_COUNT]M = undefined;
            @memcpy(out[0..FIXED_COUNT], &fixed);
            for (0..8) |i| out[FIXED_COUNT + i] = M.fromCanonical(@as(u8, @truncate((length * 8) >> @intCast(56 - 8 * i))));
            return out;
        }
        /// Each wire is reconstructed from the exact committed boundary bytes,
        /// not from a separate six-cell request table or an adaptive copy.
        pub fn terms(fixed: [FIXED_VALUES_COUNT]S, main: [MAIN_COUNT]S, c: Self.Challenge) [WIRE_COUNT]Self.Term {
            var out: [WIRE_COUNT]Self.Term = undefined;
            for (0..2) |block| {
                const base = SOURCE_MAIN_COUNT + block * 128;
                const active = fixed[if (block == 0) 0 else 3];
                const call = fixed[4 + block];
                for (0..32) |wire| {
                    var values: [6]S = undefined;
                    values[0] = call;
                    const supply = wire < 24;
                    values[1] = scalar(if (supply) Graph.input_boundary_offset + @as(u32, @intCast(wire)) else Rows.topology.output[wire - 24]);
                    if (wire < 8 or wire >= 24) {
                        const start = base + if (wire < 8) wire * 4 else 96 + (wire - 24) * 4;
                        for (0..4) |byte| values[2 + byte] = main[start + byte];
                    } else {
                        const start = base + 32 + (wire - 8) * 4;
                        for (0..4) |byte| values[2 + byte] = main[start + (3 - byte)];
                    }
                    var denominator = c.z.neg();
                    for (values, c.powers) |value, power| denominator = denominator.add(value.mul(power));
                    out[block * 32 + wire] = .{ .numerator = if (supply) active else active.neg(), .denominator = denominator };
                }
            }
            return out;
        }
        pub fn constraints(fixed: [FIXED_VALUES_COUNT]S, main: [MAIN_COUNT]S, current: [INTERACTION_COUNT]S, previous: [INTERACTION_COUNT]S, normalized: [PAIRS]S, c: Self.Challenge) [CONSTRAINT_COUNT]S {
            @setEvalBranchQuota(2_000_000);
            var out: [CONSTRAINT_COUNT]S = undefined;
            var at: usize = 0;
            for (main[0..SOURCE_MAIN_COUNT]) |value| {
                out[at] = value.mul(value.sub(S.one()));
                at += 1;
            }
            const b1 = main[SOURCE_MAIN_COUNT..][0..128];
            const b2 = main[SOURCE_MAIN_COUNT + 128 ..][0..128];
            for (b1) |value| {
                out[at] = S.one().sub(fixed[0]).mul(value);
                at += 1;
            }
            for (b2) |value| {
                out[at] = S.one().sub(fixed[3]).mul(value);
                at += 1;
            }
            for (0..512) |i| {
                out[at] = main[i].mul(S.one().sub(fixed[6 + i / 8]));
                at += 1;
            }
            for (SHA.initial_state, 0..) |word, w| for (0..32) |i| {
                out[at] = fixed[1].mul(main[512 + 32 * w + i].sub(scalar((word >> @intCast(i)) & 1)));
                at += 1;
            };
            for (0..32) |i| {
                out[at] = fixed[0].mul(b1[i].sub(pack(main[512 + 8 * i ..][0..8])));
                at += 1;
            }
            for (0..64) |i| {
                out[at] = fixed[0].mul(b1[32 + i].sub(fixed[6 + i].mul(pack(main[8 * i ..][0..8]))).sub(fixed[70 + i]));
                at += 1;
            }
            for (0..32) |i| {
                out[at] = fixed[3].mul(b2[i].sub(b1[96 + i]));
                at += 1;
            }
            for (0..64) |i| {
                const expected = if (i < 56) S.zero() else fixed[FIXED_COUNT + i - 56];
                out[at] = fixed[3].mul(b2[32 + i].sub(expected));
                at += 1;
            }
            for (0..8) |word| for (0..4) |i| {
                const digest_index = 134 + 4 * word + (3 - i);
                const result = S.one().sub(fixed[3]).mul(b1[96 + word * 4 + i]).add(fixed[3].mul(b2[96 + word * 4 + i]));
                out[at] = fixed[2].mul(result.sub(fixed[digest_index]));
                at += 1;
            };
            std.debug.assert(at == DIRECT_CONSTRAINT_COUNT);
            const requests = terms(fixed, main, c);
            for (0..PAIRS) |pair| {
                const left = requests[2 * pair];
                const right = requests[2 * pair + 1];
                const delta = S.fromPartialEvals(current[4 * pair ..][0..4].*).sub(S.fromPartialEvals(previous[4 * pair ..][0..4].*)).add(normalized[pair]);
                out[at] = delta.mul(left.denominator).mul(right.denominator).sub(left.numerator.mul(right.denominator)).sub(right.numerator.mul(left.denominator));
                at += 1;
            }
            std.debug.assert(at == out.len);
            return out;
        }
    };
}
pub fn degree(index: usize) !u8 {
    if (index >= CONSTRAINT_COUNT) return error.InvalidSourceShaConnectorConstraint;
    const digest_first = DIRECT_CONSTRAINT_COUNT - 32;
    const padded_first = SOURCE_MAIN_COUNT + 2 * 128 + 512 + 256 + 32;
    return if (index >= digest_first or (index >= padded_first and index < padded_first + 64)) 3 else 2;
}
