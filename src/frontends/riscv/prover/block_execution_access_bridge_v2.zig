//! Extract block-v2 transition sources from the same typed opcode lookup
//! program and committed main columns used by the existing execution AIR.
//! This is the source-identity half of the sidecar: the PCS adapter must also
//! prove the integer byte decompositions and transition LogUp recurrence.
const std = @import("std");
const core = @import("stwo_core");
const entries = @import("../air/lookups/opcode_entries.zig");
const lookup = @import("../air/lookups/entry.zig");
const trace = @import("../runner/trace.zig");

pub const MAX_PAIRS: usize = 3;
/// The load/store source and destination alternate between RW and register
/// space. Their authentic space is the native is_load/is_store selector,
/// already Boolean and bounded by the instruction enabler in the native AIR.
pub fn hasConditionalSpace(family: trace.OpcodeFamily, slot: usize) bool {
    return family == .load_store and (slot == 1 or slot == 2);
}
pub fn rwPairForMode(comptime S: type, family: trace.OpcodeFamily, slot: usize, pair: Pair(S), mode: u32) !Pair(S) {
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    if (mode == 0) return pair;
    if (hasConditionalSpace(family, slot)) {
        var result = pair;
        // An algebraic selector, including at arbitrary OODS points. Using
        // active*space would unnecessarily increase the quotient degree.
        result.active = pair.space;
        result.space = S.one();
        return result;
    }
    if (!pair.space.eql(S.one())) return error.MixedV5OpcodeMemoryScope;
    return pair;
}
pub const AddressUnit = enum { word_index, byte_address };

pub fn Pair(comptime S: type) type {
    return struct {
        /// The old typed AIR's emitted numerator, already tied to its
        /// instruction and conditional-access selectors.
        active: S,
        space: S,
        /// Space zero: architectural register index. Space one: an aligned
        /// address in the fixed unit below.
        source_address: S,
        /// Native opcode load/store selectors are already byte addresses;
        /// precompile callers expose word indices. This is fixed by the
        /// authenticated component family, never by witness data.
        address_unit: AddressUnit = .word_index,
        /// Leaf-local strict access subclock from the typed emit effect.
        local_clock: S,
        /// Exact consumed clock from the typed native entry. Block-v2 needs
        /// only the emitted clock; the v5 universal-memory cancellation uses
        /// both native tuples. External callers set this in their own bridge.
        consume_clock: ?S = null,
        before: [4]S,
        after: [4]S,
        /// These must be added as direct constraints in the sidecar quotient.
        /// Merely checking them while constructing a witness is insufficient.
        pair_residuals: [3]S,
        access_ordinal: ?u8,
    };
}

pub fn Pairs(comptime S: type) type {
    return struct {
        items: [MAX_PAIRS]Pair(S) = undefined,
        len: usize = 0,
    };
}

/// Replays the production opcode relation builder at the caller's already
/// committed main columns. The same function accepts M31 domain evaluations
/// and QM31 PCS point openings; no hand-maintained per-opcode column map is
/// trusted. The returned residuals must be proved by the sidecar AIR.
pub fn fromCommittedMain(comptime S: type, family: trace.OpcodeFamily, main: []const S) !Pairs(S) {
    if (main.len != trace.nColumnsForFamily(family)) return error.InvalidBlockExecutionMainGeometry;
    const list = try entries.Entries(S).fromMain(family, main);
    var result = Pairs(S){};
    var cursor: usize = 0;
    while (cursor < list.len) : (cursor += 1) {
        const consume = list.entries[cursor];
        if (consume.domain != .memory_access) continue;
        if (consume.role != .consume or cursor + 1 >= list.len) return error.InvalidTypedAccessPair;
        const emit = list.entries[cursor + 1];
        if (emit.domain != .memory_access or emit.role != .emit or
            emit.access_ordinal != consume.access_ordinal or
            consume.arity != 7 or emit.arity != 7) return error.InvalidTypedAccessPair;
        if (result.len >= MAX_PAIRS) return error.TooManyTypedAccessPairs;
        result.items[result.len] = .{
            .active = emit.numerator,
            .space = emit.values[0],
            .source_address = emit.values[1],
            .address_unit = if (family == .load_store) .byte_address else .word_index,
            .local_clock = emit.values[2],
            .consume_clock = consume.values[2],
            .before = consume.values[3..7].*,
            .after = emit.values[3..7].*,
            .pair_residuals = .{
                consume.numerator.add(emit.numerator),
                consume.values[0].sub(emit.values[0]),
                consume.values[1].sub(emit.values[1]),
            },
            .access_ordinal = emit.access_ordinal,
        };
        result.len += 1;
        cursor += 1;
    }
    return result;
}

/// Host-side witness admission used before writing sidecar byte columns.
/// The quotient repeats these equalities using `pair_residuals` and the
/// committed sidecar limbs; this check does not grant proof authority.
pub fn decodePair(pair: Pair(core.fields.qm31.QM31)) !struct {
    space: u1,
    source_address: u32,
    local_clock: u32,
    before: u32,
    after: u32,
    active: bool,
} {
    const active = try canonicalBase(pair.active);
    const space = try canonicalBase(pair.space);
    if (active > 1 or space > 1) return error.InvalidTypedAccessValue;
    for (pair.pair_residuals) |residual| if (!residual.isZero()) return error.InvalidTypedAccessPair;
    // Padded opcode rows may evaluate derived clocks as M31 negatives even
    // though their access selector is zero. Their tuple contributes nothing.
    if (active == 0) return .{ .space = 0, .source_address = 0, .local_clock = 0, .before = 0, .after = 0, .active = false };
    var before: u32 = 0;
    var after: u32 = 0;
    for (pair.before, pair.after, 0..) |prior, next, index| {
        const prior_byte = try canonicalBase(prior);
        const next_byte = try canonicalBase(next);
        if (prior_byte > 255 or next_byte > 255) return error.InvalidTypedAccessValue;
        before |= prior_byte << @intCast(index * 8);
        after |= next_byte << @intCast(index * 8);
    }
    const source_address = try canonicalBase(pair.source_address);
    const local_clock = try canonicalBase(pair.local_clock);
    // The native load/store quarter-index AIR bounds its aligned byte
    // selector below 2^30. Keep that bound here for both address units so
    // base-field byte packing cannot alias through the M31 modulus.
    if (space == 0 and source_address >= 32 or
        space == 1 and source_address >= (1 << 30) or
        space == 1 and pair.address_unit == .byte_address and source_address & 3 != 0 or
        local_clock >= (1 << 27)) return error.InvalidTypedAccessValue;
    return .{ .space = @intCast(space), .source_address = source_address, .local_clock = local_clock, .before = before, .after = after, .active = active == 1 };
}

fn canonicalBase(value: core.fields.qm31.QM31) !u32 {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.InvalidTypedAccessValue;
    return limbs[0].toU32();
}

test "block-v2 access bridge extracts every production opcode family from one typed source" {
    const Q = core.fields.qm31.QM31;
    var main: [trace.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const count = trace.nColumnsForFamily(family);
        const pairs = try fromCommittedMain(Q, family, main[0..count]);
        try std.testing.expect(pairs.len <= MAX_PAIRS);
        for (pairs.items[0..pairs.len]) |pair| {
            try std.testing.expectEqual(if (family == .load_store) AddressUnit.byte_address else AddressUnit.word_index, pair.address_unit);
            for (pair.pair_residuals) |residual| try std.testing.expect(residual.isZero());
        }
    }
}
