//! Ethereum row17: original schedule consumption plus authenticated public-word routing.
//! Word values are committed inputs. Only source coordinates and fan-out belong
//! to preprocessing; none of the statement or digest values is a circuit constant.
const std = @import("std");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.ethereum_publication_control.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 10;
pub const PREPROCESSED_COLUMN_COUNT: usize = 33;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize = 45;
pub const DIRECT_CONSTRAINT_COUNT: usize = 18;
pub const RELATION_EVENT_COUNT: usize = 13;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 7;
pub const INTERACTION_COLUMN_COUNT: usize = 28;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const SEMANTIC_DIGEST_HEX = "c57c74c861342ddeb224ccd32a56feba18f60b11c8e671708a227b1b1355b238";
pub const SEMANTIC_DIGEST = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk bytes;
};
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.meta.eql(identity.bytes, SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidEthereumPublicationControl;
        for (self.events, 0..) |event, index| if (lang.types.idIndex(event) != index)
            return error.InvalidEthereumPublicationControl;
    }
};
pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}
pub fn semanticIdentity(allocator: std.mem.Allocator) !lang.digest.Identity {
    var result = try buildRaw(allocator);
    defer result.deinit();
    return lang.digest.computeIdentity(&result.arena);
}
fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    const value = try arena.input("ethereum_publication.value", .felt, span);
    const auxiliary_names = [_][]const u8{ "raw.low", "raw.high", "raw.byte0", "raw.byte1", "raw.byte2", "raw.byte3", "raw.canonical_delta", "raw.canonical_inverse", "raw.high_byte_doubled" };
    var aux: [9]Id = undefined;
    for (&aux, auxiliary_names, 0..) |*id, name, index| id.* = try arena.input(name, if ((index >= 2 and index <= 5) or index == 8) .byte else .felt, span);
    const names = [_][]const u8{
        "control.row_mask",     "control.segment_mask", "control.verifier",       "control.sequence",  "control.tag",
        "control.arg0",         "control.arg1",         "control.arg2",           "control.arg3",      "word.row_mask",
        "word.source_mask",     "word.source_scope",    "word.source_index",      "word.hash0_mask",   "word.hash0_scope",
        "word.hash0_index",     "word.hash1_mask",      "word.hash1_scope",       "word.hash1_index",  "word.hash2_mask",
        "word.hash2_scope",     "word.hash2_index",     "word.public_mask",       "word.public_index", "word.digest_mask",
        "word.digest_verifier", "word.digest_limb",     "raw.mask",               "raw.join_mask",     "raw.source_index",
        "word.fixed_mask",      "word.fixed_value",     "word.claim_source_mask",
    };
    var pp: [PREPROCESSED_COLUMN_COUNT]Id = undefined;
    for (&pp, names) |*id, name| id.* = try arena.input(name, .felt, span);
    const segment = try arena.input("ethereum_publication.segment_active", .selector, span);
    const binary = try arena.input("ethereum_publication.binary_active", .selector, span);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const selected = try arena.add(try arena.mul(pp[1], segment, span), try arena.mul(try arena.sub(one, pp[1], span), binary, span), span);
    const control_active = try arena.mul(pp[0], selected, span);
    const word_active = try arena.mul(pp[9], segment, span);
    _ = try arena.assertZero("ethereum_publication.control_enabler", try arena.mul(one, try arena.sub(one, one, span), span), null, .semantic, span);
    _ = try arena.assertZero("ethereum_publication.inactive_word_zero", try arena.mul(try arena.sub(one, word_active, span), value, span), null, .semantic, span);
    const raw_active = try arena.mul(pp[27], segment, span);
    const join_active = try arena.mul(pp[28], segment, span);
    inline for (0..9) |index| {
        const id = aux[index];
        const name = auxiliary_names[index] ++ ".inactive";
        const gate = if (index == 0) raw_active else join_active;
        _ = try arena.assertZero(name, try arena.mul(try arena.sub(one, gate, span), id, span), null, .semantic, span);
    }
    const radix = try arena.constantField(65536, span);
    const byte_radix = try arena.constantField(256, span);
    _ = try arena.assertZero("raw.join", try arena.mul(raw_active, try arena.sub(value, try arena.add(aux[0], try arena.mul(radix, aux[1], span), span), span), span), null, .semantic, span);
    for (0..2) |index| {
        const joined = try arena.add(aux[2 + 2 * index], try arena.mul(byte_radix, aux[3 + 2 * index], span), span);
        _ = try arena.assertZero(if (index == 0) "raw.low_bytes" else "raw.high_bytes", try arena.mul(join_active, try arena.sub(aux[index], joined, span), span), null, .semantic, span);
    }
    // p=2^31-1 is3 mod4: a²+b²=0 iff both arezero. Together with
    // high<32768, excluding(low,high)=(65535,32767) makes the join canonical.
    const dlo = try arena.sub(aux[0], try arena.constantField(65535, span), span);
    const dhi = try arena.sub(aux[1], try arena.constantField(32767, span), span);
    const delta = try arena.add(try arena.mul(dlo, dlo, span), try arena.mul(dhi, dhi, span), span);
    _ = try arena.assertZero("raw.canonical_delta", try arena.mul(join_active, try arena.sub(aux[6], delta, span), span), null, .semantic, span);
    _ = try arena.assertZero("raw.canonical_inverse", try arena.mul(join_active, try arena.sub(try arena.mul(aux[6], aux[7], span), one, span), span), null, .semantic, span);
    _ = try arena.assertZero("raw.high_byte_double", try arena.mul(join_active, try arena.sub(aux[8], try arena.mul(try arena.constantField(2, span), aux[5], span), span), span), null, .semantic, span);
    const zero_byte = try arena.constantUnsigned(.byte, 0, span);
    _ = try arena.assertZero("word.admitted_constant", try arena.mul(try arena.mul(pp[30], segment, span), try arena.sub(value, pp[31], span), span), null, .semantic, span);
    const raw_scope = try arena.constantField(1114, span);
    const public_scope = try arena.constantField(@import("field_public_word_v3.zig").PUBLIC_SCOPE, span);
    const digest_kind = try arena.constantField(@import("field_public_word_v3.zig").DIGEST_INPUT_KIND, span);
    const events = try effects.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_step, .role = .consume, .values = &.{ pp[2], pp[3], pp[4], pp[5], pp[6], pp[7], pp[8] }, .weight = control_active },
        .{ .domain = .recursion_statement_word, .role = .consume, .values = &.{ pp[11], pp[12], value }, .weight = try arena.mul(word_active, pp[10], span) },
        .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = &.{ pp[14], pp[15], value }, .weight = try arena.mul(word_active, pp[13], span) },
        .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = &.{ pp[17], pp[18], value }, .weight = try arena.mul(word_active, pp[16], span) },
        .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = &.{ pp[20], pp[21], value }, .weight = try arena.mul(word_active, pp[19], span) },
        .{ .domain = .recursion_statement_word, .role = .emit, .values = &.{ public_scope, pp[23], value }, .weight = try arena.mul(word_active, pp[22], span) },
        .{ .domain = .recursion_verifier_input_word, .role = .emit, .values = &.{ pp[25], digest_kind, zero, pp[26], value }, .weight = try arena.mul(word_active, pp[24], span) },
        .{ .domain = .recursion_vm_public_claim_word, .role = .consume, .values = &.{ raw_scope, pp[29], aux[0] }, .weight = raw_active },
        .{ .domain = .recursion_vm_public_claim_word, .role = .consume, .values = &.{ raw_scope, try arena.add(pp[29], one, span), aux[1] }, .weight = join_active },
        .{ .domain = .range_check_8_8, .role = .request, .values = &.{ aux[2], aux[3] }, .weight = join_active },
        .{ .domain = .range_check_8_8, .role = .request, .values = &.{ aux[4], aux[5] }, .weight = join_active },
        .{ .domain = .range_check_8_8, .role = .request, .values = &.{ aux[8], zero_byte }, .weight = join_active },
        .{ .domain = .recursion_vm_public_claim_word, .role = .consume, .values = &.{ pp[11], pp[12], value }, .weight = try arena.mul(word_active, pp[32], span) },
    }, span);
    return .{ .arena = arena, .events = events };
}

/// Preserve the original control tuple and lane selection exactly.
pub fn controlRow(row: [11]M31) Relation.Row {
    var result = [_]M31{M31.zero()} ** LOGICAL_INPUT_COUNT;
    @memcpy(result[10..19], row[0..9]);
    @memcpy(result[PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT ..][0..PARAMETER_COUNT], row[9..11]);
    return result;
}
pub fn wordRow(value: M31, preprocessing: [PREPROCESSED_COLUMN_COUNT]u32) Relation.Row {
    var result = [_]M31{M31.zero()} ** LOGICAL_INPUT_COUNT;
    result[0] = value;
    for (result[PHYSICAL_MAIN_COLUMN_COUNT..][0..PREPROCESSED_COLUMN_COUNT], preprocessing) |*destination, word| destination.* = M31.fromCanonical(word);
    result[PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT] = M31.one();
    return result;
}
pub fn rawWordRow(value: M31, low: M31, high: M31, joined: bool, source_index: u32, preprocessing: [PREPROCESSED_COLUMN_COUNT]u32) !Relation.Row {
    const lo = low.toU32();
    const hi = high.toU32();
    if (joined) {
        if (lo > 65535 or hi > 32767 or (lo == 65535 and hi == 32767)) return error.NoncanonicalPublicationWord;
    } else if (hi != 0) return error.NoncanonicalPublicationWord;
    if (@as(u64, lo) + @as(u64, hi) * 65536 != value.toU32()) return error.NoncanonicalPublicationWord;
    var pp = preprocessing;
    pp[27] = 1;
    pp[28] = @intFromBool(joined);
    pp[29] = source_index;
    var result = wordRow(value, pp);
    result[1] = low;
    if (joined) {
        result[2] = high;
        result[3] = M31.fromCanonical(lo & 255);
        result[4] = M31.fromCanonical(lo >> 8);
        result[5] = M31.fromCanonical(hi & 255);
        result[6] = M31.fromCanonical(hi >> 8);
        const dlo = low.sub(M31.fromCanonical(65535));
        const dhi = high.sub(M31.fromCanonical(32767));
        result[7] = dlo.mul(dlo).add(dhi.mul(dhi));
        result[8] = try result[7].inv();
        result[9] = M31.fromCanonical((hi >> 8) * 2);
    }
    return result;
}
