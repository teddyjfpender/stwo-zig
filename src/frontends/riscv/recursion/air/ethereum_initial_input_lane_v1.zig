//! Opt-in linear initial-input role lane. This module is not selected by any
//! manifest yet. Header and native relation coefficients are authenticated
//! wire inputs; no proof-derived value belongs to its preprocessing.
//!
//! Integration contract (not supplied by this module):
//! - the admitted graph derives z/alpha powers and the canonical claim header;
//! - row12 supplies each present/value claim word with one additional use;
//! - the bounded completion graph supplies five canonical program packets;
//! - the admitted public sum consumes the one streamed input subtotal;
//! - the existing role hash consumes every emitted canonical tuple word.
//! Output count zero, public-input digest/shape, role header and completion
//! semantics still belong to their existing authenticated owners. Every row
//! through role_capacity is populated, including nonzero-coefficient padding.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const qm31 = @import("qm31_mul.zig");
const claim = @import("../vm_public_claim.zig");
const Id = lang.types.ValueId;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const VERSION: u16 = 1;
pub const STABLE_NAME = "recursion.ethereum_initial_input_lane.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 49;
pub const PREPROCESSED_COLUMN_COUNT: usize = 6;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = 55;
pub const DIRECT_CONSTRAINT_COUNT: usize = 35;
pub const RELATION_EVENT_COUNT: usize = 42;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 21;
pub const INTERACTION_COLUMN_COUNT: usize = 84;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 5;
pub const SOURCE_SCOPE: u32 = 0x494e50; // INP: fixed wire namespace, not a claim scope.
pub const STATE_SCOPE: u32 = SOURCE_SCOPE + 1;
pub const HEADER_SLOT: u32 = 6;
pub const SUM_SLOT: u32 = 7;
pub const PROGRAM_FIRST_SLOT: u32 = 8;
pub const PROGRAM_PACKET_COUNT: usize = 5;
pub const PROGRAM_WORD_COUNT: usize = 18;
pub const ROLE_HASH_SCOPE: u32 = 1100;
pub const RANGE_REQUEST_COUNT: usize = 5;
const RANGE_MAIN_PAIRS = [RANGE_REQUEST_COUNT][2]?u8{ .{ 0, 1 }, .{ 2, 3 }, .{ 10, 11 }, .{ 12, 13 }, .{ 15, null } };
pub const CLAIM_SOURCE_SCOPE = @import("vm_public_claim_input.zig").VM_PUBLIC_LOGUP_SCOPE;
pub const SEMANTIC_DIGEST_HEX = "487faca476d9d26334696c03adc9f7d814ceaffc0e77868b3f41994e949e49f8";
pub const SEMANTIC_DIGEST: lang.digest.Digest = blk: {
    var value: lang.digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&value, SEMANTIC_DIGEST_HEX) catch unreachable;
    break :blk value;
};
pub const Relation = @import("universal_relation_binding.zig").Binding(@This());
pub const Row = [LOGICAL_INPUT_COUNT]M31;
const span = lang.source.SourceSpan.generated();
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.meta.eql(identity.bytes, SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidEthereumInitialInputAir;
        for (self.events, 0..) |event, index| if (lang.types.idIndex(event) != index) return error.InvalidEthereumInitialInputAir;
    }
};
pub fn build(allocator: std.mem.Allocator) !Definition {
    var value = try buildRaw(allocator);
    errdefer value.deinit();
    try value.validate();
    return value;
}
pub fn semanticIdentity(allocator: std.mem.Allocator) !lang.digest.Identity {
    var value = try buildRaw(allocator);
    defer value.deinit();
    try lang.validate.validate(&value.arena);
    return lang.digest.computeIdentity(&value.arena);
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var a = Author{ .arena = lang.ir.Arena.init(allocator) };
    errdefer a.arena.deinit();
    var m: [49]Id = undefined;
    inline for (&m, 0..) |*value, index| value.* = try a.arena.input(std.fmt.comptimePrint("initial_input.main.{d}", .{index}), if (index < 4 or (index >= 10 and index < 14) or index == 15) .byte else if (index == 8 or index == 9 or index == 14) .selector else .felt, span);
    var p: [6]Id = undefined;
    inline for (&p, 0..) |*value, index| value.* = try a.arena.input(std.fmt.comptimePrint("initial_input.preprocessed.{d}", .{index}), if (index < 3) .selector else .felt, span);
    const zero = try a.c(0);
    const one = try a.c(1);
    const inactive = try a.sub(one, m[8]);
    const program = try a.sub(m[9], m[8]);
    const hash_weight = try a.sub(one, program);
    const radix = try a.c(65536);
    const byte_radix = try a.c(256);
    for ([_]Id{ m[8], m[9], m[14] }) |bit| try a.root(try a.mul(bit, try a.sub(bit, one)));
    try a.root(try a.mul(try a.sub(one, m[9]), m[8]));
    try a.root(try a.mul(p[0], try a.sub(m[9], one)));
    try a.root(try a.mul(p[1], m[8]));
    try a.root(try a.mul(try a.sub(one, p[2]), m[8]));
    for (m[0..4]) |byte| try a.root(try a.mul(inactive, byte));
    for (m[10..14]) |byte| try a.root(try a.mul(inactive, byte));
    try a.root(try a.mul(inactive, m[14]));
    try a.root(try a.sub(m[15], try a.mul(try a.c(2), m[13])));
    // The 31-bit byte representation must also exclude the M31 modulus.
    // This nonnegative byte-distance is zero only at0x7fffffff.
    var delta = try a.sub(try a.c(127), m[13]);
    for (m[10..13]) |byte| delta = try a.add(delta, try a.sub(try a.c(255), byte));
    try a.root(try a.sub(try a.mul(delta, m[48]), m[8]));
    try a.root(try a.mul(inactive, m[48]));
    const address_low = try a.add(m[10], try a.mul(byte_radix, m[11]));
    const address_high = try a.add(m[12], try a.mul(byte_radix, m[13]));
    const offset_low = try a.sub(try a.mul(try a.c(4), p[3]), try a.mul(radix, p[5]));
    try a.root(try a.mul(m[8], try a.sub(try a.add(m[4], offset_low), try a.add(address_low, try a.mul(radix, m[14])))));
    try a.root(try a.mul(m[8], try a.sub(try a.add(try a.add(m[5], p[5]), m[14]), address_high)));
    const index_low = try a.sub(p[3], try a.mul(radix, p[4]));
    try a.root(try a.mul(program, try a.sub(m[6], index_low)));
    try a.root(try a.mul(program, try a.sub(m[7], p[4])));
    for (m[44..48]) |word| try a.root(try a.mul(p[0], word));
    // Coefficients are z, alpha, alpha^3, alpha^4, alpha^5, alpha^6.
    // Native memory tuple is (1,address,0,byte0,byte1,byte2,byte3).
    const address = try a.add(address_low, try a.mul(radix, address_high));
    var denominator: [4]Id = undefined;
    for (&denominator, 0..) |*value, limb| {
        value.* = try a.sub(if (limb == 0) one else zero, m[16 + limb]);
        value.* = try a.add(value.*, try a.mul(m[20 + limb], address));
        for (0..4) |byte| value.* = try a.add(value.*, try a.mul(m[24 + byte * 4 + limb], m[byte]));
    }
    const product = try qm31.productCoordinates(&a.arena, denominator, m[40..44].*, span);
    for (product, 0..) |word, limb| try a.root(try a.sub(word, if (limb == 0) m[8] else zero));
    for (m[40..44]) |word| try a.root(try a.mul(inactive, word));
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    var at: usize = 0;
    const source_scope = try a.c(SOURCE_SCOPE);
    const state_scope = try a.c(STATE_SCOPE);
    for (0..6) |coefficient| {
        events[at] = try a.event(.recursion_wire, .consume, &(.{ source_scope, try a.c(@intCast(coefficient)) } ++ m[16 + 4 * coefficient ..][0..4].*), hash_weight);
        at += 1;
    }
    events[at] = try a.event(.recursion_wire, .consume, &(.{ source_scope, try a.c(HEADER_SLOT) } ++ m[4..8].*), one);
    at += 1;
    const current = try a.mul(try a.c(2), p[3]);
    const not_first = try a.sub(one, p[0]);
    const not_last = try a.sub(one, p[1]);
    events[at] = try a.event(.recursion_wire, .consume, &(.{ state_scope, current } ++ m[44..48].*), not_first);
    at += 1;
    events[at] = try a.event(.recursion_wire, .consume, &.{ state_scope, try a.add(current, one), m[9], zero, zero, zero }, not_first);
    at += 1;
    var next_sum: [4]Id = undefined;
    for (&next_sum, m[44..48], m[40..44]) |*sum, previous, term| sum.* = try a.add(previous, term);
    const next_scope = try a.add(try a.mul(not_last, state_scope), try a.mul(p[1], source_scope));
    const next_slot = try a.add(try a.mul(not_last, try a.add(current, try a.c(2))), try a.mul(p[1], try a.c(SUM_SLOT)));
    events[at] = try a.event(.recursion_wire, .emit, &(.{ next_scope, next_slot } ++ next_sum), one);
    at += 1;
    events[at] = try a.event(.recursion_wire, .emit, &.{ state_scope, try a.add(current, try a.c(3)), m[8], zero, zero, zero }, not_last);
    at += 1;
    const claim_scope = try a.c(CLAIM_SOURCE_SCOPE);
    const claim_index = try a.add(try a.c(claim.canonical_layout.input_slots_start), try a.mul(try a.c(claim.INPUT_SLOT_WORDS), p[3]));
    const claim_words = [_]Id{ m[8], try a.add(m[0], try a.mul(byte_radix, m[1])), try a.add(m[2], try a.mul(byte_radix, m[3])) };
    for (claim_words, 0..) |word, limb| {
        events[at] = try a.event(.recursion_vm_public_claim_word, .consume, &.{ claim_scope, try a.add(claim_index, try a.c(@intCast(limb))), word }, p[2]);
        at += 1;
    }
    // At the unique count boundary, these cells carry the bounded program
    // graph's canonical role words. Its last packet has two explicit zeros.
    for (0..PROGRAM_PACKET_COUNT) |packet| {
        var payload: [4]Id = @splat(zero);
        for (&payload, 0..) |*word, limb| if (packet * 4 + limb < PROGRAM_WORD_COUNT) {
            word.* = m[16 + packet * 4 + limb];
        };
        events[at] = try a.event(.recursion_wire, .consume, &(.{ source_scope, try a.c(PROGRAM_FIRST_SLOT + @as(u32, @intCast(packet))) } ++ payload), program);
        at += 1;
    }
    const role_words = [_]Id{ m[8], m[8], m[8], try a.mul(try a.c(7), m[8]), m[8], zero, address_low, address_high, zero, zero, m[0], zero, m[1], zero, m[2], zero, m[3], zero };
    const hash_index = try a.add(try a.c(6), try a.mul(try a.c(18), p[3]));
    for (role_words, 0..) |word, index| {
        events[at] = try a.event(.recursion_vm_public_claim_word, .emit, &.{ try a.c(ROLE_HASH_SCOPE), try a.add(hash_index, try a.c(@intCast(index))), try a.add(word, try a.mul(program, m[16 + index])) }, one);
        at += 1;
    }
    const zero_byte = try a.arena.constantUnsigned(.byte, 0, span);
    for (RANGE_MAIN_PAIRS) |indices| {
        const pair = [2]Id{ if (indices[0]) |index| m[index] else zero_byte, if (indices[1]) |index| m[index] else zero_byte };
        events[at] = try a.event(.range_check_8_8, .request, &pair, one);
        at += 1;
    }
    if (at != RELATION_EVENT_COUNT or a.constraints != DIRECT_CONSTRAINT_COUNT) return error.InvalidEthereumInitialInputAir;
    return .{ .arena = a.arena, .events = events };
}
const Author = struct {
    arena: lang.ir.Arena,
    constraints: usize = 0,
    fn c(self: *Author, value: u32) !Id {
        return self.arena.constantField(value, span);
    }
    fn add(self: *Author, a: Id, b: Id) !Id {
        return self.arena.add(a, b, span);
    }
    fn sub(self: *Author, a: Id, b: Id) !Id {
        return self.arena.sub(a, b, span);
    }
    fn mul(self: *Author, a: Id, b: Id) !Id {
        return self.arena.mul(a, b, span);
    }
    fn root(self: *Author, value: Id) !void {
        var buffer: [64]u8 = undefined;
        _ = try self.arena.assertZero(try std.fmt.bufPrint(&buffer, "initial_input.constraint.{d}", .{self.constraints}), value, null, .semantic, span);
        self.constraints += 1;
    }
    fn event(self: *Author, domain: lang.relation.Domain, role: lang.relation.Role, values: []const Id, weight: Id) !lang.types.EffectId {
        return effects.append(&self.arena, .{ .domain = domain, .role = role, .values = values, .weight = weight }, span);
    }
};

/// Geometry-only schedule. Capacity is admitted, never inferred from witnesses.
pub const Shape = struct {
    max_input_words: u32,
    role_capacity: u32,
    pub fn init(max_input_words: u32) !Shape {
        if (max_input_words > (1 << 24)) return error.InvalidEthereumInitialInputShape;
        return .{ .max_input_words = max_input_words, .role_capacity = try std.math.ceilPowerOfTwo(u32, try std.math.add(u32, max_input_words, 1)) };
    }
    /// Fixed graph-provider fanout. The unique program row consumes the
    /// program packets instead of coefficients; no dynamic use count is PP.
    pub fn wireSourceUses(self: Shape, slot: u32) !u32 {
        if (!std.meta.eql(self, try init(self.max_input_words))) return error.InvalidEthereumInitialInputShape;
        if (slot < HEADER_SLOT) return self.role_capacity - 1;
        if (slot == HEADER_SLOT) return self.role_capacity;
        if (slot >= PROGRAM_FIRST_SLOT and slot < PROGRAM_FIRST_SLOT + PROGRAM_PACKET_COUNT) return 1;
        return error.InvalidEthereumInitialInputSource;
    }
    pub fn claimSourceUses(self: Shape, word_index: usize) !u32 {
        if (!std.meta.eql(self, try init(self.max_input_words))) return error.InvalidEthereumInitialInputShape;
        const first = claim.canonical_layout.input_slots_start;
        return @intFromBool(word_index >= first and word_index < first + @as(usize, self.max_input_words) * claim.INPUT_SLOT_WORDS);
    }
    pub fn preprocessing(self: Shape, index: u32) ![6]M31 {
        if (!std.meta.eql(self, try init(self.max_input_words)) or index >= self.role_capacity) return error.InvalidEthereumInitialInputShape;
        return .{ field(@intFromBool(index == 0)), field(@intFromBool(index + 1 == self.role_capacity)), field(@intFromBool(index < self.max_input_words)), field(index), field(index >> 16), field((index * 4) >> 16) };
    }
};
pub const Witness = struct {
    header: [4]M31, // input start low/high, input count low/high
    coefficients: [6]QM31,
    word: u32,
    present: bool,
    previous_present: bool,
    previous_sum: QM31,
    /// The unique presence-drop row must receive the canonical program tuple
    /// from the independently authenticated bounded completion graph.
    program_words: ?[PROGRAM_WORD_COUNT]M31 = null,
};
pub fn row(shape: Shape, index: u32, witness: Witness) !Row {
    for (witness.header) |word| if (word.toU32() > 65535) return error.InvalidEthereumInitialInputHeader;
    var result = [_]M31{M31.zero()} ** LOGICAL_INPUT_COUNT;
    @memcpy(result[49..], &(try shape.preprocessing(index)));
    @memcpy(result[4..8], &witness.header);
    result[8] = field(@intFromBool(witness.present));
    result[9] = field(@intFromBool(witness.previous_present));
    if (witness.present) {
        const start = @as(u32, witness.header[0].toU32()) + @as(u32, witness.header[1].toU32()) * 65536;
        const address = try std.math.add(u32, start, try std.math.mul(u32, index, 4));
        if (address >= 0x7fffffff) return error.InvalidEthereumInitialInputAddress;
        for (0..4) |byte| {
            result[byte] = field((witness.word >> @as(u5, @intCast(byte * 8))) & 255);
            result[10 + byte] = field((address >> @as(u5, @intCast(byte * 8))) & 255);
        }
        result[14] = field(@intFromBool((start & 65535) + ((index * 4) & 65535) > 65535));
        result[15] = field(2 * result[13].toU32());
        var delta: u32 = 127 - result[13].toU32();
        for (result[10..13]) |byte| delta += 255 - byte.toU32();
        result[48] = try field(delta).inv();
        var denominator = QM31.one().sub(witness.coefficients[0]).add(witness.coefficients[1].mul(QM31.fromBase(field(address))));
        for (0..4) |byte| denominator = denominator.add(witness.coefficients[2 + byte].mul(QM31.fromBase(result[byte])));
        @memcpy(result[40..44], &(try denominator.inv()).toM31Array());
    }
    if (witness.previous_present and !witness.present) {
        @memcpy(result[16..][0..PROGRAM_WORD_COUNT], &(witness.program_words orelse return error.MissingEthereumInitialProgramWords));
    } else {
        for (witness.coefficients, 0..) |coefficient, at| @memcpy(result[16 + at * 4 ..][0..4], &coefficient.toM31Array());
    }
    @memcpy(result[44..48], &witness.previous_sum.toM31Array());
    return result;
}
/// Exact canonical range tuples shared with the typed effect author above.
/// Requests occur on every physical row, including program and padding rows.
pub fn rangePairs(value: Row) [RANGE_REQUEST_COUNT][2]M31 {
    var pairs: [RANGE_REQUEST_COUNT][2]M31 = undefined;
    for (&pairs, RANGE_MAIN_PAIRS) |*pair, indices| for (pair, indices) |*word, index| {
        word.* = if (index) |at| value[at] else M31.zero();
    };
    return pairs;
}
fn field(value: u32) M31 {
    return M31.fromCanonical(value);
}
