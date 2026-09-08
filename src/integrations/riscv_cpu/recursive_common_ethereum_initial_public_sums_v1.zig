//! Explicit compact initial-segment policy. Not selected by active owners.
//! Reuses the existing global, raw-clock, native-root, completion-opening and
//! canonical cancellation constraints. Input role terms are streamed by the
//! admitted linear lane; no operation count scales with the input capacity.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
pub const support = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
const packet = @import("recursive_common_ethereum_initial_input_packet_v1.zig");
const role = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const claim = frontend.recursion.vm_public_claim;
const arithmetic = frontend.recursion.arithmetic_circuit;
const Value = arithmetic.Value;
const M31 = core.fields.m31.M31;
pub const POLICY_VERSION: u16 = 1;
pub const EXPECTED_OUTPUT_CAPACITY: u32 = 12;
pub const PACKET_INPUT_COUNT = packet.INPUT_COUNT;
pub const DECODED_BIT_COUNT: usize = 128;
pub fn inputCount(opening_count: usize) !usize {
    return std.math.add(usize, 1 + support.STATEMENT_WORD_COUNT + support.CLOCK_LIMB_COUNT + support.REGISTER_BYTE_COUNT + role.HEADER_WORD_COUNT + 6 + support.NONFINAL_COMPLETION_INPUT_COUNT + support.global_binding.WORD_COUNT + support.global_binding.AUX_COUNT + support.CLOCK_AUX_INPUT_COUNT + DECODED_BIT_COUNT + PACKET_INPUT_COUNT + 2 + support.CHALLENGE_WORD_COUNT + support.CANONICAL_CLAIM_WORD_COUNT, opening_count);
}
pub const Source = union(enum) {
    existing: support.InputSourceV4,
    packet_limb: u6,
};
pub const Built = struct {
    circuit: arithmetic.Circuit,
    bindings: []Source,
    claim_shape: claim.Shape,
    packet_first_input: u32,
    pub fn deinit(self: *Built, allocator: std.mem.Allocator) void {
        self.circuit.deinit();
        allocator.free(self.bindings);
        self.* = undefined;
    }
};
const Author = struct {
    allocator: std.mem.Allocator,
    builder: arithmetic.Builder,
    bindings: std.ArrayList(Source) = .empty,
    fn input(self: *Author, source: Source) !Value {
        const index: u32 = @intCast(self.bindings.items.len);
        try self.bindings.append(self.allocator, source);
        return self.builder.input(index);
    }
    fn old(self: *Author, source: support.InputSourceV4) !Value {
        return self.input(.{ .existing = source });
    }
};
pub fn build(allocator: std.mem.Allocator, shape: claim.Shape, admission: *const support.program_admission.ProgramAdmissionV1) !Built {
    if (!std.meta.eql(shape, try claim.Shape.init(shape.max_input_words, shape.max_output_words)) or shape.max_input_words == 0 or shape.max_output_words != EXPECTED_OUTPUT_CAPACITY) return error.InvalidEthereumInitialInputAdmission;
    if (admission.openingInputWordCount() == 0) return error.EthereumInitialProgramOpeningRequired;
    const lane_shape = try packet.Air.lane.Shape.init(shape.max_input_words);
    var author = Author{ .allocator = allocator, .builder = arithmetic.Builder.initDefault(allocator) };
    defer author.builder.deinit();
    errdefer author.bindings.deinit(allocator);
    const builder = &author.builder;
    const selected = try author.old(.segment_selector);
    var statement: [support.STATEMENT_WORD_COUNT]Value = undefined;
    for (&statement, 0..) |*v, i| v.* = try author.old(.{ .statement_word = @intCast(i) });
    var clocks: [support.CLOCK_LIMB_COUNT]Value = undefined;
    for (&clocks, 0..) |*v, i| v.* = try author.old(.{ .register_clock_limb = .{ .boundary = @enumFromInt(i / 64), .register = @intCast((i % 64) / 2), .limb = @intCast(i % 2) } });
    var bytes: [support.REGISTER_BYTE_COUNT]Value = undefined;
    for (&bytes, 0..) |*v, i| v.* = try author.old(.{ .register_byte = .{ .boundary = @enumFromInt(i / 128), .register = @intCast((i % 128) / 4), .byte = @intCast(i % 4) } });
    var role_header: [role.HEADER_WORD_COUNT]Value = undefined;
    for (&role_header, 0..) |*v, i| v.* = try author.old(.{ .role_io_word = @intCast(i) });
    // Input start/count and zero output count are the exact canonical claim
    // coordinates for the admitted job shape, never the default1024 shape.
    const starts = [_]usize{ claim.canonical_layout.input_start_start, claim.canonical_layout.input_word_count_start, claim.canonical_layout.outputWordCountStart(shape) };
    var header: [6]Value = undefined;
    for (&header, 0..) |*v, i| v.* = try author.old(.{ .role_source = .{ .claim_word = @intCast(starts[i / 2] + i % 2) } });
    var completion: [support.NONFINAL_COMPLETION_INPUT_COUNT]Value = undefined;
    for (completion[0..4], 0..) |*v, i| v.* = try author.old(.{ .role_source = .{ .completion_word = @intCast(i) } });
    for (completion[4..8], 0..) |*v, i| v.* = try author.old(.{ .role_source = .{ .completion_decoded_word = @intCast(i) } });
    for (completion[8..11], 0..) |*v, i| v.* = try author.old(.{ .role_source = .{ .completion_policy_word = @intCast(i) } });
    completion[11] = try author.old(.{ .role_source = .nonfinal_inverse });
    var global: [support.global_binding.WORD_COUNT]Value = undefined;
    for (&global, 0..) |*v, i| v.* = try author.old(.{ .global_statement_word = @intCast(i) });
    var global_aux: [support.global_binding.AUX_COUNT]Value = undefined;
    for (&global_aux, 0..) |*v, i| v.* = try author.old(.{ .global_aux = try support.global_binding.sourceAt(i) });
    var clock_aux: [support.CLOCK_AUX_INPUT_COUNT]Value = undefined;
    for (&clock_aux, 0..) |*v, i| v.* = try author.old(.{ .clock_aux = try support.clockAuxSourceAt(i) });
    const opening = try allocator.alloc(Value, admission.openingInputWordCount());
    defer allocator.free(opening);
    for (opening, 0..) |*v, i| v.* = try author.old(.{ .completion_opening_word = @intCast(i) });
    var decoded_bits: [DECODED_BIT_COUNT]Value = undefined;
    for (&decoded_bits, 0..) |*v, i| v.* = try author.old(.{ .role_source = .{ .limb_bit = .{ .slot = shape.max_input_words, .limb = @intCast(2 + i / 16), .bit = @intCast(i % 16) } } });
    const packet_first_input: u32 = @intCast(author.bindings.items.len);
    var packets: [PACKET_INPUT_COUNT]Value = undefined;
    for (&packets, 0..) |*v, i| v.* = try author.input(.{ .packet_limb = @intCast(i) });
    var roots: [2]Value = undefined;
    for (&roots, 0..) |*v, i| v.* = try author.old(.{ .native_continuation_root = @intCast(i) });
    // Preserve the existing challenge32 + canonical claim172 tail exactly.
    var challenges: [support.CHALLENGE_WORD_COUNT]Value = undefined;
    for (&challenges, 0..) |*v, i| v.* = try author.old(.{ .relation_challenge_word = .{ .domain = @enumFromInt(i / 8), .alpha = i % 8 >= 4, .limb = @intCast(i % 4) } });
    var claims: [support.CANONICAL_CLAIM_WORD_COUNT]Value = undefined;
    for (&claims, 0..) |*v, i| v.* = try author.old(.{ .canonical_claim_word = .{ .item = @intCast(i / 4), .limb = @intCast(i % 4) } });
    var relations: [support.DOMAIN_COUNT]support.BoundRelation = undefined;
    for (&relations, [_]u8{ 2, 7, 5, 4 }, 0..) |*relation, arity, i| relation.* = try support.BoundRelation.init(builder, challenges[i * 8 ..][0..8], arity);
    var accumulator = support.Accumulator{ .builder = builder, .relations = &relations };
    try equal(builder, selected, Value.one());
    try support.constrainRoleHeader(builder, &role_header, lane_shape.role_capacity);
    try equal(builder, role_header[3], base(shape.max_input_words + 1));
    try constrainInitialHeader(builder, shape, &statement, header);
    try support.constrainRawClocks(builder, &statement, &clocks, &clock_aux);
    try support.global_binding.constrain(builder, &statement, &global, &global_aux);
    try support.addBaseTerms(builder, &accumulator, &statement, &clocks, &bytes, .fixed_program_narrow_v1, roots);
    const program_words = try constrainCompletion(builder, admission, &statement, &completion, &decoded_bits, opening);
    const memory = relations[@intFromEnum(support.Domain.memory_access)];
    const subtotal = try packet.constrainPackets(builder, packets, memory.z, memory.alpha_powers[1], header[0..4].*, program_words);
    accumulator.sums[@intFromEnum(support.Domain.memory_access)] = try builder.add(accumulator.sums[@intFromEnum(support.Domain.memory_access)], subtotal);
    var program_values: [5]Value = undefined;
    for (&program_values, 0..) |*v, i| v.* = try support.u32At(builder, &program_words, 4 + i * 2);
    try accumulator.add(.program_access, &program_values, .negative);
    try support.constrainGlobalCancellation(builder, accumulator.sums, &claims);
    const bindings = try author.bindings.toOwnedSlice(allocator);
    errdefer allocator.free(bindings);
    return .{ .circuit = try builder.finish(), .bindings = bindings, .claim_shape = shape, .packet_first_input = packet_first_input };
}
/// Initial input policy is exact, not a dynamic prefix of a bigger job input.
/// Output capacity12 is part of the independently admitted job shape, while
/// this initial nonfinal leaf must have zero actual outputs.
pub fn constrainInitialHeader(builder: *arithmetic.Builder, shape: claim.Shape, statement: *const [support.STATEMENT_WORD_COUNT]Value, header: [6]Value) !void {
    const layout = support.span.canonical_layout;
    for (statement[layout.first_segment_start..][0..2]) |limb| try equal(builder, limb, Value.zero());
    try equal(builder, header[2], base(shape.max_input_words & 65535));
    try equal(builder, header[3], base(shape.max_input_words >> 16));
    try equal(builder, header[4], Value.zero());
    try equal(builder, header[5], Value.zero());
}
/// Reuses the admitted full-program opening and native completion policy.
/// Returned canonical words are exactly the program packet/hash preimage.
pub fn constrainCompletion(builder: *arithmetic.Builder, admission: *const support.program_admission.ProgramAdmissionV1, statement: *const [support.STATEMENT_WORD_COUNT]Value, completion: *const [12]Value, bits: *const [DECODED_BIT_COUNT]Value, opening: []const Value) ![18]Value {
    try support.constrainNonfinalCompletionHeader(builder, statement, completion);
    const result = try canonicalProgram(builder, completion, bits);
    try support.constrainNonfinalCompletionOpening(builder, admission, statement, completion, opening);
    return result;
}
fn canonicalProgram(builder: *arithmetic.Builder, completion: *const [12]Value, bits: *const [DECODED_BIT_COUNT]Value) ![18]Value {
    const metadata = try (try role.TupleV4.init(.program_completion, &.{ 0, 0, 0, 0, 0 })).words();
    var result: [18]Value = undefined;
    for (&result, metadata) |*v, word| v.* = base(word);
    result[4..6].* = completion[0..2].*;
    for (0..4) |field| {
        const field_bits = bits[field * 32 ..][0..32];
        for (0..2) |limb| {
            var value = Value.zero();
            for (field_bits[limb * 16 ..][0..16], 0..) |bit, i| {
                _ = try builder.markOutput(try builder.mul(bit, try builder.sub(bit, Value.one())));
                value = try builder.add(value, try builder.mul(bit, base(@as(u32, 1) << @as(u5, @intCast(i)))));
            }
            result[6 + field * 2 + limb] = value;
        }
        try support.role_binding.constrainCanonicalFieldBits(builder, field_bits.*, Value.one());
        try equal(builder, try support.u32At(builder, &result, 6 + field * 2), completion[4 + field]);
    }
    return result;
}
fn base(value: u32) Value {
    return Value.fromBase(M31.fromCanonical(value));
}
fn equal(builder: *arithmetic.Builder, left: Value, right: Value) !void {
    _ = try builder.markOutput(try builder.sub(left, right));
}
