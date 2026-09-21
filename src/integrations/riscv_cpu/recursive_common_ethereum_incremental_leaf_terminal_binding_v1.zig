//! Explicit halt-flag completion for the admitted Ethereum execution profile.
//! This is composed with the existing global projection, native clock and role
//! source constraints. It adds no witness arrays or program-fetch opening.
const frontend = @import("stwo_riscv_frontend");
const arithmetic = frontend.recursion.arithmetic_circuit;
const role = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const binding = @import("recursive_common_ethereum_incremental_leaf_role_binding_v4.zig");
const global = @import("recursive_common_ethereum_incremental_leaf_global_binding_v1.zig");
const program = @import("recursive_common_ethereum_incremental_leaf_program_admission_v1.zig");
const Value = arithmetic.Value;
const Builder = arithmetic.Builder;
pub const VERSION: u16 = 1;
pub const COMPLETION_INPUT_COUNT: usize = 12;
pub const Inputs = struct {
    statement: []const Value,
    global_aux: []const Value,
    native_end_bits: []const Value,
    role_sources: []const Value,
    role_words: []const Value,
    selectors: []const Value,
    /// Address2, raw2, decoded4, kind1, clock2, terminal-reserved0.
    completion: []const Value,
};

/// `admission` supplies the linker-defined halt address from the pinned ELF.
/// The existing graph must also constrain global_aux through global.constrain,
/// native_end_bits through constrainRawClocks, and role_sources through
/// role_binding.constrain. The same role words feed the memory lookup sum.
pub fn constrain(builder: *Builder, admission: *const program.ProgramAdmissionV1, capacity: u32, in: Inputs) !void {
    if (in.statement.len != global.WORD_COUNT) return error.InvalidEthereumTerminalInputs;
    try equal(builder, in.statement[frontend.recursion.span_statement.canonical_layout.program_start], base(admission.programRoot()));
    return constrainAddress(builder, try admission.haltFlagAddress(), capacity, in);
}

fn constrainAddress(builder: *Builder, halt_address: u32, capacity: u32, in: Inputs) !void {
    if ((halt_address & 3) != 0 or halt_address >= 0x7fff_fffc) return error.InvalidEthereumTerminalHaltAddress;
    if (in.statement.len != global.WORD_COUNT or in.global_aux.len != global.AUX_COUNT or in.native_end_bits.len != 25 or
        in.role_sources.len != (try binding.budget(capacity)).input_count or
        in.role_words.len != role.HEADER_WORD_COUNT + @as(usize, capacity) * role.TUPLE_WORD_COUNT or
        in.selectors.len != @as(usize, capacity) * 5 or in.completion.len != COMPLETION_INPUT_COUNT)
        return error.InvalidEthereumTerminalInputs;
    const layout = frontend.recursion.span_statement.canonical_layout;
    // Exact final segment in two u16 limbs, including carry across 65535.
    const first = in.statement[layout.first_segment_start..][0..2];
    const total = in.statement[layout.job_segment_count_start..][0..2];
    try equal(builder, in.statement[layout.executed_segment_count_start], Value.one());
    try zero(builder, in.statement[layout.executed_segment_count_start + 1]);
    const delta = try builder.sub(try builder.add(first[0], Value.one()), total[0]);
    try zero(builder, try builder.mul(delta, try builder.sub(delta, base(65536))));
    try equal(builder, try builder.add(try builder.mul(first[1], base(65536)), delta), try builder.mul(total[1], base(65536)));
    // The existing no-overflow u64 projection proves end + remaining = total.
    for (in.global_aux[192..256]) |bit| try zero(builder, bit);
    const completion = in.completion;
    for (0..2) |limb| try equal(builder, completion[limb], base((halt_address >> @as(u5, @intCast(16 * limb))) & 65535));
    try equal(builder, completion[8], base(@intFromEnum(frontend.air.public_data.CompletionKind.halt_flag)));
    for (completion[4..8]) |decoded| try zero(builder, decoded);
    try zero(builder, completion[11]);
    const memory_count = try builder.add(try join(builder, in.role_sources[0..2]), try join(builder, in.role_sources[2..4]));
    const bits_start = binding.HEADER_INPUT_COUNT + @as(usize, capacity) * (binding.INPUT_SLOT_INPUT_COUNT + binding.OUTPUT_SLOT_INPUT_COUNT);
    var halt_count = Value.zero();
    for (0..capacity) |slot| {
        const selected = in.selectors[slot * 5 ..][0..5];
        const halt = selected[3];
        try zero(builder, selected[4]);
        halt_count = try builder.add(halt_count, halt);
        try selectedEqual(builder, halt, base(@intCast(slot)), memory_count);
        const words = in.role_words[role.HEADER_WORD_COUNT + slot * role.TUPLE_WORD_COUNT ..][0..role.TUPLE_WORD_COUNT];
        try selectedEqual(builder, halt, words[4], Value.one());
        try selectedEqual(builder, halt, words[5], Value.zero());
        for (0..2) |limb| {
            try selectedEqual(builder, halt, words[6 + limb], completion[limb]);
            try selectedEqual(builder, halt, words[8 + limb], completion[9 + limb]);
        }
        // Each memory value is four bytes, with the same u16 bit witnesses
        // used by the role hash and memory logup. Enforce byte range before
        // comparing split raw words so M31 aliases cannot cancel.
        var raw_is_zero = Value.one();
        for (0..4) |byte| {
            const bits = in.role_sources[bits_start + (slot * binding.LIMB_COUNT + 6 + 2 * byte) * binding.BIT_COUNT ..][0..16];
            for (bits[0..8]) |bit| raw_is_zero = try builder.mul(raw_is_zero, try builder.sub(Value.one(), bit));
            for (bits[8..]) |bit| try zero(builder, try builder.mul(halt, bit));
            try zero(builder, try builder.mul(halt, words[11 + 2 * byte]));
        }
        try zero(builder, try builder.mul(halt, raw_is_zero));
        for (0..2) |limb| try selectedEqual(builder, halt, completion[2 + limb], try builder.add(words[10 + 4 * limb], try builder.mul(base(256), words[12 + 4 * limb])));
        const clock_bits = in.role_sources[bits_start + (slot * binding.LIMB_COUNT + 4) * binding.BIT_COUNT ..][0..32];
        for (clock_bits[26..]) |bit| try zero(builder, try builder.mul(halt, bit));
        // A halt is an actual memory access: ordinals1/2/3 only, never zero.
        const residue = try builder.sub(try builder.add(clock_bits[0], clock_bits[1]), try builder.mul(clock_bits[0], clock_bits[1]));
        try selectedEqual(builder, halt, residue, Value.one());
        var bucket = [_]Value{Value.zero()} ** 25;
        @memcpy(bucket[0..24], clock_bits[2..26]);
        try selectedEqual(builder, halt, try binding.lessThanBits(builder, &bucket, in.native_end_bits), Value.one());
    }
    try equal(builder, halt_count, Value.one());
}
fn base(value: u32) Value {
    return Value.fromBase(@import("stwo_core").fields.m31.M31.fromCanonical(value));
}
fn zero(builder: *Builder, value: Value) !void {
    _ = try builder.markOutput(value);
}
fn equal(builder: *Builder, a: Value, b: Value) !void {
    try zero(builder, try builder.sub(a, b));
}
fn selectedEqual(builder: *Builder, selected: Value, a: Value, b: Value) !void {
    try zero(builder, try builder.mul(selected, try builder.sub(a, b)));
}
fn join(builder: *Builder, limbs: []const Value) !Value {
    return builder.add(limbs[0], try builder.mul(base(65536), limbs[1]));
}
