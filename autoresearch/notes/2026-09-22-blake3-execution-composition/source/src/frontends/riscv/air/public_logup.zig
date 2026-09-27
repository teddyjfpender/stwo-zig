//! Public LogUp compensation terms for an RV32IM statement.
//!
//! The relation algebra and serialized field order follow pinned Stark-V
//! `PublicData::logup_sum`; memory-boundary clock values use this
//! implementation's strict derived access clocks. Each domain is exposed
//! separately so callers cannot accidentally offset an unclosed claim against
//! another relation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const public_data = @import("public_data.zig");
const program_decode = @import("program/decode.zig");
const relation_challenges = @import("relation_challenges.zig");

const arithmetic = @import("public_logup_arithmetic.zig");
pub const Error = arithmetic.Error;

/// Public compensation split by independent LogUp relation. These domains
/// must cancel independently; offsetting a forged memory claim with a Merkle
/// or CPU-state claim is not valid.
pub const Sums = SumsFor(QM31);
pub const SumsFor = arithmetic.SumsFor;

/// Exact verifier-side compensation for public CPU, root, register, input,
/// and output boundary values.
pub fn sum(
    data: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    try data.validate();
    return (try relationSums(data, relations)).total();
}

pub fn relationSums(
    data: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) Error!Sums {
    const result = Sums{
        .registers_state = try registersStateSum(data, relations),
        .merkle = try merkleSum(data, relations),
        .memory_access = try memoryAccessSum(data, relations),
        .program_access = try programAccessSum(data, relations),
    };

    return result;
}

/// BLAKE3 root sinks are fixed columns of the hash components, so they do
/// not emit legacy scalar Merkle tuples. The component admission must bind those
/// sinks to these public roots; this function compensates execution boundaries.
pub fn blake3RelationSums(data: *const public_data.Blake3PublicData, relations: *const relation_challenges.Relations) Error!Sums {
    return blake3RelationSumsFor(QM31, data, relations);
}
pub const blake3RelationSumsFor = arithmetic.blake3RelationSumsFor;

/// Public compensation for the active CPU state-chain relation.
pub fn registersStateSum(
    data: anytype,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    return arithmetic.registersStateSumFor(QM31, data, relations);
}

/// Public compensation for optional roots. Presence is semantic: an absent
/// root contributes no tuple, while a present zero root emits a zero-valued
/// tuple and is therefore distinct from absence.
pub fn merkleSum(
    data: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    var result = QM31.zero();
    // Every present root is emitted once on Merkle(index, depth, value, root).
    for ([_]?u32{ data.program_root, data.initial_rw_root, data.final_rw_root }) |maybe_root| {
        if (maybe_root) |root| {
            try arithmetic.addInverseFor(QM31, &result, relations.merkle.combineBase(.{
                M31.zero(), M31.zero(), base(root), base(root),
            }), .emit);
        }
    }
    return result;
}

/// Public compensation for register and public-I/O memory boundaries.
pub fn memoryAccessSum(
    data: anytype,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    return arithmetic.memoryAccessSumFor(QM31, data, relations);
}

/// Role-aware public-I/O memory compensation without register endpoints.
///
/// Incremental full-state profiles use this exact V1 authority after removing
/// the V2 sparse-RW transition terms. Keeping it separate prevents an
/// untouched public input from disappearing merely because its value and
/// predecessor clock are both zero.
pub fn publicIoMemoryAccessSum(
    data: anytype,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    try data.validate();
    return arithmetic.publicIoMemoryAccessSumAssumeValidFor(QM31, data, relations);
}

/// The unretired completion sentinel is present in the committed program with
/// multiplicity one and is consumed only by this public boundary term.
pub fn programAccessSum(
    data: anytype,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    return arithmetic.programAccessSumFor(QM31, data, relations);
}

/// Versioned profile-aware program-boundary compensation.
///
/// Legacy public data can only expose the canonical base self-loop and keeps
/// using `programAccessSum`. Incremental Ethereum V4 additionally admits one
/// actual, unretired declared-program fetch at a nonfinal segment boundary;
/// that word must be decoded under the selected execution profile because it
/// may be a CUSTOM-0 instruction.
pub fn programAccessSumForProfile(
    selected_profile: program_decode.ExecutionProfile,
    data: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    var result = QM31.zero();
    const completion = data.completion orelse return error.MissingCompletion;
    switch (completion.kind) {
        .halt_flag => return result,
        .unretired_self_loop, .unretired_program_fetch => {},
    }
    const values = program_decode.decodeProgramWordForProfile(
        selected_profile,
        completion.value,
    ) catch return error.InvalidCompletionValue;
    try arithmetic.addInverseFor(QM31, &result, relations.program_access.combineBase(.{
        base(completion.address),
        base(values[0]),
        base(values[1]),
        base(values[2]),
        base(values[3]),
    }), .consume);
    return result;
}

const base = arithmetic.base;

fn emptyPublicData() public_data.PublicData {
    return .{
        .initial_pc = 0,
        .final_pc = 0,
        .clock = 0,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = public_data.Completion.canonicalSelfLoop(0),
        .io_entries = .{
            .input_start = 0,
            .input_len = 0,
            .input_words = &.{},
            .output_len = 0,
            .output_len_addr = 0,
            .output_data_addr = 0,
            .output_words = &.{},
        },
    };
}

test "public LogUp: exact strict-access public-boundary dummy-relation vector" {
    var data = emptyPublicData();
    data.initial_pc = 0x1000;
    data.final_pc = 0x1040;
    data.completion = public_data.Completion.canonicalSelfLoop(data.final_pc);
    data.clock = 17;
    data.initial_regs[1] = 0x0403_0201;
    data.final_regs[1] = 0x0807_0605;
    data.reg_last_clock[1] = 9;
    data.initial_regs[31] = 11;
    data.final_regs[31] = 12;
    data.program_root = 101;
    data.final_rw_root = 303;
    const input_words = [_]u32{ 0x0403_0201, 0x0000_0605 };
    const output_words = [_]public_data.OutputWord{
        .{ .addr = 0x0010_0004, .value = 4, .clock = 14 },
        .{ .addr = 0x0010_0008, .value = 0x4443_4241, .clock = 15 },
    };
    data.io_entries = .{
        .input_start = 0x0018_0000,
        .input_len = 6,
        .input_words = &input_words,
        .output_len = 4,
        .output_len_addr = 0x0010_0004,
        .output_data_addr = 0x0010_0008,
        .output_words = &output_words,
    };

    const actual = try sum(&data, &relation_challenges.Relations.dummy());
    const previous_combined_sum = QM31.fromU32Unchecked(
        748137912,
        668873569,
        1441913112,
        794627628,
    );
    try std.testing.expect(actual.eql(
        previous_combined_sum.add(try programAccessSum(&data, &relation_challenges.Relations.dummy())),
    ));
}

test "public LogUp: clock-zero state and untouched register remain constrained" {
    const relations = relation_challenges.Relations.dummy();
    var data = emptyPublicData();
    data.initial_pc = 7;
    data.final_pc = 8;
    try std.testing.expect(!(try registersStateSum(&data, &relations)).eql(QM31.zero()));
    data.final_pc = 7;
    try std.testing.expect((try registersStateSum(&data, &relations)).eql(QM31.zero()));

    data.initial_pc = 1;
    data.final_pc = 1;
    data.initial_regs[31] = 11;
    data.final_regs[31] = 12;
    try std.testing.expect(!(try memoryAccessSum(&data, &relations)).eql(QM31.zero()));
    data.final_regs[31] = 11;
    try std.testing.expect((try memoryAccessSum(&data, &relations)).eql(QM31.zero()));
}

test "public LogUp: final clock overflow fails closed" {
    const relations = relation_challenges.Relations.dummy();
    var data = emptyPublicData();
    data.program_root = 0;
    data.clock = std.math.maxInt(u32);
    try std.testing.expectError(error.ClockOverflow, sum(&data, &relations));
}

test "public LogUp: malformed public input fails before address wrapping" {
    const relations = relation_challenges.Relations.dummy();
    var data = emptyPublicData();
    data.program_root = 0;
    const input_words = [_]u32{1};
    data.io_entries.input_start = std.math.maxInt(u32);
    data.io_entries.input_len = 1;
    data.io_entries.input_words = &input_words;
    try std.testing.expectError(error.InputAddressOverflow, sum(&data, &relations));
}

test "public LogUp: missing mandatory program root fails closed" {
    const relations = relation_challenges.Relations.dummy();
    const data = emptyPublicData();
    try std.testing.expectError(error.MissingProgramRoot, sum(&data, &relations));
}

test "public LogUp: relation domains are independent and total is their sum" {
    const relations = relation_challenges.Relations.dummy();
    var data = emptyPublicData();
    data.initial_pc = 0x1000;
    data.final_pc = 0x1010;
    data.completion = public_data.Completion.canonicalSelfLoop(data.final_pc);
    data.clock = 4;
    data.program_root = 77;
    data.final_regs[5] = 9;
    data.reg_last_clock[5] = 3;

    const sums = try relationSums(&data, &relations);
    // Every domain must be individually nonzero for this statement, and no
    // domain may absorb another: the total is exactly their field sum.
    try std.testing.expect(!sums.registers_state.eql(QM31.zero()));
    try std.testing.expect(!sums.merkle.eql(QM31.zero()));
    try std.testing.expect(!sums.memory_access.eql(QM31.zero()));
    try std.testing.expect(!sums.program_access.eql(QM31.zero()));
    try std.testing.expect(sums.total().eql(
        sums.registers_state
            .add(sums.merkle)
            .add(sums.memory_access)
            .add(sums.program_access),
    ));
    try std.testing.expect((try sum(&data, &relations)).eql(sums.total()));

    // A forged register boundary moves ONLY the memory-access domain.
    var forged = data;
    forged.final_regs[5] = 10;
    const forged_sums = try relationSums(&forged, &relations);
    try std.testing.expect(forged_sums.registers_state.eql(sums.registers_state));
    try std.testing.expect(forged_sums.merkle.eql(sums.merkle));
    try std.testing.expect(forged_sums.program_access.eql(sums.program_access));
    try std.testing.expect(!forged_sums.memory_access.eql(sums.memory_access));
}
