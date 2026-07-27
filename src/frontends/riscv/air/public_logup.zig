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

pub const Error = public_data.ValidationError || error{ ZeroDenominator, ClockOverflow };

/// Public compensation split by independent LogUp relation. These domains
/// must cancel independently; offsetting a forged memory claim with a Merkle
/// or CPU-state claim is not valid.
pub const Sums = struct {
    registers_state: QM31,
    merkle: QM31,
    memory_access: QM31,
    program_access: QM31,

    pub fn total(self: Sums) QM31 {
        return self.registers_state
            .add(self.merkle)
            .add(self.memory_access)
            .add(self.program_access);
    }
};

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

/// Public compensation for the active CPU state-chain relation.
pub fn registersStateSum(
    data: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    var result = QM31.zero();
    // Registers-state bus: public initial emit and final consume. Stark-V
    // instruction clocks start at one, hence the `clock + 1` final boundary.
    const final_clock = std.math.add(u32, data.clock, 1) catch return error.ClockOverflow;
    try addInverse(&result, relations.registers_state.combineBase(.{
        base(data.initial_pc),
        base(1),
    }), .emit);
    try addInverse(&result, relations.registers_state.combineBase(.{
        base(data.final_pc),
        base(final_clock),
    }), .consume);
    return result;
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
            try addInverse(&result, relations.merkle.combineBase(.{
                M31.zero(), M31.zero(), base(root), base(root),
            }), .emit);
        }
    }
    return result;
}

/// Public compensation for register and public-I/O memory boundaries.
pub fn memoryAccessSum(
    data: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    var result = QM31.zero();
    // Register address space: emit the clock-zero initial word and consume
    // the word at its final access clock, including never-accessed registers.
    for (0..32) |index| {
        const addr = base(@as(u32, @intCast(index)));
        try addInverse(&result, relations.memory_access.combineBase(memoryTuple(
            0,
            addr,
            M31.zero(),
            data.initial_regs[index],
        )), .emit);
        try addInverse(&result, relations.memory_access.combineBase(memoryTuple(
            0,
            addr,
            base(data.reg_last_clock[index]),
            data.final_regs[index],
        )), .consume);
    }

    // Public input words are initial RW-memory values at clock zero. The public
    // validator restricts addresses to the non-wrapping subset of the pinned
    // Rust arithmetic, and this helper repeats the checked derivation here.
    for (data.io_entries.input_words, 0..) |word, index| {
        const addr = try data.io_entries.inputWordAddress(index);
        try addInverse(&result, relations.memory_access.combineBase(memoryTuple(
            1,
            base(addr),
            M31.zero(),
            word,
        )), .emit);
    }

    // Public output words are consumed at their last committed access clock.
    for (data.io_entries.output_words) |word| {
        try addInverse(&result, relations.memory_access.combineBase(memoryTuple(
            1,
            base(word.addr),
            base(word.clock),
            word.value,
        )), .consume);
    }
    if (data.completion) |completion| {
        if (completion.kind == .halt_flag) {
            try addInverse(&result, relations.memory_access.combineBase(memoryTuple(
                1,
                base(completion.address),
                base(completion.clock),
                completion.value,
            )), .consume);
        }
    }
    return result;
}

/// The unretired completion sentinel is present in the committed program with
/// multiplicity one and is consumed only by this public boundary term.
pub fn programAccessSum(
    data: *const public_data.PublicData,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    var result = QM31.zero();
    const completion = data.completion orelse return error.MissingCompletion;
    if (completion.kind != .unretired_self_loop) return result;
    const values = program_decode.decodeProgramWord(completion.value) catch unreachable;
    try addInverse(&result, relations.program_access.combineBase(.{
        base(completion.address),
        base(values[0]),
        base(values[1]),
        base(values[2]),
        base(values[3]),
    }), .consume);
    return result;
}

const Direction = enum { emit, consume };

fn addInverse(result: *QM31, denominator: QM31, direction: Direction) Error!void {
    const inverse = denominator.inv() catch return error.ZeroDenominator;
    result.* = switch (direction) {
        .emit => result.add(inverse),
        .consume => result.sub(inverse),
    };
}

fn memoryTuple(addr_space: u32, addr: M31, clock: M31, word: u32) [7]M31 {
    return .{
        base(addr_space),
        addr,
        clock,
        base(@as(u8, @truncate(word))),
        base(@as(u8, @truncate(word >> 8))),
        base(@as(u8, @truncate(word >> 16))),
        base(@as(u8, @truncate(word >> 24))),
    };
}

fn base(value: anytype) M31 {
    return M31.fromU64(@as(u64, value));
}

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
    const legacy = QM31.fromU32Unchecked(
        748137912,
        668873569,
        1441913112,
        794627628,
    );
    try std.testing.expect(actual.eql(
        legacy.add(try programAccessSum(&data, &relation_challenges.Relations.dummy())),
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
