//! Canonical public compensation arithmetic shared by native verification and
//! symbolic recursion recording. Public statement selection/custody is identical;
//! only the field scalar and relation-challenge representation are generic.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const public_data = @import("public_data.zig");
const program_decode = @import("program/decode.zig");
pub const Error = public_data.ValidationError || error{ ZeroDenominator, ClockOverflow };
pub const Direction = enum { emit, consume };
pub fn SumsFor(comptime S: type) type {
    return struct {
        registers_state: S,
        merkle: S,
        memory_access: S,
        program_access: S,

        pub fn total(self: @This()) S {
            return self.registers_state
                .add(self.merkle)
                .add(self.memory_access)
                .add(self.program_access);
        }
    };
}

pub fn blake3RelationSumsFor(comptime S: type, data: *const public_data.Blake3PublicData, relations: anytype) Error!SumsFor(S) {
    try data.validate();
    return .{
        .registers_state = try registersStateSumFor(S, data, relations),
        .merkle = S.zero(),
        .memory_access = try memoryAccessSumFor(S, data, relations),
        .program_access = try programAccessSum(true, S, data, relations),
    };
}

pub fn registersStateSumFor(
    comptime S: type,
    data: anytype,
    relations: anytype,
) Error!S {
    var result = S.zero();
    // Registers-state bus: public initial emit and final consume. Stark-V
    // instruction clocks start at one, hence the `clock + 1` final boundary.
    const final_clock = std.math.add(u32, data.clock, 1) catch return error.ClockOverflow;
    try addInverseFor(S, &result, relations.registers_state.combineBase(.{
        base(data.initial_pc),
        base(1),
    }), .emit);
    try addInverseFor(S, &result, relations.registers_state.combineBase(.{
        base(data.final_pc),
        base(final_clock),
    }), .consume);
    return result;
}

pub fn memoryAccessSumFor(
    comptime S: type,
    data: anytype,
    relations: anytype,
) Error!S {
    var result = S.zero();
    // Register address space: emit the clock-zero initial word and consume
    // the word at its final access clock, including never-accessed registers.
    for (0..32) |index| {
        const addr = base(@as(u32, @intCast(index)));
        try addInverseFor(S, &result, relations.memory_access.combineBase(memoryTuple(
            0,
            addr,
            M31.zero(),
            data.initial_regs[index],
        )), .emit);
        try addInverseFor(S, &result, relations.memory_access.combineBase(memoryTuple(
            0,
            addr,
            base(data.reg_last_clock[index]),
            data.final_regs[index],
        )), .consume);
    }

    return result.add(try publicIoMemoryAccessSumAssumeValidFor(
        S,
        data,
        relations,
    ));
}

pub fn publicIoMemoryAccessSumAssumeValidFor(
    comptime S: type,
    data: anytype,
    relations: anytype,
) Error!S {
    var result = S.zero();

    // Public input words are initial RW-memory values at clock zero. The public
    // validator restricts addresses to the non-wrapping subset of the pinned
    // Rust arithmetic, and this helper repeats the checked derivation here.
    for (data.io_entries.input_words, 0..) |word, index| {
        const addr = try data.io_entries.inputWordAddress(index);
        try addInverseFor(S, &result, relations.memory_access.combineBase(memoryTuple(
            1,
            base(addr),
            M31.zero(),
            word,
        )), .emit);
    }

    // Public output words are consumed at their last committed access clock.
    for (data.io_entries.output_words) |word| {
        try addInverseFor(S, &result, relations.memory_access.combineBase(memoryTuple(
            1,
            base(word.addr),
            base(word.clock),
            word.value,
        )), .consume);
    }
    if (data.completion) |completion| {
        if (completion.kind == .halt_flag) {
            try addInverseFor(S, &result, relations.memory_access.combineBase(memoryTuple(
                1,
                base(completion.address),
                base(completion.clock),
                completion.value,
            )), .consume);
        }
    }
    return result;
}

pub fn programAccessSumFor(
    comptime S: type,
    data: anytype,
    relations: anytype,
) Error!S {
    return programAccessSum(false, S, data, relations);
}
fn programAccessSum(comptime boundary_fetch: bool, comptime S: type, data: anytype, relations: anytype) Error!S {
    var result = S.zero();
    const completion = data.completion orelse return error.MissingCompletion;
    if (completion.kind != .unretired_self_loop and !(boundary_fetch and completion.kind == .unretired_program_fetch)) return result;
    const values = program_decode.decodeProgramWord(completion.value) catch return error.InvalidCompletionValue;
    try addInverseFor(S, &result, relations.program_access.combineBase(.{
        base(completion.address),
        base(values[0]),
        base(values[1]),
        base(values[2]),
        base(values[3]),
    }), .consume);
    return result;
}

pub fn addInverseFor(comptime S: type, result: *S, denominator: S, direction: Direction) Error!void {
    const inverse = if (comptime @hasDecl(S, "inverse")) denominator.inverse() else denominator.inv() catch return error.ZeroDenominator;
    result.* = switch (direction) {
        .emit => result.add(inverse),
        .consume => result.sub(inverse),
    };
}

pub fn memoryTuple(addr_space: u32, addr: M31, clock: M31, word: u32) [7]M31 {
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

pub fn base(value: anytype) M31 {
    return M31.fromU64(@as(u64, value));
}
