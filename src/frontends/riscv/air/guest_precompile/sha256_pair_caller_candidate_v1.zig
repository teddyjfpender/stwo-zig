//! Non-production caller and memory relation for fixed SHA-256 pair hashing.
//!
//! The proposed instruction reads a 64-byte pair at `record_ptr` and writes
//! the 32-byte digest at `record_ptr + 64`. This module describes the exact
//! program/state/register/memory effects and the field-native call/output
//! tuples. No instruction word or opcode identifier is allocated, so these
//! events cannot enter a production VM proof.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const access_clock = @import("../../access_clock.zig");
const sha = @import("sha256_pair_candidate_v1.zig");
const direct = @import("sha256_pair_direct_candidate_v1.zig");

pub const production_active = false;
pub const opcode_allocated = false;
pub const program_relation_ready = false;
pub const record_word_count: usize = sha.record_bytes / @sizeOf(u32);
pub const input_word_count: usize = sha.input_bytes / @sizeOf(u32);
pub const output_word_count: usize = sha.output_bytes / @sizeOf(u32);
pub const data_address_limit: u32 = @as(u32, 1) << 30;
pub const Digest = sha.Digest;

pub const Error = error{
    InvalidCall,
    InvalidOutput,
    RelationMismatch,
};

pub const RecordV1 = struct {
    execution_clock: u32,
    pc: u32,
    pointer_register: u5,
    pointer_previous_clock: u32,
    record_ptr: u32,
    memory_previous_clocks: [record_word_count]u32,
    output_before: [sha.output_bytes]u8,
    input: [sha.input_bytes]u8,
    output: [sha.output_bytes]u8,
    call_index: u32,

    pub fn validate(self: RecordV1) Error!void {
        if (self.execution_clock == 0 or self.record_ptr & 3 != 0)
            return error.InvalidCall;
        const end = std.math.add(u32, self.record_ptr, sha.record_bytes) catch
            return error.InvalidCall;
        if (end > data_address_limit or
            access_clock.maximum(self.execution_clock) > std.math.maxInt(u32))
        {
            return error.InvalidCall;
        }
        const register_clock = access_clock.encode(self.execution_clock, .first);
        if (self.pointer_previous_clock >= register_clock)
            return error.InvalidCall;
        const memory_clock = access_clock.encode(self.execution_clock, .second);
        for (self.memory_previous_clocks) |previous| {
            if (previous >= memory_clock) return error.InvalidCall;
        }
        const expected = sha.hashPair(self.input);
        if (!std.mem.eql(u8, &self.output, &expected))
            return error.InvalidOutput;
    }

    pub fn inputTuple(self: RecordV1) [direct.input_relation_arity]M31 {
        var result: [direct.input_relation_arity]M31 = undefined;
        result[0] = M31.fromCanonical(direct.relation_schema_numeric_id);
        result[1] = M31.fromCanonical(self.call_index);
        for (self.input, 0..) |byte, index|
            result[2 + index] = M31.fromCanonical(byte);
        return result;
    }

    pub fn outputTuple(self: RecordV1) [direct.output_relation_arity]M31 {
        var result: [direct.output_relation_arity]M31 = undefined;
        result[0] = M31.fromCanonical(direct.relation_schema_numeric_id);
        result[1] = M31.fromCanonical(self.call_index);
        for (self.output, 0..) |byte, index|
            result[2 + index] = M31.fromCanonical(byte);
        return result;
    }

    pub fn relationEvents(self: RecordV1) Error!RelationEventsV1 {
        try self.validate();
        const register_clock = access_clock.encode(self.execution_clock, .first);
        const memory_clock = access_clock.encode(self.execution_clock, .second);
        var memory: [record_word_count]MemoryChainV1 = undefined;
        for (&memory, 0..) |*chain, word| {
            const address = self.record_ptr / 4 + @as(u32, @intCast(word));
            const before = if (word < input_word_count)
                self.input[word * 4 ..][0..4].*
            else
                self.output_before[(word - input_word_count) * 4 ..][0..4].*;
            const after = if (word < input_word_count)
                before
            else
                self.output[(word - input_word_count) * 4 ..][0..4].*;
            chain.* = .{
                .before = .{
                    .address = address,
                    .clock = self.memory_previous_clocks[word],
                    .bytes = before,
                },
                .after = .{
                    .address = address,
                    .clock = memory_clock,
                    .bytes = after,
                },
                .gap = memory_clock - self.memory_previous_clocks[word] - 1,
            };
        }
        const pointer_bytes = littleEndianBytes(self.record_ptr);
        return .{
            .dispatch_intent = .{
                .pc = self.pc,
                .execution_clock = self.execution_clock,
                .pointer_register = self.pointer_register,
                .semantic_program_identity = callerProgramIdentity(),
            },
            .state_before = .{ self.pc, self.execution_clock },
            .state_after = .{ self.pc + 4, self.execution_clock + 1 },
            .pointer = .{
                .before = .{
                    .address_space = 0,
                    .address = self.pointer_register,
                    .clock = self.pointer_previous_clock,
                    .bytes = pointer_bytes,
                },
                .after = .{
                    .address_space = 0,
                    .address = self.pointer_register,
                    .clock = register_clock,
                    .bytes = pointer_bytes,
                },
                .gap = register_clock - self.pointer_previous_clock - 1,
            },
            .memory = memory,
            .input_call = self.inputTuple(),
            .output_call = self.outputTuple(),
        };
    }
};

pub const DispatchIntentV1 = struct {
    pc: u32,
    execution_clock: u32,
    pointer_register: u5,
    semantic_program_identity: Digest,
};

pub const MemoryTupleV1 = struct {
    address_space: u1 = 1,
    address: u32,
    clock: u32,
    bytes: [4]u8,
};

pub const MemoryChainV1 = struct {
    before: MemoryTupleV1,
    after: MemoryTupleV1,
    gap: u32,
};

pub const RegisterTupleV1 = struct {
    address_space: u1,
    address: u5,
    clock: u32,
    bytes: [4]u8,
};

pub const RegisterChainV1 = struct {
    before: RegisterTupleV1,
    after: RegisterTupleV1,
    gap: u32,
};

pub const RelationEventsV1 = struct {
    dispatch_intent: DispatchIntentV1,
    state_before: [2]u32,
    state_after: [2]u32,
    pointer: RegisterChainV1,
    memory: [record_word_count]MemoryChainV1,
    input_call: [direct.input_relation_arity]M31,
    output_call: [direct.output_relation_arity]M31,
};

pub fn validateAgainstAir(
    record: RecordV1,
    first: *const direct.Row(M31),
    last: *const direct.Row(M31),
) Error!void {
    try record.validate();
    const caller_input = record.inputTuple();
    const caller_output = record.outputTuple();
    const input = direct.inputRelationTuple(M31, first);
    const output = direct.outputRelationTuple(M31, last);
    if (!m31SlicesEqual(&caller_input, &input) or
        !m31SlicesEqual(&caller_output, &output))
    {
        return error.RelationMismatch;
    }
}

pub fn callerProgramIdentity() Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.sha256-pair-64-caller-program.v1\x00");
    const semantic = sha.verifierProgramIdentity();
    const round_air = direct.airProgramIdentity();
    hash.update(&semantic);
    hash.update(&round_air);
    hashInt(&hash, sha.input_offset);
    hashInt(&hash, sha.output_offset);
    hashInt(&hash, sha.record_bytes);
    hashInt(&hash, record_word_count);
    hashInt(&hash, direct.relation_schema_numeric_id);
    hashInt(&hash, direct.input_relation_arity);
    hashInt(&hash, direct.output_relation_arity);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn littleEndianBytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

fn m31SlicesEqual(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!a.sub(b).isZero()) return false;
    }
    return true;
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (record_word_count != 24 or input_word_count != 16 or
        output_word_count != 8 or production_active or opcode_allocated or
        program_relation_ready)
    {
        @compileError("fixed SHA-256 pair caller candidate geometry drifted");
    }
}
