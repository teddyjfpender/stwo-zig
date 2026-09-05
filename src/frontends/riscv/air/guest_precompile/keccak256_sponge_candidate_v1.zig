//! Non-production Ethereum Keccak-256 sponge semantic authority.
//!
//! This candidate moves the byte absorption, legacy-Keccak padding and
//! 32-byte squeeze around the existing authenticated Keccak-f[1600]
//! permutation authority.  It is deliberately not an execution-profile or
//! AIR admission: the variable-span guest-memory relation is not yet wired.

const std = @import("std");
const permutation = @import("keccakf_authority.zig");

pub const production_active = false;
pub const air_ready = false;
pub const schema_version: u16 = 1;
pub const rate_bytes: usize = 136;
pub const capacity_bytes: usize = 64;
pub const output_bytes: usize = 32;
pub const legacy_keccak_suffix: u8 = 0x01;
pub const terminal_padding_bit: u8 = 0x80;
pub const Digest = [32]u8;
pub const State = permutation.State;

pub const Error = error{
    ArithmeticOverflow,
    InputTooLarge,
    InvalidBlockCount,
    InvalidBlockIndex,
    InvalidInputLength,
    InvalidPadding,
    InvalidPermutationInput,
    InvalidPermutationOutput,
    InvalidPlan,
    InvalidSpongeChain,
    InvalidSpongeOutput,
    OutOfMemory,
};

pub const PlanV1 = struct {
    schema: u16,
    input_len: u32,
    block_count: u32,
    permutation_call_count: u32,
    semantic_call_rows: u32,
    semantic_block_rows: u32,
    padded_input_bytes: u64,
    verifier_program_identity: Digest,
    instance_identity: Digest,

    pub fn validate(self: PlanV1) Error!void {
        const expected = try compile(self.input_len);
        if (!std.meta.eql(self, expected)) return error.InvalidPlan;
    }
};

pub const BlockV1 = struct {
    block_index: u32,
    input_offset: u32,
    input_count: u8,
    is_final: bool,
    state_before: State,
    input_rate: [rate_bytes]u8,
    padded_rate: [rate_bytes]u8,
    permutation_input: State,
    permutation_output: State,
};

pub const WitnessV1 = struct {
    allocator: std.mem.Allocator,
    plan: PlanV1,
    blocks: []BlockV1,
    output: [output_bytes]u8,

    pub fn deinit(self: *WitnessV1) void {
        self.allocator.free(self.blocks);
        self.* = undefined;
    }

    pub fn validate(self: *const WitnessV1, input: []const u8) Error!void {
        if (input.len > std.math.maxInt(u32)) return error.InputTooLarge;
        if (self.plan.input_len != input.len) return error.InvalidInputLength;
        try self.plan.validate();
        if (self.blocks.len != self.plan.block_count)
            return error.InvalidBlockCount;

        var state: State = @splat(0);
        for (self.blocks, 0..) |actual, block_index| {
            const expected = try buildBlock(
                input,
                @intCast(block_index),
                self.plan.block_count,
                state,
            );
            if (actual.block_index != expected.block_index or
                actual.input_offset != expected.input_offset or
                actual.input_count != expected.input_count or
                actual.is_final != expected.is_final)
            {
                return error.InvalidBlockIndex;
            }
            if (!std.mem.eql(u64, &actual.state_before, &expected.state_before))
                return error.InvalidSpongeChain;
            if (!std.mem.eql(u8, &actual.input_rate, &expected.input_rate))
                return error.InvalidInputLength;
            if (!std.mem.eql(u8, &actual.padded_rate, &expected.padded_rate))
                return error.InvalidPadding;
            if (!std.mem.eql(
                u64,
                &actual.permutation_input,
                &expected.permutation_input,
            )) return error.InvalidPermutationInput;
            if (!std.mem.eql(
                u64,
                &actual.permutation_output,
                &expected.permutation_output,
            )) return error.InvalidPermutationOutput;
            state = actual.permutation_output;
        }
        const expected_output = squeeze(state);
        if (!std.mem.eql(u8, &self.output, &expected_output))
            return error.InvalidSpongeOutput;
    }
};

pub fn compile(input_len: u32) Error!PlanV1 {
    const block_count = input_len / rate_bytes + 1;
    const padded_input_bytes = std.math.mul(
        u64,
        block_count,
        rate_bytes,
    ) catch return error.ArithmeticOverflow;
    var result = PlanV1{
        .schema = schema_version,
        .input_len = input_len,
        .block_count = block_count,
        .permutation_call_count = block_count,
        .semantic_call_rows = 1,
        .semantic_block_rows = block_count,
        .padded_input_bytes = padded_input_bytes,
        .verifier_program_identity = verifierProgramIdentity(),
        .instance_identity = undefined,
    };
    result.instance_identity = instanceIdentity(result);
    return result;
}

pub fn buildWitness(
    allocator: std.mem.Allocator,
    input: []const u8,
) Error!WitnessV1 {
    if (input.len > std.math.maxInt(u32)) return error.InputTooLarge;
    const plan = try compile(@intCast(input.len));
    const blocks = allocator.alloc(BlockV1, plan.block_count) catch
        return error.OutOfMemory;
    errdefer allocator.free(blocks);
    var state: State = @splat(0);
    for (blocks, 0..) |*block, block_index| {
        block.* = try buildBlock(
            input,
            @intCast(block_index),
            plan.block_count,
            state,
        );
        state = block.permutation_output;
    }
    const result = WitnessV1{
        .allocator = allocator,
        .plan = plan,
        .blocks = blocks,
        .output = squeeze(state),
    };
    try result.validate(input);
    return result;
}

pub fn hash(input: []const u8) Error![output_bytes]u8 {
    if (input.len > std.math.maxInt(u32)) return error.InputTooLarge;
    const plan = try compile(@intCast(input.len));
    var state: State = @splat(0);
    for (0..plan.block_count) |block_index| {
        const block = try buildBlock(
            input,
            @intCast(block_index),
            plan.block_count,
            state,
        );
        state = block.permutation_output;
    }
    return squeeze(state);
}

pub fn verifierProgramIdentity() Digest {
    var hash_state = std.crypto.hash.sha2.Sha256.init(.{});
    hash_state.update("stwo.riscv.keccak256-sponge-verifier-program.v1\x00");
    hashInt(&hash_state, schema_version);
    hashInt(&hash_state, rate_bytes);
    hashInt(&hash_state, capacity_bytes);
    hashInt(&hash_state, output_bytes);
    hashInt(&hash_state, legacy_keccak_suffix);
    hashInt(&hash_state, terminal_padding_bit);
    hash_state.update(&permutation.execution_semantic_digest);
    var result: Digest = undefined;
    hash_state.final(&result);
    return result;
}

fn buildBlock(
    input: []const u8,
    block_index: u32,
    block_count: u32,
    state_before: State,
) Error!BlockV1 {
    if (block_count == 0 or block_index >= block_count)
        return error.InvalidBlockIndex;
    const offset = std.math.mul(u64, block_index, rate_bytes) catch
        return error.ArithmeticOverflow;
    if (offset > input.len) return error.InvalidInputLength;
    const remaining = input.len - @as(usize, @intCast(offset));
    const input_count: usize = @min(remaining, rate_bytes);
    const is_final = block_index + 1 == block_count;
    if ((!is_final and input_count != rate_bytes) or
        (is_final and input_count >= rate_bytes))
    {
        return error.InvalidInputLength;
    }

    var input_rate = [_]u8{0} ** rate_bytes;
    @memcpy(input_rate[0..input_count], input[@intCast(offset)..][0..input_count]);
    var padded_rate = input_rate;
    if (is_final) {
        padded_rate[input_count] ^= legacy_keccak_suffix;
        padded_rate[rate_bytes - 1] ^= terminal_padding_bit;
    }
    var permutation_input = state_before;
    for (padded_rate, 0..) |byte, byte_index| {
        const lane = byte_index / @sizeOf(u64);
        const shift: u6 = @intCast(8 * (byte_index % @sizeOf(u64)));
        permutation_input[lane] ^= @as(u64, byte) << shift;
    }
    var permutation_output = permutation_input;
    permutation.permute(&permutation_output);
    return .{
        .block_index = block_index,
        .input_offset = @intCast(offset),
        .input_count = @intCast(input_count),
        .is_final = is_final,
        .state_before = state_before,
        .input_rate = input_rate,
        .padded_rate = padded_rate,
        .permutation_input = permutation_input,
        .permutation_output = permutation_output,
    };
}

fn squeeze(state: State) [output_bytes]u8 {
    var result: [output_bytes]u8 = undefined;
    for (&result, 0..) |*byte, byte_index| {
        const lane = byte_index / @sizeOf(u64);
        const shift: u6 = @intCast(8 * (byte_index % @sizeOf(u64)));
        byte.* = @truncate(state[lane] >> shift);
    }
    return result;
}

fn instanceIdentity(plan: PlanV1) Digest {
    var hash_state = std.crypto.hash.sha2.Sha256.init(.{});
    hash_state.update("stwo.riscv.keccak256-sponge-instance.v1\x00");
    hash_state.update(&plan.verifier_program_identity);
    hashInt(&hash_state, plan.input_len);
    hashInt(&hash_state, plan.block_count);
    hashInt(&hash_state, plan.permutation_call_count);
    hashInt(&hash_state, plan.semantic_call_rows);
    hashInt(&hash_state, plan.semantic_block_rows);
    hashInt(&hash_state, plan.padded_input_bytes);
    var result: Digest = undefined;
    hash_state.final(&result);
    return result;
}

fn hashInt(hash_state: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash_state.update(&bytes);
}

comptime {
    if (rate_bytes + capacity_bytes != permutation.lane_count * @sizeOf(u64) or
        output_bytes > rate_bytes or production_active or air_ready)
    {
        @compileError("Keccak-256 sponge candidate geometry drifted");
    }
}
