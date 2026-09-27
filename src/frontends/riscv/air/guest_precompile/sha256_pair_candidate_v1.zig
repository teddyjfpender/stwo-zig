//! Non-production fixed-64-byte SHA-256 pair-hash semantic authority.
//!
//! SSZ Merkle hashing always computes `SHA256(left || right)` for two 32-byte
//! nodes. The message therefore owns exactly two compression blocks: one raw
//! 64-byte block and one fixed SHA-256 padding block. This candidate does not
//! claim variable-length SHA-256 or reuse the unauthenticated host syscall.

const std = @import("std");
const compression = @import("sha256_compression.zig");

pub const production_active = false;
pub const opcode_registry_ready = false;
pub const air_ready = false;
pub const schema_version: u16 = 1;
pub const input_bytes: usize = 64;
pub const output_bytes: usize = 32;
pub const record_bytes: usize = input_bytes + output_bytes;
pub const input_offset: usize = 0;
pub const output_offset: usize = input_bytes;
pub const block_count: usize = 2;
pub const block_bytes: usize = 64;
pub const round_count: usize = 64;
pub const state_word_count: usize = 8;
pub const schedule_word_count: usize = 64;
pub const opcode_semantic_tag = "stwo.sha256-pair-64.v1";
pub const Digest = [32]u8;
pub const State = [state_word_count]u32;

pub const initial_state = compression.initial_state;
pub const round_constants = compression.round_constants;

pub const Error = error{
    InvalidBlockInput,
    InvalidBlockState,
    InvalidInstanceIdentity,
    InvalidOutput,
    InvalidPadding,
    InvalidProgramIdentity,
    InvalidSchedule,
};

pub const BlockTraceV1 = compression.Trace;

pub const WitnessV1 = struct {
    input: [input_bytes]u8,
    blocks: [block_count]BlockTraceV1,
    output: [output_bytes]u8,
    verifier_program_identity: Digest,
    instance_identity: Digest,

    pub fn validate(self: WitnessV1) Error!void {
        const expected = buildWitness(self.input);
        if (!std.mem.eql(u8, &self.input, &expected.input))
            return error.InvalidBlockInput;
        if (!std.meta.eql(self.blocks[0].input, expected.blocks[0].input) or
            !std.meta.eql(self.blocks[1].input, expected.blocks[1].input))
        {
            return error.InvalidPadding;
        }
        for (self.blocks, expected.blocks) |actual, wanted| {
            if (!std.meta.eql(actual.schedule, wanted.schedule))
                return error.InvalidSchedule;
            if (!std.meta.eql(actual.states, wanted.states) or
                !std.meta.eql(actual.output_state, wanted.output_state))
            {
                return error.InvalidBlockState;
            }
        }
        if (!std.mem.eql(u8, &self.output, &expected.output))
            return error.InvalidOutput;
        if (!std.mem.eql(
            u8,
            &self.verifier_program_identity,
            &expected.verifier_program_identity,
        )) return error.InvalidProgramIdentity;
        if (!std.mem.eql(u8, &self.instance_identity, &expected.instance_identity))
            return error.InvalidInstanceIdentity;
    }
};

pub fn buildWitness(input: [input_bytes]u8) WitnessV1 {
    const first = compress(initial_state, input);
    const padding = paddingBlock();
    const second = compress(first.output_state, padding);
    const output = stateBytes(second.output_state);
    const program_identity = verifierProgramIdentity();
    return .{
        .input = input,
        .blocks = .{ first, second },
        .output = output,
        .verifier_program_identity = program_identity,
        .instance_identity = instanceIdentity(program_identity, input, output),
    };
}

pub fn hashPair(input: [input_bytes]u8) [output_bytes]u8 {
    return buildWitness(input).output;
}

pub fn paddingBlock() [block_bytes]u8 {
    var result = [_]u8{0} ** block_bytes;
    result[0] = 0x80;
    // The original message is exactly 64 bytes = 512 bits, encoded big-endian.
    result[block_bytes - 2] = 0x02;
    result[block_bytes - 1] = 0x00;
    return result;
}

pub fn verifierProgramIdentity() Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.sha256-pair-64-verifier-program.v1\x00");
    hashInt(&hash, schema_version);
    hashInt(&hash, input_bytes);
    hashInt(&hash, output_bytes);
    hashInt(&hash, block_count);
    hashInt(&hash, round_count);
    hash.update(opcode_semantic_tag);
    for (initial_state) |word| hashInt(&hash, word);
    for (round_constants) |word| hashInt(&hash, word);
    const padding = paddingBlock();
    hash.update(&padding);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

pub const sigmaSmall0 = compression.sigmaSmall0;
pub const sigmaSmall1 = compression.sigmaSmall1;
pub const sigmaBig0 = compression.sigmaBig0;
pub const sigmaBig1 = compression.sigmaBig1;
pub const choose = compression.choose;
pub const majority = compression.majority;
const compress = compression.witness;
const stateBytes = compression.stateBytes;

fn instanceIdentity(
    program_identity: Digest,
    input: [input_bytes]u8,
    output: [output_bytes]u8,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.sha256-pair-64-instance.v1\x00");
    hash.update(&program_identity);
    hash.update(&input);
    hash.update(&output);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (input_offset != 0 or output_offset != 64 or record_bytes != 96 or
        block_count != 2 or round_count != 64 or state_word_count != 8 or
        production_active or opcode_registry_ready or air_ready)
    {
        @compileError("fixed SHA-256 pair candidate geometry drifted");
    }
}
