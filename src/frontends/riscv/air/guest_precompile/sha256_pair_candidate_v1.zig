//! Non-production fixed-64-byte SHA-256 pair-hash semantic authority.
//!
//! SSZ Merkle hashing always computes `SHA256(left || right)` for two 32-byte
//! nodes. The message therefore owns exactly two compression blocks: one raw
//! 64-byte block and one fixed SHA-256 padding block. This candidate does not
//! claim variable-length SHA-256 or reuse the unauthenticated host syscall.

const std = @import("std");

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

pub const initial_state: State = .{
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
};

pub const round_constants: [round_count]u32 = .{
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
    0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
    0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
    0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
    0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
};

pub const Error = error{
    InvalidBlockInput,
    InvalidBlockState,
    InvalidInstanceIdentity,
    InvalidOutput,
    InvalidPadding,
    InvalidProgramIdentity,
    InvalidSchedule,
};

pub const BlockTraceV1 = struct {
    input: [block_bytes]u8,
    schedule: [schedule_word_count]u32,
    states: [round_count + 1]State,
    output_state: State,
};

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

pub fn sigmaSmall0(value: u32) u32 {
    return std.math.rotr(u32, value, 7) ^
        std.math.rotr(u32, value, 18) ^ (value >> 3);
}

pub fn sigmaSmall1(value: u32) u32 {
    return std.math.rotr(u32, value, 17) ^
        std.math.rotr(u32, value, 19) ^ (value >> 10);
}

pub fn sigmaBig0(value: u32) u32 {
    return std.math.rotr(u32, value, 2) ^
        std.math.rotr(u32, value, 13) ^
        std.math.rotr(u32, value, 22);
}

pub fn sigmaBig1(value: u32) u32 {
    return std.math.rotr(u32, value, 6) ^
        std.math.rotr(u32, value, 11) ^
        std.math.rotr(u32, value, 25);
}

pub fn choose(e: u32, f: u32, g: u32) u32 {
    return (e & f) ^ (~e & g);
}

pub fn majority(a: u32, b: u32, c: u32) u32 {
    return (a & b) ^ (a & c) ^ (b & c);
}

fn compress(initial: State, input: [block_bytes]u8) BlockTraceV1 {
    var schedule: [schedule_word_count]u32 = undefined;
    for (0..16) |word| schedule[word] = std.mem.readInt(
        u32,
        input[word * 4 ..][0..4],
        .big,
    );
    for (16..schedule_word_count) |word| schedule[word] =
        sigmaSmall1(schedule[word - 2]) +%
        schedule[word - 7] +%
        sigmaSmall0(schedule[word - 15]) +%
        schedule[word - 16];

    var states: [round_count + 1]State = undefined;
    states[0] = initial;
    for (0..round_count) |round| {
        const state = states[round];
        const t1 = state[7] +% sigmaBig1(state[4]) +%
            choose(state[4], state[5], state[6]) +%
            round_constants[round] +% schedule[round];
        const t2 = sigmaBig0(state[0]) +%
            majority(state[0], state[1], state[2]);
        states[round + 1] = .{
            t1 +% t2,
            state[0],
            state[1],
            state[2],
            state[3] +% t1,
            state[4],
            state[5],
            state[6],
        };
    }
    var output_state: State = undefined;
    for (&output_state, initial, states[round_count]) |*out, base, work|
        out.* = base +% work;
    return .{
        .input = input,
        .schedule = schedule,
        .states = states,
        .output_state = output_state,
    };
}

fn stateBytes(state: State) [output_bytes]u8 {
    var result: [output_bytes]u8 = undefined;
    for (state, 0..) |word, index|
        std.mem.writeInt(u32, result[index * 4 ..][0..4], word, .big);
    return result;
}

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
