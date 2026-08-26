//! Internal transcript program v2 authority shard; use transcript_program_v2.zig publicly.

const dependency_0 = @import("transcript_program_v2_contract.zig");
const dependency_1 = @import("transcript_program_v2_program.zig");

const COMPONENT_CLAIM_COUNT = dependency_0.COMPONENT_CLAIM_COUNT;
const Check = dependency_0.Check;
const Draw = dependency_0.Draw;
const Error = dependency_0.Error;
const Execution = dependency_1.Execution;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const HashFrame = dependency_0.HashFrame;
const HashPurpose = dependency_0.HashPurpose;
const Inputs = dependency_1.Inputs;
const Instruction = dependency_0.Instruction;
const Layout = dependency_1.Layout;
const M31 = dependency_0.M31;
const Operation = dependency_1.Operation;
const PoseidonCall = dependency_0.PoseidonCall;
const Program = dependency_1.Program;
const RATE = dependency_0.RATE;
const WIDTH = dependency_0.WIDTH;
const add = dependency_0.add;
const canonical = dependency_1.canonical;
const channel = dependency_0.channel;
const executionIdentity = dependency_1.executionIdentity;
const frameCallCount = dependency_1.frameCallCount;
const permutation = dependency_0.permutation;
const public_data_v2 = dependency_0.public_data_v2;
const rawDigest = dependency_1.rawDigest;
const relation_challenges = dependency_0.relation_challenges;
const std = dependency_0.std;
const writePayload = dependency_1.writePayload;
const writeU64 = dependency_1.writeU64;

pub fn execute(
    allocator: std.mem.Allocator,
    program: *const Program,
    data: *const public_data_v2.PublicDataV2,
    inputs: Inputs,
) Error!Execution {
    try data.validate();
    if (!std.meta.eql(data.wireId(), program.wire_id) or
        data.words().len != program.wire_word_count)
    {
        return error.AuthorityMismatch;
    }
    try inputs.validate(program);
    const layout = try Layout.init(program);
    const calls = try allocator.alloc(PoseidonCall, layout.call_count);
    errdefer allocator.free(calls);
    const frames = try allocator.alloc(HashFrame, layout.frame_count);
    errdefer allocator.free(frames);
    const checks = try allocator.alloc(Check, layout.pow_count);
    errdefer allocator.free(checks);
    const words = try allocator.alloc(M31, layout.word_count);
    errdefer allocator.free(words);
    const operations = try allocator.alloc(Operation, program.instructions.len);
    errdefer allocator.free(operations);

    var kernel = Kernel{
        .calls = calls,
        .frames = frames,
        .checks = checks,
        .words = words,
    };
    for (program.instructions, 0..) |instruction, index| {
        const first_frame = kernel.frame_at;
        const first_call = kernel.call_at;
        const semantic_draw: ?Draw = switch (instruction.effect()) {
            .mix => blk: {
                try kernel.mix(program, data, inputs, instruction);
                break :blk null;
            },
            .draw => try kernel.draw(),
            .pow => blk: {
                const nonce = if (instruction.kind == .interaction_pow)
                    inputs.interaction_pow
                else
                    inputs.pcs_pow;
                try kernel.mixPow(nonce);
                try kernel.verifyPow(nonce, instruction.args[0]);
                break :blk null;
            },
        };
        operations[index] = .{
            .instruction_index = @intCast(index),
            .first_hash_id = @intCast(first_frame),
            .hash_count = @intCast(kernel.frame_at - first_frame),
            .first_call_id = @intCast(first_call),
            .call_count = @intCast(kernel.call_at - first_call),
            .draw = semantic_draw,
        };
    }
    if (!kernel.complete(layout)) return error.IncompleteProgram;
    var result = Execution{
        .allocator = allocator,
        .program_id = program.identity,
        .wire_id = program.wire_id,
        .statement_authority_id = program.statement_authority_id,
        .poseidon_calls = calls,
        .hash_frames = frames,
        .pow_checks = checks,
        .word_storage = words,
        .operations = operations,
        .final_digest = rawDigest(kernel.digest),
        .final_draw_count = kernel.draw_count,
        .identity = undefined,
    };
    result.identity = executionIdentity(&result);
    try result.validateAgainst(program);
    return result;
}

pub const Kernel = struct {
    calls: []PoseidonCall,
    frames: []HashFrame,
    checks: []Check,
    words: []M31,
    digest: Draw = .{M31.zero()} ** RATE,
    draw_count: u32 = 0,
    call_at: usize = 0,
    frame_at: usize = 0,
    check_at: usize = 0,
    word_at: usize = 0,

    fn mix(
        self: *Kernel,
        program: *const Program,
        data: *const public_data_v2.PublicDataV2,
        inputs: Inputs,
        instruction: Instruction,
    ) Error!void {
        const payload_count = try instruction.payloadWordCount();
        const words = try self.claimWords(try add(RATE, payload_count));
        @memcpy(words[0..RATE], &self.digest);
        try writePayload(words[RATE..], program, data, inputs, instruction);
        const output = try self.hashFrame(.mix, words);
        self.digest = output[0..RATE].*;
        self.draw_count = 0;
    }

    fn mixPow(self: *Kernel, nonce: u64) Error!void {
        const words = try self.claimWords(RATE + 4);
        @memcpy(words[0..RATE], &self.digest);
        writeU64(words[RATE..], nonce);
        const output = try self.hashFrame(.mix, words);
        self.digest = output[0..RATE].*;
        self.draw_count = 0;
    }

    fn draw(self: *Kernel) Error!Draw {
        const words = try self.claimWords(RATE + 2);
        @memcpy(words[0..RATE], &self.digest);
        words[RATE] = try canonical(self.draw_count);
        words[RATE + 1] = try canonical(channel.DRAW_TAG);
        const output = try self.hashFrame(.draw, words);
        self.draw_count = std.math.add(u32, self.draw_count, 1) catch
            return error.DrawCountOverflow;
        return output[0..RATE].*;
    }

    fn verifyPow(self: *Kernel, nonce: u64, bits: u32) Error!void {
        if (bits > 31) return error.InvalidProofOfWork;
        const draw_words = try self.draw();
        if (@ctz(draw_words[0].toU32()) < bits)
            return error.InvalidProofOfWork;
        self.checks[self.check_at] = .{
            .call_id = @intCast(self.call_at - 1),
            .nonce = nonce,
            .bits = bits,
            .word = draw_words[0],
        };
        self.check_at += 1;
        self.draw_count = 0;
    }

    fn claimWords(self: *Kernel, count: usize) Error![]M31 {
        const end = try add(self.word_at, count);
        if (end > self.words.len) return error.IncompleteProgram;
        const result = self.words[self.word_at..end];
        self.word_at = end;
        return result;
    }

    fn hashFrame(
        self: *Kernel,
        purpose: HashPurpose,
        words: []const M31,
    ) Error![WIDTH]M31 {
        const call_count = try frameCallCount(words.len);
        const first_call = self.call_at;
        var state = [_]M31{M31.zero()} ** WIDTH;
        for (0..call_count) |step| {
            if (self.call_at >= self.calls.len) return error.IncompleteProgram;
            const input = addChunk(state, words, step);
            var output = input;
            permutation.permute(&output);
            self.calls[self.call_at] = .{
                .id = .{
                    .call_id = @intCast(self.call_at),
                    .hash_id = @intCast(self.frame_at),
                    .step = @intCast(step),
                },
                .input = input,
                .output = output,
            };
            state = output;
            self.call_at += 1;
        }
        self.frames[self.frame_at] = .{
            .hash_id = @intCast(self.frame_at),
            .first_call_id = @intCast(first_call),
            .call_count = @intCast(call_count),
            .purpose = purpose,
            .words = words,
            .output = state,
        };
        self.frame_at += 1;
        return state;
    }

    fn complete(self: Kernel, layout: Layout) bool {
        return self.call_at == layout.call_count and
            self.frame_at == layout.frame_count and
            self.check_at == layout.pow_count and
            self.word_at == layout.word_count;
    }
};

pub fn addChunk(previous: [WIDTH]M31, words: []const M31, step: usize) [WIDTH]M31 {
    var input = previous;
    for (0..RATE) |lane| {
        const index = step * RATE + lane;
        const word = if (index < words.len)
            words[index]
        else if (index == words.len)
            M31.one()
        else
            M31.zero();
        input[lane] = input[lane].add(word);
    }
    return input;
}

comptime {
    if (FORMAT_VERSION == 1 or RATE != 8 or WIDTH != 16 or
        COMPONENT_CLAIM_COUNT != 28 or relation_challenges.RELATION_COUNT != 12)
    {
        @compileError("V2 generic transcript constants drifted");
    }
}
