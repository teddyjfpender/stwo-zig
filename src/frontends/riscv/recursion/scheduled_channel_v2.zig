//! Fail-closed generic Poseidon channel adapter for V2 recursive transcripts.
//!
//! Unlike the frozen V1 scheduled channel, this adapter adds no transcript
//! headers and changes no call boundaries. It checks each ordinary STWO
//! channel call against `transcript_program_v2.Program`, then forwards the call
//! unchanged. A proof produced through this adapter is therefore transcript-
//! identical to the ordinary V2 Poseidon engine.

const std = @import("std");
const stwo_core = @import("stwo_core");

const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const PcsConfig = stwo_core.pcs.PcsConfig;
const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_v1 = @import("../air/statement.zig");
const channel_mod = @import("poseidon2_channel.zig");
const schedule = @import("air/verifier_schedule.zig");
const transcript = @import("transcript_program_v2.zig");

pub const Error = transcript.Error || error{
    ChannelNotInitialized,
    IncompleteSchedule,
    TranscriptFault,
    UnexpectedChannelOperation,
};

pub const Channel = struct {
    program: ?*const transcript.Program = null,
    data: ?*const public_data_v2.PublicDataV2 = null,
    inner: channel_mod.Channel = .{},
    next_instruction: usize = 0,
    pending_pow_nonce: ?u64 = null,
    first_fault: ?anyerror = null,
    n_draws: u32 = 0,

    const Self = @This();

    pub fn init(
        program: *const transcript.Program,
        plan: *const schedule.Plan,
        pcs_config: PcsConfig,
        data: *const public_data_v2.PublicDataV2,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) Error!Self {
        try program.validateAgainst(
            plan,
            pcs_config,
            data,
            component_descs,
            infra_descs,
        );
        return .{ .program = program, .data = data };
    }

    pub fn complete(self: *const Self) Error!void {
        if (self.first_fault != null) return error.TranscriptFault;
        const program = self.program orelse return error.ChannelNotInitialized;
        if (self.next_instruction != program.instructions.len or
            self.pending_pow_nonce != null)
        {
            return error.IncompleteSchedule;
        }
    }

    pub fn digestWords(self: Self) channel_mod.Digest {
        return self.inner.digestWords();
    }

    pub fn digestBytes(self: Self) [channel_mod.RATE * @sizeOf(u32)]u8 {
        return self.inner.digestBytes();
    }

    pub fn mixFelts(self: *Self, values: []const QM31) void {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return;
        };
        const accepted = switch (instruction.kind) {
            .pcs_config => pcsPayloadEql(values, self.program.?.pcs_config),
            .claimed_sum => values.len == 1,
            .sampled_values, .last_layer_coefficients => values.len == instruction.args[0],
            else => false,
        };
        if (!accepted) {
            self.recordFault(error.UnexpectedChannelOperation);
            return;
        }
        self.inner.mixFelts(values);
        self.advance();
    }

    pub fn mixU32s(self: *Self, values: []const u32) void {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return;
        };
        const program = self.program.?;
        const expected = switch (instruction.kind) {
            .statement_header => eqlU32(values, &.{
                public_data_v2.STATEMENT_TRANSCRIPT_DOMAIN,
                public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
                public_data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION,
                program.wire_word_count,
            }),
            .statement_wire_id => eqlU32(values, &program.wire_id),
            .shard_header => eqlU32(values, &.{
                0x5348_5244,
                instruction.args[0],
                instruction.args[1],
            }),
            .shard_component, .shard_infra => eqlU32(values, &instruction.args),
            else => false,
        };
        if (!expected) {
            self.recordFault(error.UnexpectedChannelOperation);
            return;
        }
        self.inner.mixU32s(values);
        self.advance();
    }

    pub fn mixU64(self: *Self, value: u64) void {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return;
        };
        const expected = switch (instruction.kind) {
            .main_log_size => value == instruction.args[1],
            .interaction_log_count => value == instruction.args[0],
            .interaction_log_size => value == instruction.args[1],
            .interaction_pow, .pcs_pow => self.pending_pow_nonce != null and
                value == self.pending_pow_nonce.?,
            else => false,
        };
        if (!expected) {
            self.recordFault(error.UnexpectedChannelOperation);
            return;
        }
        self.inner.mixU64(value);
        self.pending_pow_nonce = null;
        self.advance();
    }

    pub fn mixCanonicalM31Words(self: *Self, words: []const M31) void {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return;
        };
        const data = self.data orelse {
            self.recordFault(error.ChannelNotInitialized);
            return;
        };
        if (instruction.kind != .statement_words or
            words.len != instruction.args[0] or
            words.len != data.words().len or
            !fieldSlicesEql(words, data.words()))
        {
            self.recordFault(error.UnexpectedChannelOperation);
            return;
        }
        data.validate() catch |err| {
            self.recordFault(err);
            return;
        };
        self.inner.mixCanonicalM31Words(words);
        self.advance();
    }

    pub fn drawSecureFelts(
        self: *Self,
        allocator: std.mem.Allocator,
        count: usize,
    ) ![]QM31 {
        try self.checkHealthy();
        if (count % 2 != 0) return error.UnexpectedChannelOperation;
        const result = try allocator.alloc(QM31, count);
        errdefer allocator.free(result);
        var at: usize = 0;
        while (at < count) : (at += 2) {
            const instruction = try self.peek();
            if (instruction.kind != .relation_draw)
                return error.UnexpectedChannelOperation;
            const words = self.inner.drawU32s();
            result[at] = QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
            result[at + 1] = QM31.fromU32Unchecked(words[4], words[5], words[6], words[7]);
            self.advance();
        }
        return result;
    }

    pub fn drawSecureFelt(self: *Self) QM31 {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return QM31.zero();
        };
        switch (instruction.kind) {
            .composition_draw, .oods_draw, .deep_draw, .fri_alpha_draw => {},
            else => {
                self.recordFault(error.UnexpectedChannelOperation);
                return QM31.zero();
            },
        }
        const result = self.inner.drawSecureFelt();
        self.advance();
        return result;
    }

    pub fn drawU32s(self: *Self) channel_mod.Digest {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return .{0} ** channel_mod.RATE;
        };
        if (instruction.kind != .query_draw) {
            self.recordFault(error.UnexpectedChannelOperation);
            return .{0} ** channel_mod.RATE;
        }
        const result = self.inner.drawU32s();
        self.advance();
        return result;
    }

    pub fn verifyPowNonce(self: *Self, bits: u32, nonce: u64) bool {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return false;
        };
        if ((instruction.kind != .interaction_pow and instruction.kind != .pcs_pow) or
            bits != instruction.args[0] or self.pending_pow_nonce != null)
        {
            self.recordFault(error.UnexpectedChannelOperation);
            return false;
        }
        const accepted = self.inner.verifyPowNonce(bits, nonce);
        if (accepted) self.pending_pow_nonce = nonce;
        return accepted;
    }

    pub fn grind(self: *Self, bits: u32) u64 {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return 0;
        };
        if ((instruction.kind != .interaction_pow and instruction.kind != .pcs_pow) or
            bits != instruction.args[0] or self.pending_pow_nonce != null)
        {
            self.recordFault(error.UnexpectedChannelOperation);
            return 0;
        }
        const nonce = self.inner.grind(bits);
        self.pending_pow_nonce = nonce;
        return nonce;
    }

    fn mixRoot(self: *Self, root: channel_mod.Digest) void {
        const instruction = self.peek() catch |err| {
            self.recordFault(err);
            return;
        };
        if (instruction.kind != .trace_commitment and
            instruction.kind != .fri_commitment)
        {
            self.recordFault(error.UnexpectedChannelOperation);
            return;
        }
        for (root) |word| if (word >= m31.Modulus) {
            self.recordFault(error.InvalidFieldElement);
            return;
        };
        var words: [channel_mod.RATE]M31 = undefined;
        for (&words, root) |*destination, word|
            destination.* = M31.fromCanonical(word);
        self.inner.mixCanonicalM31Words(&words);
        self.advance();
    }

    fn peek(self: *Self) Error!transcript.Instruction {
        try self.checkHealthy();
        const program = self.program orelse return error.ChannelNotInitialized;
        if (self.next_instruction >= program.instructions.len)
            return error.IncompleteSchedule;
        return program.instructions[self.next_instruction];
    }

    fn advance(self: *Self) void {
        self.next_instruction += 1;
        self.n_draws = self.inner.n_draws;
    }

    fn checkHealthy(self: *const Self) Error!void {
        if (self.first_fault != null) return error.TranscriptFault;
        if (self.program == null or self.data == null)
            return error.ChannelNotInitialized;
    }

    fn recordFault(self: *Self, err: anyerror) void {
        if (self.first_fault == null) self.first_fault = err;
    }
};

pub const MerkleChannel = struct {
    pub fn mixRoot(channel: *Channel, root: channel_mod.Digest) void {
        channel.mixRoot(root);
    }
};

fn pcsPayloadEql(values: []const QM31, config: PcsConfig) bool {
    const expected_count: usize = if (config.fri_config.fold_step !=
        stwo_core.fri.FOLD_STEP or config.lifting_log_size != null) 2 else 1;
    if (values.len != expected_count) return false;
    const first = QM31.fromU32Unchecked(
        config.pow_bits,
        config.fri_config.log_blowup_factor,
        @intCast(config.fri_config.n_queries),
        config.fri_config.log_last_layer_degree_bound,
    );
    if (!values[0].eql(first)) return false;
    if (values.len == 2) {
        const second = QM31.fromU32Unchecked(
            config.fri_config.fold_step,
            config.lifting_log_size orelse 0,
            0,
            0,
        );
        if (!values[1].eql(second)) return false;
    }
    return true;
}

fn eqlU32(actual: []const u32, expected: []const u32) bool {
    return std.mem.eql(u32, actual, expected);
}

fn fieldSlicesEql(actual: []const M31, expected: []const M31) bool {
    if (actual.len != expected.len) return false;
    for (actual, expected) |left, right| if (!left.eql(right)) return false;
    return true;
}

comptime {
    if (transcript.FORMAT_VERSION == 1 or channel_mod.RATE != 8)
        @compileError("V2 scheduled channel must remain disjoint from V1");
}
