//! Authenticated Fiat-Shamir topology for resident Cairo CUDA proofs.
//!
//! `ProofProgram.transcript` deliberately records coarse semantic barriers.
//! Cairo's resident device channel has a finer physical order: statement
//! fields are absorbed separately and both proof-of-work boundaries are
//! explicit. This schedule binds that exact order to the proof and executable
//! identities without deriving any challenge on the host.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const statement_bootstrap = @import("stwo_cairo_frontend").statement_bootstrap;
const cairo_identity = @import("../../identity.zig");

pub const max_rejection_rounds: u32 = 64;

pub const bootstrap_mix_ordinals = [_]u32{
    1,
    2,
    3,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    20,
};

comptime {
    if (!std.mem.eql(
        u32,
        bootstrap_mix_ordinals[0..2],
        statement_bootstrap.ORDINALS[0..2],
    )) {
        @compileError("Cairo transcript bootstrap prefix drifted");
    }
    if (!std.mem.eql(
        u32,
        bootstrap_mix_ordinals[3..10],
        statement_bootstrap.ORDINALS[2..],
    )) {
        @compileError("Cairo transcript statement order drifted");
    }
}

pub const Operation = union(enum) {
    mix_bootstrap: u32,
    absorb_interaction_pow,
    draw_relation_elements,
    mix_interaction_claims,
    mix_interaction_root,
    draw_composition_alpha,
    mix_composition_root,
    draw_oods_point,
    mix_sampled_values,
    draw_quotient_alpha,
    mix_fri_root: u32,
    draw_fri_alpha: u32,
    mix_last_layer,
    absorb_query_pow,
    draw_queries,
};

pub const Boundary = struct {
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
};

pub const Schedule = struct {
    protocol: compact.CompactProtocolV1,
    semantic_proof_identity: proof_ir.Digest,
    executable_program_identity: proof_ir.Digest,
    schedule_identity: proof_ir.Digest,
    seed_chain: u64,
    operation_count: u32,

    pub fn init(
        program: proof_ir.ProofProgram,
        protocol: compact.CompactProtocolV1,
    ) !Schedule {
        try program.validate();
        try protocol.validate();
        const protocol_identity = try cairo_identity.protocolDigest(protocol);
        if (program.identity.frontend != .cairo or
            !std.mem.eql(
                u8,
                &program.identity.protocol,
                &protocol_identity,
            ) or
            program.commitments.len != protocol.commitment_count or
            program.fri_layers.len != protocol.fri_tree_count or
            program.quotient.evaluation_log_rows !=
                protocol.max_log_degree_bound or
            digestEmpty(program.semantic_digest) or
            digestEmpty(program.program_digest))
        {
            return error.InvalidCairoTranscriptAuthority;
        }
        const roles = [_]proof_ir.CommitmentRole{
            .preprocessed,
            .main,
            .interaction,
            .composition,
        };
        for (program.commitments, roles, 0..) |
            tree,
            role,
            index,
        | {
            if (tree.id != index or tree.role != role)
                return error.InvalidCairoTranscriptAuthority;
        }
        try validateCoarseBarriers(program, protocol);
        const count = operationCount(protocol.fri_tree_count);
        const identity = scheduleIdentity(program, protocol, count);
        return .{
            .protocol = protocol,
            .semantic_proof_identity = program.semantic_digest,
            .executable_program_identity = program.program_digest,
            .schedule_identity = identity,
            .seed_chain = std.mem.readInt(u64, identity[0..8], .little),
            .operation_count = count,
        };
    }

    pub fn operation(self: Schedule, step: u32) !Operation {
        if (step >= self.operation_count)
            return error.InvalidTranscriptStep;
        if (step < bootstrap_mix_ordinals.len) {
            return .{
                .mix_bootstrap = bootstrap_mix_ordinals[@intCast(step)],
            };
        }
        return switch (step) {
            11 => .absorb_interaction_pow,
            12 => .draw_relation_elements,
            13 => .mix_interaction_claims,
            14 => .mix_interaction_root,
            15 => .draw_composition_alpha,
            16 => .mix_composition_root,
            17 => .draw_oods_point,
            18 => .mix_sampled_values,
            19 => .draw_quotient_alpha,
            else => self.operationAfterQuotient(step),
        };
    }

    pub fn boundary(self: Schedule, step: u32) !Boundary {
        _ = try self.operation(step);
        return .{
            .expected_step = step,
            .expected_chain = chainAt(self.seed_chain, step),
            .next_chain = chainAt(self.seed_chain, step + 1),
        };
    }

    pub fn initialChain(self: Schedule) u64 {
        return chainAt(self.seed_chain, 0);
    }

    pub fn stage(self: Schedule, step: u32) !telemetry.Stage {
        const operation_value = try self.operation(step);
        return switch (operation_value) {
            .mix_bootstrap,
            .absorb_interaction_pow,
            .draw_relation_elements,
            .mix_interaction_claims,
            .mix_interaction_root,
            .draw_composition_alpha,
            => .trace_commit,
            .mix_composition_root, .draw_oods_point => .constraint_evaluation,
            .mix_sampled_values, .draw_quotient_alpha => .oods,
            .mix_fri_root, .draw_fri_alpha, .mix_last_layer => .fri_commit,
            .absorb_query_pow => .pow,
            .draw_queries => .decommit,
        };
    }

    pub fn inputOrdinal(
        self: Schedule,
        step: u32,
    ) !?u32 {
        return switch (try self.operation(step)) {
            .mix_bootstrap => |ordinal| ordinal,
            .absorb_interaction_pow => 21,
            .mix_interaction_claims => 22,
            .mix_interaction_root => 23,
            .mix_composition_root => 24,
            .mix_sampled_values => 25,
            .mix_fri_root => |round| friInputOrdinal(round),
            .mix_last_layer => 30,
            .absorb_query_pow => 31,
            else => null,
        };
    }

    pub fn outputOrdinal(
        self: Schedule,
        step: u32,
    ) !?u32 {
        return switch (try self.operation(step)) {
            .draw_relation_elements => 1,
            .draw_composition_alpha => 2,
            .draw_oods_point => 3,
            .draw_quotient_alpha => 4,
            .draw_fri_alpha => |round| friInputOrdinal(round) + 1,
            .draw_queries => 5,
            else => null,
        };
    }

    pub fn secureFeltCount(
        self: Schedule,
        step: u32,
    ) !?u32 {
        return switch (try self.operation(step)) {
            .draw_relation_elements => 2,
            .draw_composition_alpha,
            .draw_oods_point,
            .draw_quotient_alpha,
            .draw_fri_alpha,
            => 1,
            else => null,
        };
    }

    pub fn powBits(self: Schedule, step: u32) !?u32 {
        return switch (try self.operation(step)) {
            .absorb_interaction_pow => self.protocol.interaction_pow_bits,
            .absorb_query_pow => self.protocol.query_pow_bits,
            else => null,
        };
    }

    pub fn validateM31(self: Schedule, step: u32) !bool {
        return switch (try self.operation(step)) {
            .mix_interaction_claims,
            .mix_sampled_values,
            .mix_last_layer,
            => true,
            .mix_bootstrap,
            .mix_interaction_root,
            .mix_composition_root,
            .mix_fri_root,
            => false,
            else => return error.InvalidTranscriptOperation,
        };
    }

    pub fn validateInputWords(
        self: Schedule,
        step: u32,
        words: usize,
    ) !void {
        const ordinal = (try self.inputOrdinal(step)) orelse
            return error.InvalidTranscriptOperation;
        if (expectedInputWords(self.protocol, ordinal)) |expected| {
            if (words != expected)
                return error.InvalidTranscriptPayload;
        } else if (words == 0 or words % 4 != 0) {
            // Public claim ordinal 14 is runtime-sized and M31-padded.
            return error.InvalidTranscriptPayload;
        }
    }

    pub fn validateOutputWords(
        self: Schedule,
        step: u32,
        words: usize,
    ) !void {
        const operation_value = try self.operation(step);
        const expected: usize = switch (operation_value) {
            .draw_relation_elements => 8,
            .draw_composition_alpha,
            .draw_oods_point,
            .draw_quotient_alpha,
            .draw_fri_alpha,
            => 4,
            .draw_queries => self.protocol.query_count,
            else => return error.InvalidTranscriptOperation,
        };
        if (words != expected)
            return error.InvalidTranscriptPayload;
    }

    fn operationAfterQuotient(
        self: Schedule,
        step: u32,
    ) Operation {
        const fri_offset = step - 20;
        const fri_operations = self.protocol.fri_tree_count * 2;
        if (fri_offset < fri_operations) {
            const round = fri_offset / 2;
            return if (fri_offset % 2 == 0)
                .{ .mix_fri_root = round }
            else
                .{ .draw_fri_alpha = round };
        }
        return switch (fri_offset - fri_operations) {
            0 => .mix_last_layer,
            1 => .absorb_query_pow,
            2 => .draw_queries,
            else => unreachable,
        };
    }
};

pub fn operationCount(fri_tree_count: u32) u32 {
    return 23 + fri_tree_count * 2;
}

pub fn friInputOrdinal(round: u32) u32 {
    return 65_536 + round * 4;
}

fn expectedInputWords(
    protocol: compact.CompactProtocolV1,
    ordinal: u32,
) ?usize {
    return switch (ordinal) {
        1 => 4,
        2 => 8,
        3, 15, 16, 20, 23, 24 => 8,
        10, 13 => 4,
        11 => alignedFour(compact.component_enable_count),
        12 => alignedFour(protocol.interaction_sum_count),
        14 => null,
        21, 31 => 2,
        22 => @as(usize, protocol.interaction_sum_count) * 4,
        25 => protocol.sampled_value_words,
        30 => @as(usize, protocol.final_line_coefficient_count) * 4,
        else => if (ordinal >= 65_536 and
            (ordinal - 65_536) % 4 == 0)
            8
        else
            null,
    };
}

fn alignedFour(value: u32) usize {
    return (@as(usize, value) + 3) & ~@as(usize, 3);
}

fn validateCoarseBarriers(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !void {
    const expected_count = 16 + protocol.fri_tree_count * 2;
    if (program.transcript.len != expected_count)
        return error.InvalidCairoTranscriptBarriers;
    const prefix_kinds = [_]proof_ir.TranscriptKind{
        .mix,
        .mix,
        .mix,
        .mix,
        .pow,
        .challenge,
        .mix,
        .mix,
        .challenge,
        .mix,
        .challenge,
        .mix,
        .challenge,
    };
    const prefix_counts = [_]u32{
        1,
        1,
        0,
        1,
        1,
        2,
        protocol.interaction_sum_count,
        1,
        1,
        1,
        1,
        protocol.sampled_value_words / 4,
        1,
    };
    for (prefix_kinds, prefix_counts, 0..) |kind, count, index| {
        const barrier = program.transcript[index];
        if (barrier.kind != kind or
            (count == 0 and barrier.value_count == 0) or
            (count != 0 and barrier.value_count != count))
        {
            return error.InvalidCairoTranscriptBarriers;
        }
    }
    var cursor: usize = prefix_kinds.len;
    for (0..protocol.fri_tree_count) |_| {
        if (program.transcript[cursor].kind != .mix or
            program.transcript[cursor].value_count != 1 or
            program.transcript[cursor + 1].kind != .challenge or
            program.transcript[cursor + 1].value_count != 1)
        {
            return error.InvalidCairoTranscriptBarriers;
        }
        cursor += 2;
    }
    const suffix_kinds = [_]proof_ir.TranscriptKind{
        .mix,
        .pow,
        .queries,
    };
    const suffix_counts = [_]u32{
        protocol.final_line_coefficient_count,
        1,
        protocol.query_count,
    };
    for (suffix_kinds, suffix_counts) |kind, count| {
        if (program.transcript[cursor].kind != kind or
            program.transcript[cursor].value_count != count)
        {
            return error.InvalidCairoTranscriptBarriers;
        }
        cursor += 1;
    }
    std.debug.assert(cursor == program.transcript.len);
}

fn scheduleIdentity(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    count: u32,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/transcript-schedule/v1\x00");
    hash.update(&program.identity.air);
    hash.update(&program.identity.statement);
    hash.update(&program.identity.protocol);
    hash.update(&program.semantic_digest);
    hash.update(&program.program_digest);
    hash.update(&(protocol.encode() catch unreachable));
    hashInt(&hash, u32, count);
    var step: u32 = 0;
    while (step < count) : (step += 1) {
        const operation_value = operationForIdentity(
            protocol.fri_tree_count,
            step,
        );
        hashOperation(&hash, operation_value);
    }
    return hash.finalResult();
}

fn operationForIdentity(
    fri_tree_count: u32,
    step: u32,
) Operation {
    if (step < bootstrap_mix_ordinals.len)
        return .{
            .mix_bootstrap = bootstrap_mix_ordinals[@intCast(step)],
        };
    return switch (step) {
        11 => .absorb_interaction_pow,
        12 => .draw_relation_elements,
        13 => .mix_interaction_claims,
        14 => .mix_interaction_root,
        15 => .draw_composition_alpha,
        16 => .mix_composition_root,
        17 => .draw_oods_point,
        18 => .mix_sampled_values,
        19 => .draw_quotient_alpha,
        else => after: {
            const offset = step - 20;
            const fri_operations = fri_tree_count * 2;
            if (offset < fri_operations) {
                const round = offset / 2;
                break :after if (offset % 2 == 0)
                    .{ .mix_fri_root = round }
                else
                    .{ .draw_fri_alpha = round };
            }
            break :after switch (offset - fri_operations) {
                0 => .mix_last_layer,
                1 => .absorb_query_pow,
                2 => .draw_queries,
                else => unreachable,
            };
        },
    };
}

fn hashOperation(
    hash: *std.crypto.hash.sha2.Sha256,
    operation_value: Operation,
) void {
    hashInt(hash, u8, @intFromEnum(operation_value));
    switch (operation_value) {
        .mix_bootstrap,
        .mix_fri_root,
        .draw_fri_alpha,
        => |value| hashInt(hash, u32, value),
        else => {},
    }
}

fn chainAt(seed: u64, step: u32) u64 {
    var value = seed ^
        (@as(u64, step) *% 0x9e37_79b9_7f4a_7c15);
    value ^= value >> 30;
    value *%= 0xbf58_476d_1ce4_e5b9;
    value ^= value >> 27;
    value *%= 0x94d0_49bb_1331_11eb;
    value ^= value >> 31;
    return value;
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn digestEmpty(value: proof_ir.Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}
