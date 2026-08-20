//! Internal transcript program v2 authority shard; use transcript_program_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const M31 = m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const PcsConfig = stwo_core.pcs.PcsConfig;
pub const permutation = @import("../air/memory_commitment/poseidon2.zig");
pub const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
pub const public_data_v2 = @import("../air/public_data_v2.zig");
pub const relation_challenges = @import("../air/relation_challenges.zig");
pub const statement_v1 = @import("../air/statement.zig");
pub const statement_v2 = @import("../air/statement_v2.zig");
pub const transcript_claims = @import("../air/transcript/claims.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const schedule = @import("air/verifier_schedule.zig");
pub const trace_mod = @import("air/pow_frame_witness.zig");
pub const pow_check = @import("air/pow_check_witness.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROGRAM_ID_DOMAIN: u32 = 0x5450_5632; // "TPV2"
pub const EVIDENCE_ID_DOMAIN: u32 = 0x5452_5632; // "TRV2"
pub const RATE: usize = channel.RATE;
pub const WIDTH: usize = permutation.WIDTH;
pub const COMPONENT_CLAIM_COUNT: usize = transcript_claims.COMPONENT_COUNT;

pub const TranscriptTrace = trace_mod.TranscriptTrace;
pub const PoseidonCall = trace_mod.PoseidonCall;
pub const HashFrame = trace_mod.HashFrame;
pub const HashPurpose = trace_mod.HashPurpose;
pub const Check = pow_check.Check;
pub const Digest = channel.Digest;
pub const Draw = [RATE]M31;

pub const Error = schedule.Error || public_data_v2.Error || statement_v2.Error ||
    std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    CallCountOutOfRange,
    DestinationLengthMismatch,
    DrawCountOverflow,
    FrameCountOutOfRange,
    IncompleteProgram,
    InvalidFieldElement,
    InvalidInputCount,
    InvalidPcsConfiguration,
    InvalidProofOfWork,
    InvalidTranscriptTrace,
    OperationCountOutOfRange,
    ProgramShapeMismatch,
    UnsupportedVersion,
    WordCountOutOfRange,
};

pub const Kind = enum(u8) {
    pcs_config,
    statement_header,
    statement_wire_id,
    statement_words,
    trace_commitment,
    main_log_size,
    shard_header,
    shard_component,
    shard_infra,
    interaction_pow,
    relation_draw,
    claimed_sum,
    interaction_log_count,
    interaction_log_size,
    composition_draw,
    oods_draw,
    sampled_values,
    deep_draw,
    fri_commitment,
    fri_alpha_draw,
    last_layer_coefficients,
    pcs_pow,
    query_draw,
};

pub const Effect = enum(u8) { mix, draw, pow };

/// One exact generic-channel call (or one verify-then-absorb PoW transaction).
/// `args` are kind-specific, verifier-owned constants and are always included
/// in the program identity.
pub const Instruction = struct {
    kind: Kind,
    verifier_sequence: u32,
    sub_index: u32,
    args: [4]u32 = .{ 0, 0, 0, 0 },

    pub fn effect(self: Instruction) Effect {
        return switch (self.kind) {
            .relation_draw,
            .composition_draw,
            .oods_draw,
            .deep_draw,
            .fri_alpha_draw,
            .query_draw,
            => .draw,
            .interaction_pow, .pcs_pow => .pow,
            else => .mix,
        };
    }

    pub fn payloadWordCount(self: Instruction) Error!usize {
        return switch (self.kind) {
            .pcs_config => try timesFour(self.args[0]),
            .statement_header => 8,
            .statement_wire_id => 2 * RATE,
            .statement_words => @intCast(self.args[0]),
            .trace_commitment, .fri_commitment => RATE,
            .main_log_size,
            .interaction_pow,
            .interaction_log_count,
            .interaction_log_size,
            .pcs_pow,
            => 4,
            .shard_header => 6,
            .shard_component, .shard_infra => 8,
            .claimed_sum => 4,
            .sampled_values, .last_layer_coefficients => try timesFour(self.args[0]),
            .relation_draw,
            .composition_draw,
            .oods_draw,
            .deep_draw,
            .fri_alpha_draw,
            .query_draw,
            => 0,
        };
    }
};

pub fn buildInstructions(
    allocator: std.mem.Allocator,
    destination: *std.ArrayList(Instruction),
    plan: *const schedule.Plan,
    pcs_config: PcsConfig,
    wire_word_count: u32,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!void {
    var core: statement_v1.RiscVStatement = undefined;
    core.n_components = @intCast(component_descs.len);
    @memcpy(core.component_descs[0..component_descs.len], component_descs);
    core.n_infra = @intCast(infra_descs.len);
    @memcpy(core.infra_descs[0..infra_descs.len], infra_descs);
    const main_claim = core.canonicalMainClaim();
    const interaction_log_count = try interactionLogCount(component_descs, infra_descs);
    const pcs_felt_count: u32 = if (pcs_config.fri_config.fold_step !=
        stwo_core.fri.FOLD_STEP or pcs_config.lifting_log_size != null) 2 else 1;

    for (plan.steps, 0..) |verifier_step, sequence_usize| {
        const sequence: u32 = @intCast(sequence_usize);
        var sub_index: u32 = 0;
        switch (verifier_step) {
            .bind_protocol, .bind_statement => {},
            .bind_pcs_parameters => {
                try appendInstruction(allocator, destination, sequence, &sub_index, .pcs_config, .{
                    pcs_felt_count, 0, 0, 0,
                });
                try appendInstruction(allocator, destination, 1, &sub_index, .statement_header, .{0} ** 4);
                try appendInstruction(allocator, destination, 1, &sub_index, .statement_wire_id, .{0} ** 4);
                try appendInstruction(allocator, destination, 1, &sub_index, .statement_words, .{
                    wire_word_count, 0, 0, 0,
                });
            },
            .absorb_trace_commitment => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .trace_commitment,
                .{ item.tree, @intFromEnum(item.round), item.height, 0 },
            ),
            .absorb_public_claim => {
                for (main_claim.log_sizes, 0..) |log_size, index| {
                    try appendInstruction(allocator, destination, sequence, &sub_index, .main_log_size, .{
                        @intCast(index), log_size, 0, 0,
                    });
                }
                try appendInstruction(allocator, destination, sequence, &sub_index, .shard_header, .{
                    @intCast(component_descs.len), @intCast(infra_descs.len), 0, 0,
                });
                for (component_descs, 0..) |descriptor, index| {
                    try appendInstruction(allocator, destination, sequence, &sub_index, .shard_component, .{
                        @intFromEnum(descriptor.family), descriptor.log_size,
                        descriptor.n_rows,               descriptor.n_columns,
                    });
                    _ = index;
                }
                for (infra_descs) |descriptor| {
                    try appendInstruction(allocator, destination, sequence, &sub_index, .shard_infra, .{
                        @intFromEnum(descriptor.kind), descriptor.log_size,
                        descriptor.n_rows,             descriptor.n_columns,
                    });
                }
            },
            .verify_and_absorb_interaction_pow => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .interaction_pow,
                .{ item.bits, 0, 0, 0 },
            ),
            .draw_relation_challenge => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .relation_draw,
                .{ item.challenge, 0, 0, 0 },
            ),
            .absorb_claimed_sums => |item| {
                if (item.count != COMPONENT_CLAIM_COUNT)
                    return error.ProgramShapeMismatch;
                for (0..item.count) |index| try appendInstruction(
                    allocator,
                    destination,
                    sequence,
                    &sub_index,
                    .claimed_sum,
                    .{ @intCast(index), 0, 0, 0 },
                );
                try appendInstruction(allocator, destination, sequence, &sub_index, .interaction_log_count, .{
                    interaction_log_count, 0, 0, 0,
                });
                var log_index: u32 = 0;
                for (component_descs) |descriptor| {
                    for (0..opcode_interaction.nColumns(descriptor.family)) |_| {
                        try appendInstruction(allocator, destination, sequence, &sub_index, .interaction_log_size, .{
                            log_index, descriptor.log_size, 0, 0,
                        });
                        log_index += 1;
                    }
                }
                for (infra_descs) |descriptor| {
                    for (0..statement_v1.nInteractionColsForInfra(descriptor.kind)) |_| {
                        try appendInstruction(allocator, destination, sequence, &sub_index, .interaction_log_size, .{
                            log_index, descriptor.log_size, 0, 0,
                        });
                        log_index += 1;
                    }
                }
                if (log_index != interaction_log_count)
                    return error.ProgramShapeMismatch;
            },
            .draw_composition_randomness => try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .composition_draw,
                .{0} ** 4,
            ),
            .draw_oods_point => try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .oods_draw,
                .{0} ** 4,
            ),
            .absorb_sampled_values => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .sampled_values,
                .{ item.count, 0, 0, 0 },
            ),
            .draw_deep_randomness => try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .deep_draw,
                .{0} ** 4,
            ),
            .absorb_fri_commitment => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .fri_commitment,
                .{ item.layer, 0, 0, 0 },
            ),
            .draw_fri_alpha => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .fri_alpha_draw,
                .{ item.layer, 0, 0, 0 },
            ),
            .absorb_last_layer_coefficients => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .last_layer_coefficients,
                .{ item.count, 0, 0, 0 },
            ),
            .verify_and_absorb_pcs_pow => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .pcs_pow,
                .{ item.bits, 0, 0, 0 },
            ),
            .draw_query_block => |item| try appendInstruction(
                allocator,
                destination,
                sequence,
                &sub_index,
                .query_draw,
                .{ item.block, item.first_query, item.query_count, 0 },
            ),
            else => {},
        }
    }
}

pub fn appendInstruction(
    allocator: std.mem.Allocator,
    destination: *std.ArrayList(Instruction),
    verifier_sequence: u32,
    sub_index: *u32,
    kind: Kind,
    args: [4]u32,
) Error!void {
    try destination.append(allocator, .{
        .kind = kind,
        .verifier_sequence = verifier_sequence,
        .sub_index = sub_index.*,
        .args = args,
    });
    sub_index.* = std.math.add(u32, sub_index.*, 1) catch
        return error.ArithmeticOverflow;
}

pub fn validatePlanPrefix(plan: *const schedule.Plan) Error!void {
    if (plan.schema != .vm or plan.steps.len < 4 or
        plan.steps[0] != .bind_protocol or
        plan.steps[1] != .bind_statement or
        plan.steps[2] != .bind_pcs_parameters or
        plan.spec.relation_challenge_count != relation_challenges.RELATION_COUNT)
    {
        return error.ProgramShapeMismatch;
    }
}

pub fn validatePcsAgainstPlan(config: PcsConfig, plan: *const schedule.Plan) Error!void {
    var saw_pcs_pow = false;
    var query_count: u64 = 0;
    var fri_layers: usize = 0;
    for (plan.steps) |step| switch (step) {
        .verify_and_absorb_pcs_pow => |item| {
            if (saw_pcs_pow or item.bits != config.pow_bits)
                return error.InvalidPcsConfiguration;
            saw_pcs_pow = true;
        },
        .draw_query_block => |item| query_count += item.query_count,
        .absorb_fri_commitment => fri_layers += 1,
        else => {},
    };
    if (!saw_pcs_pow or query_count != config.fri_config.n_queries or fri_layers == 0)
        return error.InvalidPcsConfiguration;
}

pub fn interactionLogCount(
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!u32 {
    var result: u64 = 0;
    for (component_descs) |descriptor|
        result += opcode_interaction.nColumns(descriptor.family);
    for (infra_descs) |descriptor|
        result += statement_v1.nInteractionColsForInfra(descriptor.kind);
    return std.math.cast(u32, result) orelse error.ArithmeticOverflow;
}

pub fn hashPcsConfig(hash: *IdentityHasher, config: PcsConfig) void {
    hash.u32Value(config.pow_bits);
    hash.u32Value(config.fri_config.log_blowup_factor);
    hash.u32Value(@intCast(config.fri_config.n_queries));
    hash.u32Value(config.fri_config.log_last_layer_degree_bound);
    hash.u32Value(config.fri_config.fold_step);
    hash.scalar(@intFromBool(config.lifting_log_size != null));
    hash.u32Value(config.lifting_log_size orelse 0);
}

pub fn timesFour(value: u32) Error!usize {
    return std.math.mul(usize, @as(usize, value), 4) catch
        return error.ArithmeticOverflow;
}

pub fn add(left: usize, right: anytype) Error!usize {
    return std.math.add(usize, left, @intCast(right)) catch
        return error.ArithmeticOverflow;
}

pub fn countKind(instructions: []const Instruction, kind: Kind) usize {
    var result: usize = 0;
    for (instructions) |instruction| result += @intFromBool(instruction.kind == kind);
    return result;
}

pub fn pcsConfigEql(left: PcsConfig, right: PcsConfig) bool {
    return left.pow_bits == right.pow_bits and
        left.fri_config.log_blowup_factor == right.fri_config.log_blowup_factor and
        left.fri_config.n_queries == right.fri_config.n_queries and
        left.fri_config.log_last_layer_degree_bound ==
            right.fri_config.log_last_layer_degree_bound and
        left.fri_config.fold_step == right.fri_config.fold_step and
        left.lifting_log_size == right.lifting_log_size;
}

pub const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn scalar(self: *IdentityHasher, value: anytype) void {
        const raw: u32 = @intCast(value);
        std.debug.assert(raw < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(raw)};
        self.inner.update(&words);
    }

    pub fn u32Value(self: *IdentityHasher, value: u32) void {
        self.scalar(value & 0xffff);
        self.scalar(value >> 16);
    }

    pub fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.scalar(word);
    }

    pub fn bytes(self: *IdentityHasher, value: []const u8) void {
        self.u32Value(@intCast(value.len));
        for (value) |byte| self.scalar(byte);
    }

    pub fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};
