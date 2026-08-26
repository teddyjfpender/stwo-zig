//! Fixed executable authority for native typed RV32 JALR.
//!
//! The authenticated typed graph owns the PC-relative link, register-derived
//! target, immediate reconstruction, read-only source, x0 destination, witness
//! recipe, direct roots, and ordered relations. This facade retains that
//! identity as a pointer-free capability after the cold authored arena is
//! released. Admitted row operations allocate nothing and perform no string,
//! map, or indirect semantic dispatch.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const access_clock = @import("../../access_clock.zig");
const isa_profile = @import("../../isa/profile.zig");
const state_chain = @import("../../runner/state_chain.zig");
const decode = @import("../../runner/decode.zig");
const trace_row = @import("../../runner/trace_row.zig");
const entry = @import("../lookups/entry.zig");
const common = @import("../semantics/common.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const lower_effects = @import("lower_effects.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const typed_jalr = @import("typed_jalr.zig");
const witness = @import("typed_jalr_witness.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_jalr.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed_jalr.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed_jalr.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed_jalr.LOOKUP_BATCH_SIZE;
pub const OPCODE_ID: u32 = typed_jalr.OPCODE_ID;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/jalr-fixed-authority/v1";

// Cold construction independently recomputes this complete binding identity
// before a capability can be admitted. The compile-time check at the end of
// this file prevents an unreviewed semantic, witness, target, or relation
// change from silently entering the pinned path.
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "1570bb5a80ad2929a39c3962577bae9f9caea9ccf722158e351224d3b299de98";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = hexDigest(
    AUTHORITY_BINDING_DIGEST_HEX,
    "invalid typed JALR authority-binding digest",
);

pub const ExecutionRecipe = enum(u8) {
    rs1_plus_i_immediate_clear_lsb_link_write_x0_discard = 0,
};

pub const ControlTargetAlgorithm = enum(u8) {
    program_authenticated_wrapping_rs1_plus_i_immediate_clear_lsb = 0,
};

pub const ControlTargetBinding = struct {
    algorithm: ControlTargetAlgorithm,
    immediate_bits: u8,
    encoding_alignment: u8,
    admitted_target_alignment: u8,
    program_address_bits: u8,
    source_access_ordinal: u8,
    destination_access_ordinal: u8,
};

pub const CANONICAL_CONTROL_TARGET = ControlTargetBinding{
    .algorithm = .program_authenticated_wrapping_rs1_plus_i_immediate_clear_lsb,
    .immediate_bits = 12,
    .encoding_alignment = 1,
    .admitted_target_alignment = isa_profile.instruction_alignment,
    .program_address_bits = isa_profile.program_commitment_address_bits,
    .source_access_ordinal = 1,
    .destination_access_ordinal = 2,
};

pub const DirectRecipe = enum(u8) {
    enabler_bit = 0,
    unaligned_target_lsb_bit = 1,
    immediate_sign_bit = 2,
    immediate_reconstruction = 3,
    target_reconstruction = 4,
    target_over_two_reconstruction = 5,
    addition_carry_0_bit = 6,
    addition_carry_1_bit = 7,
    addition_carry_2_bit = 8,
    addition_carry_3_bit = 9,
    link_pc_plus_four = 10,
    destination_nonzero_bit = 11,
    destination_zero_address = 12,
    destination_inverse = 13,
    destination_result_0 = 14,
    destination_result_1 = 15,
    destination_result_2 = 16,
    destination_result_3 = 17,
    source_read_only_0 = 18,
    source_read_only_1 = 19,
    source_read_only_2 = 20,
    source_read_only_3 = 21,
    active_placement = 22,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .enabler_bit,
    .unaligned_target_lsb_bit,
    .immediate_sign_bit,
    .immediate_reconstruction,
    .target_reconstruction,
    .target_over_two_reconstruction,
    .addition_carry_0_bit,
    .addition_carry_1_bit,
    .addition_carry_2_bit,
    .addition_carry_3_bit,
    .link_pc_plus_four,
    .destination_nonzero_bit,
    .destination_zero_address,
    .destination_inverse,
    .destination_result_0,
    .destination_result_1,
    .destination_result_2,
    .destination_result_3,
    .source_read_only_0,
    .source_read_only_1,
    .source_read_only_2,
    .source_read_only_3,
    .active_placement,
};

pub const LookupRecipe = enum(u8) {
    program_fetch = 0,
    source_consume = 1,
    source_emit = 2,
    source_clock_gap = 3,
    source_middle_range = 4,
    source_outer_range = 5,
    target_word_low_range = 6,
    target_word_high_range = 7,
    target_middle_range = 8,
    target_outer_range = 9,
    immediate_range = 10,
    state_consume = 11,
    state_emit = 12,
    result_middle_range = 13,
    result_outer_range = 14,
    destination_consume = 15,
    destination_emit = 16,
    destination_clock_gap = 17,
};

pub const LookupDescriptor = struct {
    recipe: LookupRecipe,
    domain: entry.Domain,
    role: entry.EventRole,
    arity: u8,
    access_ordinal: ?u8,
};

pub const CANONICAL_LOOKUP_RECIPE = [LOOKUP_COUNT]LookupDescriptor{
    .{ .recipe = .program_fetch, .domain = .program_access, .role = .request, .arity = 5, .access_ordinal = null },
    .{ .recipe = .source_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .recipe = .source_middle_range, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .source_outer_range, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .target_word_low_range, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = null },
    .{ .recipe = .target_word_high_range, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .target_middle_range, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .target_outer_range, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .immediate_range, .domain = .range_check_8_8_4, .role = .request, .arity = 3, .access_ordinal = null },
    .{ .recipe = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2, .access_ordinal = null },
    .{ .recipe = .state_emit, .domain = .registers_state, .role = .emit, .arity = 2, .access_ordinal = null },
    .{ .recipe = .result_middle_range, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .result_outer_range, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_id: u32,
    semantic_digest: digest.Digest,
    witness_binding_digest: digest.Digest,
    main_column_count: u16,
    execution: ExecutionRecipe,
    control_target: ControlTargetBinding,
    direct: [DIRECT_CONSTRAINT_COUNT]DirectRecipe,
    lookups: [LOOKUP_COUNT]LookupDescriptor,
    lookup_batch_size: u8,

    pub fn canonical(
        definition: *const typed_jalr.Definition,
    ) witness.ConstructionError!Binding {
        const physical = witness.WitnessBinding.canonical(definition);
        const physical_digest = physical.identityDigest();
        if (!std.mem.eql(u8, &physical_digest, &witness.WITNESS_BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return CANONICAL_BINDING;
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(AUTHORITY_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hashInt(&hash, u32, self.opcode_id);
        hash.update(&self.semantic_digest);
        hash.update(&self.witness_binding_digest);
        hashInt(&hash, u16, self.main_column_count);
        hashInt(&hash, u8, @intFromEnum(self.execution));
        hashInt(&hash, u8, @intFromEnum(self.control_target.algorithm));
        hashInt(&hash, u8, self.control_target.immediate_bits);
        hashInt(&hash, u8, self.control_target.encoding_alignment);
        hashInt(&hash, u8, self.control_target.admitted_target_alignment);
        hashInt(&hash, u8, self.control_target.program_address_bits);
        hashInt(&hash, u8, self.control_target.source_access_ordinal);
        hashInt(&hash, u8, self.control_target.destination_access_ordinal);
        hashInt(&hash, u16, self.direct.len);
        for (self.direct) |recipe|
            hashInt(&hash, u8, @intFromEnum(recipe));
        hashInt(&hash, u16, self.lookups.len);
        for (self.lookups) |lookup| {
            hashInt(&hash, u8, @intFromEnum(lookup.recipe));
            hashInt(&hash, u8, @intFromEnum(lookup.domain));
            hashInt(&hash, u8, @intFromEnum(lookup.role));
            hashInt(&hash, u8, lookup.arity);
            hashInt(&hash, u8, @intFromBool(lookup.access_ordinal != null));
            hashInt(&hash, u8, lookup.access_ordinal orelse 0);
        }
        hashInt(&hash, u8, self.lookup_batch_size);
        return hash.finalResult();
    }
};

pub const CANONICAL_BINDING = Binding{
    .format_version = AUTHORITY_BINDING_FORMAT_VERSION,
    .semantic_format_version = digest.program_control_target_format_version,
    .opcode_id = OPCODE_ID,
    .semantic_digest = typed_jalr.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .rs1_plus_i_immediate_clear_lsb_link_write_x0_discard,
    .control_target = CANONICAL_CONTROL_TARGET,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{
    InvalidAuthorityBinding,
};

pub const ExecutionError = error{
    InvalidJalrImmediate,
    JumpTargetOutOfRange,
    MisalignedJumpTarget,
    MisalignedProgramCounter,
    ProgramCounterOutOfRange,
    WrongJalrOpcode,
};

pub const Retirement = struct {
    rd: u5,
    write_enabled: bool,
    attempted_value: u32,
    visible_value: u32,
    next_pc: u32,
    branch_taken: bool,
};

inline fn canonicalRetirement(
    instruction: DecodedInst,
    pc_before: u32,
    rs1_value: u32,
) ExecutionError!Retirement {
    if (instruction.opcode != .JALR) return error.WrongJalrOpcode;
    if (instruction.imm < -2048 or instruction.imm > 2047)
        return error.InvalidJalrImmediate;
    isa_profile.requireProgramWordAddress(pc_before) catch |err| return switch (err) {
        error.MisalignedProgramWord => error.MisalignedProgramCounter,
        error.ProgramAddressOutOfRange => error.ProgramCounterOutOfRange,
    };
    const unaligned = rs1_value +% @as(u32, @bitCast(instruction.imm));
    const target = unaligned & ~@as(u32, 1);
    isa_profile.requireProgramWordAddress(target) catch |err| return switch (err) {
        error.MisalignedProgramWord => error.MisalignedJumpTarget,
        error.ProgramAddressOutOfRange => error.JumpTargetOutOfRange,
    };
    const link = pc_before +% 4;
    const write_enabled = instruction.rd != 0;
    return .{
        .rd = instruction.rd,
        .write_enabled = write_enabled,
        .attempted_value = link,
        .visible_value = if (write_enabled) link else 0,
        .next_pc = target,
        .branch_taken = target != link,
    };
}

pub inline fn acceptsRetirement(
    instruction: DecodedInst,
    pc_before: u32,
    rs1_value: u32,
    visible_value: u32,
    next_pc: u32,
    branch_taken: bool,
) bool {
    const expected = canonicalRetirement(
        instruction,
        pc_before,
        rs1_value,
    ) catch return false;
    return visible_value == expected.visible_value and
        next_pc == expected.next_pc and
        branch_taken == expected.branch_taken;
}

pub const Authority = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_jalr.Definition,
        supplied: *const Binding,
    ) ConstructionError!Authority {
        try definition.validate();
        try validateBinding(definition, supplied);
        const physical = witness.WitnessBinding.canonical(definition);
        _ = try witness.Executor.init(definition, &physical);
        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &AUTHORITY_BINDING_DIGEST))
            return error.InvalidAuthorityBinding;
        return .{ .binding = owned, .binding_digest = binding_digest };
    }

    pub inline fn pinned() Authority {
        return .{
            .binding = CANONICAL_BINDING,
            .binding_digest = AUTHORITY_BINDING_DIGEST,
        };
    }

    pub fn identitySnapshot(self: *const Authority) Binding {
        return self.binding;
    }

    pub fn identityDigest(self: *const Authority) digest.Digest {
        return self.binding_digest;
    }

    pub inline fn retire(
        _: *const Authority,
        instruction: DecodedInst,
        pc_before: u32,
        rs1_value: u32,
    ) ExecutionError!Retirement {
        return canonicalRetirement(instruction, pc_before, rs1_value);
    }

    pub fn generateMainInto(
        self: *const Authority,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        rows: []const TraceRow,
        log_size: u32,
    ) direct_witness_executor.Error!void {
        return direct_witness_executor.generateMainInto(
            M31,
            TraceRow,
            MAIN_COLUMN_COUNT,
            columns,
            rows,
            log_size,
            M31.zero(),
            self,
            validateTraceRow,
            writeActiveRowUnchecked,
        );
    }

    pub inline fn writeActiveRow(
        _: *const Authority,
        columns: anytype,
        row_index: usize,
        row: TraceRow,
    ) void {
        std.debug.assert(validTraceRow(row));
        writeActiveRowUnchecked(columns, row_index, row);
    }

    pub fn buildProgram(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        pc_polynomial: S,
        is_active: S,
    ) !Evaluator(S).ConstraintProgram {
        return Evaluator(S).build(columns, pc_polynomial, is_active);
    }

    pub fn evaluateDirect(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        pc_polynomial: S,
        is_active: S,
    ) !Evaluator(S).DirectConstraints {
        return Evaluator(S).direct(columns, pc_polynomial, is_active);
    }

    pub fn buildLookupsInto(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        result: *entry.Builder(S).List,
    ) !void {
        return Evaluator(S).lookupsInto(columns, result);
    }
};

pub fn Evaluator(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const e = entry.Builder(S);

        pub const DirectConstraints = struct {
            values: [DIRECT_CONSTRAINT_COUNT]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value| if (!value.isZero()) return false;
                return true;
            }
        };

        pub const ConstraintProgram = struct {
            active_row: S,
            direct_constraints: DirectConstraints,
            lookup_entries: e.List,
        };

        pub const Row = struct {
            enabler: S,
            clock: S,
            pc: S,
            rd: ops.Access,
            rs1: ops.Access,
            to_pc_over_two: S,
            to_pc_lsb: S,
            imm_felt: S,
            result: [4]S,
            destination: ops.Destination,
            target_word_low_20: S,
            target_word_high_8: S,
            target_limbs: [4]S,
            imm_byte_0: S,
            imm_nibble: S,
            imm_sign: S,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ops.accessFromColumns(columns[3..13]),
                    .rs1 = ops.accessFromColumns(columns[13..23]),
                    .to_pc_over_two = columns[23],
                    .to_pc_lsb = columns[24],
                    .imm_felt = columns[25],
                    .result = columns[26..30].*,
                    .destination = ops.destinationFromColumns(columns[30..32]),
                    .target_word_low_20 = columns[32],
                    .target_word_high_8 = columns[33],
                    .target_limbs = columns[34..38].*,
                    .imm_byte_0 = columns[38],
                    .imm_nibble = columns[39],
                    .imm_sign = columns[40],
                };
            }
        };

        pub fn direct(
            columns: []const S,
            pc_polynomial: S,
            is_active: S,
        ) !DirectConstraints {
            return directRow(
                try Row.fromMainColumns(columns),
                pc_polynomial,
                is_active,
            );
        }

        pub fn build(
            columns: []const S,
            pc_polynomial: S,
            is_active: S,
        ) !ConstraintProgram {
            const row = try Row.fromMainColumns(columns);
            const direct_constraints = directRow(
                row,
                pc_polynomial,
                is_active,
            );
            var lookup_entries: e.List = undefined;
            lookupsRowInto(row, &lookup_entries);
            return .{
                .active_row = row.enabler,
                .direct_constraints = direct_constraints,
                .lookup_entries = lookup_entries,
            };
        }

        inline fn targetWord(row: Row) S {
            return row.target_word_low_20.add(
                row.target_word_high_8.mul(ops.q(@as(u32, 1) << 20)),
            );
        }

        inline fn jumpTarget(row: Row) S {
            return ops.q(4).mul(targetWord(row));
        }

        pub fn directRow(
            row: Row,
            pc_polynomial: S,
            is_active: S,
        ) DirectConstraints {
            // The fixed twenty-three-root recipe is intentionally unrolled.
            // Symbolic and compile-time geometry instantiations need a larger
            // analysis allowance; emitted native evaluation remains unchanged.
            @setEvalBranchQuota(100_000);
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            var index: usize = 0;
            out[index] = ops.bit(row.enabler);
            index += 1;
            out[index] = ops.bit(row.to_pc_lsb);
            index += 1;
            out[index] = ops.bit(row.imm_sign);
            index += 1;
            out[index] = row.imm_byte_0
                .add(row.imm_nibble.mul(ops.q(256)))
                .sub(row.imm_sign.mul(ops.q(4096)))
                .sub(row.imm_felt);
            index += 1;
            out[index] = ops.composeU32(row.target_limbs).sub(jumpTarget(row));
            index += 1;
            out[index] = row.to_pc_over_two.sub(targetWord(row).mul(ops.q(2)));
            index += 1;

            const immediate = [4]S{
                row.imm_byte_0,
                row.imm_nibble.add(row.imm_sign.mul(ops.q(240))),
                row.imm_sign.mul(ops.q(255)),
                row.imm_sign.mul(ops.q(255)),
            };
            var carry = S.zero();
            inline for (0..4) |limb| {
                const result_limb = row.target_limbs[limb].add(
                    if (limb == 0) row.to_pc_lsb else S.zero(),
                );
                carry = row.rs1.next[limb]
                    .add(immediate[limb])
                    .add(carry)
                    .sub(result_limb)
                    .mul(ops.INV_BYTE_RADIX());
                out[index] = ops.bit(carry);
                index += 1;
            }

            out[index] = row.enabler.mul(
                ops.composeU32(row.result).sub(pc_polynomial.add(ops.q(4))),
            );
            index += 1;
            inline for (ops.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            inline for (ops.destinationResultConstraints(row.rd, row.result, row.destination)) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            inline for (ops.readOnlyAccessConstraints(row.rs1, row.enabler)) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            out[index] = row.enabler.sub(is_active);
            index += 1;
            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        pub fn lookupsInto(columns: []const S, result: *e.List) !void {
            lookupsRowInto(try Row.fromMainColumns(columns), result);
        }

        fn lookupsRowInto(row: Row, result: *e.List) void {
            const active = row.enabler;
            const negative_active = active.neg();
            const zero = S.zero();
            const one = S.one();
            const four = ops.q(4);
            const source_clock = row.clock.sub(one).mul(four).add(one);
            // Spell the second access clock from the instruction clock, as the
            // authored AccessSchedule does. This preserves the exact symbolic
            // DAG identity in addition to field-value equivalence.
            const destination_clock = row.clock.sub(one).mul(four).add(ops.q(2));
            const source_gap = source_clock.sub(row.rs1.previous_clock).sub(one);
            const destination_gap = destination_clock
                .sub(row.rd.previous_clock).sub(one);
            const target = jumpTarget(row);
            const next_clock = row.clock.add(one);
            const immediate_high = row.imm_nibble
                .sub(row.imm_sign.mul(ops.q(8)))
                .mul(ops.q(2));

            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, negative_active, .{
                row.pc, ops.q(OPCODE_ID), row.rd.addr, row.rs1.addr, row.imm_felt,
            });
            appendLookup(result, 1, negative_active, .{
                zero,                row.rs1.addr,        row.rs1.previous_clock,
                row.rs1.previous[0], row.rs1.previous[1], row.rs1.previous[2],
                row.rs1.previous[3],
            });
            appendLookup(result, 2, active, .{
                zero,            row.rs1.addr,    source_clock,
                row.rs1.next[0], row.rs1.next[1], row.rs1.next[2],
                row.rs1.next[3],
            });
            appendLookup(result, 3, negative_active, .{source_gap});
            appendLookup(result, 4, negative_active, .{
                row.rs1.next[1], row.rs1.next[2],
            });
            appendLookup(result, 5, negative_active, .{
                row.rs1.next[0], row.rs1.next[3],
            });
            appendLookup(result, 6, negative_active, .{row.target_word_low_20});
            appendLookup(result, 7, negative_active, .{
                row.target_word_high_8, zero,
            });
            appendLookup(result, 8, negative_active, .{
                row.target_limbs[1], row.target_limbs[2],
            });
            appendLookup(result, 9, negative_active, .{
                row.target_limbs[0], row.target_limbs[3],
            });
            appendLookup(result, 10, negative_active, .{
                row.imm_byte_0, zero, immediate_high,
            });
            appendLookup(result, 11, negative_active, .{ row.pc, row.clock });
            appendLookup(result, 12, active, .{ target, next_clock });
            appendLookup(result, 13, negative_active, .{
                row.result[1], row.result[2],
            });
            appendLookup(result, 14, negative_active, .{
                row.result[0], row.result[3],
            });
            appendLookup(result, 15, negative_active, .{
                zero,               row.rd.addr,        row.rd.previous_clock,
                row.rd.previous[0], row.rd.previous[1], row.rd.previous[2],
                row.rd.previous[3],
            });
            appendLookup(result, 16, active, .{
                zero,           row.rd.addr,    destination_clock,
                row.rd.next[0], row.rd.next[1], row.rd.next[2],
                row.rd.next[3],
            });
            appendLookup(result, 17, negative_active, .{destination_gap});
            std.debug.assert(result.len == LOOKUP_COUNT);
        }

        inline fn appendLookup(
            result: *e.List,
            comptime index: usize,
            numerator: S,
            values: anytype,
        ) void {
            const descriptor = CANONICAL_LOOKUP_RECIPE[index];
            comptime if (@intFromEnum(descriptor.recipe) != index or
                descriptor.arity != values.len)
            {
                @compileError("typed JALR fixed lookup append drifted");
            };
            const target = &result.entries[index];
            target.* = .{
                .domain = descriptor.domain,
                .numerator = numerator,
                .arity = descriptor.arity,
                .role = descriptor.role,
                .access_ordinal = descriptor.access_ordinal,
            };
            inline for (values, 0..) |value, value_index|
                target.values[value_index] = value;
            result.len = index + 1;
        }
    };
}

fn validateBinding(
    definition: *const typed_jalr.Definition,
    supplied: *const Binding,
) ConstructionError!void {
    const canonical = try Binding.canonical(definition);
    if (!std.meta.eql(canonical, supplied.*))
        return error.InvalidAuthorityBinding;

    const validated = lower_effects.ValidatedProgram.init(&definition.arena) catch
        return error.InvalidAuthorityBinding;
    inline for (CANONICAL_LOOKUP_RECIPE, 0..) |expected, index| {
        const effect_id = types.idFromIndex(types.EffectId, index) catch
            return error.InvalidAuthorityBinding;
        const actual = validated.event(effect_id) orelse
            return error.InvalidAuthorityBinding;
        const schema = relation.getById(actual.schema) orelse
            return error.InvalidAuthorityBinding;
        const expected_kind: program.EffectKind = switch (expected.recipe) {
            .program_fetch => .program_fetch,
            .source_consume, .source_emit, .source_clock_gap => .register_read,
            .state_consume => .state_consume,
            .state_emit => .state_produce,
            .destination_consume,
            .destination_emit,
            .destination_clock_gap,
            => .register_write,
            else => .range_request,
        };
        if (actual.kind != expected_kind or
            schema.domain != @as(relation.Domain, @enumFromInt(@intFromEnum(expected.domain))) or
            actual.role != @as(types.RelationRole, @enumFromInt(@intFromEnum(expected.role))) or
            actual.values.len != expected.arity or
            actual.access_ordinal != expected.access_ordinal or
            actual.liveness != definition.columns.enabler or
            actual.schema_version != schema.version)
        {
            return error.InvalidAuthorityBinding;
        }
    }
}

pub fn validateTraceRow(row: TraceRow) direct_witness_executor.Error!void {
    if (!validTraceRow(row)) return error.InvalidTraceRow;
}

inline fn writeActiveRowUnchecked(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    witness.writeActiveRow(columns, row_index, row);
}

inline fn validTraceRow(row: TraceRow) bool {
    if (!acceptsRetirement(
        .{
            .opcode = row.opcode,
            .rd = row.rd,
            .rs1 = row.rs1,
            .rs2 = row.rs2,
            .imm = row.imm,
        },
        row.pc,
        row.rs1_val,
        row.rd_val,
        row.next_pc,
        row.branch_taken,
    ) or row.clk == 0 or
        access_clock.maximum(row.clk) >= state_chain.CLOCK_PREV_BOUND or
        row.is_load or row.is_store or
        row.rs2_prev_clk != 0 or
        (row.rs1 == 0 and row.rs1_val != 0) or
        (row.rd == 0 and (row.rd_prev_val != 0 or row.rd_val != 0)))
    {
        return false;
    }
    const source_clock = access_clock.encode(row.clk, .first);
    const destination_clock = access_clock.encode(row.clk, .second);
    if (row.rs1_prev_clk >= source_clock or
        source_clock - row.rs1_prev_clk - 1 >= (@as(u32, 1) << 20))
    {
        return false;
    }
    if (row.rd == row.rs1) {
        return row.rd_prev_val == row.rs1_val and
            row.rd_prev_clk == source_clock;
    }
    return row.rd_prev_clk < destination_clock and
        destination_clock - row.rd_prev_clk - 1 < (@as(u32, 1) << 20);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    @setEvalBranchQuota(100_000);
    if (MAIN_COLUMN_COUNT != 41 or
        DIRECT_CONSTRAINT_COUNT != 23 or
        LOOKUP_COUNT != 18 or
        LOOKUP_BATCH_SIZE != 2)
    {
        @compileError("typed JALR fixed authority geometry drifted");
    }
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index| {
        if (@intFromEnum(recipe) != index)
            @compileError("typed JALR direct recipe is not canonical");
    }
    for (CANONICAL_LOOKUP_RECIPE, 0..) |lookup, index| {
        if (@intFromEnum(lookup.recipe) != index or
            lookup.arity != entry.expectedArity(lookup.domain))
        {
            @compileError("typed JALR lookup recipe is not canonical");
        }
    }
    if (CANONICAL_CONTROL_TARGET.admitted_target_alignment != 4 or
        CANONICAL_CONTROL_TARGET.program_address_bits != 30 or
        CANONICAL_CONTROL_TARGET.source_access_ordinal != 1 or
        CANONICAL_CONTROL_TARGET.destination_access_ordinal != 2)
    {
        @compileError("typed JALR target/access profile drifted");
    }
    if (@sizeOf(Authority) > 640)
        @compileError("typed JALR fixed authority exceeded its stack budget");
    const calculated_binding_digest = CANONICAL_BINDING.identityDigest();
    if (!std.mem.eql(
        u8,
        &calculated_binding_digest,
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed JALR canonical authority digest drifted");
}
