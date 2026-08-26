//! Fixed executable authority for native typed RV32 JAL.
//!
//! `typed_jal.zig` owns the authenticated semantic graph and
//! `typed_jal_witness.zig` owns its exact twenty-column physical recipe. This
//! facade binds those identities to one pointer-free executable capability for
//! architectural retirement, witness projection, direct roots, ordered
//! relations, and the program-authenticated jump target policy. Authored
//! arenas stay on the cold admission path; admitted row operations allocate
//! nothing and perform no string lookup or indirect semantic dispatch.

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
const typed_jal = @import("typed_jal.zig");
const witness = @import("typed_jal_witness.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_jal.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed_jal.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed_jal.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed_jal.LOOKUP_BATCH_SIZE;
pub const OPCODE_ID: u32 = typed_jal.OPCODE_ID;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/jal-fixed-authority/v1";

// Cold construction independently recomputes this complete binding identity
// before a capability can be admitted. The compile-time check at the end of
// this file prevents an unreviewed semantic, witness, target, or relation
// change from silently entering the pinned path.
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "5bbec19054a41de222c3e7bbad2e4ee900b5f7fe1fd62804b80aedff9bbe4aea";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = hexDigest(
    AUTHORITY_BINDING_DIGEST_HEX,
    "invalid typed JAL authority-binding digest",
);

pub const ExecutionRecipe = enum(u8) {
    pc_relative_jump_link_write_x0_discard = 0,
};

pub const ControlTargetAlgorithm = enum(u8) {
    program_authenticated_wrapping_pc_plus_j_immediate = 0,
};

/// Stable target policy which is not inferable from physical columns alone.
/// The immediate encoding permits two-byte granularity, while the selected
/// zkVM program commitment admits only four-byte-aligned word addresses.
pub const ControlTargetBinding = struct {
    algorithm: ControlTargetAlgorithm,
    immediate_bits: u8,
    encoding_low_zero_bits: u8,
    target_alignment: u8,
    program_address_bits: u8,
};

pub const CANONICAL_CONTROL_TARGET = ControlTargetBinding{
    .algorithm = .program_authenticated_wrapping_pc_plus_j_immediate,
    .immediate_bits = 21,
    .encoding_low_zero_bits = 1,
    .target_alignment = isa_profile.instruction_alignment,
    .program_address_bits = isa_profile.program_commitment_address_bits,
};

pub const DirectRecipe = enum(u8) {
    enabler_bit = 0,
    link_pc_plus_four = 1,
    destination_nonzero_bit = 2,
    destination_zero_address = 3,
    destination_inverse = 4,
    destination_result_0 = 5,
    destination_result_1 = 6,
    destination_result_2 = 7,
    destination_result_3 = 8,
    active_placement = 9,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .enabler_bit,
    .link_pc_plus_four,
    .destination_nonzero_bit,
    .destination_zero_address,
    .destination_inverse,
    .destination_result_0,
    .destination_result_1,
    .destination_result_2,
    .destination_result_3,
    .active_placement,
};

pub const LookupRecipe = enum(u8) {
    program_fetch = 0,
    state_consume = 1,
    state_emit = 2,
    result_middle_range = 3,
    result_outer_range = 4,
    destination_consume = 5,
    destination_emit = 6,
    destination_clock_gap = 7,
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
    .{ .recipe = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2, .access_ordinal = null },
    .{ .recipe = .state_emit, .domain = .registers_state, .role = .emit, .arity = 2, .access_ordinal = null },
    .{ .recipe = .result_middle_range, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .result_outer_range, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
};

/// Pointer-free identity of every executable surface owned by this facade.
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
        definition: *const typed_jal.Definition,
    ) witness.ConstructionError!Binding {
        const physical = try witness.WitnessBinding.canonical(definition);
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
        hashInt(&hash, u8, self.control_target.encoding_low_zero_bits);
        hashInt(&hash, u8, self.control_target.target_alignment);
        hashInt(&hash, u8, self.control_target.program_address_bits);
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
    .semantic_digest = typed_jal.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .pc_relative_jump_link_write_x0_discard,
    .control_target = CANONICAL_CONTROL_TARGET,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{
    InvalidAuthorityBinding,
};

pub const ExecutionError = error{
    InvalidJalImmediate,
    JumpTargetOutOfRange,
    MisalignedJumpTarget,
    MisalignedProgramCounter,
    ProgramCounterOutOfRange,
    WrongJalOpcode,
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
) ExecutionError!Retirement {
    if (instruction.opcode != .JAL) return error.WrongJalOpcode;
    if (instruction.imm < -1_048_576 or
        instruction.imm > 1_048_574 or
        (@as(u32, @bitCast(instruction.imm)) & 1) != 0)
    {
        return error.InvalidJalImmediate;
    }
    return retirementForAdmittedInstruction(instruction, pc_before);
}

inline fn retirementForAdmittedInstruction(
    instruction: DecodedInst,
    pc_before: u32,
) ExecutionError!Retirement {
    std.debug.assert(instruction.opcode == .JAL);
    std.debug.assert(instruction.imm >= -1_048_576);
    std.debug.assert(instruction.imm <= 1_048_574);
    std.debug.assert((@as(u32, @bitCast(instruction.imm)) & 1) == 0);
    isa_profile.requireProgramWordAddress(pc_before) catch |err| return switch (err) {
        error.MisalignedProgramWord => error.MisalignedProgramCounter,
        error.ProgramAddressOutOfRange => error.ProgramCounterOutOfRange,
    };
    const target = pc_before +% @as(u32, @bitCast(instruction.imm));
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
    visible_value: u32,
    next_pc: u32,
    branch_taken: bool,
) bool {
    const expected = canonicalRetirement(instruction, pc_before) catch return false;
    return visible_value == expected.visible_value and
        next_pc == expected.next_pc and
        branch_taken == expected.branch_taken;
}

/// Immutable executable capability. It owns no pointer, allocator, dynamic
/// dispatch table, or retained scratch and remains valid after the authored
/// arena is released.
pub const Authority = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_jal.Definition,
        supplied: *const Binding,
    ) ConstructionError!Authority {
        try definition.validate();
        try validateBinding(definition, supplied);
        const physical = try witness.WitnessBinding.canonical(definition);
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
    ) ExecutionError!Retirement {
        return canonicalRetirement(instruction, pc_before);
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

/// Generic scalar evaluator over the production QM31, base-field lifted, and
/// symbolic scalar contracts.
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
            imm_felt: S,
            result: [4]S,
            destination: ops.Destination,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ops.accessFromColumns(columns[3..13]),
                    .imm_felt = columns[13],
                    .result = columns[14..18].*,
                    .destination = ops.destinationFromColumns(columns[18..20]),
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

        pub fn directRow(
            row: Row,
            pc_polynomial: S,
            is_active: S,
        ) DirectConstraints {
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            out[0] = ops.bit(row.enabler);
            out[1] = row.enabler.mul(
                ops.composeU32(row.result).sub(pc_polynomial.add(ops.q(4))),
            );
            out[2] = ops.bit(row.destination.nonzero);
            out[3] = row.rd.addr.mul(S.one().sub(row.destination.nonzero));
            out[4] = row.rd.addr.mul(row.destination.inverse)
                .sub(row.destination.nonzero);
            inline for (0..4) |limb| {
                out[5 + limb] = row.rd.next[limb]
                    .sub(row.destination.nonzero.mul(row.result[limb]));
            }
            out[9] = row.enabler.sub(is_active);
            return .{ .values = out };
        }

        pub fn lookups(columns: []const S) !e.List {
            var result: e.List = undefined;
            try lookupsInto(columns, &result);
            return result;
        }

        pub fn lookupsInto(columns: []const S, result: *e.List) !void {
            lookupsRowInto(try Row.fromMainColumns(columns), result);
        }

        fn lookupsRowInto(row: Row, result: *e.List) void {
            const active = row.enabler;
            const negative_active = active.neg();
            const zero = S.zero();
            const one = S.one();
            const next_pc = row.pc.add(row.imm_felt);
            const next_clock = row.clock.add(one);
            const current_clock = row.clock.sub(one).mul(ops.q(4)).add(one);
            const destination_gap = current_clock
                .sub(row.rd.previous_clock).sub(one);

            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, negative_active, .{
                row.pc, ops.q(OPCODE_ID), row.rd.addr, row.imm_felt, zero,
            });
            appendLookup(result, 1, negative_active, .{ row.pc, row.clock });
            appendLookup(result, 2, active, .{ next_pc, next_clock });
            appendLookup(result, 3, negative_active, .{
                row.result[1], row.result[2],
            });
            appendLookup(result, 4, negative_active, .{
                row.result[0], row.result[3],
            });
            appendLookup(result, 5, negative_active, .{
                zero,
                row.rd.addr,
                row.rd.previous_clock,
                row.rd.previous[0],
                row.rd.previous[1],
                row.rd.previous[2],
                row.rd.previous[3],
            });
            appendLookup(result, 6, active, .{
                zero,
                row.rd.addr,
                current_clock,
                row.rd.next[0],
                row.rd.next[1],
                row.rd.next[2],
                row.rd.next[3],
            });
            appendLookup(result, 7, negative_active, .{destination_gap});
            std.debug.assert(result.len == LOOKUP_COUNT);
            std.debug.assert(result.batch_size == LOOKUP_BATCH_SIZE);
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
                @compileError("typed JAL fixed lookup append drifted");
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
    definition: *const typed_jal.Definition,
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
            .state_consume => .state_consume,
            .state_emit => .state_produce,
            .result_middle_range, .result_outer_range => .range_request,
            .destination_consume,
            .destination_emit,
            .destination_clock_gap,
            => .register_write,
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
        row.rd_val,
        row.next_pc,
        row.branch_taken,
    ) or row.clk == 0 or
        access_clock.maximum(row.clk) >= state_chain.CLOCK_PREV_BOUND or
        row.is_load or row.is_store or
        (row.rd == 0 and row.rd_prev_val != 0))
    {
        return false;
    }
    const current_clock = access_clock.encode(row.clk, .first);
    return row.rd_prev_clk < current_clock and
        current_clock - row.rd_prev_clk - 1 < (@as(u32, 1) << 20);
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
    if (MAIN_COLUMN_COUNT != 20 or
        DIRECT_CONSTRAINT_COUNT != 10 or
        LOOKUP_COUNT != 8 or
        LOOKUP_BATCH_SIZE != 2)
    {
        @compileError("typed JAL fixed authority geometry drifted");
    }
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index| {
        if (@intFromEnum(recipe) != index)
            @compileError("typed JAL direct recipe is not canonically ordered");
    }
    for (CANONICAL_LOOKUP_RECIPE, 0..) |lookup, index| {
        if (@intFromEnum(lookup.recipe) != index or
            lookup.arity != entry.expectedArity(lookup.domain))
        {
            @compileError("typed JAL lookup recipe is not canonical");
        }
    }
    if (CANONICAL_CONTROL_TARGET.target_alignment != 4 or
        CANONICAL_CONTROL_TARGET.program_address_bits != 30)
    {
        @compileError("typed JAL program-target profile drifted");
    }
    const calculated_binding_digest = CANONICAL_BINDING.identityDigest();
    if (!std.mem.eql(
        u8,
        &calculated_binding_digest,
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed JAL canonical authority digest drifted");
    if (@sizeOf(Authority) > 320)
        @compileError("typed JAL fixed authority exceeded its stack budget");
}
