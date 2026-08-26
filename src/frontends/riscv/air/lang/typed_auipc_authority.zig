//! Fixed executable authority for native typed RV32 AUIPC.
//!
//! `typed_auipc.zig` owns the authenticated semantic graph and
//! `typed_auipc_witness.zig` owns its exact 29-column physical recipe. This
//! facade binds those identities to one pointer-free executable capability for
//! architectural retirement, witness projection, direct roots, ordered
//! relations, and formal/runtime export. Compiler arenas and validation remain
//! cold; admitted row operations allocate nothing and perform no string or
//! indirect semantic dispatch.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const common = @import("../semantics/common.zig");
const decode = @import("../../runner/decode.zig");
const trace_row = @import("../../runner/trace_row.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const lower_effects = @import("lower_effects.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const typed_auipc = @import("typed_auipc.zig");
const witness = @import("typed_auipc_witness.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_auipc.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed_auipc.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed_auipc.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = 2;
pub const OPCODE_ID: u32 = typed_auipc.OPCODE_ID;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/auipc-fixed-authority/v1";

// This literal is replaced only after the cold binding test independently
// reconstructs the complete semantic/witness/execution/direct/relation
// identity. A zero pin deliberately prevents accidental production admission.
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "a3c2cdfaab6b4e469c60ee7c06e2fdfebbec91ce1ce0a498fee83b9a25ca0ce7";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed AUIPC authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    pc_plus_u_immediate_write_x0_discard = 0,
};

/// Stable numeric direct-root recipes in production order.
pub const DirectRecipe = enum(u8) {
    enabler_bit = 0,
    pc_decomposition = 1,
    immediate_decomposition = 2,
    immediate_sign_bit = 3,
    immediate_low_zero = 4,
    carry_0_bit = 5,
    carry_1_bit = 6,
    carry_2_bit = 7,
    carry_3_bit = 8,
    destination_nonzero_bit = 9,
    destination_zero_address = 10,
    destination_inverse = 11,
    destination_result_0 = 12,
    destination_result_1 = 13,
    destination_result_2 = 14,
    destination_result_3 = 15,
    active_placement = 16,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .enabler_bit,
    .pc_decomposition,
    .immediate_decomposition,
    .immediate_sign_bit,
    .immediate_low_zero,
    .carry_0_bit,
    .carry_1_bit,
    .carry_2_bit,
    .carry_3_bit,
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
    result_range_low = 3,
    result_range_high = 4,
    pc_range_middle = 5,
    pc_range_outer = 6,
    immediate_range_middle = 7,
    immediate_range_outer = 8,
    destination_consume = 9,
    destination_emit = 10,
    destination_clock_gap = 11,
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
    .{ .recipe = .result_range_low, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .result_range_high, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .pc_range_middle, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .pc_range_outer, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .immediate_range_middle, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .immediate_range_outer, .domain = .range_check_m31, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_id: u32,
    semantic_digest: digest.Digest,
    witness_binding_digest: digest.Digest,
    main_column_count: u16,
    execution: ExecutionRecipe,
    direct: [DIRECT_CONSTRAINT_COUNT]DirectRecipe,
    lookups: [LOOKUP_COUNT]LookupDescriptor,
    lookup_batch_size: u8,

    pub fn canonical(
        definition: *const typed_auipc.Definition,
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
        hashInt(&hash, u16, self.direct.len);
        for (self.direct) |recipe| hashInt(&hash, u8, @intFromEnum(recipe));
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
    .semantic_format_version = digest.range_refinement_format_version,
    .opcode_id = OPCODE_ID,
    .semantic_digest = typed_auipc.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .pc_plus_u_immediate_write_x0_discard,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{
    InvalidAuthorityBinding,
};
pub const ExecutionError = error{
    WrongAuipcOpcode,
    InvalidAuipcImmediate,
    ProgramCounterOutOfRange,
};

pub const Retirement = struct {
    rd: u5,
    write_enabled: bool,
    attempted_value: u32,
    visible_value: u32,
    next_pc: u32,
};

inline fn canonicalRetirement(
    instruction: DecodedInst,
    pc_before: u32,
) Retirement {
    std.debug.assert(instruction.opcode == .AUIPC);
    const immediate: u32 = @bitCast(instruction.imm);
    const attempted = pc_before +% immediate;
    const write_enabled = instruction.rd != 0;
    return .{
        .rd = instruction.rd,
        .write_enabled = write_enabled,
        .attempted_value = attempted,
        .visible_value = if (write_enabled) attempted else 0,
        .next_pc = pc_before +% 4,
    };
}

pub inline fn acceptsRetirement(
    instruction: DecodedInst,
    pc_before: u32,
    visible_value: u32,
    next_pc: u32,
) bool {
    const immediate: u32 = @bitCast(instruction.imm);
    if (instruction.opcode != .AUIPC or
        immediate & 0xfff != 0 or
        pc_before >= (@as(u32, 1) << 30))
    {
        return false;
    }
    const expected = canonicalRetirement(instruction, pc_before);
    return visible_value == expected.visible_value and
        next_pc == expected.next_pc;
}

/// Immutable executable capability. It owns no pointer, allocator, dynamic
/// dispatch table, or retained scratch and remains valid after cold authored
/// graph validation releases its arena.
pub const Authority = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_auipc.Definition,
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
        if (instruction.opcode != .AUIPC) return error.WrongAuipcOpcode;
        const immediate: u32 = @bitCast(instruction.imm);
        if (immediate & 0xfff != 0) return error.InvalidAuipcImmediate;
        if (pc_before >= (@as(u32, 1) << 30))
            return error.ProgramCounterOutOfRange;
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
        is_active: S,
    ) !Evaluator(S).ConstraintProgram {
        return Evaluator(S).build(columns, is_active);
    }

    pub fn evaluateDirect(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        is_active: S,
    ) !Evaluator(S).DirectConstraints {
        return Evaluator(S).direct(columns, is_active);
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

/// Generic scalar evaluator over the same production contracts used by the
/// QM31 verifier, base-field lifted-domain prover, and symbolic extractor.
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
            pc_limbs: [4]S,
            imm_limbs: [4]S,
            imm_sign: S,

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
                    .pc_limbs = columns[20..24].*,
                    .imm_limbs = columns[24..28].*,
                    .imm_sign = columns[28],
                };
            }
        };

        pub fn direct(columns: []const S, is_active: S) !DirectConstraints {
            return directRow(try Row.fromMainColumns(columns), is_active);
        }

        pub fn build(columns: []const S, is_active: S) !ConstraintProgram {
            const row = try Row.fromMainColumns(columns);
            const direct_constraints = directRow(row, is_active);
            var lookup_entries: e.List = undefined;
            lookupsRowInto(row, &lookup_entries);
            return .{
                .active_row = row.enabler,
                .direct_constraints = direct_constraints,
                .lookup_entries = lookup_entries,
            };
        }

        pub fn directRow(row: Row, is_active: S) DirectConstraints {
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            var index: usize = 0;
            out[index] = ops.bit(row.enabler);
            index += 1;
            out[index] = ops.composeU32(row.pc_limbs).sub(row.pc);
            index += 1;
            out[index] = ops.composeU32(row.imm_limbs)
                .sub(row.imm_felt)
                .sub(row.imm_sign.mul(ops.q(2)));
            index += 1;
            out[index] = ops.bit(row.imm_sign);
            index += 1;
            out[index] = ops.selected(row.enabler, row.imm_limbs[0]);
            index += 1;
            var carry = S.zero();
            inline for (0..4) |limb| {
                const numerator = row.pc_limbs[limb]
                    .add(row.imm_limbs[limb])
                    .add(carry)
                    .sub(row.result[limb]);
                carry = numerator.mul(ops.INV_BYTE_RADIX());
                out[index] = ops.bit(carry);
                index += 1;
            }
            inline for (ops.destinationConstraints(row.rd.addr, row.destination)) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            inline for (ops.destinationResultConstraints(row.rd, row.result, row.destination)) |constraint| {
                out[index] = constraint;
                index += 1;
            }
            out[index] = row.enabler.sub(is_active);
            index += 1;
            std.debug.assert(index == out.len);
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
            const opcode = ops.q(OPCODE_ID);
            const zero = S.zero();
            const negative_active = active.neg();
            const one = S.one();
            const four = ops.q(4);
            const next_pc = row.pc.add(four);
            const next_clock = row.clock.add(one);
            const immediate_outer_high = row.imm_limbs[3]
                .sub(row.imm_sign.mul(ops.q(128)));
            const current_clock = row.clock.sub(one).mul(four).add(one);
            const destination_gap = current_clock
                .sub(row.rd.previous_clock).sub(one);

            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, negative_active, .{
                row.pc, opcode, row.rd.addr, row.imm_felt, zero,
            });
            appendLookup(result, 1, negative_active, .{ row.pc, row.clock });
            appendLookup(result, 2, active, .{ next_pc, next_clock });
            appendLookup(result, 3, negative_active, .{ row.result[0], row.result[1] });
            appendLookup(result, 4, negative_active, .{ row.result[2], row.result[3] });
            appendLookup(result, 5, negative_active, .{ row.pc_limbs[1], row.pc_limbs[2] });
            appendLookup(result, 6, negative_active, .{ row.pc_limbs[0], row.pc_limbs[3] });
            appendLookup(result, 7, negative_active, .{ row.imm_limbs[1], row.imm_limbs[2] });
            appendLookup(result, 8, negative_active, .{ row.imm_limbs[0], immediate_outer_high });
            appendLookup(result, 9, negative_active, .{
                zero,               row.rd.addr,        row.rd.previous_clock,
                row.rd.previous[0], row.rd.previous[1], row.rd.previous[2],
                row.rd.previous[3],
            });
            appendLookup(result, 10, active, .{
                zero,           row.rd.addr,    current_clock,
                row.rd.next[0], row.rd.next[1], row.rd.next[2],
                row.rd.next[3],
            });
            appendLookup(result, 11, negative_active, .{destination_gap});
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
                @compileError("typed AUIPC fixed lookup append drifted");
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
    definition: *const typed_auipc.Definition,
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
            .result_range_low,
            .result_range_high,
            .pc_range_middle,
            .pc_range_outer,
            .immediate_range_middle,
            .immediate_range_outer,
            => .range_request,
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
    const immediate: u32 = @bitCast(row.imm);
    const result = row.pc +% immediate;
    if (row.opcode != .AUIPC or
        immediate & 0xfff != 0 or
        row.pc >= (@as(u32, 1) << 30) or
        row.clk == 0 or
        row.next_pc != row.pc +% 4 or
        row.is_load or row.is_store or row.branch_taken or
        row.rd_val != (if (row.rd == 0) 0 else result) or
        (row.rd == 0 and (row.rd_prev_val != 0 or row.rd_prev_clk != 0)))
    {
        return false;
    }
    const current_clock = accessClock(row.clk) orelse return false;
    return row.rd_prev_clk < current_clock and
        current_clock - row.rd_prev_clk - 1 < (@as(u32, 1) << 20);
}

inline fn accessClock(clock: u32) ?u32 {
    if (clock == 0) return null;
    return std.math.cast(u32, (@as(u64, clock) - 1) * 4 + 1);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    @setEvalBranchQuota(100_000);
    if (MAIN_COLUMN_COUNT != 29 or
        DIRECT_CONSTRAINT_COUNT != 17 or
        LOOKUP_COUNT != 12 or
        LOOKUP_BATCH_SIZE != 2)
    {
        @compileError("typed AUIPC fixed authority geometry drifted");
    }
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index| {
        if (@intFromEnum(recipe) != index)
            @compileError("typed AUIPC direct recipe is not canonically ordered");
    }
    for (CANONICAL_LOOKUP_RECIPE, 0..) |lookup, index| {
        if (@intFromEnum(lookup.recipe) != index or
            lookup.arity != entry.expectedArity(lookup.domain))
        {
            @compileError("typed AUIPC lookup recipe is not canonical");
        }
    }
    const calculated_binding_digest = CANONICAL_BINDING.identityDigest();
    if (!std.mem.eql(
        u8,
        &calculated_binding_digest,
        &AUTHORITY_BINDING_DIGEST,
    )) {
        @compileError("typed AUIPC canonical authority digest drifted");
    }
    if (@sizeOf(Authority) > 320)
        @compileError("typed AUIPC fixed authority exceeded its stack budget");
}
