//! Fixed executable authority for RV32 BASE_ALU_REG.
//!
//! One authenticated, pointer-free binding owns ADD, SUB, XOR, OR, and AND
//! architectural retirement, physical witness projection, direct roots, and
//! ordered lookup events. Cold construction authenticates the native typed
//! graph and complete witness recipe; hot execution retains neither arenas nor
//! allocators and performs no dynamic, textual, or callback dispatch.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const common = @import("../semantics/common.zig");
const read_access = @import("../semantics/read_access.zig");
const decode = @import("../../runner/decode.zig");
const trace_row = @import("../../runner/trace_row.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const typed = @import("typed_base_alu_reg.zig");
const witness = @import("typed_base_alu_reg_witness.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed.RELATION_EVENT_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed.RELATION_BATCH_SIZE;
pub const OPCODE_IDS = [5]u32{
    typed.ADD_OPCODE_ID,
    typed.SUB_OPCODE_ID,
    typed.XOR_OPCODE_ID,
    typed.OR_OPCODE_ID,
    typed.AND_OPCODE_ID,
};

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/base-alu-reg-fixed-authority/v1";

// Updated only through the binding-identity admission test. Keeping a literal
// receipt makes execution, root, lookup-order, or witness-geometry drift an
// explicit protocol review.
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "ab6f594fea12f5d296126f074f05d3540ca689df30367435ac775123b60302df";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed BASE_ALU_REG authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    rs1_rs2_write_x0_discard = 0,
};

pub const DirectRecipe = enum(u8) {
    active_bit = 0,
    add_bit = 1,
    sub_bit = 2,
    xor_bit = 3,
    or_bit = 4,
    and_bit = 5,
    add_carry_0 = 6,
    add_carry_1 = 7,
    add_carry_2 = 8,
    add_carry_3 = 9,
    sub_carry_0 = 10,
    sub_carry_1 = 11,
    sub_carry_2 = 12,
    sub_carry_3 = 13,
    destination_nonzero_bit = 14,
    destination_zero_address = 15,
    destination_inverse = 16,
    destination_result_0 = 17,
    destination_result_1 = 18,
    destination_result_2 = 19,
    destination_result_3 = 20,
    active_placement = 21,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .active_bit,
    .add_bit,
    .sub_bit,
    .xor_bit,
    .or_bit,
    .and_bit,
    .add_carry_0,
    .add_carry_1,
    .add_carry_2,
    .add_carry_3,
    .sub_carry_0,
    .sub_carry_1,
    .sub_carry_2,
    .sub_carry_3,
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
    source_1_consume = 3,
    source_1_emit = 4,
    source_1_clock_gap = 5,
    source_2_consume = 6,
    source_2_emit = 7,
    source_2_clock_gap = 8,
    bitwise_0 = 9,
    bitwise_1 = 10,
    bitwise_2 = 11,
    bitwise_3 = 12,
    result_range_low = 13,
    result_range_high = 14,
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
    .{ .recipe = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2, .access_ordinal = null },
    .{ .recipe = .state_emit, .domain = .registers_state, .role = .emit, .arity = 2, .access_ordinal = null },
    .{ .recipe = .source_1_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_1_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .recipe = .source_1_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .recipe = .source_2_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .source_2_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .recipe = .source_2_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
    .{ .recipe = .bitwise_0, .domain = .bitwise, .role = .request, .arity = 4, .access_ordinal = null },
    .{ .recipe = .bitwise_1, .domain = .bitwise, .role = .request, .arity = 4, .access_ordinal = null },
    .{ .recipe = .bitwise_2, .domain = .bitwise, .role = .request, .arity = 4, .access_ordinal = null },
    .{ .recipe = .bitwise_3, .domain = .bitwise, .role = .request, .arity = 4, .access_ordinal = null },
    .{ .recipe = .result_range_low, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .result_range_high, .domain = .range_check_8_8, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 3 },
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_ids: [5]u32,
    semantic_digest: digest.Digest,
    witness_binding_digest: digest.Digest,
    main_column_count: u16,
    execution: ExecutionRecipe,
    direct: [DIRECT_CONSTRAINT_COUNT]DirectRecipe,
    lookups: [LOOKUP_COUNT]LookupDescriptor,
    lookup_batch_size: u8,

    pub fn canonical(definition: *const typed.Definition) witness.ConstructionError!Binding {
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
        for (self.opcode_ids) |opcode_id| hashInt(&hash, u32, opcode_id);
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
    .semantic_format_version = digest.sequential_retirement_format_version,
    .opcode_ids = OPCODE_IDS,
    .semantic_digest = typed.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .rs1_rs2_write_x0_discard,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{InvalidAuthorityBinding};
pub const ExecutionError = error{ WrongBaseAluRegOpcode, InvalidImmediate };

pub const Retirement = struct {
    rd: u5,
    source_1_value: u32,
    source_2_value: u32,
    write_enabled: bool,
    attempted_value: u32,
    visible_value: u32,
};

pub inline fn isFamilyOpcode(opcode: decode.Opcode) bool {
    return switch (opcode) {
        .ADD, .SUB, .XOR, .OR, .AND => true,
        else => false,
    };
}

pub inline fn resultFor(opcode: decode.Opcode, source_1: u32, source_2: u32) u32 {
    return switch (opcode) {
        .ADD => source_1 +% source_2,
        .SUB => source_1 -% source_2,
        .XOR => source_1 ^ source_2,
        .OR => source_1 | source_2,
        .AND => source_1 & source_2,
        else => unreachable,
    };
}

inline fn canonicalRetirement(
    instruction: DecodedInst,
    source_1: u32,
    source_2: u32,
) Retirement {
    const attempted = resultFor(instruction.opcode, source_1, source_2);
    return .{
        .rd = instruction.rd,
        .source_1_value = source_1,
        .source_2_value = source_2,
        .write_enabled = instruction.rd != 0,
        .attempted_value = attempted,
        .visible_value = if (instruction.rd == 0) 0 else attempted,
    };
}

pub inline fn acceptsRetirement(
    instruction: DecodedInst,
    source_1: u32,
    source_2: u32,
    visible_value: u32,
) bool {
    if (!isFamilyOpcode(instruction.opcode) or instruction.imm != 0) return false;
    return visible_value == canonicalRetirement(
        instruction,
        source_1,
        source_2,
    ).visible_value;
}

pub const Authority = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed.Definition,
        supplied: *const Binding,
    ) ConstructionError!Authority {
        try definition.validate();
        const canonical = try Binding.canonical(definition);
        if (!std.meta.eql(canonical, supplied.*)) return error.InvalidAuthorityBinding;
        const physical = try witness.WitnessBinding.canonical(definition);
        _ = try witness.Executor.init(definition, &physical);
        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &AUTHORITY_BINDING_DIGEST))
            return error.InvalidAuthorityBinding;
        return .{ .binding = owned, .binding_digest = binding_digest };
    }

    pub inline fn pinned() Authority {
        return .{ .binding = CANONICAL_BINDING, .binding_digest = AUTHORITY_BINDING_DIGEST };
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
        source_1: u32,
        source_2: u32,
    ) ExecutionError!Retirement {
        if (!isFamilyOpcode(instruction.opcode)) return error.WrongBaseAluRegOpcode;
        if (instruction.imm != 0) return error.InvalidImmediate;
        return canonicalRetirement(instruction, source_1, source_2);
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

    pub inline fn evaluateDirect(
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

pub fn Evaluator(comptime S: type) type {
    return struct {
        const ops = common.Ops(S);
        const reads = read_access.Ops(S, ops.Access);
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
            clk: S,
            pc: S,
            rd: ops.Access,
            rs1: reads.ReadAccess,
            rs2: reads.ReadAccess,
            is_add: S,
            is_sub: S,
            is_xor: S,
            is_or: S,
            is_and: S,
            result: [4]S,
            destination: ops.Destination,

            pub inline fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .clk = columns[0],
                    .pc = columns[1],
                    .rd = ops.accessFromColumns(columns[2..12]),
                    .rs1 = reads.fromColumns(columns[12..18]),
                    .rs2 = reads.fromColumns(columns[18..24]),
                    .is_add = columns[24],
                    .is_sub = columns[25],
                    .is_xor = columns[26],
                    .is_or = columns[27],
                    .is_and = columns[28],
                    .result = columns[29..33].*,
                    .destination = ops.destinationFromColumns(columns[33..35]),
                };
            }

            pub inline fn active(self: Row) S {
                return self.is_add.add(self.is_sub).add(self.is_xor)
                    .add(self.is_or).add(self.is_and);
            }
        };

        pub inline fn direct(columns: []const S, is_active: S) !DirectConstraints {
            return directRow(try Row.fromMainColumns(columns), is_active);
        }

        pub fn build(columns: []const S, is_active: S) !ConstraintProgram {
            const row = try Row.fromMainColumns(columns);
            const direct_constraints = directRow(row, is_active);
            var lookup_entries: e.List = undefined;
            lookupsRowInto(row, &lookup_entries);
            return .{
                .active_row = row.active(),
                .direct_constraints = direct_constraints,
                .lookup_entries = lookup_entries,
            };
        }

        pub inline fn directRow(row: Row, is_active: S) DirectConstraints {
            @setEvalBranchQuota(10_000);
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            var index: usize = 0;
            const active = row.active();
            out[index] = ops.bit(active);
            index += 1;
            inline for (.{ row.is_add, row.is_sub, row.is_xor, row.is_or, row.is_and }) |flag| {
                out[index] = ops.bit(flag);
                index += 1;
            }
            var carry = S.zero();
            inline for (0..4) |limb| {
                const numerator = row.rs1.value[limb].add(row.rs2.value[limb])
                    .add(carry).sub(row.result[limb]);
                carry = numerator.mul(ops.INV_BYTE_RADIX());
                out[index] = ops.selected(row.is_add, ops.bit(carry));
                index += 1;
            }
            carry = S.zero();
            inline for (0..4) |limb| {
                const numerator = row.result[limb].add(row.rs2.value[limb])
                    .add(carry).sub(row.rs1.value[limb]);
                carry = numerator.mul(ops.INV_BYTE_RADIX());
                out[index] = ops.selected(row.is_sub, ops.bit(carry));
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
            out[index] = active.sub(is_active);
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
            const active = row.active();
            const negative_active = active.neg();
            const bitwise_active = row.is_xor.add(row.is_or).add(row.is_and);
            const negative_bitwise = bitwise_active.neg();
            const zero = S.zero();
            const one = S.one();
            const four = ops.q(4);
            const source_1_clock = row.clk.sub(one).mul(four).add(one);
            const source_2_clock = row.clk.sub(one).mul(four).add(ops.q(2));
            const destination_clock = row.clk.sub(one).mul(four).add(ops.q(3));
            const source_1_gap = source_1_clock.sub(row.rs1.previous_clock).sub(one);
            const source_2_gap = source_2_clock.sub(row.rs2.previous_clock).sub(one);
            const destination_gap = destination_clock.sub(row.rd.previous_clock).sub(one);
            const opcode = row.is_add.mul(ops.q(OPCODE_IDS[0]))
                .add(row.is_sub.mul(ops.q(OPCODE_IDS[1])))
                .add(row.is_xor.mul(ops.q(OPCODE_IDS[2])))
                .add(row.is_or.mul(ops.q(OPCODE_IDS[3])))
                .add(row.is_and.mul(ops.q(OPCODE_IDS[4])));
            const operation_id = row.is_xor.mul(ops.q(2)).add(row.is_or);
            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, negative_active, .{
                row.pc, opcode, row.rd.addr, row.rs1.addr, row.rs2.addr,
            });
            appendLookup(result, 1, negative_active, .{ row.pc, row.clk });
            appendLookup(result, 2, active, .{ row.pc.add(four), row.clk.add(one) });
            appendLookup(result, 3, negative_active, .{
                zero,             row.rs1.addr,     row.rs1.previous_clock,
                row.rs1.value[0], row.rs1.value[1], row.rs1.value[2],
                row.rs1.value[3],
            });
            appendLookup(result, 4, active, .{
                zero,             row.rs1.addr,     source_1_clock,
                row.rs1.value[0], row.rs1.value[1], row.rs1.value[2],
                row.rs1.value[3],
            });
            appendLookup(result, 5, negative_active, .{source_1_gap});
            appendLookup(result, 6, negative_active, .{
                zero,             row.rs2.addr,     row.rs2.previous_clock,
                row.rs2.value[0], row.rs2.value[1], row.rs2.value[2],
                row.rs2.value[3],
            });
            appendLookup(result, 7, active, .{
                zero,             row.rs2.addr,     source_2_clock,
                row.rs2.value[0], row.rs2.value[1], row.rs2.value[2],
                row.rs2.value[3],
            });
            appendLookup(result, 8, negative_active, .{source_2_gap});
            inline for (0..4) |limb| appendLookup(result, 9 + limb, negative_bitwise, .{
                row.rs1.value[limb], row.rs2.value[limb], row.result[limb], operation_id,
            });
            appendLookup(result, 13, negative_active, .{ row.result[0], row.result[1] });
            appendLookup(result, 14, negative_active, .{ row.result[2], row.result[3] });
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
                @compileError("typed BASE_ALU_REG fixed lookup append drifted");
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

pub fn validateTraceRow(row: TraceRow) direct_witness_executor.Error!void {
    if (!validTraceRow(row)) return error.InvalidTraceRow;
}

inline fn writeActiveRowUnchecked(columns: anytype, row_index: usize, row: TraceRow) void {
    witness.writeActiveRow(columns, row_index, row);
}

inline fn validTraceRow(row: TraceRow) bool {
    if (!isFamilyOpcode(row.opcode) or row.imm != 0 or row.clk == 0 or
        row.next_pc != row.pc +% 4 or row.is_load or row.is_store or
        row.branch_taken)
    {
        return false;
    }
    const source_1_clock = accessClock(row.clk, 1) orelse return false;
    const source_2_clock = accessClock(row.clk, 2) orelse return false;
    const destination_clock = accessClock(row.clk, 3) orelse return false;
    if (!validGap(row.rs1_prev_clk, source_1_clock) or
        !validGap(row.rs2_prev_clk, source_2_clock) or
        !validGap(row.rd_prev_clk, destination_clock)) return false;
    if ((row.rs1 == 0 and row.rs1_val != 0) or
        (row.rs2 == 0 and row.rs2_val != 0) or
        (row.rd == 0 and row.rd_prev_val != 0) or
        (row.rs1 == row.rs2 and
            (row.rs1_val != row.rs2_val or row.rs2_prev_clk != source_1_clock)))
    {
        return false;
    }
    const expected_previous_clock = if (row.rd == row.rs2)
        source_2_clock
    else if (row.rd == row.rs1)
        source_1_clock
    else
        row.rd_prev_clk;
    const expected_previous_value = if (row.rd == row.rs2)
        row.rs2_val
    else if (row.rd == row.rs1)
        row.rs1_val
    else
        row.rd_prev_val;
    if ((row.rd == row.rs1 or row.rd == row.rs2) and
        (row.rd_prev_clk != expected_previous_clock or
            row.rd_prev_val != expected_previous_value))
    {
        return false;
    }
    const expected = resultFor(row.opcode, row.rs1_val, row.rs2_val);
    return row.rd_val == (if (row.rd == 0) 0 else expected);
}

inline fn accessClock(clock: u32, phase: u32) ?u32 {
    if (clock == 0 or phase == 0 or phase > 3) return null;
    return std.math.cast(u32, (@as(u64, clock) - 1) * 4 + phase);
}

inline fn validGap(previous: u32, current: u32) bool {
    return previous < current and current - previous - 1 < (@as(u32, 1) << 20);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    @setEvalBranchQuota(20_000);
    if (!std.mem.eql(
        u8,
        &CANONICAL_BINDING.identityDigest(),
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed BASE_ALU_REG canonical authority digest drifted");
}
