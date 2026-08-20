//! Fixed executable authority for RV32 `MUL`.
//!
//! Cold construction authenticates the native typed graph, its exact physical
//! witness projection, all seventeen direct roots, and all sixteen ordered
//! lookup events.  The retained capability is pointer-free.  Its hot paths
//! allocate nothing and perform no arena traversal, textual lookup, callback
//! dispatch, or runtime interpretation of the authored graph.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const entry = @import("../lookups/entry.zig");
const common = @import("../semantics/common.zig");
const decode = @import("../../runner/decode.zig");
const trace_row = @import("../../runner/trace_row.zig");
const digest = @import("digest.zig");
const direct_witness_executor = @import("direct_witness_executor.zig");
const typed = @import("typed_mul.zig");
const witness = @import("typed_mul_witness.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = typed.LOOKUP_BATCH_SIZE;
pub const OPCODE_ID: u32 = typed.OPCODE_ID;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/mul-fixed-authority/v1";
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "01799d3073a05cfb8ee7d9025dc98c4172a91c6d7cf6d3a1ce96eca000d315d8";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed MUL authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    low_word_product_write_x0_discard = 0,
    reserved = 255,
};

pub const DirectRecipe = enum(u8) {
    enabler_bit = 0,
    destination_nonzero_bit = 1,
    destination_zero_address = 2,
    destination_inverse = 3,
    destination_result_0 = 4,
    destination_result_1 = 5,
    destination_result_2 = 6,
    destination_result_3 = 7,
    source_1_read_only_0 = 8,
    source_1_read_only_1 = 9,
    source_1_read_only_2 = 10,
    source_1_read_only_3 = 11,
    source_2_read_only_0 = 12,
    source_2_read_only_1 = 13,
    source_2_read_only_2 = 14,
    source_2_read_only_3 = 15,
    active_placement = 16,
};

pub const CANONICAL_DIRECT_RECIPE: [DIRECT_CONSTRAINT_COUNT]DirectRecipe = blk: {
    var result: [DIRECT_CONSTRAINT_COUNT]DirectRecipe = undefined;
    for (&result, 0..) |*recipe, index| recipe.* = @enumFromInt(index);
    break :blk result;
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
    product_range_0 = 9,
    product_range_1 = 10,
    product_range_2 = 11,
    product_range_3 = 12,
    destination_consume = 13,
    destination_emit = 14,
    destination_clock_gap = 15,
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
    .{ .recipe = .product_range_0, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .product_range_1, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .product_range_2, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .product_range_3, .domain = .range_check_8_11, .role = .request, .arity = 2, .access_ordinal = null },
    .{ .recipe = .destination_consume, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_emit, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 3 },
    .{ .recipe = .destination_clock_gap, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 3 },
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

    pub fn canonical(definition: *const typed.Definition) witness.ConstructionError!Binding {
        const physical = witness.WitnessBinding.canonical(definition);
        const physical_digest = physical.identityDigest();
        if (!std.mem.eql(u8, &physical_digest, &witness.WITNESS_BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        _ = try witness.Executor.init(definition, &physical);
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
    .semantic_digest = typed.SEMANTIC_DIGEST,
    .witness_binding_digest = witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .low_word_product_write_x0_discard,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = witness.ConstructionError || error{InvalidAuthorityBinding};
pub const ExecutionError = error{ WrongMulOpcode, InvalidImmediate };

pub const Retirement = struct {
    rd: u5,
    source_1_value: u32,
    source_2_value: u32,
    write_enabled: bool,
    attempted_value: u32,
    visible_value: u32,
};

pub inline fn resultFor(source_1: u32, source_2: u32) u32 {
    return @truncate(@as(u64, source_1) *% @as(u64, source_2));
}

inline fn canonicalRetirement(
    instruction: DecodedInst,
    source_1: u32,
    source_2: u32,
) Retirement {
    const attempted = resultFor(source_1, source_2);
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
    if (instruction.opcode != .MUL or instruction.imm != 0) return false;
    return visible_value == canonicalRetirement(
        instruction,
        source_1,
        source_2,
    ).visible_value;
}

/// Authenticate the complete R-type encoding carried beside a decoded MUL.
/// Trace projection does not commit `inst_word`, so admitting a `TraceRow`
/// must reject metadata that could not have produced its decoded operands.
pub inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    if (instruction.opcode != .MUL or instruction.imm != 0) return false;
    const reconstructed = (@as(u32, 1) << 25) |
        (@as(u32, instruction.rs2) << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (@as(u32, instruction.rd) << 7) |
        0b0110011;
    return inst_word == reconstructed;
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
        if (instruction.opcode != .MUL) return error.WrongMulOpcode;
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
            rs2: ops.Access,
            result: [4]S,
            destination: ops.Destination,

            pub inline fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ops.accessFromColumns(columns[3..13]),
                    .rs1 = ops.accessFromColumns(columns[13..23]),
                    .rs2 = ops.accessFromColumns(columns[23..33]),
                    .result = columns[33..37].*,
                    .destination = ops.destinationFromColumns(columns[37..39]),
                };
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
                .active_row = row.enabler,
                .direct_constraints = direct_constraints,
                .lookup_entries = lookup_entries,
            };
        }

        pub inline fn deriveCarries(row: Row) [4]S {
            const lhs = row.rs1.next;
            const rhs = row.rs2.next;
            var carries: [4]S = undefined;
            carries[0] = lhs[0].mul(rhs[0]).sub(row.result[0])
                .mul(ops.INV_BYTE_RADIX());
            carries[1] = carries[0].add(lhs[1].mul(rhs[0]))
                .add(lhs[0].mul(rhs[1])).sub(row.result[1])
                .mul(ops.INV_BYTE_RADIX());
            carries[2] = carries[1].add(lhs[2].mul(rhs[0]))
                .add(lhs[1].mul(rhs[1])).add(lhs[0].mul(rhs[2]))
                .sub(row.result[2]).mul(ops.INV_BYTE_RADIX());
            carries[3] = carries[2].add(lhs[3].mul(rhs[0]))
                .add(lhs[2].mul(rhs[1])).add(lhs[1].mul(rhs[2]))
                .add(lhs[0].mul(rhs[3])).sub(row.result[3])
                .mul(ops.INV_BYTE_RADIX());
            return carries;
        }

        pub inline fn directRow(row: Row, is_active: S) DirectConstraints {
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            const one = S.one();
            out[0] = row.enabler.mul(one.sub(row.enabler));
            out[1] = row.destination.nonzero.mul(
                row.destination.nonzero.sub(one),
            );
            out[2] = row.rd.addr.mul(one.sub(row.destination.nonzero));
            out[3] = row.rd.addr.mul(row.destination.inverse)
                .sub(row.destination.nonzero);
            inline for (0..4) |limb| {
                out[4 + limb] = row.rd.next[limb].sub(
                    row.destination.nonzero.mul(row.result[limb]),
                );
                out[8 + limb] = row.enabler.mul(
                    row.rs1.next[limb].sub(row.rs1.previous[limb]),
                );
                out[12 + limb] = row.enabler.mul(
                    row.rs2.next[limb].sub(row.rs2.previous[limb]),
                );
            }
            out[16] = row.enabler.sub(is_active);
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
            @setEvalBranchQuota(100_000);
            const active = row.enabler;
            const negative_active = active.neg();
            const zero = S.zero();
            const one = S.one();
            const four = ops.q(4);
            const source_1_clock = row.clock.sub(one).mul(four).add(one);
            const source_2_clock = row.clock.sub(one).mul(four).add(ops.q(2));
            const destination_clock = row.clock.sub(one).mul(four).add(ops.q(3));
            const source_1_gap = source_1_clock.sub(row.rs1.previous_clock).sub(one);
            const source_2_gap = source_2_clock.sub(row.rs2.previous_clock).sub(one);
            const destination_gap = destination_clock.sub(row.rd.previous_clock).sub(one);
            const carries = deriveCarries(row);

            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, negative_active, .{
                row.pc, ops.q(OPCODE_ID), row.rd.addr, row.rs1.addr, row.rs2.addr,
            });
            appendLookup(result, 1, negative_active, .{ row.pc, row.clock });
            appendLookup(result, 2, active, .{ row.pc.add(four), row.clock.add(one) });
            appendLookup(result, 3, negative_active, .{
                zero,                row.rs1.addr,        row.rs1.previous_clock,
                row.rs1.previous[0], row.rs1.previous[1], row.rs1.previous[2],
                row.rs1.previous[3],
            });
            appendLookup(result, 4, active, .{
                zero,            row.rs1.addr,    source_1_clock,
                row.rs1.next[0], row.rs1.next[1], row.rs1.next[2],
                row.rs1.next[3],
            });
            appendLookup(result, 5, negative_active, .{source_1_gap});
            appendLookup(result, 6, negative_active, .{
                zero,                row.rs2.addr,        row.rs2.previous_clock,
                row.rs2.previous[0], row.rs2.previous[1], row.rs2.previous[2],
                row.rs2.previous[3],
            });
            appendLookup(result, 7, active, .{
                zero,            row.rs2.addr,    source_2_clock,
                row.rs2.next[0], row.rs2.next[1], row.rs2.next[2],
                row.rs2.next[3],
            });
            appendLookup(result, 8, negative_active, .{source_2_gap});
            inline for (carries, 0..) |carry, limb|
                appendLookup(result, 9 + limb, negative_active, .{ row.result[limb], carry });
            appendLookup(result, 13, negative_active, .{
                zero,               row.rd.addr,        row.rd.previous_clock,
                row.rd.previous[0], row.rd.previous[1], row.rd.previous[2],
                row.rd.previous[3],
            });
            appendLookup(result, 14, active, .{
                zero,           row.rd.addr,    destination_clock,
                row.rd.next[0], row.rd.next[1], row.rd.next[2],
                row.rd.next[3],
            });
            appendLookup(result, 15, negative_active, .{destination_gap});
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
                @compileError("typed MUL fixed lookup append drifted");
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
    if (!instructionMatchesWord(.{
        .opcode = row.opcode,
        .rd = row.rd,
        .rs1 = row.rs1,
        .rs2 = row.rs2,
        .imm = row.imm,
    }, row.inst_word) or row.clk == 0 or
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
        (row.rd == 0 and (row.rd_prev_val != 0 or row.rd_val != 0)) or
        (row.rs1 == row.rs2 and
            (row.rs1_val != row.rs2_val or row.rs2_prev_clk != source_1_clock)))
    {
        return false;
    }
    if (row.rd == row.rs2 and
        (row.rd_prev_clk != source_2_clock or row.rd_prev_val != row.rs2_val))
    {
        return false;
    }
    if (row.rd != row.rs2 and row.rd == row.rs1 and
        (row.rd_prev_clk != source_1_clock or row.rd_prev_val != row.rs1_val))
    {
        return false;
    }
    const expected = resultFor(row.rs1_val, row.rs2_val);
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
    @setEvalBranchQuota(50_000);
    if (DIRECT_CONSTRAINT_COUNT != 17 or LOOKUP_COUNT != 16 or
        CANONICAL_DIRECT_RECIPE.len != 17)
    {
        @compileError("typed MUL fixed authority geometry drifted");
    }
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index|
        if (@intFromEnum(recipe) != index)
            @compileError("typed MUL direct recipe is not canonical");
    if (!std.mem.eql(
        u8,
        &CANONICAL_BINDING.identityDigest(),
        &AUTHORITY_BINDING_DIGEST,
    )) @compileError("typed MUL canonical authority digest drifted");
}
