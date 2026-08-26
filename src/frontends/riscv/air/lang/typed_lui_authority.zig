//! Fixed executable facade for the native typed RV32 LUI definition.
//!
//! `typed_lui.zig` remains the semantic source. This module is its small,
//! pointer-free executable binding: construction authenticates the complete
//! typed semantic digest, the physical witness recipe, the ordered relation
//! ABI, and the fixed direct/effect recipes. Once constructed, execution,
//! witness projection, direct evaluation, and lookup construction are all
//! allocation-free and contain no string lookup or runtime function dispatch.
//!
//! The production runner, witness writer, direct AIR, lookup AIR, and formal
//! exporter consume this authority. The retired Stark-V-shaped implementation
//! remains reachable only from differential tests; bypassing the generated
//! retirement path fails closed.

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
const typed_lui = @import("typed_lui.zig");
const typed_lui_witness = @import("typed_lui_witness.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_lui.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed_lui.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed_lui.RELATION_EVENT_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = 2;
pub const OPCODE_ID: u32 = typed_lui.OPCODE_ID;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/lui-fixed-authority/v1";

pub const AUTHORITY_BINDING_DIGEST_HEX =
    "4bf20ea25d84fb9373f5aee3fc85870f2fe97127aa71c862f3e191a8559a2599";

pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed LUI authority-binding digest");
    break :blk result;
};

/// Stable numeric code for the architectural forward effect.
pub const ExecutionRecipe = enum(u8) {
    u_immediate_write_x0_discard = 0,
};

/// Stable numeric direct-root recipes in production order.
pub const DirectRecipe = enum(u8) {
    enabler_bit = 0,
    destination_nonzero_bit = 1,
    destination_zero_address = 2,
    destination_inverse = 3,
    result_byte_0 = 4,
    result_byte_1 = 5,
    result_byte_2 = 6,
    result_byte_3 = 7,
    active_placement = 8,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .enabler_bit,
    .destination_nonzero_bit,
    .destination_zero_address,
    .destination_inverse,
    .result_byte_0,
    .result_byte_1,
    .result_byte_2,
    .result_byte_3,
    .active_placement,
};

/// Stable numeric lookup recipes in transcript order.
pub const LookupRecipe = enum(u8) {
    program_fetch = 0,
    state_consume = 1,
    state_emit = 2,
    immediate_range = 3,
    destination_consume = 4,
    destination_emit = 5,
    destination_clock_gap = 6,
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
    .{ .recipe = .immediate_range, .domain = .range_check_8_8_4, .role = .request, .arity = 3, .access_ordinal = null },
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
    direct: [DIRECT_CONSTRAINT_COUNT]DirectRecipe,
    lookups: [LOOKUP_COUNT]LookupDescriptor,
    lookup_batch_size: u8,

    pub fn canonical(_: *const typed_lui.Definition) Binding {
        return CANONICAL_BINDING;
    }

    /// Canonical digest of the complete fixed executable binding. Padding,
    /// pointers, source locations, and enum declaration order are excluded.
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
    .semantic_format_version = digest.sequential_retirement_format_version,
    .opcode_id = OPCODE_ID,
    .semantic_digest = typed_lui.SEMANTIC_DIGEST,
    .witness_binding_digest = typed_lui_witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .u_immediate_write_x0_discard,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = typed_lui_witness.ConstructionError || error{
    InvalidAuthorityBinding,
};

pub const ExecutionError = error{WrongLuiOpcode};

pub const Retirement = struct {
    rd: u5,
    write_enabled: bool,
    attempted_value: u32,
    visible_value: u32,
};

/// Fixed-facade validation used by staged runner plans after construction.
/// Keeping this predicate beside `Authority.retire` prevents the runner from
/// acquiring a second copy of LUI/x0 semantics.
pub inline fn acceptsVisibleRetirement(
    instruction: DecodedInst,
    visible_value: u32,
) bool {
    if (instruction.opcode != .LUI) return false;
    return visible_value == canonicalRetirement(instruction).visible_value;
}

inline fn canonicalRetirement(instruction: DecodedInst) Retirement {
    std.debug.assert(instruction.opcode == .LUI);
    const attempted: u32 = @bitCast(instruction.imm);
    const write_enabled = instruction.rd != 0;
    return .{
        .rd = instruction.rd,
        .write_enabled = write_enabled,
        .attempted_value = attempted,
        .visible_value = if (write_enabled) attempted else 0,
    };
}

/// Immutable executable capability. It owns no pointer, allocator, dynamic
/// dispatch table, or retained scratch and remains valid after the authored
/// arena is destroyed.
pub const Authority = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_lui.Definition,
        supplied: *const Binding,
    ) ConstructionError!Authority {
        // Validate the semantic graph before trusting any caller-supplied
        // executable metadata.
        try definition.validate();
        try validateBinding(definition, supplied);

        // Reuse the independently pinned physical recipe gate. The resulting
        // executor is intentionally not retained: its hot writer is static and
        // this facade retains the digest in its own binding.
        const witness_binding = typed_lui_witness.WitnessBinding.canonical(definition);
        _ = try typed_lui_witness.Executor.init(definition, &witness_binding);

        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &AUTHORITY_BINDING_DIGEST))
            return error.InvalidAuthorityBinding;
        return .{ .binding = owned, .binding_digest = binding_digest };
    }

    /// Allocation-free capability for the repository's compile-time-pinned
    /// LUI program. Dynamic or test-authored definitions must still enter
    /// through `init`; this route is valid because the complete canonical
    /// binding digest is recomputed at compile time below, while admission
    /// tests authenticate the same binding against the authored graph.
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

    /// Pure architectural forward effect. `attempted_value` records the U-type
    /// write value; `visible_value` applies the architectural x0 discard.
    pub inline fn retire(_: *const Authority, instruction: DecodedInst) ExecutionError!Retirement {
        if (instruction.opcode != .LUI) return error.WrongLuiOpcode;
        return canonicalRetirement(instruction);
    }

    /// Checked batch projection. Shape, aliasing, opcode, result, and x0
    /// consistency are rejected before the first destination store.
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

    /// Infallible admitted-row hot path. All eighteen stores remain the
    /// compile-time-unrolled typed witness recipe.
    pub inline fn writeActiveRow(
        _: *const Authority,
        columns: anytype,
        row_index: usize,
        row: TraceRow,
    ) void {
        std.debug.assert(validTraceRow(row));
        writeActiveRowUnchecked(columns, row_index, row);
    }

    /// Build the complete direct/relation program through this authenticated
    /// capability. Authentication is an admission-time invariant: the hot
    /// scalar program remains pointer-free and pays no per-row digest check.
    pub fn buildProgram(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        is_active: S,
    ) !Evaluator(S).ConstraintProgram {
        return Evaluator(S).build(columns, is_active);
    }

    /// Direct-only view used by the production semantic evaluator and runtime
    /// polynomial export.
    pub fn evaluateDirect(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        is_active: S,
    ) !Evaluator(S).DirectConstraints {
        return Evaluator(S).direct(columns, is_active);
    }

    /// Caller-owned lookup view. Keeping the result out of an error-union
    /// return preserves the fixed writer's small Debug stack footprint.
    pub fn buildLookupsInto(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        result: *entry.Builder(S).List,
    ) !void {
        return Evaluator(S).lookupsInto(columns, result);
    }
};

/// Generic direct/relation evaluator over the same scalar contract used by
/// production (`QM31`, the base-field adapter, or the symbolic recorder).
pub fn Evaluator(comptime S: type) type {
    return struct {
        const Self = @This();
        const ops = common.Ops(S);
        const e = entry.Builder(S);

        pub const DirectConstraints = struct {
            values: [DIRECT_CONSTRAINT_COUNT]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value| {
                    if (!value.isZero()) return false;
                }
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
            imm_0: S,
            imm_1: S,
            imm_2: S,
            destination_nonzero: S,
            destination_inverse: S,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = ops.accessFromColumns(columns[3..13]),
                    .imm_0 = columns[13],
                    .imm_1 = columns[14],
                    .imm_2 = columns[15],
                    .destination_nonzero = columns[16],
                    .destination_inverse = columns[17],
                };
            }
        };

        pub fn direct(
            columns: []const S,
            is_active: S,
        ) !DirectConstraints {
            return directRow(try Row.fromMainColumns(columns), is_active);
        }

        /// Complete fixed program in production event order. Parsing happens
        /// once and both sections share the exact same row projection.
        pub fn build(
            columns: []const S,
            is_active: S,
        ) !ConstraintProgram {
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
            var values: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            values[0] = ops.bit(row.enabler);
            values[1] = ops.bit(row.destination_nonzero);
            values[2] = row.rd.addr.mul(
                S.one().sub(row.destination_nonzero),
            );
            values[3] = row.rd.addr
                .mul(row.destination_inverse)
                .sub(row.destination_nonzero);
            const result = resultLimbs(row);
            values[4] = row.rd.next[0].sub(
                row.destination_nonzero.mul(result[0]),
            );
            values[5] = row.rd.next[1].sub(
                row.destination_nonzero.mul(result[1]),
            );
            values[6] = row.rd.next[2].sub(
                row.destination_nonzero.mul(result[2]),
            );
            values[7] = row.rd.next[3].sub(
                row.destination_nonzero.mul(result[3]),
            );
            values[8] = row.enabler.sub(is_active);
            return .{ .values = values };
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

            // Preserve the canonical evaluator's symbolic construction order:
            // it prepares the register chain, then the complete program
            // request, then the state request. This ordering is semantically
            // irrelevant in a field evaluator but makes formal/runtime DAGs
            // and their serialized node IDs byte-identical.
            const current_clock = row.clock.sub(S.one())
                .mul(ops.q(4)).add(S.one());
            const zero = S.zero();
            const clock_gap = current_clock.sub(row.rd.previous_clock).sub(S.one());
            const opcode = ops.q(OPCODE_ID);
            const decoded_immediate = immediate(row);
            const negative_active = active.neg();
            const next_pc = row.pc.add(ops.q(4));
            const next_clock = row.clock.add(S.one());
            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };

            // Keep this as one straight-line, compile-time-known store program.
            // Fixed append writes into caller storage directly, avoiding the
            // 32-scalar temporary Entry copies in the generic relation builder.
            appendLookup(
                result,
                0,
                negative_active,
                .{ row.pc, opcode, row.rd.addr, decoded_immediate, zero },
            );
            appendLookup(
                result,
                1,
                negative_active,
                .{ row.pc, row.clock },
            );
            appendLookup(
                result,
                2,
                active,
                .{ next_pc, next_clock },
            );
            appendLookup(
                result,
                3,
                negative_active,
                .{ row.imm_1, row.imm_2, row.imm_0 },
            );
            appendLookup(
                result,
                4,
                negative_active,
                .{
                    zero,
                    row.rd.addr,
                    row.rd.previous_clock,
                    row.rd.previous[0],
                    row.rd.previous[1],
                    row.rd.previous[2],
                    row.rd.previous[3],
                },
            );
            appendLookup(
                result,
                5,
                active,
                .{
                    zero,
                    row.rd.addr,
                    current_clock,
                    row.rd.next[0],
                    row.rd.next[1],
                    row.rd.next[2],
                    row.rd.next[3],
                },
            );
            appendLookup(result, 6, negative_active, .{clock_gap});
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
            comptime {
                if (@intFromEnum(descriptor.recipe) != index or
                    descriptor.arity != values.len)
                {
                    @compileError("typed LUI fixed lookup append drifted");
                }
            }
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

        pub inline fn immediate(row: Row) S {
            return row.imm_0
                .add(row.imm_1.mul(ops.q(1 << 4)))
                .add(row.imm_2.mul(ops.q(1 << 12)));
        }

        pub inline fn resultLimbs(row: Row) [4]S {
            return .{
                S.zero(),
                row.imm_0.mul(ops.q(1 << 4)),
                row.imm_1,
                row.imm_2,
            };
        }
    };
}

fn validateBinding(
    definition: *const typed_lui.Definition,
    supplied: *const Binding,
) error{InvalidAuthorityBinding}!void {
    const canonical = Binding.canonical(definition);
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
            .immediate_range => .range_request,
            .destination_consume, .destination_emit, .destination_clock_gap => .register_write,
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
    typed_lui_witness.writeActiveRow(columns, row_index, row);
}

inline fn validTraceRow(row: TraceRow) bool {
    if (row.opcode != .LUI) return false;
    const attempted: u32 = @bitCast(row.imm);
    return row.rd_val == if (row.rd == 0) 0 else attempted;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    @setEvalBranchQuota(100_000);
    if (MAIN_COLUMN_COUNT != 18 or
        DIRECT_CONSTRAINT_COUNT != 9 or
        LOOKUP_COUNT != 7 or
        LOOKUP_BATCH_SIZE != 2)
    {
        @compileError("typed LUI fixed authority geometry drifted");
    }
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index| {
        if (@intFromEnum(recipe) != index)
            @compileError("typed LUI direct recipe is not canonically ordered");
    }
    for (CANONICAL_LOOKUP_RECIPE, 0..) |lookup, index| {
        if (@intFromEnum(lookup.recipe) != index or
            lookup.arity != entry.expectedArity(lookup.domain))
        {
            @compileError("typed LUI lookup recipe is not canonical");
        }
    }
    const calculated_binding_digest = CANONICAL_BINDING.identityDigest();
    if (!std.mem.eql(
        u8,
        &calculated_binding_digest,
        &AUTHORITY_BINDING_DIGEST,
    )) {
        @compileError("typed LUI pinned authority digest drifted");
    }
    if (@sizeOf(Authority) > 256)
        @compileError("typed LUI fixed authority exceeded its stack budget");
}
