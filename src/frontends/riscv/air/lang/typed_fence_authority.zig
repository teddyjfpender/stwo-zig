//! Fixed executable facade for native typed RV32 FENCE.
//!
//! The authored definition remains the semantic source. Construction
//! authenticates its full semantic digest, six-slot witness recipe, ordered
//! relation ABI, and fixed direct/effect recipes. The retained capability is
//! pointer-free and every hot operation is allocation-free, loop-free over
//! runtime metadata, and free of string lookup or dynamic dispatch.
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
const typed_fence = @import("typed_fence.zig");
const typed_fence_witness = @import("typed_fence_witness.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_fence.MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = typed_fence.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = typed_fence.LOOKUP_COUNT;
pub const LOOKUP_BATCH_SIZE: usize = 2;
pub const OPCODE_ID: u32 = typed_fence.OPCODE_ID;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;

pub const AUTHORITY_BINDING_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/fence-fixed-authority/v1";
pub const AUTHORITY_BINDING_DIGEST_HEX =
    "ae17af6006b917c52ba824380dfb9bf2223c5b6f34651b71cd56e29b206d199e";
pub const AUTHORITY_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, AUTHORITY_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed FENCE authority-binding digest");
    break :blk result;
};

pub const ExecutionRecipe = enum(u8) {
    state_only_sequential = 0,
};

pub const DirectRecipe = enum(u8) {
    enabler_bit = 0,
    active_placement = 1,
};

pub const CANONICAL_DIRECT_RECIPE = [DIRECT_CONSTRAINT_COUNT]DirectRecipe{
    .enabler_bit,
    .active_placement,
};

pub const LookupRecipe = enum(u8) {
    program_fetch = 0,
    state_consume = 1,
    state_emit = 2,
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
        definition: *const typed_fence.Definition,
    ) typed_fence_witness.ConstructionError!Binding {
        const witness = try typed_fence_witness.WitnessBinding.canonical(definition);
        const witness_digest = witness.identityDigest();
        if (!std.mem.eql(
            u8,
            &witness_digest,
            &typed_fence_witness.WITNESS_BINDING_DIGEST,
        )) return error.InvalidWitnessBinding;
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
    .semantic_format_version = digest.sequential_retirement_format_version,
    .opcode_id = OPCODE_ID,
    .semantic_digest = typed_fence.SEMANTIC_DIGEST,
    .witness_binding_digest = typed_fence_witness.WITNESS_BINDING_DIGEST,
    .main_column_count = MAIN_COLUMN_COUNT,
    .execution = .state_only_sequential,
    .direct = CANONICAL_DIRECT_RECIPE,
    .lookups = CANONICAL_LOOKUP_RECIPE,
    .lookup_batch_size = LOOKUP_BATCH_SIZE,
};

pub const ConstructionError = typed_fence_witness.ConstructionError || error{
    InvalidAuthorityBinding,
};
pub const ExecutionError = error{ WrongFenceOpcode, InvalidFenceImmediate };

pub const Retirement = struct {
    next_pc: u32,
};

inline fn canonicalRetirement(instruction: DecodedInst, pc_before: u32) Retirement {
    std.debug.assert(instruction.opcode == .FENCE);
    std.debug.assert(instruction.imm >= -2048 and instruction.imm <= 2047);
    return .{ .next_pc = pc_before +% 4 };
}

/// Fixed-facade check used after a staged plan has left construction.
pub inline fn acceptsRetirement(
    instruction: DecodedInst,
    pc_before: u32,
    next_pc: u32,
) bool {
    if (instruction.opcode != .FENCE or
        instruction.imm < -2048 or instruction.imm > 2047)
    {
        return false;
    }
    return next_pc == canonicalRetirement(instruction, pc_before).next_pc;
}

pub const Authority = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_fence.Definition,
        supplied: *const Binding,
    ) ConstructionError!Authority {
        try definition.validate();
        try validateBinding(definition, supplied);
        const witness_binding = try typed_fence_witness.WitnessBinding.canonical(definition);
        _ = try typed_fence_witness.Executor.init(definition, &witness_binding);

        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &AUTHORITY_BINDING_DIGEST))
            return error.InvalidAuthorityBinding;
        return .{ .binding = owned, .binding_digest = binding_digest };
    }

    /// Allocation-free capability for the repository's compile-time-pinned
    /// FENCE program. Dynamic or test-authored definitions still enter through
    /// `init`; admission tests authenticate this exact value against the full
    /// authored graph and witness recipe.
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
        if (instruction.opcode != .FENCE) return error.WrongFenceOpcode;
        if (instruction.imm < -2048 or instruction.imm > 2047)
            return error.InvalidFenceImmediate;
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

    /// Build the complete production direct/relation program through this
    /// authenticated capability. The scalar hot path is fixed and performs no
    /// per-row identity work.
    pub fn buildProgram(
        _: *const Authority,
        comptime S: type,
        columns: []const S,
        is_active: S,
    ) !Evaluator(S).ConstraintProgram {
        return Evaluator(S).build(columns, is_active);
    }
};

pub fn Evaluator(comptime S: type) type {
    return struct {
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
            rd: S,
            rs1: S,
            immediate: S,

            pub fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .enabler = columns[0],
                    .clock = columns[1],
                    .pc = columns[2],
                    .rd = columns[3],
                    .rs1 = columns[4],
                    .immediate = columns[5],
                };
            }
        };

        pub fn direct(columns: []const S, is_active: S) !DirectConstraints {
            return directRow(try Row.fromMainColumns(columns), is_active);
        }

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
            inline for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index| {
                values[index] = switch (recipe) {
                    .enabler_bit => ops.bit(row.enabler),
                    .active_placement => row.enabler.sub(is_active),
                };
            }
            return .{ .values = values };
        }

        pub fn lookups(columns: []const S) !e.List {
            var result: e.List = undefined;
            try lookupsInto(columns, &result);
            return result;
        }

        pub fn lookupsInto(columns: []const S, result: *e.List) !void {
            const row = try Row.fromMainColumns(columns);
            lookupsRowInto(row, result);
        }

        fn lookupsRowInto(row: Row, result: *e.List) void {
            const active = row.enabler;
            const negative_active = active.neg();
            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(
                result,
                0,
                negative_active,
                .{ row.pc, ops.q(OPCODE_ID), row.rd, row.rs1, row.immediate },
            );
            appendLookup(result, 1, negative_active, .{ row.pc, row.clock });
            appendLookup(
                result,
                2,
                active,
                .{ row.pc.add(ops.q(4)), row.clock.add(S.one()) },
            );
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
                    @compileError("typed FENCE fixed lookup append drifted");
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
    };
}

fn validateBinding(
    definition: *const typed_fence.Definition,
    supplied: *const Binding,
) error{InvalidAuthorityBinding}!void {
    const canonical = Binding.canonical(definition) catch
        return error.InvalidAuthorityBinding;
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
    typed_fence_witness.writeActiveRow(columns, row_index, row);
}

inline fn validTraceRow(row: TraceRow) bool {
    return row.opcode == .FENCE and
        row.imm >= -2048 and row.imm <= 2047 and
        row.next_pc == row.pc +% 4 and
        !row.branch_taken and !row.is_load and !row.is_store and
        row.rd_val == row.rd_prev_val and
        row.rs1_prev_clk == 0 and row.rs2_prev_clk == 0 and
        row.rd_prev_clk == 0 and
        row.mem_addr == 0 and row.mem_val == 0 and
        row.mem_prev_word == 0 and row.mem_next_word == 0 and
        row.mem_prev_clk == 0;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    @setEvalBranchQuota(100_000);
    const canonical_digest = CANONICAL_BINDING.identityDigest();
    if (!std.mem.eql(u8, &canonical_digest, &AUTHORITY_BINDING_DIGEST))
        @compileError("typed FENCE canonical authority digest drifted");
    if (MAIN_COLUMN_COUNT != 6 or
        DIRECT_CONSTRAINT_COUNT != 2 or
        LOOKUP_COUNT != 3 or
        LOOKUP_BATCH_SIZE != 2)
    {
        @compileError("typed FENCE fixed authority geometry drifted");
    }
    for (CANONICAL_DIRECT_RECIPE, 0..) |recipe, index| {
        if (@intFromEnum(recipe) != index)
            @compileError("typed FENCE direct recipe is not canonically ordered");
    }
    for (CANONICAL_LOOKUP_RECIPE, 0..) |lookup, index| {
        if (@intFromEnum(lookup.recipe) != index or
            lookup.arity != entry.expectedArity(lookup.domain))
        {
            @compileError("typed FENCE lookup recipe is not canonical");
        }
    }
    if (@sizeOf(Authority) > 192)
        @compileError("typed FENCE fixed authority exceeded its stack budget");
}
