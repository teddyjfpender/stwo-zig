//! Non-production 48-column load/store verifier-program candidate.
//!
//! The production witness commits `src_addr_selector` and
//! `dst_addr_selector` even though every one of the eight opcode paths writes
//! those cells identically to `src.addr` and `dst.addr`.  This append-only
//! candidate authors the same 63 roots and 17 ordered relation events while
//! wiring the selector values directly to the access-address inputs.  No
//! production profile selects this program.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const conditional_access = @import("conditional_access_plan.zig");
const constraints_mod = @import("typed_load_store_constraints.zig");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const instruction_effects = @import("instruction_effects.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const range_refinement = @import("range_refinement.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const typed = @import("typed_load_store.zig");
const types = @import("types.zig");
const validate_mod = @import("validate.zig");
const witness = @import("typed_load_store_witness.zig");

pub const production_active = false;
pub const schema_version: u16 = 1;
pub const canonical_main_column_count: usize = typed.MAIN_COLUMN_COUNT;
pub const main_column_count: usize = canonical_main_column_count - 2;
pub const source_selector_column: usize = @intFromEnum(witness.RowSource.src_addr_selector);
pub const destination_selector_column: usize = @intFromEnum(witness.RowSource.dst_addr_selector);
pub const source_address_column: usize = @intFromEnum(witness.RowSource.src_addr);
pub const destination_address_column: usize = @intFromEnum(witness.RowSource.dst_addr);
pub const maximum_shard_rows: u32 = 1 << 16;
pub const minimum_log_size: u32 = 4;
pub const raw_m31_bytes: u64 = @sizeOf(u32);
pub const Digest = [32]u8;
pub const TraceRow = witness.TraceRow;
pub const CanonicalRow = [canonical_main_column_count]M31;
pub const CandidateRow = [main_column_count]M31;

pub const CostProjection = struct {
    leaf_count: u32,
    active_rows: u64,
    shard_count: u64,
    padded_domain_rows: u64,
    canonical_main_cells: u64,
    candidate_main_cells: u64,
    saved_main_cells: u64,
    saved_raw_bytes: u64,
};

pub const DefinitionV1 = struct {
    arena: ir.Arena,
    columns: typed.Columns,
    physical: [main_column_count]types.ValueId,
    is_active: types.ValueId,
    model: constraints_mod.Result,
    events: typed.Events,
    verifier_program_identity: Digest,

    pub fn deinit(self: *DefinitionV1) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const DefinitionV1) !void {
        try validate_mod.validate(&self.arena);
        if (self.columns.src_addr_selector != self.columns.src.addr or
            self.columns.dst_addr_selector != self.columns.dst.addr or
            types.idIndex(self.is_active) != main_column_count or
            self.arena.constraintsView().len != typed.DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != typed.LOOKUP_COUNT or
            self.arena.conditional_access_plans.items.len != 1 or
            self.arena.range_refinements.items.len != 5 or
            self.arena.fixed_table_requests.items.len != 5)
        {
            return error.InvalidSelectorAliasProgram;
        }
        for (self.physical, 0..) |value, index| {
            if (types.idIndex(value) != index)
                return error.InvalidSelectorAliasProgram;
        }
        try validateEventOrder(self);
        const expected = try programIdentity(&self.arena);
        if (!std.mem.eql(u8, &expected, &self.verifier_program_identity))
            return error.InvalidSelectorAliasProgram;
    }
};

pub fn build(allocator: std.mem.Allocator) !DefinitionV1 {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();
    const columns = typed.Columns{
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .dst = try accessInputs(&arena, "dst", .felt, span),
        .rs1 = try readInputs(&arena, "rs1", .register_index, span),
        .src = try readInputs(&arena, "src", .felt, span),
        .r2_idx = try arena.input("r2_idx", .register_index, span),
        .imm_felt = try arena.input("imm_felt", .felt, span),
        .src_msb = try arena.input("src_msb", .bit, span),
        .shift_amount = try arena.input("shift_amount", .felt, span),
        .src_addr_selector = undefined,
        .dst_addr_selector = undefined,
        .markers = try bitInputs(&arena, "marker", span),
        .is_lb = try arena.input("opcode_lb_flag", .bit, span),
        .is_lh = try arena.input("opcode_lh_flag", .bit, span),
        .is_lbu = try arena.input("opcode_lbu_flag", .bit, span),
        .is_lhu = try arena.input("opcode_lhu_flag", .bit, span),
        .is_lw = try arena.input("opcode_lw_flag", .bit, span),
        .is_sb = try arena.input("opcode_sb_flag", .bit, span),
        .is_sh = try arena.input("opcode_sh_flag", .bit, span),
        .is_sw = try arena.input("opcode_sw_flag", .bit, span),
        .result = try byteInputs(&arena, "result", span),
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
        .aligned_addr_quarter = try arena.input(
            "aligned_addr_quarter",
            try types.Type.boundedField(28),
            span,
        ),
        .aligned_addr_low20 = try arena.input("aligned_addr_low20", .uint20, span),
    };
    var aliased = columns;
    aliased.src_addr_selector = aliased.src.addr;
    aliased.dst_addr_selector = aliased.dst.addr;
    const physical = candidatePhysical(aliased);
    const is_active = try arena.input("is_active", .selector, span);
    const model = try constraints_mod.author(&arena, aliased, is_active, span);
    const events = try authorEffects(&arena, aliased, model, span);
    var result = DefinitionV1{
        .arena = arena,
        .columns = aliased,
        .physical = physical,
        .is_active = is_active,
        .model = model,
        .events = events,
        .verifier_program_identity = undefined,
    };
    result.verifier_program_identity = try programIdentity(&result.arena);
    try result.validate();
    return result;
}

pub fn project(canonical: CanonicalRow) !CandidateRow {
    if (canonical[source_selector_column].toU32() != canonical[source_address_column].toU32() or
        canonical[destination_selector_column].toU32() != canonical[destination_address_column].toU32())
    {
        return error.SelectorAliasMismatch;
    }
    var result: CandidateRow = undefined;
    var destination: usize = 0;
    for (canonical, 0..) |value, column| {
        if (isOmitted(column)) continue;
        result[destination] = value;
        destination += 1;
    }
    std.debug.assert(destination == result.len);
    return result;
}

pub fn expand(candidate: CandidateRow) CanonicalRow {
    var result: CanonicalRow = undefined;
    var source_index: usize = 0;
    for (&result, 0..) |*value, column| {
        value.* = if (column == source_selector_column)
            result[source_address_column]
        else if (column == destination_selector_column)
            result[destination_address_column]
        else blk: {
            const committed = candidate[source_index];
            source_index += 1;
            break :blk committed;
        };
    }
    std.debug.assert(source_index == candidate.len);
    return result;
}

pub fn canonicalTraceRow(row: witness.TraceRow) !CanonicalRow {
    try witness.validateTraceRow(row);
    var columns: [canonical_main_column_count][1]M31 = undefined;
    witness.writeActiveRow(&columns, 0, row);
    var result: CanonicalRow = undefined;
    for (&result, columns) |*value, column| value.* = column[0];
    return result;
}

pub fn projectTraceRow(row: witness.TraceRow) !CandidateRow {
    return project(try canonicalTraceRow(row));
}

pub fn projectGeometry(rows_by_leaf: []const u32) !CostProjection {
    var result = CostProjection{
        .leaf_count = @intCast(rows_by_leaf.len),
        .active_rows = 0,
        .shard_count = 0,
        .padded_domain_rows = 0,
        .canonical_main_cells = 0,
        .candidate_main_cells = 0,
        .saved_main_cells = 0,
        .saved_raw_bytes = 0,
    };
    for (rows_by_leaf) |leaf_rows| {
        result.active_rows = try add(u64, result.active_rows, leaf_rows);
        var remaining = leaf_rows;
        while (remaining != 0) {
            const shard_rows = @min(remaining, maximum_shard_rows);
            const log_size = @max(
                minimum_log_size,
                std.math.log2_int_ceil(u32, shard_rows),
            );
            const domain_rows = @as(u64, 1) << @intCast(log_size);
            result.shard_count = try add(u64, result.shard_count, 1);
            result.padded_domain_rows = try add(
                u64,
                result.padded_domain_rows,
                domain_rows,
            );
            remaining -= shard_rows;
        }
    }
    result.canonical_main_cells = try mul(
        result.padded_domain_rows,
        canonical_main_column_count,
    );
    result.candidate_main_cells = try mul(
        result.padded_domain_rows,
        main_column_count,
    );
    result.saved_main_cells = result.canonical_main_cells - result.candidate_main_cells;
    result.saved_raw_bytes = try mul(result.saved_main_cells, raw_m31_bytes);
    return result;
}

fn candidatePhysical(columns: typed.Columns) [main_column_count]types.ValueId {
    const canonical = columns.physical();
    var result: [main_column_count]types.ValueId = undefined;
    var destination: usize = 0;
    for (canonical, 0..) |value, column| {
        if (isOmitted(column)) continue;
        result[destination] = value;
        destination += 1;
    }
    std.debug.assert(destination == result.len);
    return result;
}

fn isOmitted(column: usize) bool {
    return column == source_selector_column or column == destination_selector_column;
}

fn programIdentity(arena: *const ir.Arena) !Digest {
    const semantic = try digest.computeIdentity(arena);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.load-store-selector-alias-verifier-program.v1\x00");
    hashInt(&hash, schema_version);
    hashInt(&hash, semantic.format_version);
    hash.update(&semantic.bytes);
    hash.update(&typed.SEMANTIC_DIGEST);
    hashInt(&hash, canonical_main_column_count);
    hashInt(&hash, main_column_count);
    hashInt(&hash, source_selector_column);
    hashInt(&hash, source_address_column);
    hashInt(&hash, destination_selector_column);
    hashInt(&hash, destination_address_column);
    hashInt(&hash, typed.DIRECT_CONSTRAINT_COUNT);
    hashInt(&hash, typed.LOOKUP_COUNT);
    hashInt(&hash, typed.LOOKUP_BATCH_SIZE);
    hashInt(&hash, typed.MAX_LOOKUP_ARITY);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn validateEventOrder(definition: *const DefinitionV1) !void {
    const event_ids = [_]types.EffectId{
        definition.events.program_fetch,
        definition.events.retirement.consume,
        definition.events.retirement.produce,
        definition.events.rs1.consume,
        definition.events.rs1.emit,
        definition.events.rs1.gap,
        definition.events.aligned_address_range,
        definition.events.base_address_range,
        definition.events.source.consume,
        definition.events.source.emit,
        definition.events.source.gap,
        definition.events.destination.consume,
        definition.events.destination.emit,
        definition.events.destination.gap,
        definition.events.lb_sign_range,
        definition.events.lh_sign_range,
        definition.events.aligned_address_high_range,
    };
    for (event_ids, 0..) |event, index| {
        if (types.idIndex(event) != index)
            return error.InvalidSelectorAliasProgram;
    }
}

fn authorEffects(
    arena: *ir.Arena,
    c: typed.Columns,
    model: constraints_mod.Result,
    span: source.SourceSpan,
) !typed.Events {
    const one = try arena.constantField(1, span);
    const c128 = try arena.constantField(128, span);
    const active = try range_refinement.booleanFromConstraint(
        arena,
        model.active,
        model.constraints[0],
        span,
    );
    const store_selector = try arena.oneHotSelector(
        &.{ c.is_sb, c.is_sh, c.is_sw },
        span,
    );
    const program_fetch = try effects.programFetch(arena, .{
        .pc = c.pc,
        .opcode_id = model.opcode_id,
        .rd = c.rs1.addr,
        .rs1 = c.r2_idx,
        .operand = c.imm_felt,
    }, active, span);
    const retirement = (try instruction_effects.retireSequential(arena, .{
        .pc = c.pc,
        .clock = c.clock,
    }, active, span)).events;
    var schedule = try effects.AccessSchedule.begin(arena, c.clock, active, span);
    const rs1_group = try schedule.registerRead(.{
        .index = c.rs1.addr,
        .previous_clock = c.rs1.previous_clock,
        .value = c.rs1.value,
    }, span);
    const rs1 = typed.AccessEvents{
        .consume = rs1_group.consume,
        .emit = rs1_group.emit,
        .gap = rs1_group.clock_gap,
    };
    const aligned = try range_refinement.rangeCheck20Typed(
        arena,
        c.aligned_addr_low20,
        active,
        span,
    );
    const high_source = try arena.mul(
        try arena.sub(c.aligned_addr_quarter, c.aligned_addr_low20, span),
        try arena.constantField(1 << 11, span),
        span,
    );
    const zero_byte = try arena.constantUnsigned(.byte, 0, span);
    const doubled_base_high = try arena.mul(
        c.rs1.value[3],
        try arena.constantField(2, span),
        span,
    );
    const base = try range_refinement.rangeCheckM31(
        arena,
        c.rs1.value[0],
        doubled_base_high,
        active,
        span,
    );
    const second_clock = try accessClock(arena, c.clock, 2, span);
    const source_address = try conditional_access.internAlias(
        arena,
        c.src_addr_selector,
        .address,
        span,
    );
    const source_clock_source = try arena.add(second_clock, model.is_load, span);
    const source_clock = try conditional_access.internAlias(
        arena,
        source_clock_source,
        .clock,
        span,
    );
    const source_gap_source = try arena.sub(
        try arena.sub(source_clock_source, c.src.previous_clock, span),
        one,
        span,
    );
    const source_gap = try conditional_access.internAlias(
        arena,
        source_gap_source,
        .uint20,
        span,
    );
    const source_events = try appendConditionalAccess(
        arena,
        .memory_read,
        model.is_load,
        source_address.target,
        c.src.previous_clock,
        c.src.value,
        source_clock.target,
        c.src.value,
        source_gap.target,
        active,
        2,
        span,
    );
    const destination_address = try conditional_access.internAlias(
        arena,
        c.dst_addr_selector,
        .address,
        span,
    );
    const destination_clock_source = try arena.add(second_clock, model.is_store, span);
    const destination_clock = try conditional_access.internAlias(
        arena,
        destination_clock_source,
        .clock,
        span,
    );
    const destination_gap_source = try arena.sub(
        try arena.sub(destination_clock_source, c.dst.previous_clock, span),
        one,
        span,
    );
    const destination_gap = try conditional_access.internAlias(
        arena,
        destination_gap_source,
        .uint20,
        span,
    );
    const destination_events = try appendConditionalAccess(
        arena,
        .memory_write,
        model.is_store,
        destination_address.target,
        c.dst.previous_clock,
        c.dst.previous,
        destination_clock.target,
        c.dst.next,
        destination_gap.target,
        active,
        3,
        span,
    );
    try arena.conditional_access_plans.ensureUnusedCapacity(arena.allocator, 1);
    arena.conditional_access_plans.appendAssumeCapacity(.{
        .first_effect = rs1.consume,
        .aligned_range = aligned.effect,
        .base_range = base.effect,
        .active_source = model.active,
        .active = active,
        .store_source = model.is_store,
        .store_selector = store_selector,
        .is_load = model.is_load,
        .instruction_clock = c.clock,
        .second_clock = second_clock,
        .memory_address = model.mem_addr,
        .shift_amount = c.shift_amount,
        .register_index = c.r2_idx,
        .word_source = model.aligned_addr_quarter_source,
        .word_index = c.aligned_addr_quarter,
        .base_low = base.values[0],
        .base_high = base.values[1],
        .source_address_constraint = model.constraints[constraints_mod.SOURCE_ADDRESS_CONSTRAINT_INDEX],
        .destination_address_constraint = model.constraints[constraints_mod.DESTINATION_ADDRESS_CONSTRAINT_INDEX],
        .source_address = source_address,
        .source_clock = source_clock,
        .source_gap = source_gap,
        .destination_address = destination_address,
        .destination_clock = destination_clock,
        .destination_gap = destination_gap,
        .source_span = span,
    });
    const lb_sign = try range_refinement.rangeCheckM31(
        arena,
        zero_byte,
        try arena.sub(c.result[0], try arena.mul(c.src_msb, c128, span), span),
        c.is_lb,
        span,
    );
    const lh_sign = try range_refinement.rangeCheckM31(
        arena,
        zero_byte,
        try arena.sub(c.result[1], try arena.mul(c.src_msb, c128, span), span),
        c.is_lh,
        span,
    );
    const aligned_high = try range_refinement.rangeCheck88FirstRefined(
        arena,
        high_source,
        zero_byte,
        active,
        span,
    );
    return .{
        .program_fetch = program_fetch,
        .retirement = retirement,
        .rs1 = rs1,
        .aligned_address_range = aligned.effect,
        .base_address_range = base.effect,
        .source = source_events,
        .destination = destination_events,
        .lb_sign_range = lb_sign.effect,
        .lh_sign_range = lh_sign.effect,
        .aligned_address_high_range = aligned_high.effect,
    };
}

fn appendConditionalAccess(
    arena: *ir.Arena,
    kind: program.EffectKind,
    address_space: types.ValueId,
    address: types.ValueId,
    previous_clock: types.ValueId,
    previous: [4]types.ValueId,
    current_clock: types.ValueId,
    next: [4]types.ValueId,
    gap: types.ValueId,
    active: types.ValueId,
    ordinal: u8,
    span: source.SourceSpan,
) !typed.AccessEvents {
    const consume_values = [_]types.ValueId{
        address_space, address,     previous_clock,
        previous[0],   previous[1], previous[2],
        previous[3],
    };
    const emit_values = [_]types.ValueId{
        address_space, address, current_clock,
        next[0],       next[1], next[2],
        next[3],
    };
    return .{
        .consume = try arena.addBoundEffectUnchecked(
            kind,
            relationBinding(.memory_access, .consume),
            &consume_values,
            active,
            ordinal,
            span,
        ),
        .emit = try arena.addBoundEffectUnchecked(
            kind,
            relationBinding(.memory_access, .emit),
            &emit_values,
            active,
            ordinal,
            span,
        ),
        .gap = try arena.addBoundEffectUnchecked(
            kind,
            relationBinding(.range_check_20, .request),
            &.{gap},
            active,
            ordinal,
            span,
        ),
    };
}

fn relationBinding(domain: relation.Domain, role: relation.Role) program.RelationBinding {
    const schema = relation.get(domain);
    return .{ .schema = schema.id, .schema_version = schema.version, .role = role };
}

fn accessClock(
    arena: *ir.Arena,
    instruction_clock: types.ValueId,
    phase: u32,
    span: source.SourceSpan,
) !types.ValueId {
    const one = try arena.constantField(1, span);
    const four = try arena.constantField(4, span);
    const phase_value = try arena.constantField(phase, span);
    return arena.add(
        try arena.mul(try arena.sub(instruction_clock, one, span), four, span),
        phase_value,
        span,
    );
}

fn accessInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    addr_type: types.Type,
    span: source.SourceSpan,
) !typed.AccessColumns {
    return .{
        .addr = try arena.input(prefix ++ "_addr", addr_type, span),
        .previous = try byteInputs(arena, prefix ++ "_prev", span),
        .previous_clock = try arena.input(prefix ++ "_clock_prev", .clock, span),
        .next = try byteInputs(arena, prefix ++ "_next", span),
    };
}

fn readInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    addr_type: types.Type,
    span: source.SourceSpan,
) !typed.ReadColumns {
    return .{
        .addr = try arena.input(prefix ++ "_addr", addr_type, span),
        .value = try byteInputs(arena, prefix ++ "_prev", span),
        .previous_clock = try arena.input(prefix ++ "_clock_prev", .clock, span),
    };
}

fn byteInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var result: [4]types.ValueId = undefined;
    inline for (&result, 0..) |*value, index| value.* = try arena.input(
        std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
        .byte,
        span,
    );
    return result;
}

fn bitInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var result: [4]types.ValueId = undefined;
    inline for (&result, 0..) |*value, index| value.* = try arena.input(
        std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
        .bit,
        span,
    );
    return result;
}

fn add(comptime T: type, lhs: T, rhs: T) !T {
    return std.math.add(T, lhs, rhs) catch error.ArithmeticOverflow;
}

fn mul(lhs: u64, rhs: anytype) !u64 {
    return std.math.mul(u64, lhs, @intCast(rhs)) catch error.ArithmeticOverflow;
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (canonical_main_column_count != 50 or main_column_count != 48 or
        source_selector_column != 28 or destination_selector_column != 29 or
        source_address_column != 18 or destination_address_column != 2 or
        production_active)
    {
        @compileError("load/store selector-alias candidate geometry drifted");
    }
}
