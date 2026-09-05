//! Allocation-conscious replay and normalization for the typed signed-load pilot.

const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const conditional_access = @import("conditional_access_plan.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const polynomial = @import("typed_load_store_polynomial_test_support.zig");
const range_refinement = @import("range_refinement.zig");
const relation = @import("relation.zig");
const typed_load_store = @import("typed_load_store.zig");
const types = @import("types.zig");

pub const ROW_WIDTH: usize = typed_load_store.MAIN_COLUMN_COUNT + 1;
pub const AUTHORED_BINDING_COUNT: usize = ROW_WIDTH;
pub const Fingerprint = polynomial.Fingerprint;
pub const Binding = polynomial.Binding;
pub const eventNumeratorFingerprint = polynomial.eventNumeratorFingerprint;
pub const expectFingerprintEqual = polynomial.expectFingerprintEqual;
pub const fingerprintAt = polynomial.fingerprintAt;
pub const fingerprintProgram = polynomial.fingerprintProgram;

pub const LbCase = struct {
    aligned_address: u32 = 0x2000,
    offset: u2 = 0,
    selected_byte: u8 = 0x80,
    rd: u5 = 4,
    rs1: u5 = 5,
    clock: u32 = 2,
    pc: u32 = 0x1000,
    dst_previous: u32 = 0xa5a5_5a5a,
    rs1_previous_clock: u32 = 0,
    src_previous_clock: u32 = 0,
    dst_previous_clock: u32 = 0,
};

pub fn typedBindings(
    definition: *const typed_load_store.Definition,
) [AUTHORED_BINDING_COUNT]Binding {
    var bindings: [AUTHORED_BINDING_COUNT]Binding = undefined;
    for (
        definition.columns.physical(),
        bindings[0..typed_load_store.MAIN_COLUMN_COUNT],
        0..,
    ) |value, *binding, column| binding.* = .{
        .value = value,
        .column = @intCast(column),
    };
    bindings[typed_load_store.MAIN_COLUMN_COUNT] = .{
        .value = definition.is_active,
        .column = typed_load_store.MAIN_COLUMN_COUNT,
    };
    return bindings;
}

pub fn honestLbRow(case: LbCase) ![ROW_WIDTH]M31 {
    if (case.aligned_address & 3 != 0 or case.aligned_address > 0x3fff_fffc)
        return error.InvalidAlignedAddress;
    var row = [_]M31{M31.zero()} ** ROW_WIDTH;
    row[0] = m(case.clock);
    row[1] = m(case.pc);
    row[2] = m(case.rd);
    writeWord(
        &row,
        3,
        if (case.rd == case.rs1) case.aligned_address else case.dst_previous,
    );
    row[7] = m(case.dst_previous_clock);

    const selected_signed: i8 = @bitCast(case.selected_byte);
    const result: u32 = @bitCast(@as(i32, selected_signed));
    if (case.rd != 0) writeWord(&row, 8, result);

    row[12] = m(case.rs1);
    writeWord(&row, 13, case.aligned_address);
    row[17] = m(case.rs1_previous_clock);
    row[18] = m(case.aligned_address);
    const other_bytes = [_]u8{ 0x11, 0x32, 0x53, 0x74 };
    for (other_bytes, 0..) |byte, index|
        row[19 + index] = m(if (index == case.offset) case.selected_byte else byte);
    row[23] = m(case.src_previous_clock);
    row[24] = m(case.rd);
    row[25] = m(case.offset);
    row[26] = m(case.selected_byte >> 7);
    row[27] = m(case.offset);
    row[28] = m(case.aligned_address);
    row[29] = m(case.rd);
    row[30 + @as(usize, case.offset)] = M31.one();
    row[34] = M31.one();
    writeWord(&row, 42, result);
    if (case.rd != 0) {
        row[46] = M31.one();
        row[47] = m(case.rd).invUncheckedNonZero();
    }
    const word_index = case.aligned_address >> 2;
    row[48] = m(word_index);
    row[49] = m(word_index & ((1 << 20) - 1));
    row[50] = M31.one();
    return row;
}

pub fn paddingRow() [ROW_WIDTH]M31 {
    return [_]M31{M31.zero()} ** ROW_WIDTH;
}

pub fn evaluateInto(
    arena: *const ir.Arena,
    bindings: []const Binding,
    columns: []const M31,
    values: []M31,
) !void {
    if (values.len != arena.nodeCount()) return error.InvalidScratchShape;
    for (arena.nodesView(), 0..) |node, index| {
        const id = try types.idFromIndex(types.ValueId, index);
        values[index] = if (columnFor(bindings, id)) |column|
            columns[column]
        else if (aliasSource(arena, id)) |alias|
            at(values, alias)
        else switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field, .unsigned => |value| M31.fromU64(value),
            },
            .add => |binary| at(values, binary.lhs).add(at(values, binary.rhs)),
            .sub => |binary| at(values, binary.lhs).sub(at(values, binary.rhs)),
            .mul => |binary| at(values, binary.lhs).mul(at(values, binary.rhs)),
            .neg => |value| at(values, value).neg(),
            .select => |selection| if (at(values, selection.selector).isZero())
                at(values, selection.when_false)
            else
                at(values, selection.when_true),
            .machine_derived => |derived| evaluateMachine(values, derived),
            .input => return error.UnmappedInput,
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
}

pub fn rowAccepted(
    definition: *const typed_load_store.Definition,
    values: []const M31,
) bool {
    if (!directConstraintsZero(definition, values)) return false;
    for (definition.arena.effectsView(), 0..) |effect, index| {
        const liveness = effect.liveness orelse return false;
        if (at(values, liveness).isZero()) continue;
        const effect_id = types.idFromIndex(types.EffectId, index) catch return false;
        const fields = definition.arena.effectValues(effect_id) orelse return false;
        const valid = switch (relation.getById(effect.binding.?.schema).?.domain) {
            .range_check_20 => canonical(at(values, fields[0])) < 1 << 20,
            .range_check_m31 => canonical(at(values, fields[0])) < 256 and
                canonical(at(values, fields[1])) < 128,
            .range_check_8_8 => canonical(at(values, fields[0])) < 256 and
                canonical(at(values, fields[1])) < 256,
            else => true,
        };
        if (!valid) return false;
    }
    return true;
}

pub fn directConstraintsZero(
    definition: *const typed_load_store.Definition,
    values: []const M31,
) bool {
    for (definition.model.constraints) |id| {
        const constraint = definition.arena.constraint(id) orelse return false;
        if (!at(values, constraint.root).isZero()) return false;
    }
    return true;
}

pub fn effectFields(
    definition: *const typed_load_store.Definition,
    index: usize,
) []const types.ValueId {
    const effect = types.idFromIndex(types.EffectId, index) catch unreachable;
    return definition.arena.effectValues(effect).?;
}

pub fn eventNumeratorValue(values: []const M31, effect: program.Effect) M31 {
    const liveness = at(values, effect.liveness.?);
    return switch (effect.binding.?.role) {
        .emit => liveness,
        .request, .consume => liveness.neg(),
    };
}

fn aliasSource(arena: *const ir.Arena, value: types.ValueId) ?types.ValueId {
    return range_refinement.sourceForTarget(arena, value) orelse
        conditional_access.sourceForTarget(arena, value);
}

fn evaluateMachine(values: []const M31, derived: expr.MachineDerived) M31 {
    return switch (derived) {
        .register_address => |item| at(values, item.index),
        .aligned_word_address => |item| at(values, item.word_index).mul(m(4)),
        .access_clock => |item| at(values, item.instruction_clock)
            .sub(M31.one()).mul(m(4)).add(m(@intFromEnum(item.phase))),
        .strict_clock_gap => |item| at(values, item.current_clock)
            .sub(at(values, item.previous_clock)).sub(M31.one()),
        .instruction_next_pc => |item| at(values, item.current).add(m(4)),
        .instruction_next_clock => |item| at(values, item.current).add(M31.one()),
    };
}

fn writeWord(row: []M31, start: usize, word: u32) void {
    for (0..4) |index|
        row[start + index] = m((word >> @intCast(8 * index)) & 0xff);
}

fn m(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

fn at(values: []const M31, id: types.ValueId) M31 {
    return values[types.idIndex(id)];
}

fn canonical(value: M31) u32 {
    return value.toU32();
}

fn columnFor(bindings: []const Binding, value: types.ValueId) ?usize {
    for (bindings) |binding| if (binding.value == value) return binding.column;
    return null;
}
