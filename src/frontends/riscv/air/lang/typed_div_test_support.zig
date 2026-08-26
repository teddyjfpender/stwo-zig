//! Allocation-conscious replay and normalization for typed DIV pilot tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const corpus = @import("typed_div_corpus.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const relation = @import("relation.zig");
const typed_div = @import("typed_div.zig");
const types = @import("types.zig");

pub const ROW_WIDTH: usize = typed_div.MAIN_COLUMN_COUNT + 1;
pub const AUTHORED_BINDING_COUNT: usize = ROW_WIDTH;
pub const Fingerprint = [32]u8;
pub const Binding = struct { value: types.ValueId, column: u32 };
pub const OperandClass = corpus.OperandClass;
pub const OPERAND_CLASS_COUNT = corpus.OPERAND_CLASS_COUNT;
pub const CORPUS_ROW_COUNT = corpus.CORPUS_ROW_COUNT;
pub const operandClass = corpus.operandClass;
pub const opcode = corpus.opcode;
pub const honestRow = corpus.honestRow;

pub fn typedBindings(
    definition: *const typed_div.Definition,
) [AUTHORED_BINDING_COUNT]Binding {
    var bindings: [AUTHORED_BINDING_COUNT]Binding = undefined;
    for (definition.columns.physical(), bindings[0..typed_div.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed_div.MAIN_COLUMN_COUNT] = .{
        .value = definition.is_active,
        .column = typed_div.MAIN_COLUMN_COUNT,
    };
    return bindings;
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
            .input => return error.UnmappedInput,
            .machine_derived => |derived| evaluateDerived(values, derived),
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
}

pub fn rowAccepted(definition: *const typed_div.Definition, values: []const M31) bool {
    if (!directConstraintsZero(definition, values)) return false;
    for (definition.arena.effectsView(), 0..) |effect, index| {
        const liveness = effect.liveness orelse return false;
        if (at(values, liveness).isZero()) continue;
        const id = types.idFromIndex(types.EffectId, index) catch return false;
        const fields = definition.arena.effectValues(id) orelse return false;
        const binding = effect.binding orelse return false;
        const valid = switch (relation.getById(binding.schema).?.domain) {
            .range_check_20 => canonical(at(values, fields[0])) < 1 << 20,
            .range_check_8_11 => canonical(at(values, fields[0])) < 256 and
                canonical(at(values, fields[1])) < 1 << 11,
            .range_check_8_8 => canonical(at(values, fields[0])) < 256 and
                canonical(at(values, fields[1])) < 256,
            .range_check_m31 => canonical(at(values, fields[0])) < 256 and
                canonical(at(values, fields[1])) < 128,
            else => true,
        };
        if (!valid) return false;
    }
    return true;
}

pub fn directConstraintsZero(
    definition: *const typed_div.Definition,
    values: []const M31,
) bool {
    for (definition.model.constraints) |id| {
        const root = definition.arena.constraint(id) orelse return false;
        if (!at(values, root.root).isZero()) return false;
    }
    return true;
}

pub fn fingerprintProgram(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    bindings: []const Binding,
) ![]Fingerprint {
    const fingerprints = try allocator.alloc(Fingerprint, arena.nodeCount());
    errdefer allocator.free(fingerprints);
    for (arena.nodesView(), 0..) |node, index| {
        const id = try types.idFromIndex(types.ValueId, index);
        fingerprints[index] = if (columnFor(bindings, id)) |column|
            scalarFingerprint(0, @intCast(column))
        else switch (node.key.op) {
            .constant => |constant| scalarFingerprint(1, switch (constant) {
                .field, .unsigned => |value| value,
            }),
            .add => |binary| binaryFingerprint(
                2,
                fingerprintAt(fingerprints, binary.lhs),
                fingerprintAt(fingerprints, binary.rhs),
                true,
            ),
            .sub => |binary| binaryFingerprint(
                3,
                fingerprintAt(fingerprints, binary.lhs),
                fingerprintAt(fingerprints, binary.rhs),
                false,
            ),
            .mul => |binary| binaryFingerprint(
                4,
                fingerprintAt(fingerprints, binary.lhs),
                fingerprintAt(fingerprints, binary.rhs),
                true,
            ),
            .neg => |value| unaryFingerprint(5, fingerprintAt(fingerprints, value)),
            .select => |selection| selectFingerprint(fingerprints, selection),
            .input => return error.UnmappedInput,
            .machine_derived => |derived| derivedFingerprint(fingerprints, derived),
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
    return fingerprints;
}

pub fn fingerprintAt(values: []const Fingerprint, id: types.ValueId) Fingerprint {
    return values[types.idIndex(id)];
}

fn evaluateDerived(values: []const M31, derived: expr.MachineDerived) M31 {
    return switch (derived) {
        .register_address => |address| at(values, address.index),
        .aligned_word_address => |address| at(values, address.word_index)
            .mul(M31.fromCanonical(4)),
        .access_clock => |clock| at(values, clock.instruction_clock)
            .sub(M31.one()).mul(M31.fromCanonical(4))
            .add(M31.fromCanonical(@intFromEnum(clock.phase))),
        .strict_clock_gap => |gap| at(values, gap.current_clock)
            .sub(at(values, gap.previous_clock)).sub(M31.one()),
        .instruction_next_pc => |next| at(values, next.current)
            .add(M31.fromCanonical(4)),
        .instruction_next_clock => |next| at(values, next.current).add(M31.one()),
    };
}

fn derivedFingerprint(values: []const Fingerprint, derived: expr.MachineDerived) Fingerprint {
    const one = scalarFingerprint(1, 1);
    const four = scalarFingerprint(1, 4);
    return switch (derived) {
        .register_address => |address| fingerprintAt(values, address.index),
        .aligned_word_address => |address| binaryFingerprint(
            4,
            fingerprintAt(values, address.word_index),
            four,
            true,
        ),
        .access_clock => |clock| binaryFingerprint(
            2,
            binaryFingerprint(
                4,
                binaryFingerprint(
                    3,
                    fingerprintAt(values, clock.instruction_clock),
                    one,
                    false,
                ),
                four,
                true,
            ),
            scalarFingerprint(1, @intFromEnum(clock.phase)),
            true,
        ),
        .strict_clock_gap => |gap| binaryFingerprint(
            3,
            binaryFingerprint(
                3,
                fingerprintAt(values, gap.current_clock),
                fingerprintAt(values, gap.previous_clock),
                false,
            ),
            one,
            false,
        ),
        .instruction_next_pc => |next| binaryFingerprint(
            2,
            fingerprintAt(values, next.current),
            four,
            true,
        ),
        .instruction_next_clock => |next| binaryFingerprint(
            2,
            fingerprintAt(values, next.current),
            one,
            true,
        ),
    };
}

fn selectFingerprint(values: []const Fingerprint, selection: expr.Selection) Fingerprint {
    const difference = binaryFingerprint(
        3,
        fingerprintAt(values, selection.when_true),
        fingerprintAt(values, selection.when_false),
        false,
    );
    return binaryFingerprint(
        2,
        fingerprintAt(values, selection.when_false),
        binaryFingerprint(
            4,
            fingerprintAt(values, selection.selector),
            difference,
            true,
        ),
        true,
    );
}

pub fn unaryFingerprint(tag: u8, value: Fingerprint) Fingerprint {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&.{tag});
    hash.update(&value);
    return hash.finalResult();
}

fn scalarFingerprint(tag: u8, value: u32) Fingerprint {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&.{tag});
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
    return hash.finalResult();
}

fn binaryFingerprint(
    tag: u8,
    first_unordered: Fingerprint,
    second_unordered: Fingerprint,
    commutative: bool,
) Fingerprint {
    var first = first_unordered;
    var second = second_unordered;
    if (commutative and std.mem.order(u8, &first, &second) == .gt)
        std.mem.swap(Fingerprint, &first, &second);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&.{tag});
    hash.update(&first);
    hash.update(&second);
    return hash.finalResult();
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
