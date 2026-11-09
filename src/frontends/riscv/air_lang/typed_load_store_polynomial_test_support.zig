//! Canonical polynomial fingerprints for the native load/store differential.

const std = @import("std");
const conditional_access = @import("conditional_access_plan.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const range_refinement = @import("range_refinement.zig");
const types = @import("types.zig");

pub const Fingerprint = [32]u8;
pub const Binding = struct { value: types.ValueId, column: u32 };

pub fn eventNumeratorFingerprint(
    fingerprints: []const Fingerprint,
    effect: program.Effect,
) Fingerprint {
    const liveness = fingerprintAt(fingerprints, effect.liveness.?);
    return switch (effect.binding.?.role) {
        .emit => liveness,
        .request, .consume => unaryFingerprint(5, liveness),
    };
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
        else if (aliasSource(arena, id)) |alias|
            fingerprintAt(fingerprints, alias)
        else switch (node.key.op) {
            .constant => |constant| scalarFingerprint(1, switch (constant) {
                .field, .unsigned => |value| value,
            }),
            .add => |item| binaryFingerprint(
                2,
                fingerprintAt(fingerprints, item.lhs),
                fingerprintAt(fingerprints, item.rhs),
                true,
            ),
            .sub => |item| binaryFingerprint(
                3,
                fingerprintAt(fingerprints, item.lhs),
                fingerprintAt(fingerprints, item.rhs),
                false,
            ),
            .mul => |item| binaryFingerprint(
                4,
                fingerprintAt(fingerprints, item.lhs),
                fingerprintAt(fingerprints, item.rhs),
                true,
            ),
            .neg => |value| unaryFingerprint(5, fingerprintAt(fingerprints, value)),
            .select => |selection| selectFingerprint(fingerprints, selection),
            .machine_derived => |derived| machineFingerprint(fingerprints, derived),
            .input => return error.UnmappedInput,
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
    return fingerprints;
}

pub fn fingerprintAt(values: []const Fingerprint, id: types.ValueId) Fingerprint {
    return values[types.idIndex(id)];
}

pub fn expectFingerprintEqual(
    expected: []const Fingerprint,
    expected_id: types.ValueId,
    actual: []const Fingerprint,
    actual_id: ?types.ValueId,
    event_index: usize,
    field: ?usize,
    actual_override: ?Fingerprint,
) !void {
    const wanted = fingerprintAt(expected, expected_id);
    const observed = actual_override orelse fingerprintAt(actual, actual_id.?);
    if (std.mem.eql(u8, &wanted, &observed)) return;
    if (field) |field_index| {
        std.log.err("load/store event fingerprint mismatch at {d}:{d}", .{
            event_index,
            field_index,
        });
    } else {
        std.log.err("load/store numerator fingerprint mismatch at {d}", .{event_index});
    }
    return error.EventFingerprintMismatch;
}

fn aliasSource(arena: *const ir.Arena, value: types.ValueId) ?types.ValueId {
    return range_refinement.sourceForTarget(arena, value) orelse
        conditional_access.sourceForTarget(arena, value);
}

fn machineFingerprint(values: []const Fingerprint, derived: expr.MachineDerived) Fingerprint {
    const one = scalarFingerprint(1, 1);
    const four = scalarFingerprint(1, 4);
    return switch (derived) {
        .register_address => |item| fingerprintAt(values, item.index),
        .aligned_word_address => |item| binaryFingerprint(
            4,
            fingerprintAt(values, item.word_index),
            four,
            true,
        ),
        .access_clock => |item| binaryFingerprint(
            2,
            binaryFingerprint(
                4,
                binaryFingerprint(
                    3,
                    fingerprintAt(values, item.instruction_clock),
                    one,
                    false,
                ),
                four,
                true,
            ),
            scalarFingerprint(1, @intFromEnum(item.phase)),
            true,
        ),
        .strict_clock_gap => |item| binaryFingerprint(
            3,
            binaryFingerprint(
                3,
                fingerprintAt(values, item.current_clock),
                fingerprintAt(values, item.previous_clock),
                false,
            ),
            one,
            false,
        ),
        .instruction_next_pc => |item| binaryFingerprint(
            2,
            fingerprintAt(values, item.current),
            four,
            true,
        ),
        .instruction_next_clock => |item| binaryFingerprint(
            2,
            fingerprintAt(values, item.current),
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

fn unaryFingerprint(tag: u8, value: Fingerprint) Fingerprint {
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

fn columnFor(bindings: []const Binding, value: types.ValueId) ?usize {
    for (bindings) |binding| if (binding.value == value) return binding.column;
    return null;
}
