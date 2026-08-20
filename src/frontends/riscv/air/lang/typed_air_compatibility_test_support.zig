//! Structural fingerprint helpers for native typed/production AIR parity.

const std = @import("std");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const range_refinement = @import("range_refinement.zig");
const types = @import("types.zig");

pub const Fingerprint = [32]u8;
pub const Binding = struct { value: types.ValueId, column: u32 };

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
            scalar(0, @intCast(column))
        else switch (node.key.op) {
            .constant => |constant| scalar(1, switch (constant) {
                .field, .unsigned => |value| value,
            }),
            .add => |binary| binaryHash(
                2,
                at(fingerprints, binary.lhs),
                at(fingerprints, binary.rhs),
                true,
            ),
            .sub => |binary| binaryHash(
                3,
                at(fingerprints, binary.lhs),
                at(fingerprints, binary.rhs),
                false,
            ),
            .mul => |binary| binaryHash(
                4,
                at(fingerprints, binary.lhs),
                at(fingerprints, binary.rhs),
                true,
            ),
            .neg => |value| unary(5, at(fingerprints, value)),
            .select => |selection| selectFingerprint(fingerprints, selection),
            .machine_derived => |derived| derivedFingerprint(fingerprints, derived),
            .input => if (range_refinement.sourceForTarget(arena, id)) |source_value|
                at(fingerprints, source_value)
            else
                return error.UnmappedInput,
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
    return fingerprints;
}

pub fn at(values: []const Fingerprint, id: types.ValueId) Fingerprint {
    return values[types.idIndex(id)];
}

pub fn unary(tag: u8, value: Fingerprint) Fingerprint {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&.{tag});
    hash.update(&value);
    return hash.finalResult();
}

fn derivedFingerprint(values: []const Fingerprint, derived: expr.MachineDerived) Fingerprint {
    const one = scalar(1, 1);
    const four = scalar(1, 4);
    return switch (derived) {
        .register_address => |address| at(values, address.index),
        .aligned_word_address => |address| binaryHash(
            4,
            at(values, address.word_index),
            four,
            true,
        ),
        .access_clock => |clock| binaryHash(
            2,
            binaryHash(
                4,
                binaryHash(3, at(values, clock.instruction_clock), one, false),
                four,
                true,
            ),
            scalar(1, @intFromEnum(clock.phase)),
            true,
        ),
        .strict_clock_gap => |gap| binaryHash(
            3,
            binaryHash(
                3,
                at(values, gap.current_clock),
                at(values, gap.previous_clock),
                false,
            ),
            one,
            false,
        ),
        .instruction_next_pc => |next| binaryHash(
            2,
            at(values, next.current),
            four,
            true,
        ),
        .instruction_next_clock => |next| binaryHash(
            2,
            at(values, next.current),
            one,
            true,
        ),
    };
}

fn selectFingerprint(values: []const Fingerprint, selection: expr.Selection) Fingerprint {
    const difference = binaryHash(
        3,
        at(values, selection.when_true),
        at(values, selection.when_false),
        false,
    );
    return binaryHash(
        2,
        at(values, selection.when_false),
        binaryHash(4, at(values, selection.selector), difference, true),
        true,
    );
}

fn scalar(tag: u8, value: u32) Fingerprint {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&.{tag});
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
    return hash.finalResult();
}

fn binaryHash(
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
