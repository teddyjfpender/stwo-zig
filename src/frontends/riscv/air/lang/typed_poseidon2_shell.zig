//! Canonical function-shell checks for the typed Poseidon2 adapter.

const std = @import("std");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const poseidon = @import("typed_poseidon2.zig");
const types = @import("types.zig");

pub const Error = error{CanonicalDefinitionMismatch};

pub fn validate(
    arena: *const ir.Arena,
    definition: poseidon.Definition,
) Error!void {
    const declared = functions.get(arena, definition.function) orelse
        return error.CanonicalDefinitionMismatch;
    const declared_name = arena.name(declared.name) orelse
        return error.CanonicalDefinitionMismatch;
    const inputs = functions.inputs(arena, definition.function) orelse
        return error.CanonicalDefinitionMismatch;
    const outputs = functions.outputs(arena, definition.function) orelse
        return error.CanonicalDefinitionMismatch;
    const expected_inputs = poseidon.values(definition.inputs);
    const expected_outputs = poseidon.values(definition.outputs);
    if (!declared.complete or
        !std.mem.eql(u8, declared_name, poseidon.function_name) or
        !std.mem.eql(types.ValueId, inputs, &expected_inputs) or
        !std.mem.eql(types.ValueId, outputs, &expected_outputs))
    {
        return error.CanonicalDefinitionMismatch;
    }
    for (expected_inputs, poseidon.input_names) |value, expected_name| {
        const node = arena.node(value) orelse return error.CanonicalDefinitionMismatch;
        const name = switch (node.key.op) {
            .input => |name_id| arena.name(name_id) orelse
                return error.CanonicalDefinitionMismatch,
            else => return error.CanonicalDefinitionMismatch,
        };
        if (!std.meta.eql(node.key.ty, types.Type.felt) or
            !std.mem.eql(u8, name, expected_name))
        {
            return error.CanonicalDefinitionMismatch;
        }
    }
}
