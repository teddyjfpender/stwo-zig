//! Canonical primitive and record encoders for typed-AIR manifests.

const std = @import("std");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub fn writeFunctionBody(writer: anytype, body: ?program.FunctionBody) !void {
    if (body) |present| {
        try writeInt(writer, u8, 1);
        inline for (.{
            present.constraints,
            present.effects,
            present.hints,
            present.calls,
        }) |range| {
            try writeInt(writer, u32, range.start);
            try writeInt(writer, u32, range.len);
        }
    } else {
        try writeInt(writer, u8, 0);
    }
}

pub fn writeCommittedProgramControlTarget(
    writer: anytype,
    arena: *const ir.Arena,
    proof: program.CommittedProgramControlTargetProof,
) !void {
    try writeInt(writer, u32, @intFromEnum(proof.program_effect));
    inline for (.{
        proof.current_pc,
        proof.current_pc_polynomial,
        proof.offset,
        proof.condition,
    }) |value| try writeValueId(writer, value);
    try writeInt(writer, u32, @intFromEnum(proof.condition_constraint));
    try writeValueId(writer, proof.committed_target);
    try writeValueId(writer, proof.committed_target_polynomial);
    try writeInt(writer, u32, @intFromEnum(proof.target_constraint));
    try writeValueId(writer, proof.liveness);
    try writeSpan(writer, arena, proof.source_span);
}

pub fn writeConditionalAccessPlan(
    writer: anytype,
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
) !void {
    try writeInt(writer, u32, @intFromEnum(proof.first_effect));
    try writeInt(writer, u32, @intFromEnum(proof.aligned_range));
    try writeInt(writer, u32, @intFromEnum(proof.base_range));
    inline for (.{
        proof.active_source,
        proof.active,
        proof.store_source,
        proof.store_selector,
        proof.is_load,
        proof.instruction_clock,
        proof.second_clock,
        proof.memory_address,
        proof.shift_amount,
        proof.register_index,
        proof.word_source,
        proof.word_index,
        proof.base_low,
        proof.base_high,
    }) |value| try writeValueId(writer, value);
    try writeInt(writer, u32, @intFromEnum(proof.source_address_constraint));
    try writeInt(writer, u32, @intFromEnum(proof.destination_address_constraint));
    inline for (.{
        proof.source_address,
        proof.source_clock,
        proof.source_gap,
        proof.destination_address,
        proof.destination_clock,
        proof.destination_gap,
    }) |alias| {
        try writeValueId(writer, alias.source);
        try writeValueId(writer, alias.target);
    }
    try writeSpan(writer, arena, proof.source_span);
}

pub fn writeRelationBinding(
    writer: anytype,
    binding: ?program.RelationBinding,
) !void {
    if (binding) |present| {
        try writeInt(writer, u8, 1);
        try writeInt(writer, u16, @intFromEnum(present.schema));
        try writeInt(writer, u16, present.schema_version);
        try writeInt(writer, u8, @intFromEnum(present.role));
    } else {
        try writeInt(writer, u8, 0);
    }
}

pub fn writeNode(writer: anytype, arena: *const ir.Arena, node: expr.Node) !void {
    try writeType(writer, node.key.ty);
    switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| {
                try writeInt(writer, u8, 0);
                try writeInt(writer, u32, value);
            },
            .unsigned => |value| {
                try writeInt(writer, u8, 1);
                try writeInt(writer, u32, value);
            },
        },
        .input => |name| {
            try writeInt(writer, u8, 2);
            try writeName(writer, arena, name);
        },
        .add => |binary| {
            try writeInt(writer, u8, 3);
            try writeBinary(writer, binary);
        },
        .sub => |binary| {
            try writeInt(writer, u8, 4);
            try writeBinary(writer, binary);
        },
        .mul => |binary| {
            try writeInt(writer, u8, 5);
            try writeBinary(writer, binary);
        },
        .neg => |value| {
            try writeInt(writer, u8, 6);
            try writeValueId(writer, value);
        },
        .select => |selection| {
            try writeInt(writer, u8, 7);
            try writeValueId(writer, selection.selector);
            try writeValueId(writer, selection.when_true);
            try writeValueId(writer, selection.when_false);
        },
        .hint_output => |output| {
            try writeInt(writer, u8, 8);
            try writeInt(writer, u32, @intFromEnum(output.hint));
            try writeInt(writer, u16, output.index);
        },
        .call_output => |output| {
            try writeInt(writer, u8, 9);
            try writeInt(writer, u32, @intFromEnum(output.call));
            try writeInt(writer, u16, output.index);
        },
        .machine_derived => |derived| {
            try writeInt(writer, u8, 10);
            switch (derived) {
                .register_address => |address| {
                    try writeInt(writer, u8, 0);
                    try writeValueId(writer, address.index);
                },
                .aligned_word_address => |address| {
                    try writeInt(writer, u8, 3);
                    try writeValueId(writer, address.word_index);
                },
                .access_clock => |clock| {
                    try writeInt(writer, u8, 1);
                    try writeValueId(writer, clock.instruction_clock);
                    try writeInt(writer, u8, @intFromEnum(clock.phase));
                },
                .strict_clock_gap => |gap| {
                    try writeInt(writer, u8, 2);
                    try writeValueId(writer, gap.current_clock);
                    try writeValueId(writer, gap.previous_clock);
                    try writeValueId(writer, gap.active);
                    try writeInt(writer, u8, @intFromEnum(gap.phase));
                },
                .instruction_next_pc => |next| {
                    try writeInt(writer, u8, 4);
                    try writeValueId(writer, next.current);
                },
                .instruction_next_clock => |next| {
                    try writeInt(writer, u8, 5);
                    try writeValueId(writer, next.current);
                },
            }
        },
    }
    try writeSpan(writer, arena, node.primary_source);
}

pub fn writeType(writer: anytype, ty: types.Type) !void {
    switch (ty) {
        .felt => try writeInt(writer, u8, 0),
        .bit => try writeInt(writer, u8, 1),
        .byte => try writeInt(writer, u8, 2),
        .uint16 => try writeInt(writer, u8, 3),
        .uint20 => try writeInt(writer, u8, 4),
        .word32 => try writeInt(writer, u8, 5),
        .register_index => try writeInt(writer, u8, 6),
        .address => try writeInt(writer, u8, 7),
        .pc => try writeInt(writer, u8, 8),
        .clock => try writeInt(writer, u8, 9),
        .selector => try writeInt(writer, u8, 10),
        .bounded_uint => |bounded| {
            try writeInt(writer, u8, 11);
            try writeInt(writer, u8, bounded.bits);
            switch (bounded.representation) {
                .canonical_field => try writeInt(writer, u8, 0),
                .little_endian_limbs => |layout| {
                    try writeInt(writer, u8, 1);
                    try writeInt(writer, u8, layout.limb_bits);
                    try writeInt(writer, u8, layout.limb_count);
                },
            }
        },
        .array => |array| {
            try writeInt(writer, u8, 12);
            try writeInt(writer, u8, arrayElementTag(array.element));
            try writeInt(writer, u16, array.len);
        },
    }
}

pub fn writeSpan(
    writer: anytype,
    arena: *const ir.Arena,
    span: source.SourceSpan,
) !void {
    if (span.source) |source_id| {
        try writeInt(writer, u8, 1);
        try writeString(writer, arena.sourcePath(source_id).?);
        try writePosition(writer, span.start);
        try writePosition(writer, span.end);
    } else {
        try writeInt(writer, u8, 0);
    }
}

pub fn writePosition(writer: anytype, position: source.Position) !void {
    try writeInt(writer, u32, position.byte_offset);
    try writeInt(writer, u32, position.line);
    try writeInt(writer, u32, position.column);
}

pub fn writeName(writer: anytype, arena: *const ir.Arena, id: types.NameId) !void {
    try writeString(writer, arena.name(id).?);
}

pub fn writeString(writer: anytype, value: []const u8) !void {
    try writeCount(writer, value.len);
    try writer.writeAll(value);
}

pub fn writeValues(writer: anytype, values: []const types.ValueId) !void {
    try writeCount(writer, values.len);
    for (values) |value| try writeValueId(writer, value);
}

pub fn writeBinary(writer: anytype, binary: expr.Binary) !void {
    try writeValueId(writer, binary.lhs);
    try writeValueId(writer, binary.rhs);
}

pub fn writeValueId(writer: anytype, id: types.ValueId) !void {
    try writeInt(writer, u32, @intFromEnum(id));
}

pub fn writeOptionalValueId(writer: anytype, id: ?types.ValueId) !void {
    if (id) |value| {
        try writeInt(writer, u8, 1);
        try writeValueId(writer, value);
    } else {
        try writeInt(writer, u8, 0);
    }
}

pub fn writeOptionalFunctionId(writer: anytype, id: ?types.FunctionId) !void {
    if (id) |value| {
        try writeInt(writer, u8, 1);
        try writeInt(writer, u32, @intFromEnum(value));
    } else {
        try writeInt(writer, u8, 0);
    }
}

pub fn writeHintBindingTarget(
    writer: anytype,
    target: program.HintBindingTarget,
) !void {
    switch (target) {
        .constraint => |id| {
            try writeInt(writer, u8, 0);
            try writeInt(writer, u32, @intFromEnum(id));
        },
        .effect => |id| {
            try writeInt(writer, u8, 1);
            try writeInt(writer, u32, @intFromEnum(id));
        },
    }
}

pub fn writeOptionalInt(writer: anytype, comptime T: type, value: ?T) !void {
    if (value) |present| {
        try writeInt(writer, u8, 1);
        try writeInt(writer, T, present);
    } else {
        try writeInt(writer, u8, 0);
    }
}

pub fn writeCount(writer: anytype, value: usize) !void {
    const count = std.math.cast(u32, value) orelse
        return error.ManifestTooLarge;
    try writeInt(writer, u32, count);
}

pub fn writeInt(writer: anytype, comptime T: type, value: T) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try writer.writeAll(&encoded);
}

pub fn arrayElementTag(element: types.ArrayElement) u8 {
    return switch (element) {
        .felt => 0,
        .bit => 1,
        .byte => 2,
        .uint16 => 3,
        .uint20 => 4,
        .word32 => 5,
        .register_index => 6,
        .address => 7,
        .pc => 8,
        .clock => 9,
        .selector => 10,
    };
}

pub fn constraintCategoryTag(category: program.ConstraintCategory) u8 {
    return switch (category) {
        .semantic => 0,
        .materialization => 1,
        .type_range => 2,
        .hint_binding => 3,
        .boundary => 4,
        .transition => 5,
        .relation_transition => 6,
    };
}

pub fn effectKindTag(kind: program.EffectKind) u8 {
    return switch (kind) {
        .program_fetch => 0,
        .register_read => 1,
        .register_write => 2,
        .memory_read => 3,
        .memory_write => 4,
        .range_request => 5,
        .state_consume => 6,
        .state_produce => 7,
        .component_call => 8,
        .public_consume => 9,
        .public_produce => 10,
        .bitwise_request => 11,
    };
}

pub fn callStrategyTag(strategy: program.CallStrategy) u8 {
    return switch (strategy) {
        .inline_expansion => 0,
        .relation_backed => 1,
    };
}
