//! Authenticated relation binding shared by the two exact control slices.

const compiler = @import("relation_interaction.zig");
const types = @import("../../air/lang/types.zig");

pub fn Binding(comptime Air: type) type {
    return struct {
        pub const Runtime = compiler.Runtime(
            Air.LOGICAL_INPUT_COUNT,
            Air.RELATION_EVENT_COUNT,
            Air.LOOKUP_BATCH_SIZE,
        );
        pub const Plan = Runtime.Plan;
        pub const Row = Runtime.Row;
        pub const Entry = compiler.Entry;
        pub const Claims = Runtime.Claims;
        pub const Interaction = Runtime.Interaction;

        pub fn authenticate(definition: *const Air.Definition) !Plan {
            try definition.validate();
            return Runtime.authenticate(
                &definition.arena,
                Air.SEMANTIC_DIGEST,
                .{definition.event},
            );
        }

        pub fn events(
            definition: *const Air.Definition,
        ) [Air.RELATION_EVENT_COUNT]types.EffectId {
            return .{definition.event};
        }

        comptime {
            if (Runtime.BATCH_COUNT != Air.INTERACTION_BATCH_COUNT or
                Runtime.INTERACTION_COLUMN_COUNT != Air.INTERACTION_COLUMN_COUNT)
            {
                @compileError("control-slice interaction geometry drifted");
            }
        }
    };
}
