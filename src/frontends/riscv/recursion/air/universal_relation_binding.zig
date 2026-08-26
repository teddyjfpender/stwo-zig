//! Component-agnostic binding from typed relation effects to the universal
//! recursion challenge bundle.
//!
//! Most logical recursion rows already expose a small component-local facade
//! over `relation_interaction.Runtime`.  The three `wire(6)` arithmetic rows
//! predate that universal compiler and retain a dedicated interaction API.
//! This factory admits them without copying a tuple, weight, denominator, or
//! batching rule: all four are compiled from the authenticated typed arena.

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
                events(definition),
            );
        }

        pub fn events(
            definition: *const Air.Definition,
        ) [Air.RELATION_EVENT_COUNT]types.EffectId {
            if (comptime @hasField(Air.Definition, "events")) {
                const Events = @TypeOf(definition.events);
                if (comptime @typeInfo(Events) == .array)
                    return definition.events;
                if (comptime @hasDecl(Events, "ordered"))
                    return definition.events.ordered();
            }
            if (comptime Air.RELATION_EVENT_COUNT == 1 and
                @hasField(Air.Definition, "event"))
            {
                return .{definition.event};
            }
            @compileError("typed recursion relation has no canonical event order");
        }

        comptime {
            if (Runtime.BATCH_COUNT != Air.INTERACTION_BATCH_COUNT or
                Runtime.INTERACTION_COLUMN_COUNT != Air.INTERACTION_COLUMN_COUNT)
            {
                @compileError("universal relation binding geometry drifted");
            }
        }
    };
}
