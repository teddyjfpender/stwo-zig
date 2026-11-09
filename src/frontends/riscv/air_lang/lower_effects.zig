//! Allocation-free projection of validated typed effects into relation events.

const ir = @import("ir.zig");
const program = @import("program.zig");
const types = @import("types.zig");
const validate_mod = @import("validate.zig");

pub const EventView = struct {
    effect: types.EffectId,
    kind: program.EffectKind,
    schema: types.RelationSchemaId,
    schema_version: u16,
    role: types.RelationRole,
    liveness: types.ValueId,
    values: []const types.ValueId,
    access_ordinal: ?u8,
};

/// Borrowed proof that the arena passed whole-program validation.
///
/// The owner must not mutate or deinitialize the arena while this capability
/// or any `EventView` derived from it remains in use. Construction is a cold,
/// allocation-free validation pass; projection and iteration remain O(1) per
/// visited effect with no dynamic dispatch or allocation.
pub const ValidatedProgram = struct {
    arena: *const ir.Arena,

    pub fn init(arena: *const ir.Arena) validate_mod.Error!ValidatedProgram {
        try validate_mod.validate(arena);
        return .{ .arena = arena };
    }

    pub fn event(self: ValidatedProgram, effect_id: types.EffectId) ?EventView {
        return project(self.arena, effect_id);
    }

    pub fn iterator(self: ValidatedProgram) Iterator {
        return .{ .program = self };
    }
};

fn project(arena: *const ir.Arena, effect_id: types.EffectId) ?EventView {
    const effect = arena.effect(effect_id) orelse return null;
    const binding = effect.binding orelse return null;
    // Keep this borrowed projection fail-closed even if a caller violates the
    // documented validate-before-lower boundary. The valid path is still two
    // predictable optional checks and performs no allocation.
    const liveness = effect.liveness orelse return null;
    const values = arena.effectValues(effect_id) orelse return null;
    return .{
        .effect = effect_id,
        .kind = effect.kind,
        .schema = binding.schema,
        .schema_version = binding.schema_version,
        .role = binding.role,
        .liveness = liveness,
        .values = values,
        .access_ordinal = effect.access_ordinal,
    };
}

/// Numeric iterator that skips non-relation effects while retaining declared
/// order.  It performs no name lookup, hashing, dispatch by string, or heap work.
pub const Iterator = struct {
    program: ValidatedProgram,
    cursor: usize = 0,

    pub fn next(self: *Iterator) ?EventView {
        while (self.cursor < self.program.arena.effectsView().len) {
            const index = self.cursor;
            self.cursor += 1;
            const id = types.idFromIndex(types.EffectId, index) catch return null;
            if (project(self.program.arena, id)) |event| return event;
        }
        return null;
    }
};
