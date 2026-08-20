//! Allocation-free capability probes shared by semantic identities and wire
//! manifests. These identify representation features, never proof validity;
//! callers must validate the arena before selecting a version.

const std = @import("std");
const ir = @import("ir.zig");
const types = @import("types.zig");

pub fn hasRelationBindings(arena: *const ir.Arena) bool {
    for (arena.effectsView()) |effect| if (effect.binding != null) return true;
    return false;
}

pub fn hasMachineDerivedNodes(arena: *const ir.Arena) bool {
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => return true,
        else => {},
    };
    return false;
}

pub fn hasMemoryAccess(arena: *const ir.Arena) bool {
    for (arena.effectsView()) |effect| switch (effect.kind) {
        .memory_read, .memory_write => return true,
        else => {},
    };
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => |derived| switch (derived) {
            .aligned_word_address => return true,
            else => {},
        },
        else => {},
    };
    return false;
}

pub fn hasSequentialRetirement(arena: *const ir.Arena) bool {
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => |derived| switch (derived) {
            .instruction_next_pc, .instruction_next_clock => return true,
            else => {},
        },
        else => {},
    };
    return false;
}

pub fn hasTypedLookupRequest(arena: *const ir.Arena) bool {
    for (arena.effectsView()) |effect| if (effect.kind == .bitwise_request)
        return true;
    for (arena.nodesView()) |node| switch (node.key.op) {
        .add, .mul => if (!std.meta.eql(node.key.ty, types.Type.felt) and
            !std.meta.eql(node.key.ty, types.Type.selector)) return true,
        else => {},
    };
    return false;
}

pub fn hasRangeRefinement(arena: *const ir.Arena) bool {
    return arena.range_refinements.items.len != 0 or
        arena.fixed_table_requests.items.len != 0;
}

/// True only when the arena needs the post-v8 semantic identity / post-v10
/// manifest encoding for a program-authenticated control target.
pub fn hasProgramControlTarget(arena: *const ir.Arena) bool {
    for (arena.range_refinements.items) |item| switch (item.premise) {
        .program_control_target => return true,
        else => {},
    };
    return false;
}

/// True only when an already-committed physical control target is authorized
/// by the post-v9 semantic identity / post-v11 manifest proof record.
pub fn hasCommittedProgramControlTarget(arena: *const ir.Arena) bool {
    return arena.committed_program_control_targets.items.len != 0;
}

pub fn hasConditionalAccess(arena: *const ir.Arena) bool {
    return arena.conditional_access_plans.items.len != 0;
}

/// True only for the opt-in sealed function-body authority. Ownerless legacy
/// functions deliberately do not select a new semantic or manifest version.
pub fn hasFunctionBodyOwnership(arena: *const ir.Arena) bool {
    for (arena.functions.items) |function| if (function.body != null) return true;
    return false;
}
