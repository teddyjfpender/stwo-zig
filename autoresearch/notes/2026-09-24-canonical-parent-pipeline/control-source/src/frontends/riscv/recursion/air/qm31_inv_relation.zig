//! Component-bound facade over the generic typed `wire(6)` interaction compiler.

const std = @import("std");
const full = @import("qm31_inv.zig");
const wire_interaction = @import("wire_interaction.zig");

const Runtime = wire_interaction.Runtime(
    full.PHYSICAL_MAIN_COLUMN_COUNT,
    full.RELATION_EVENT_COUNT,
);

pub const EVENT_COUNT = Runtime.EVENT_COUNT;
pub const BATCH_COUNT = Runtime.BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT = Runtime.INTERACTION_COLUMN_COUNT;
pub const Row = Runtime.Row;
pub const Entry = wire_interaction.Entry;
pub const Claims = Runtime.Claims;
pub const Interaction = Runtime.Interaction;
pub const Challenge = wire_interaction.Challenge;
pub const Error = wire_interaction.Error;
pub const AuthenticationError = full.ValidationError || wire_interaction.AuthenticationError;
pub const InteractionError = full.ValidationError || wire_interaction.InteractionError;
pub const ClaimError = full.ValidationError || wire_interaction.ClaimError;

pub const Plan = struct {
    compiled: Runtime.Plan,

    pub fn validateAgainst(
        self: *const Plan,
        definition: *const full.Definition,
    ) AuthenticationError!void {
        try definition.validate();
        try self.compiled.validateAgainst(
            &definition.arena,
            full.SEMANTIC_DIGEST,
            definition.events.ordered(),
        );
    }

    pub fn entries(
        self: *const Plan,
        definition: *const full.Definition,
        row: Row,
    ) AuthenticationError![EVENT_COUNT]Entry {
        try definition.validate();
        return self.compiled.entries(
            &definition.arena,
            full.SEMANTIC_DIGEST,
            definition.events.ordered(),
            row,
        );
    }

    pub fn validateEntries(
        self: *const Plan,
        definition: *const full.Definition,
        row: Row,
        entries_value: [EVENT_COUNT]Entry,
    ) AuthenticationError!void {
        try definition.validate();
        try self.compiled.validateEntries(
            &definition.arena,
            full.SEMANTIC_DIGEST,
            definition.events.ordered(),
            row,
            entries_value,
        );
    }

    pub fn rowClaims(
        self: *const Plan,
        definition: *const full.Definition,
        row: Row,
        challenge: Challenge,
    ) ClaimError!Claims {
        try definition.validate();
        return self.compiled.rowClaims(
            &definition.arena,
            full.SEMANTIC_DIGEST,
            definition.events.ordered(),
            row,
            challenge,
        );
    }

    pub fn generateInteraction(
        self: *const Plan,
        allocator: std.mem.Allocator,
        definition: *const full.Definition,
        rows: []const Row,
        log_size: u32,
        challenge: Challenge,
    ) InteractionError!Interaction {
        try definition.validate();
        return self.compiled.generateInteraction(
            allocator,
            &definition.arena,
            full.SEMANTIC_DIGEST,
            definition.events.ordered(),
            rows,
            log_size,
            challenge,
        );
    }

    pub fn validateInteraction(
        self: *const Plan,
        allocator: std.mem.Allocator,
        definition: *const full.Definition,
        rows: []const Row,
        log_size: u32,
        challenge: Challenge,
        interaction: *const Interaction,
    ) InteractionError!void {
        try definition.validate();
        try self.compiled.validateInteraction(
            allocator,
            &definition.arena,
            full.SEMANTIC_DIGEST,
            definition.events.ordered(),
            rows,
            log_size,
            challenge,
            interaction,
        );
    }
};

pub fn authenticate(definition: *const full.Definition) AuthenticationError!Plan {
    try definition.validate();
    return .{ .compiled = try Runtime.authenticate(
        &definition.arena,
        full.SEMANTIC_DIGEST,
        definition.events.ordered(),
    ) };
}
