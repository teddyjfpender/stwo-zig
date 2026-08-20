//! Stable component storage for the Poseidon2 proof profile.
//!
//! The base frontend continues to assemble slots 0..27 into its fixed proof or
//! verification workspace. This module owns only the two appended component
//! values and one copied handle array. Copying the small fat pointers does not
//! copy component state; every pointer remains borrowed from one of the two
//! heap workspaces until the engine call returns.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const base_statement = @import("../../air/statement.zig");
const proof_workspace = @import("../proof_workspace.zig");

pub const profile_component_count: usize = 2;
pub const max_component_handles =
    proof_workspace.MAX_COMPONENT_HANDLES + profile_component_count;

pub const Placements = struct {
    caller: caller_component.Placement,
    provider: provider_component.Placement,
};

pub fn placements(
    core: *const base_statement.RiscVStatement,
) error{ColumnOffsetOverflow}!Placements {
    const preprocessed = @as(usize, core.nPreprocessedColumns());
    const main = @as(usize, core.nMainColumns());
    const interaction = @as(usize, core.nInteractionColumns());
    const provider_preprocessed = try add(preprocessed, caller_component.preprocessed_column_count);
    const provider_main = try add(main, caller_component.main_column_count);
    const provider_interaction = try add(
        interaction,
        caller_component.interaction_column_count,
    );
    return .{
        .caller = .{
            .is_first_col_idx = preprocessed,
            .is_active_col_idx = try add(preprocessed, 1),
            .main_col_offset = main,
            .interaction_col_offset = interaction,
        },
        .provider = .{
            .is_first_col_idx = provider_preprocessed,
            .is_active_col_idx = try add(provider_preprocessed, 1),
            .main_col_offset = provider_main,
            .interaction_col_offset = provider_interaction,
        },
    };
}

pub const ProverAssembly = struct {
    caller: caller_component.CallerComponent,
    provider: provider_component.ProviderComponent,
    handles: [max_component_handles]prover_component.ComponentProver,
    len: usize,

    pub fn create(
        allocator: std.mem.Allocator,
        core: *const base_statement.RiscVStatement,
        extension: *const guest_statement.ExtensionStatement,
        relations: *const guest_relations.Poseidon2V1Relations,
        base: []const prover_component.ComponentProver,
        caller_claim: caller_component.Claim,
        provider_claim: provider_component.Claim,
    ) !*ProverAssembly {
        try extension.validate(core);
        if (base.len > proof_workspace.MAX_COMPONENT_HANDLES)
            return error.TooManyComponentHandles;
        const authority = try Authorities.resolve(extension);
        const component_placements = try placements(core);
        const self = try allocator.create(ProverAssembly);
        errdefer allocator.destroy(self);
        self.caller = try caller_component.CallerComponent.initProver(
            authority.caller,
            caller_claim,
            component_placements.caller,
            relations,
        );
        self.provider = try provider_component.ProviderComponent.initProver(
            authority.provider,
            provider_claim,
            component_placements.provider,
            relations,
        );
        @memcpy(self.handles[0..base.len], base);
        self.handles[base.len] = self.caller.asProverComponent();
        self.handles[base.len + 1] = self.provider.asProverComponent();
        self.len = base.len + profile_component_count;
        return self;
    }

    pub fn active(self: *const ProverAssembly) []const prover_component.ComponentProver {
        return self.handles[0..self.len];
    }

    pub fn destroy(self: *ProverAssembly, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

pub const VerifierAssembly = struct {
    caller: caller_component.CallerComponent,
    provider: provider_component.ProviderComponent,
    handles: [max_component_handles]core_air_components.Component,
    len: usize,

    pub fn create(
        allocator: std.mem.Allocator,
        core: *const base_statement.RiscVStatement,
        extension: *const guest_statement.ExtensionStatement,
        relations: *const guest_relations.Poseidon2V1Relations,
        base: []const core_air_components.Component,
        caller_claim: caller_component.Claim,
        provider_claim: provider_component.Claim,
    ) !*VerifierAssembly {
        try extension.validate(core);
        if (base.len > proof_workspace.MAX_COMPONENT_HANDLES)
            return error.TooManyComponentHandles;
        const authority = try Authorities.resolve(extension);
        const component_placements = try placements(core);
        const self = try allocator.create(VerifierAssembly);
        errdefer allocator.destroy(self);
        self.caller = try caller_component.CallerComponent.initVerifier(
            authority.caller,
            caller_claim,
            component_placements.caller,
            relations,
        );
        self.provider = try provider_component.ProviderComponent.initVerifier(
            authority.provider,
            provider_claim,
            component_placements.provider,
            relations,
        );
        @memcpy(self.handles[0..base.len], base);
        self.handles[base.len] = self.caller.asVerifierComponent();
        self.handles[base.len + 1] = self.provider.asVerifierComponent();
        self.len = base.len + profile_component_count;
        return self;
    }

    pub fn active(self: *const VerifierAssembly) []const core_air_components.Component {
        return self.handles[0..self.len];
    }

    pub fn destroy(self: *VerifierAssembly, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

const Authorities = struct {
    caller: component_registry.CallerConstruction,
    provider: component_registry.ProviderConstruction,

    fn resolve(
        extension: *const guest_statement.ExtensionStatement,
    ) component_registry.Error!Authorities {
        const registry = component_registry.Registry.forProfile(extension.profile);
        const caller = switch (try registry.verifierConstruction(extension.components[0])) {
            .caller => |value| value,
            .provider => return error.ConstructionAuthorityMismatch,
        };
        const provider = switch (try registry.verifierConstruction(extension.components[1])) {
            .provider => |value| value,
            .caller => return error.ConstructionAuthorityMismatch,
        };
        return .{ .caller = caller, .provider = provider };
    }
};

fn add(left: usize, right: usize) error{ColumnOffsetOverflow}!usize {
    return std.math.add(usize, left, right) catch error.ColumnOffsetOverflow;
}

comptime {
    if (caller_component.main_column_count != 286 or
        provider_component.main_column_count != 445 or
        caller_component.interaction_column_count != 308 or
        provider_component.interaction_column_count != 8)
    {
        @compileError("guest component placement geometry drifted");
    }
}
