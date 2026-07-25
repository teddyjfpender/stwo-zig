//! Fail-closed callback boundary for exact Blake CUDA AIR kernels.

const std = @import("std");
const geometry_mod = @import("geometry.zig");
const slots = @import("slots.zig");
const views = @import("views.zig");

pub const abi_version: u32 = 1;

pub const Invocation = struct {
    geometry: geometry_mod.Geometry,
    views: views.TreeViews,
    preprocessed_slot: slots.SlotId,
    main_slot: slots.SlotId,
    relation_sources_slot: slots.SlotId,
    interaction_slot: slots.SlotId,
    interaction_denominators_slot: slots.SlotId,
    interaction_batch_prefix_slot: slots.SlotId,
    statement1_claims_slot: slots.SlotId,
    composition_slot: slots.SlotId,
};

pub const Callback = *const fn (
    context: *anyopaque,
    invocation: Invocation,
) anyerror!void;

pub const Trace = struct {
    version: u32,
    identity: [32]u8,
    context: *anyopaque,
    generate_preprocessed: Callback,
    generate_main: Callback,

    pub fn validate(self: Trace) !void {
        if (self.version != abi_version or isZero(self.identity))
            return error.UnavailableExactBlakeTraceFacade;
    }
};

/// Exact paired-LogUp generation is a separate authority from algebraic AIR
/// evaluation. It owns denominator construction, batch inversion, all 1,156
/// interaction base columns, and the eight claimed sums.
pub const Interaction = struct {
    version: u32,
    identity: [32]u8,
    context: *anyopaque,
    generate_interaction: Callback,

    pub fn validate(self: Interaction) !void {
        if (self.version != abi_version or isZero(self.identity))
            return error.UnavailableExactBlakeInteractionFacade;
    }
};

pub const Constraint = struct {
    version: u32,
    identity: [32]u8,
    context: *anyopaque,
    evaluate_composition: Callback,

    pub fn validate(self: Constraint) !void {
        if (self.version != abi_version or isZero(self.identity))
            return error.UnavailableExactBlakeConstraintFacade;
    }
};

pub const Set = struct {
    trace: ?Trace = null,
    interaction: ?Interaction = null,
    constraint: ?Constraint = null,

    pub fn requireReady(self: Set, authority: Authority) !Ready {
        const trace = self.trace orelse
            return error.UnavailableExactBlakeTraceFacade;
        const interaction = self.interaction orelse
            return error.UnavailableExactBlakeInteractionFacade;
        const constraint = self.constraint orelse
            return error.UnavailableExactBlakeConstraintFacade;
        try trace.validate();
        try interaction.validate();
        try constraint.validate();
        if (!std.mem.eql(
            u8,
            &trace.identity,
            &authority.trace_identity,
        )) {
            return error.UnauthenticatedExactBlakeTraceFacade;
        }
        if (!std.mem.eql(
            u8,
            &interaction.identity,
            &authority.interaction_identity,
        )) {
            return error.UnauthenticatedExactBlakeInteractionFacade;
        }
        if (!std.mem.eql(
            u8,
            &constraint.identity,
            &authority.constraint_identity,
        )) {
            return error.UnauthenticatedExactBlakeConstraintFacade;
        }
        return .{
            .trace = trace,
            .interaction = interaction,
            .constraint = constraint,
        };
    }
};

/// Expected digests come from the authenticated AOT pack, never from a prove
/// request or caller-selected frontend configuration.
pub const Authority = struct {
    trace_identity: [32]u8,
    interaction_identity: [32]u8,
    constraint_identity: [32]u8,
};

pub const Ready = struct {
    trace: Trace,
    interaction: Interaction,
    constraint: Constraint,
};

pub fn invocation(
    geometry: geometry_mod.Geometry,
    tree_views: views.TreeViews,
) Invocation {
    return .{
        .geometry = geometry,
        .views = tree_views,
        .preprocessed_slot = slots.preprocessed_evaluations,
        .main_slot = slots.main_evaluations,
        .relation_sources_slot = slots.relation_sources,
        .interaction_slot = slots.interaction_evaluations,
        .interaction_denominators_slot = slots.interaction_denominators,
        .interaction_batch_prefix_slot = slots.interaction_batch_prefix,
        .statement1_claims_slot = slots.statement1_claims,
        .composition_slot = slots.composition_evaluations,
    };
}

fn isZero(identity: [32]u8) bool {
    return std.mem.allEqual(u8, &identity, 0);
}

test "exact Blake kernel facades fail closed without both identities" {
    try std.testing.expectError(
        error.UnavailableExactBlakeTraceFacade,
        (Set{}).requireReady(.{
            .trace_identity = [_]u8{1} ** 32,
            .interaction_identity = [_]u8{3} ** 32,
            .constraint_identity = [_]u8{2} ** 32,
        }),
    );
    const callback = struct {
        fn call(_: *anyopaque, _: Invocation) anyerror!void {}
    }.call;
    var byte: u8 = 0;
    const trace = Trace{
        .version = abi_version,
        .identity = [_]u8{1} ** 32,
        .context = &byte,
        .generate_preprocessed = callback,
        .generate_main = callback,
    };
    try std.testing.expectError(
        error.UnavailableExactBlakeConstraintFacade,
        (Set{ .trace = trace }).requireReady(.{
            .trace_identity = [_]u8{1} ** 32,
            .interaction_identity = [_]u8{3} ** 32,
            .constraint_identity = [_]u8{2} ** 32,
        }),
    );
}
