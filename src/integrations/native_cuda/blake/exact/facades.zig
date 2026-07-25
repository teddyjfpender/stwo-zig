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
    interaction_slot: slots.SlotId,
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

pub const Constraint = struct {
    version: u32,
    identity: [32]u8,
    context: *anyopaque,
    generate_interaction: Callback,
    evaluate_composition: Callback,

    pub fn validate(self: Constraint) !void {
        if (self.version != abi_version or isZero(self.identity))
            return error.UnavailableExactBlakeConstraintFacade;
    }
};

pub const Set = struct {
    trace: ?Trace = null,
    constraint: ?Constraint = null,

    pub fn requireReady(self: Set) !Ready {
        const trace = self.trace orelse
            return error.UnavailableExactBlakeTraceFacade;
        const constraint = self.constraint orelse
            return error.UnavailableExactBlakeConstraintFacade;
        try trace.validate();
        try constraint.validate();
        return .{ .trace = trace, .constraint = constraint };
    }
};

pub const Ready = struct {
    trace: Trace,
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
        .interaction_slot = slots.interaction_evaluations,
        .composition_slot = slots.composition_evaluations,
    };
}

fn isZero(identity: [32]u8) bool {
    return std.mem.allEqual(u8, &identity, 0);
}

test "exact Blake kernel facades fail closed without both identities" {
    try std.testing.expectError(
        error.UnavailableExactBlakeTraceFacade,
        (Set{}).requireReady(),
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
        (Set{ .trace = trace }).requireReady(),
    );
}
