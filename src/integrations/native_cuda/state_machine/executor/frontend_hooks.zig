//! Native state-machine policy hooks for the shared resident proof pipeline.

const std = @import("std");
const canonical = @import("../canonical_ingress.zig");
const composition = @import("composition.zig");
const geometry_mod = @import("../geometry.zig");
const ingress_stage = @import("ingress.zig");
const oods_executor = @import("../../common/oods_executor.zig");
const plan_mod = @import("../plan.zig");
const program = @import("../program.zig");
const fri_executor = @import("../../common/fri_executor.zig");
const pow_decommit = @import(
    "../../common/pow_decommit_executor.zig",
);
const quotient_executor = @import(
    "../../common/quotient_executor.zig",
);
const bindings = @import("../resident_bindings.zig");
const terminal = @import("../terminal_bundle.zig");
const trace = @import("trace_commit.zig");

pub const Hooks = struct {
    pub const BundleDescriptor = terminal.Descriptor;
    pub const admit = geometry_mod.admitRequest;
    pub const planTarget = program.targetFor;

    pub fn initCanonical(
        allocator: std.mem.Allocator,
        geometry: geometry_mod.Geometry,
    ) !canonical.Pack {
        return canonical.Pack.init(allocator, geometry);
    }

    pub fn deinitCanonical(
        pack: *canonical.Pack,
        allocator: std.mem.Allocator,
    ) void {
        pack.deinit(allocator);
    }

    pub fn ingress(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        pack: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try ingress_stage.run(
            transaction,
            prepared,
            pack,
            &views,
        );
    }

    pub fn traceGeneration(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        _: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try trace.generate(transaction, prepared, &views);
    }

    pub fn traceCommit(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        _: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try trace.commit(transaction, prepared, &views);
    }

    pub fn constraintEvaluation(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        _: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try composition.run(transaction, prepared, &views);
    }

    pub fn oods(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        pack: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try oods_executor.run(
            transaction,
            prepared,
            pack,
            &views,
        );
    }

    pub fn quotient(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        pack: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try quotient_executor.run(
            transaction,
            prepared,
            pack,
            &views,
        );
    }

    pub fn friCommit(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        pack: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try fri_executor.run(
            transaction,
            prepared,
            pack,
            &views,
        );
    }

    pub fn pow(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        _: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try pow_decommit.executePow(
            transaction,
            prepared,
            &views,
        );
    }

    pub fn decommit(
        transaction: anytype,
        prepared: *plan_mod.PreparedPlan,
        _: *canonical.Pack,
    ) !void {
        const views = try bindings.bind(transaction, prepared);
        try pow_decommit.executeDecommit(
            transaction,
            prepared,
            &views,
        );
    }
};

test "state-machine frontend hooks expose only AIR-owned policy" {
    inline for (&.{
        "BundleDescriptor",
        "admit",
        "planTarget",
        "initCanonical",
        "deinitCanonical",
        "ingress",
        "traceGeneration",
        "traceCommit",
        "constraintEvaluation",
        "oods",
        "quotient",
        "friCommit",
        "pow",
        "decommit",
    }) |name| {
        try std.testing.expect(@hasDecl(Hooks, name));
    }
}
