//! Independent original compact lookup verifier equation/DEEP/FRI graphs. Public claim
//! values select no graph constants. The retained arithmetic plan is also the
//! authority for namespace allocation in the final fixed roster.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Profile = @import("block_v7_lookup_compact_fixed_profile_v1.zig");
const Equation = @import("air/block_v7_lookup_compact_composition_v1.zig");
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
pub const Limits = struct { max_bytes: usize = 2 << 30, profile: Profile.Limits = .{} };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    profile: *Profile.Owned,
    composition: Equation.Compiled,
    deep_graph: Deep.Circuit,
    fri_graph: Fri.Circuit,
    arithmetic: Assembly.Arithmetic,
    pub const fixed_setup_only = true;
    pub const complete_family_setup = false;
    pub fn derive(backing: std.mem.Allocator, input: Profile.Input, limits: Limits) !*Owned {
        if (limits.max_bytes == 0) return error.CompactLookupFixedResourceLimit;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        const profile = try Profile.Owned.derive(a, input, limits.profile);
        errdefer profile.deinit();
        var composition = try Equation.compile(a, profile);
        errdefer composition.deinit();
        var deep = try Deep.build(a, profile.deepProfile());
        errdefer deep.deinit();
        var fri = try Fri.build(a, profile.friProfile());
        errdefer fri.deinit();
        const arithmetic = try Assembly.Arithmetic.init(a, .{ composition.circuit.graph(), deep.graph(), fri.graph() });
        self.* = .{ .allocator = a, .budget = budget, .profile = profile, .composition = composition, .deep_graph = deep, .fri_graph = fri, .arithmetic = arithmetic };
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        self.arithmetic.deinit();
        self.fri_graph.deinit();
        self.deep_graph.deinit();
        self.composition.deinit();
        self.profile.deinit();
        a.destroy(self);
        budget.destroy();
    }
};
