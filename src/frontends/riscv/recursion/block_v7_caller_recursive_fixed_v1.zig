//! Independent original joint verifier equation/DEEP/FRI graphs. Public claim
//! values select no graph constants. The retained arithmetic plan is also the
//! authority for namespace allocation in the final fixed roster.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
        const Profile = Policy.FixedProfile;
        const Equation = Policy.Composition;
        const Deep = @import("air/pcs_deep_circuit.zig");
        const Fri = @import("air/fri_verifier_circuit.zig");
        const Assembly = @import("block_v5_recursive_parent_fixed_assembly_v1.zig");
        pub const Limits = struct { transcript_capacity: ?u32 = null, max_bytes: usize = 2 << 30, profile: Policy.Admission.Limits = .{} };
        pub const Owned = struct {
            allocator: std.mem.Allocator,
            budget: *Budget,
            profile: *Profile.Owned,
            composition: Equation.Compiled,
            deep_graph: Deep.Circuit,
            fri_graph: Fri.Circuit,
            arithmetic: Assembly.Arithmetic,
            transcript: ?@import("air/blake3_transcript_plan.zig").Plan = null,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = false;
            pub fn derive(backing: std.mem.Allocator, input: Profile.Input, limits: Limits) !*Owned {
                if (limits.max_bytes == 0 or (limits.transcript_capacity != null and limits.transcript_capacity.? == 0)) return error.JointFixedResourceLimit;
                const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
                errdefer budget.destroy();
                errdefer if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_PROFILE")) {
                    const usage = budget.snapshot();
                    std.debug.print("V7_WINDOW_NESTED_FAILURE phase=caller_compiler active={} limit={d} peak={d} live={d} exceeded={}\n", .{ Policy.active, usage.limit, usage.peak_live_bytes, usage.live_bytes, usage.exceeded });
                };
                const a = budget.allocator();
                const self = try a.create(Owned);
                errdefer a.destroy(self);
                const profile = try Profile.Owned.derive(a, input, limits.profile);
                errdefer profile.deinit();
                var composition = try Equation.compile(a, &profile.admitted, &profile.arithmetic, &profile.claims);
                errdefer composition.deinit();
                var deep = try Deep.build(a, profile.deepProfile());
                errdefer deep.deinit();
                var fri = try Fri.build(a, profile.friProfile());
                errdefer fri.deinit();
                var arithmetic = try Assembly.Arithmetic.init(a, .{ composition.circuit.graph(), deep.graph(), fri.graph() });
                errdefer arithmetic.deinit();
                const transcript = if (limits.transcript_capacity) |capacity| try Policy.FixedTranscript.derive(a, &profile.admitted, &profile.arithmetic, &profile.claims, capacity, .{}) else null;
                self.* = .{ .allocator = a, .budget = budget, .profile = profile, .composition = composition, .deep_graph = deep, .fri_graph = fri, .arithmetic = arithmetic, .transcript = transcript };
                return self;
            }
            pub fn deinit(self: *Owned) void {
                const a = self.allocator;
                const budget = self.budget;
                if (self.transcript) |*plan| plan.deinit();
                self.arithmetic.deinit();
                self.fri_graph.deinit();
                self.deep_graph.deinit();
                self.composition.deinit();
                self.profile.deinit();
                a.destroy(self);
                budget.destroy();
            }
        };
    };
}
