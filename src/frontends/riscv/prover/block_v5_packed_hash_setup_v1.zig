//! Per-job immutable typed AIR definitions and authenticated relation plans.
//! Only setup is shared: page geometry, witnesses, challenges and admissions
//! are never retained here. Leases keep the allocator alive across workers.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Binding = @import("../recursion/air/universal_relation_binding.zig");

pub fn ForAirs(comptime Airs: anytype) type {
    const Definitions = blk: {
        var types: [Airs.len]type = undefined;
        for (Airs, 0..) |Air, i| types[i] = Air.Definition;
        break :blk std.meta.Tuple(&types);
    };
    const Plans = blk: {
        var types: [Airs.len]type = undefined;
        for (Airs, 0..) |Air, i| types[i] = Binding.Binding(Air).Plan;
        break :blk std.meta.Tuple(&types);
    };
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        allocation_owner: ?*Budget,
        references: std.atomic.Value(usize) = .init(1),
        definitions: Definitions = undefined,
        plans: Plans = undefined,
        initialized: usize = 0,
        pub const complete_source_authority = false;

        pub fn create(a: std.mem.Allocator) !*const Self {
            const allocation_owner = Budget.fromAllocator(a);
            if (allocation_owner) |owner| _ = owner.retain();
            const self = a.create(Self) catch |failure| {
                if (allocation_owner) |owner| owner.destroy();
                return failure;
            };
            self.* = .{ .a = a, .allocation_owner = allocation_owner };
            errdefer self.destroy();
            inline for (Airs, 0..) |Air, i| {
                self.definitions[i] = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
                self.initialized += 1;
                self.plans[i] = try Binding.Binding(Air).authenticate(&self.definitions[i]);
            }
            return self;
        }

        /// The coordinator and every page own one reference. Acquiring a new
        /// lease requires a live existing reference; racing last release is
        /// forbidden, just as borrowing any other owner after destruction is.
        pub fn lease(self: *const Self) !Lease {
            const mutable = @constCast(self);
            var count = mutable.references.load(.monotonic);
            while (true) {
                if (count == 0 or count == std.math.maxInt(usize)) return error.InvalidPackedHashSetupLease;
                if (mutable.references.cmpxchgWeak(count, count + 1, .monotonic, .monotonic)) |actual| {
                    count = actual;
                } else break;
            }
            return .{ .setup = self };
        }

        pub fn release(self: *const Self) void {
            const mutable = @constCast(self);
            const previous = mutable.references.fetchSub(1, .acq_rel);
            std.debug.assert(previous != 0);
            if (previous == 1) mutable.destroy();
        }

        fn destroy(self: *Self) void {
            inline for (Airs, 0..) |_, i| if (i < self.initialized) self.definitions[i].deinit();
            const a = self.a;
            const owner = self.allocation_owner;
            a.destroy(self);
            if (owner) |retained| retained.destroy();
        }

        pub const Lease = struct {
            setup: ?*const Self,
            pub fn get(self: Lease) !*const Self {
                return self.setup orelse error.ReleasedPackedHashSetupLease;
            }
            pub fn deinit(self: *Lease) void {
                const setup = self.setup orelse return;
                self.setup = null;
                setup.release();
            }
        };
    };
}
