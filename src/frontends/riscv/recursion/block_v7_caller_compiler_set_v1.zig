//! Bounded, request-local compiler ownership for one explicit caller family.
//! Both cold and live passes borrow the same independently compiled programs.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Bus = @import("block_v7_mixed_public_v1.zig");
const Families = @import("block_v7_caller_family_v1.zig");
pub const Owned = struct {
    budget: *Budget,
    full_count: usize,
    active_count: usize,
    full_slots: [Bus.MAX_CHILDREN]?*const Families.Full.Capsule.Capsule = @splat(null),
    active_slots: [Bus.MAX_CHILDREN]?*const Families.Active.Capsule.Capsule = @splat(null),
    pub fn init(a: std.mem.Allocator, input: Inputs.Input, maximum: usize, bytes: usize, reuse: bool) !Owned {
        return initWithTranscript(a, input, maximum, bytes, reuse, null);
    }
    pub fn initWithTranscript(a: std.mem.Allocator, input: Inputs.Input, maximum: usize, bytes: usize, reuse: bool, transcript_capacity: ?u32) !Owned {
        const count = try std.math.add(usize, input.callers.len, input.active_callers.len);
        if (maximum > Bus.MAX_CHILDREN or count > maximum or bytes == 0 or (input.callers.len != 0 and input.active_callers.len != 0)) return error.CallerCompilerResourceLimit;
        const budget = try Budget.createRetainingParent(a, bytes);
        var self: Owned = .{ .budget = budget, .full_count = input.callers.len, .active_count = input.active_callers.len };
        errdefer self.deinit();
        if (reuse) {
            for (input.callers, self.full_slots[0..self.full_count]) |profile, *slot| slot.* = try Families.Full.Capsule.Capsule.derive(budget.allocator(), profile.input(), .{ .max_bytes = bytes, .transcript_capacity = transcript_capacity });
            for (input.active_callers, self.active_slots[0..self.active_count]) |profile, *slot| slot.* = try Families.Active.Capsule.Capsule.derive(budget.allocator(), profile.input(), .{ .max_bytes = bytes, .transcript_capacity = transcript_capacity });
        }
        return self;
    }
    pub fn full(self: *const Owned) []const ?*const Families.Full.Capsule.Capsule {
        return self.full_slots[0..self.full_count];
    }
    pub fn active(self: *const Owned) []const ?*const Families.Active.Capsule.Capsule {
        return self.active_slots[0..self.active_count];
    }
    pub fn clear(self: *Owned) void {
        inline for (.{ self.full_slots[0..self.full_count], self.active_slots[0..self.active_count] }) |slots| for (slots) |*slot| {
            if (slot.*) |capsule| @constCast(capsule).deinit();
            slot.* = null;
        };
    }
    pub fn deinit(self: *Owned) void {
        self.clear();
        self.budget.destroy();
        self.* = undefined;
    }
};
