//! Conservative hard planning for the actual raw local scope. No allocation is
//! permitted before this admission succeeds; scheduling estimates are separate.
const std = @import("std");
const Instance = @import("frame.zig").Instance;
pub const Plan = struct {
    input_bytes: usize = 0,
    owned_layer_bytes: usize = 0,
    binding_bytes: usize = 0,
    peak_bytes: usize = 0,
    pub fn forInstances(instances: []const Instance, limit: usize) !Plan {
        if (limit == 0) return error.MissingLocalGkrBudget;
        var p = Plan{};
        for (instances) |instance| {
            const facts = try instance.facts();
            // M31 numerator +OM31 denominator. Core currently clones input;
            // all higher binary layers may contain TWO OM31 columns.
            const input = try std.math.mul(usize, facts, 4 + 32);
            const upper = try std.math.mul(usize, facts, 64);
            p.input_bytes = try std.math.add(usize, p.input_bytes, input);
            p.owned_layer_bytes = try std.math.add(usize, p.owned_layer_bytes, try std.math.add(usize, input, upper));
            // Eq+prefix, eight base planes each. This includes base witness
            // storage only; root PCS scratch must receive its own budget lease.
            p.binding_bytes = try std.math.add(usize, p.binding_bytes, try std.math.mul(usize, try instance.rows(), 64));
        }
        p.peak_bytes = @max(try std.math.add(usize, p.input_bytes, p.owned_layer_bytes), try std.math.add(usize, p.input_bytes, p.binding_bytes));
        if (p.peak_bytes > limit) return error.LocalGkrBudgetExceeded;
        return p;
    }
};
