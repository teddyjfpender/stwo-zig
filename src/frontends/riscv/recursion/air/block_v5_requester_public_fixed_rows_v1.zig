//! Capture-free PUBLIC21 tuple/B5SS ports through the ORIGINAL shared compiler.
//! This owner has no proof, capture, MAIN columns or accepted child authority.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = @import("../block_v5_requester_public_compensation_v1.zig");
const Bus = @import("../block_v5_requester_public_bus_v1.zig");
const Composition = @import("block_v5_requester_public_composition_v1.zig");
const Kernel = @import("block_v5_global_public_export_rows_v1.zig").ForModules(Public, Composition, Bus);
const Storage = @import("blake3_parent_row_storage.zig");
pub const Limits = struct { max_graph_bytes: usize = 8 << 30, max_rows_per_cohort: usize = 1 << 24 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    lease: ?*Budget,
    graph: Composition.Prepared,
    fixed: Kernel.FixedPrepared,
    attempt_capacity: u32,
    limits: Limits,
    pub const complete_fixed_setup = false;
    pub const complete_block_authority = false;
    /// Public Owner is independently reconstructed, not a proof proposal. It
    /// must remain immutable/alive while this fixed source is validated.
    pub fn init(a: std.mem.Allocator, owner: *const Public.Owner, attempt_capacity: u32, limits: Limits) !Owned {
        if (attempt_capacity == 0 or limits.max_graph_bytes == 0 or limits.max_rows_per_cohort == 0 or limits.max_rows_per_cohort > 1 << 24) return error.RequesterPublicFixedResourceLimit;
        const lease = if (Budget.fromAllocator(a)) |budget| budget.retain() else null;
        errdefer if (lease) |budget| budget.destroy();
        var graph = try Composition.prepare(a, owner, limits.max_graph_bytes);
        errdefer graph.deinit();
        var fixed = try Kernel.prepareFixed(a, owner, &graph, attempt_capacity);
        errdefer fixed.deinit();
        inline for (0..Storage.Airs.len) |slot| if (fixed.rows.counts[slot] > limits.max_rows_per_cohort) return error.RequesterPublicFixedResourceLimit;
        return .{ .allocator = a, .lease = lease, .graph = graph, .fixed = fixed, .attempt_capacity = attempt_capacity, .limits = limits };
    }
    pub fn validateAgainst(self: *const Owned, owner: *const Public.Owner) !void {
        var expected = try Owned.init(self.allocator, owner, self.attempt_capacity, self.limits);
        defer expected.deinit();
        if (!std.meta.eql(self.fixed.identity, expected.fixed.identity) or !std.meta.eql(self.graph.circuit.identity_digest, expected.graph.circuit.identity_digest) or self.fixed.wires.len != expected.fixed.wires.len or !std.meta.eql(self.fixed.rows.counts, expected.fixed.rows.counts)) return error.UntrustedRequesterPublicFixedRows;
        for (self.fixed.wires, expected.fixed.wires) |actual, independent| if (!std.meta.eql(actual, independent)) return error.UntrustedRequesterPublicFixedRows;
        inline for (0..Storage.Airs.len) |slot| {
            const actual = try self.fixed.rows.metadata(slot);
            const independent = try expected.fixed.rows.metadata(slot);
            for (actual, independent) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedRequesterPublicFixedRows;
        }
    }
    pub fn requireComplete(_: *const Owned) error{MissingRequesterFixedFamilyPorts}!void {
        return error.MissingRequesterFixedFamilyPorts;
    }
    pub fn deinit(self: *Owned) void {
        const lease = self.lease;
        self.fixed.deinit();
        self.graph.deinit();
        self.* = undefined;
        if (lease) |budget| budget.destroy();
    }
};
