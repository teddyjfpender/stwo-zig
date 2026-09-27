//! Shared immutable template custody. Intern on the coordinator; returned
//! addresses stay stable through later inserts. Destroy after all borrowing
//! stores/readers have joined. This owns metadata, never proof authority.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Codec = @import("block_v5_recursive_provider_codec_v1.zig");
const Family = @import("block_v5_recursive_provider_family_v1.zig").Family;
pub const Limits = struct {
    codec: Codec.Limits = .{},
    max_templates: usize = 256,
    max_owned_bytes: usize = 64 << 20,
    pub fn validate(self: Limits) !void {
        try self.codec.validate();
        if (self.max_templates == 0 or self.max_owned_bytes == 0)
            return error.InvalidRecursiveProviderTemplateLimits;
    }
};
pub fn ForFamily(comptime family: Family) type {
    const D = @import("block_v5_recursive_provider_definition_v1.zig").ForFamily(family);
    const C = Codec.ForDefinition(D);
    return struct {
        const Self = @This();
        const Entry = struct { policy: C.TemplatePolicy, wires: []D.Bus.Wire };
        budget: *Budget,
        entries: std.ArrayList(*Entry) = .empty,
        limits: Limits,
        pub fn init(a: std.mem.Allocator, limits: Limits) !Self {
            try limits.validate();
            return .{ .budget = try Budget.create(a, limits.max_owned_bytes), .limits = limits };
        }
        pub fn deinit(self: *Self) void {
            const a = self.budget.allocator();
            for (self.entries.items) |entry| {
                a.free(entry.wires);
                a.destroy(entry);
            }
            self.entries.deinit(a);
            self.budget.destroy();
            self.* = undefined;
        }
        /// The caller supplies independently trusted key/schedule metadata.
        /// Interning cannot qualify a template or turn claims into receipts.
        pub fn intern(self: *Self, prepared: *const D.Prepared, template: *const C.TemplatePolicy) !*const C.TemplatePolicy {
            try template.require(prepared, self.limits.codec);
            for (self.entries.items) |entry| {
                if (!std.meta.eql(entry.policy.key_id, template.key_id)) continue;
                if (!std.meta.eql(entry.policy.key, template.key) or !D.sameWires(entry.policy.schedule, template.schedule))
                    return error.ConflictingRecursiveProviderTemplate;
                return &entry.policy;
            }
            if (self.entries.items.len >= self.limits.max_templates)
                return error.RecursiveProviderTemplateResourceLimit;
            const a = self.budget.allocator();
            const entry = try a.create(Entry);
            errdefer a.destroy(entry);
            const wires = try a.dupe(D.Bus.Wire, template.schedule);
            errdefer a.free(wires);
            entry.* = .{ .policy = .{ .key = template.key, .key_id = template.key_id, .schedule = wires }, .wires = wires };
            try self.entries.append(a, entry);
            return &entry.policy;
        }
        pub fn count(self: *const Self) usize {
            return self.entries.items.len;
        }
    };
}
