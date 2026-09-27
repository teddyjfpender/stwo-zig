//! One bounded independently derived native-memory template per family.
//! Entries are created only by original fixed-policy derivation. No proof,
//! capture, received key, artifact or producer notification can fill the cache.
//! A hit still validates the current original source admission; public values
//! and original proof verification remain per-instance duties.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Definitions = @import("block_v5_recursive_provider_definition_v1.zig");
const Stores = @import("block_v5_recursive_provider_store_v1.zig");
const Derive = @import("block_v5_cpu_recursive_template_derivation_v1.zig");
const Profile = @import("../recursion/blake3_execution_parent_protocol.zig").Profile;
pub const Family = @import("block_v5_recursive_provider_family_v1.zig").Family;
pub const Stats = struct { hits: usize = 0, misses: usize = 0 };
pub const Fingerprint = struct {
    family: Family,
    original_template: [32]u8,
    config: core.pcs.PcsConfig,
    profile: Profile,
    transcript_capacity: u32,
    preparation_byte_limit: usize,
    /// Template IDs bind the original native ABI/config, while the row log
    /// explicitly records the only native geometry input to fixed derivation.
    row_log: u32,
};
fn sameFingerprint(left: Fingerprint, right: Fingerprint) bool {
    return std.meta.eql(left, right);
}
pub fn ForFamily(comptime family: Family, comptime Backend: type) type {
    comptime if (family != .ram_lanes and family != .range16) @compileError("word expected setup cache requires RAM or range");
    const D = Definitions.ForFamily(family);
    const Template = Stores.ForFamily(family).TemplatePolicy;
    return struct {
        const Self = @This();
        const Entry = struct { fingerprint: Fingerprint, template: Template };
        budget: *Budget,
        entry: ?Entry = null,
        stats: Stats = .{},
        pub const max_entries = 1;
        pub const complete_block_authority = false;
        pub fn init(a: std.mem.Allocator, max_metadata_bytes: usize) !Self {
            if (max_metadata_bytes < @sizeOf(Entry)) return error.WordExpectedSetupCacheResourceLimit;
            return .{ .budget = try Budget.createRetainingParent(a, max_metadata_bytes) };
        }
        pub fn deinit(self: *Self) void {
            self.drop();
            self.budget.destroy();
            self.* = undefined;
        }
        fn drop(self: *Self) void {
            if (self.entry) |entry| self.budget.allocator().free(entry.template.schedule);
            self.entry = null;
        }
        fn fingerprint(admitted: *const D.Prepared, profile: Profile, capacity: u32) !Fingerprint {
            try admitted.validate(admitted.template_id);
            if (capacity == 0 or !std.meta.eql(profile.config(), admitted.config)) return error.RecursiveTemplateDerivationSecurityMismatch;
            return .{ .family = family, .original_template = admitted.template_id, .config = admitted.config, .profile = profile, .transcript_capacity = capacity, .preparation_byte_limit = admitted.limits.max_preparation_bytes, .row_log = if (family == .ram_lanes) admitted.pin.claim.row_log else @import("block_v5_range16_v1.zig").TABLE_LOG };
        }
        /// Synchronous borrow: get/deinit must not overlap use of this result.
        /// Derivation scratch is caller-budgeted and released before the entry
        /// is retained. Only compact key/routing metadata survives, never fixed
        /// columns, a private transcript or instance proof data.
        pub fn get(self: *Self, scratch: std.mem.Allocator, admitted: *const D.Prepared, profile: Profile, capacity: u32) !*const Template {
            const wanted = try fingerprint(admitted, profile, capacity);
            if (self.entry) |*entry| if (sameFingerprint(entry.fingerprint, wanted)) {
                try requireTemplate(entry.template, wanted);
                try admitted.validate(admitted.template_id);
                self.stats.hits += 1;
                return &entry.template;
            };
            // Evict before cold construction: old/new routing never double the
            // retained metadata cap; failed construction leaves an empty cache.
            self.drop();
            var independent = try Derive.providerPolicyForBackend(family, Backend, scratch, admitted, profile, capacity);
            defer independent.deinit();
            try requireTemplate(independent.template, wanted);
            const schedule = try self.budget.allocator().dupe(D.Bus.Wire, independent.template.schedule);
            errdefer self.budget.allocator().free(schedule);
            try admitted.validate(admitted.template_id);
            self.entry = .{ .fingerprint = wanted, .template = .{ .key = independent.template.key, .key_id = independent.template.key_id, .schedule = schedule } };
            self.stats.misses += 1;
            return &self.entry.?.template;
        }
        fn requireTemplate(template: Template, wanted: Fingerprint) !void {
            if (template.key.profile != wanted.profile or !std.meta.eql(template.key.config, wanted.config) or
                !std.meta.eql(template.key.context.child_config, wanted.config) or
                !std.meta.eql(template.key.context.child_key_id, wanted.original_template) or
                !std.meta.eql(try template.key.identity(), template.key_id) or
                !std.meta.eql(try D.Bus.scheduleDigest(template.schedule), template.key.public_schedule_digest)) return error.UntrustedWordExpectedSetupCache;
        }
    };
}

test "word expected setup: reuse fingerprint separates every geometry security retry and budget input" {
    // Untrusted structural proposals only, never inserted into a cache or
    // passed to admission/key derivation or a proof receiver.
    const original = Fingerprint{ .family = .ram_lanes, .original_template = @splat(3), .config = Profile.csp_q70_pow26.config(), .profile = .csp_q70_pow26, .transcript_capacity = 2, .preparation_byte_limit = 1 << 30, .row_log = 20 };
    try std.testing.expect(sameFingerprint(original, original));
    inline for (.{ "family", "original_template", "config", "profile", "transcript_capacity", "preparation_byte_limit", "row_log" }) |field| {
        var changed = original;
        if (comptime std.mem.eql(u8, field, "family")) changed.family = .range16 else if (comptime std.mem.eql(u8, field, "original_template")) changed.original_template[0] ^= 1 else if (comptime std.mem.eql(u8, field, "config")) changed.config.pow_bits -= 1 else if (comptime std.mem.eql(u8, field, "profile")) changed.profile = .diagnostic_q8_pow0 else @field(changed, field) += 1;
        try std.testing.expect(!sameFingerprint(original, changed));
    }
}
test "word expected setup: empty cache metadata custody and limits require no proof or commitment" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    inline for (.{ Family.ram_lanes, .range16 }) |family| {
        const Cache = ForFamily(family, Cpu);
        try std.testing.expectError(error.WordExpectedSetupCacheResourceLimit, Cache.init(a, 0));
        var cache = try Cache.init(a, 64 << 10);
        defer cache.deinit();
        try std.testing.expect(cache.entry == null);
        try std.testing.expectEqual(@as(usize, 0), cache.stats.hits);
        try std.testing.expectEqual(@as(usize, 0), cache.stats.misses);
    }
}
