//! One authenticated immutable fixed owner shared by collection and staging.
//! This is producer residency, never verifier authority. An explicit token
//! spans each consumer's PCS lifetime; actual shared references also prevent
//! replacement or teardown until every physical/proof lease has been released.
const std = @import("std");
const core = @import("stwo_core");
const BasisModule = @import("block_v5_native_capacity_fixed_basis_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;
pub const Limits = BasisModule.Limits;
pub const Expected = struct { template: Protocol.Template, template_id: Protocol.Digest };

pub fn requireLimits(limits: Limits) !void {
    // Values below these ceilings (including zero) are deliberate cache caps.
    // Values above protocol ceilings are malformed configuration, not a miss.
    if (limits.max_columns > 2 * Protocol.MAX_SHARDS or limits.max_log > 24) return error.InvalidNativeCapacityFixedCacheLimits;
}
pub fn sameAllocator(left: std.mem.Allocator, right: std.mem.Allocator) bool {
    return left.ptr == right.ptr and left.vtable == right.vtable;
}
/// Owned, bounded preflight metadata; does not create a commitment or receipt.
pub const Request = struct {
    allocator: std.mem.Allocator,
    capacity_digest: Protocol.Digest,
    config: core.pcs.PcsConfig,
    profile: Profile,
    logs: []u32,
    retained_bytes: usize,
    expected: ?Expected,
    pub fn deinit(self: *Request) void {
        self.allocator.free(self.logs);
        self.* = undefined;
    }
    pub fn matches(self: *const Request, template: Protocol.Template, id: Protocol.Digest) !bool {
        // A corrupt cached identity must propagate even if another geometry
        // was requested; silently evicting it would conceal a phase defect.
        if (!std.meta.eql(try template.identity(), id)) return error.UntrustedNativeCapacityFixedCache;
        if (!std.meta.eql(template.capacity_digest, self.capacity_digest) or !std.meta.eql(template.config, self.config) or template.execution_profile != self.profile) return false;
        if (self.expected) |expected| if (!std.meta.eql(template, expected.template) or !std.meta.eql(id, expected.template_id)) return error.UntrustedNativeCapacityFixedCache;
        return true;
    }
};
/// Null is exclusively a configured resource miss after source/admission
/// validation. Allocation failure or invalid source/configuration propagates.
pub fn preflight(a: std.mem.Allocator, shape: *const Shape, external: u32, config: core.pcs.PcsConfig, profile: Profile, limits: Limits, expected: ?Expected) !?Request {
    try requireLimits(limits);
    try @import("blake3_execution_protocol.zig").validateConfig(config);
    const digest = try Protocol.capacityDigest(shape, external);
    if (expected) |pin| {
        try pin.template.admit(shape, external, pin.template_id);
        if (!std.meta.eql(pin.template.config, config) or pin.template.execution_profile != profile) return error.UntrustedNativeCapacityFixedCache;
    }
    const logs = try Protocol.columnLogs(a, shape, external, .fixed);
    errdefer a.free(logs);
    const bytes = limits.requiredBytes(logs, config) catch |err| {
        if (err != error.NativeCapacityFixedBasisResourceLimit) return err;
        a.free(logs);
        return null;
    };
    return .{ .allocator = a, .capacity_digest = digest, .config = config, .profile = profile, .logs = logs, .retained_bytes = bytes, .expected = expected };
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Basis = BasisModule.ForBackend(Backend).Owner;
        pub const Cache = struct {
            allocator: std.mem.Allocator,
            limits: Limits,
            owner: ?*Basis = null,
            busy: bool = false,
            live: bool = true,
            generation: u64 = 0,
            pub fn init(a: std.mem.Allocator, limits: Limits) !Cache {
                try requireLimits(limits);
                return .{ .allocator = a, .limits = limits };
            }
            pub fn deinit(self: *Cache) !void {
                if (!self.live) return error.InvalidNativeCapacityFixedCachePhase;
                if (self.busy) return error.NativeCapacityFixedCacheBusy;
                if (self.owner) |owner| {
                    try self.requireOwner(owner);
                    owner.deinit();
                    self.allocator.destroy(owner);
                    self.owner = null;
                }
                self.live = false;
            }
            /// Serial source ownership: do not copy this cache after its first
            /// acquisition, or copy a token instead of transferring it.
            pub fn acquire(self: *Cache, a: std.mem.Allocator, shape: *const Shape, external: u32, config: core.pcs.PcsConfig, profile: Profile, expected: ?Expected) !?Lease {
                if (!self.live) return error.InvalidNativeCapacityFixedCachePhase;
                if (!sameAllocator(a, self.allocator)) return error.NativeCapacityFixedCacheAllocatorMismatch;
                if (self.busy) return error.NativeCapacityFixedCacheBusy;
                if (self.owner) |owner| try self.requireOwner(owner);
                var request = (try preflight(a, shape, external, config, profile, self.limits, expected)) orelse return null;
                defer request.deinit();
                const generation = try std.math.add(u64, self.generation, 1);
                if (self.owner) |owner| {
                    if (!(try request.matches(owner.template, owner.template_id))) {
                        // requireOwner above proves no PCS reference survived
                        // the prior token. A replacement is a real cold basis.
                        owner.deinit();
                        a.destroy(owner);
                        self.owner = null;
                    } else {
                        if (!std.mem.eql(u32, owner.trace_logs, request.logs) or owner.retained_byte_bound != request.retained_bytes or !std.meta.eql(owner.limits, self.limits)) return error.UntrustedNativeCapacityFixedCache;
                        try owner.require(a, shape, external, config, profile);
                    }
                }
                if (self.owner == null) {
                    const owner = try a.create(Basis);
                    errdefer a.destroy(owner);
                    owner.* = Basis.init(a, shape, external, config, profile, self.limits) catch |err| {
                        // Same exact caps are enforced inside the real owner.
                        // No allocation/admission error is converted to a miss.
                        if (err != error.NativeCapacityFixedBasisResourceLimit) return err;
                        a.destroy(owner);
                        return null;
                    };
                    errdefer owner.deinit();
                    if (!(try request.matches(owner.template, owner.template_id)) or !std.mem.eql(u32, owner.trace_logs, request.logs) or owner.retained_byte_bound != request.retained_bytes) return error.UntrustedNativeCapacityFixedCache;
                    try owner.require(a, shape, external, config, profile);
                    self.owner = owner;
                }
                self.busy = true;
                self.generation = generation;
                return Lease{ .cache = self, .basis = self.owner.?, .generation = generation };
            }
            fn requireOwner(self: *const Cache, owner: *Basis) !void {
                if (!sameAllocator(self.allocator, owner.allocator)) return error.NativeCapacityFixedCacheAllocatorMismatch;
                if (!owner.live or !std.meta.eql(owner.limits, self.limits) or !std.meta.eql(try owner.template.identity(), owner.template_id) or !std.meta.eql(owner.scheme.config, owner.template.config) or owner.scheme.pending_commit != null or owner.scheme.trees.items.len != 1 or owner.scheme.compact_polynomial_storage) return error.UntrustedNativeCapacityFixedCache;
                const tree = &owner.scheme.trees.items[0];
                const shared = tree.shared_owner orelse return error.UntrustedNativeCapacityFixedCache;
                if (!sameAllocator(self.allocator, shared.allocator)) return error.NativeCapacityFixedCacheAllocatorMismatch;
                if (shared.references.load(.acquire) != 1) return error.NativeCapacityFixedCacheBusy;
                if (tree.compact_polynomials or tree.coefficients == null or !std.meta.eql(tree.root(), owner.template.fixed_root) or tree.columns.len != owner.trace_logs.len or tree.coefficients.?.len != owner.trace_logs.len or try self.limits.requiredBytes(owner.trace_logs, owner.scheme.config) != owner.retained_byte_bound) return error.UntrustedNativeCapacityFixedCache;
                for (tree.columns, tree.coefficients.?, owner.trace_logs) |column, coefficient, log| {
                    if (column.log_size != log + owner.scheme.config.fri_config.log_blowup_factor or coefficient.logSize() != log) return error.UntrustedNativeCapacityFixedCache;
                    try column.validate();
                }
            }
        };
        pub const Lease = struct {
            cache: *Cache,
            basis: *Basis,
            generation: u64,
            released: bool = false,
            /// Call after every acquired PCS owner (including moved schemes)
            /// is destroyed. Failure preserves the busy token and the owner.
            pub fn release(self: *Lease) !void {
                if (self.released or !self.cache.live or !self.cache.busy or self.cache.generation != self.generation or self.cache.owner != self.basis) return error.InvalidNativeCapacityFixedCacheLease;
                try self.cache.requireOwner(self.basis);
                self.cache.busy = false;
                self.released = true;
            }
        };
    };
}
