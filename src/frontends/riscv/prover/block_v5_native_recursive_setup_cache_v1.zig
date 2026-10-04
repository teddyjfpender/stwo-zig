//! One producer-owned recursive setup entry, with explicit host/worker limits.
//! Only immutable setup and owned public routing survive an execution; native
//! captures, source rows and transcripts remain one-instance borrows. Provider
//! specializations share this body, but retain their distinct bus/protocol types.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const LegacyBus = @import("../recursion/block_v5_recursive_public_bus_v1.zig");
const LegacyProtocol = @import("../recursion/block_v5_reusable_native_parent_protocol_v1.zig");
const WorkerModule = @import("../recursion/blake3_native_parent_worker.zig");
const NativeRows = @import("../recursion/air/blake3_native_parent_rows.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Options = struct {
    profile: Parent.protocol.Profile,
    max_entries: usize = 1,
    aggregate_host_byte_limit: usize,
    worker_options: WorkerModule.Options,
};
pub const Stats = struct { hits: usize = 0, misses: usize = 0 };
fn requireExpectedKey(expected: ?[32]u8, actual: [32]u8) !void {
    if (expected) |wanted| if (!std.meta.eql(wanted, actual)) return error.V5NativeSetupCacheExpectedKeyMismatch;
}
pub fn ForBackend(comptime Backend: type) type {
    return ForModules(Backend, LegacyBus, LegacyProtocol);
}
/// B5CT uses distinct public authority and graph inputs, while retaining the
/// same exact setup fingerprint, bounded worker and consuming row lifetime.
pub fn ForCapacityBackend(comptime Backend: type) type {
    return ForModules(Backend, @import("../recursion/block_v5_capacity_recursive_public_bus_v1.zig"), @import("../recursion/block_v5_reusable_capacity_parent_protocol_v1.zig"));
}
pub fn ForRangeBackend(comptime Backend: type) type {
    return ForModules(Backend, @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig"), @import("../recursion/block_v5_reusable_range16_parent_protocol_v1.zig"));
}
/// A provider must supply the actual typed public bus and reusable protocol.
/// Prepared owns recursive rows/context and public wires/values; its protocol
/// authenticates these values anew for every request. No receipt conversion or
/// second cache implementation is involved.
pub fn ForModules(comptime Backend: type, comptime Bus: type, comptime Protocol: type) type {
    return struct {
        const Self = @This();
        const Worker = WorkerModule.WorkerForProtocolScopedAdmission(Backend, Protocol);
        const Entry = struct {
            key: Protocol.Key,
            key_id: [32]u8,
            schedule: []Bus.Wire,
            worker: *Worker,
        };
        options: Options,
        budget: *Budget,
        entry: ?Entry = null,
        stats: Stats = .{},
        busy: std.Thread.Mutex = .{},
        requests: std.Thread.Mutex = .{},
        request_lane: @import("block_v5_joined_request_lane_v1.zig").Lane = .{},
        pub fn init(a: std.mem.Allocator, options: Options) !Self {
            // Reject unusable worker geometry before any fixed-key acquisition
            // or metadata allocation; standalone stages use this same owner.
            _ = try engine.work_pool.WorkerBudget.init(options.worker_options.worker_count);
            if (options.max_entries != 1 or options.aggregate_host_byte_limit == 0 or
                options.worker_options.host_byte_limit == 0 or
                options.worker_options.host_byte_limit > options.aggregate_host_byte_limit or
                options.worker_options.retained_scratch_limit > options.worker_options.host_byte_limit)
                return error.InvalidV5NativeSetupCacheLimits;
            return .{ .options = options, .budget = try Budget.create(a, options.aggregate_host_byte_limit) };
        }
        pub fn deinit(self: *Self) void {
            if (!self.requests.tryLock()) @panic("destroying active native recursive setup cache request");
            if (!self.busy.tryLock()) @panic("destroying leased native recursive setup cache");
            self.request_lane.shutdown() catch @panic("destroying active native recursive request lane");
            self.dropEntry();
            self.budget.destroy();
            self.busy.unlock();
            self.requests.unlock();
            self.* = undefined;
        }
        fn dropEntry(self: *Self) void {
            if (self.entry) |entry| {
                entry.worker.deinit();
                self.budget.allocator().free(entry.schedule);
                self.entry = null;
            }
        }
        /// Hold the exclusive cache/worker lease through proof encoding and
        /// publication. Admission.wires borrows this cache's owned schedule.
        pub const Lease = struct {
            cache: *Self,
            worker: Worker.Lease,
            admission: Protocol.Admission,
            pub fn deinit(self: *Lease) void {
                self.worker.deinit();
                self.cache.busy.unlock();
                self.* = undefined;
            }
            pub fn prove(self: *Lease, rows: *const NativeRows.Prepared) !Parent.artifact.Owned {
                // This replaces dynamic public values even for the same key.
                return self.worker.proveAdmitted(rows, self.admission);
            }
            pub fn proveConsuming(self: *Lease, rows: *NativeRows.Prepared) !Parent.artifact.Owned {
                return self.worker.proveAdmittedConsuming(rows, self.admission);
            }
        };
        pub const Proved = struct { key: Protocol.Key, key_id: [32]u8, proof: Parent.artifact.Owned };
        const Preflight = struct {
            context: *anyopaque,
            check: *const fn (*anyopaque, Protocol.Key, [32]u8, []const Bus.Wire) anyerror!void,
        };
        /// The warm producer may already bind its coordinator pool. Recursive
        /// setup/proving uses one joined coordinator thread, binding the
        /// borrowed driver pool when supplied or an owned standalone pool.
        /// The caller's binding is never removed or overridden.
        /// Destroy the returned proof before destroying this cache.
        pub fn provePrepared(self: *Self, prepared: *Bus.Prepared) !Proved {
            return self.provePreparedMode(false, prepared, null, null);
        }
        /// Releases only one-shot recursive source columns/fixed rows after
        /// their last interaction reader, including every failure path. The
        /// separately owned public wires/values/context remain usable.
        pub fn provePreparedConsuming(self: *Self, prepared: *Bus.Prepared) !Proved {
            return self.provePreparedMode(true, prepared, null, null);
        }
        /// A caller that independently derives fixed policy may require that
        /// exact template before any STARK work. Setup/worker acquisition and
        /// all original live row checks still use the same joined request lane.
        pub fn provePreparedExpectedConsuming(self: *Self, prepared: *Bus.Prepared, expected_key_id: [32]u8) !Proved {
            return self.provePreparedMode(true, prepared, expected_key_id, null);
        }
        /// Notify the original source owner using the genuinely acquired key
        /// before proving. This synchronous borrow stays on the joined request
        /// lane and holds the same exclusive worker lease. A rejected callback
        /// performs no STARK work and consuming rows still release on failure.
        pub fn provePreparedConsumingWithPreflight(self: *Self, prepared: *Bus.Prepared, context: *anyopaque, preflight: *const fn (*anyopaque, Protocol.Key, [32]u8, []const Bus.Wire) anyerror!void) !Proved {
            return self.provePreparedMode(true, prepared, null, .{ .context = context, .check = preflight });
        }
        fn provePreparedMode(self: *Self, comptime consuming: bool, prepared: *Bus.Prepared, expected_key_id: ?[32]u8, preflight: ?Preflight) !Proved {
            defer if (consuming) prepared.recursive.rows.releaseRows();
            if (!self.requests.tryLock()) return error.V5NativeSetupCacheAlreadyLeased;
            defer self.requests.unlock();
            const Request = struct {
                cache: *Self,
                prepared: *Bus.Prepared,
                expected_key_id: ?[32]u8,
                preflight: ?Preflight,
                output: ?Proved = null,
                failure: ?anyerror = null,
                fn run(request: *@This()) void {
                    request.output = request.execute() catch |err| {
                        request.failure = err;
                        return;
                    };
                }
                fn execute(request: *@This()) !Proved {
                    var lease = try request.cache.acquire(request.prepared);
                    defer lease.deinit();
                    try requireExpectedKey(request.expected_key_id, lease.admission.expected_id);
                    if (request.preflight) |before| try before.check(before.context, lease.admission.key, lease.admission.expected_id, lease.admission.wires);
                    const proof = if (consuming)
                        try lease.proveConsuming(&request.prepared.recursive.rows)
                    else
                        try lease.prove(&request.prepared.recursive.rows);
                    return .{ .key = lease.admission.key, .key_id = lease.admission.expected_id, .proof = proof };
                }
            };
            var request = Request{ .cache = self, .prepared = prepared, .expected_key_id = expected_key_id, .preflight = preflight };
            const Dispatch = struct {
                fn run(raw: *anyopaque) void {
                    Request.run(@ptrCast(@alignCast(raw)));
                }
            };
            try self.request_lane.run(&request, Dispatch.run, 8 * 1024 * 1024);
            if (request.failure) |err| return err;
            return request.output orelse error.MissingV5CachedNativeProof;
        }
        pub fn acquire(self: *Self, prepared: *Bus.Prepared) !Lease {
            if (!self.busy.tryLock()) return error.V5NativeSetupCacheAlreadyLeased;
            errdefer self.busy.unlock();
            if (!std.meta.eql(prepared.recursive.context.child_config, self.options.profile.config()))
                return error.V5NativeSetupCacheSecurityMismatch;
            try prepared.recursive.rows.partitionHashRows();
            _ = try Bus.scheduleDigest(prepared.wires);
            if (self.entry) |entry| {
                if (try matchingAdmission(self.options.profile, entry.key, entry.key_id, entry.schedule, prepared)) |admission| {
                    var worker = try entry.worker.acquire();
                    var held = true;
                    defer if (held) worker.deinit();
                    const fixed_match = match: {
                        entry.worker.plan.validateRowsForAdmission(&prepared.recursive.rows, admission) catch |err| switch (err) {
                            error.InvalidBlake3ParentRows => break :match false,
                            else => return err,
                        };
                        break :match true;
                    };
                    if (fixed_match) {
                        self.stats.hits += 1;
                        held = false;
                        return .{ .cache = self, .worker = worker, .admission = admission };
                    }
                }
            }
            // The preceding lease has ended. Evict before constructing the next
            // entry so old and new fixed commitments cannot double the cap.
            self.dropEntry();
            const bounded = self.budget.allocator();
            const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(bounded, &prepared.recursive, self.options.profile);
            const key = try Protocol.Key.fromGeometry(geometry, prepared.wires);
            if (!std.meta.eql(key.context, prepared.recursive.context) or
                !std.meta.eql(key.config, key.context.child_config)) return error.V5NativeSetupCacheSecurityMismatch;
            const key_id = try key.identity();
            const schedule = try bounded.dupe(Bus.Wire, prepared.wires);
            errdefer bounded.free(schedule);
            const admission = try Protocol.Admission.init(key, key_id, schedule, prepared.values);
            const worker = try Worker.init(bounded, &prepared.recursive.rows, admission, self.options.worker_options);
            errdefer worker.deinit();
            const lease = try worker.acquire();
            self.entry = .{ .key = key, .key_id = key_id, .schedule = schedule, .worker = worker };
            self.stats.misses += 1;
            return .{ .cache = self, .worker = lease, .admission = admission };
        }
        /// Metadata preflight only: a non-null result still requires the real
        /// plan's exact fixed digest, row lengths, column/log inventories and
        /// worker lease checks above. Never treats public values as setup data.
        pub fn matchingAdmission(profile: Parent.protocol.Profile, key: Protocol.Key, key_id: [32]u8, schedule: []const Bus.Wire, prepared: *const Bus.Prepared) !?Protocol.Admission {
            if (!std.meta.eql(prepared.recursive.context.child_config, profile.config()))
                return error.V5NativeSetupCacheSecurityMismatch;
            const digest = try Bus.scheduleDigest(prepared.wires);
            if (key.profile != profile or !std.meta.eql(key.context, prepared.recursive.context) or
                !std.meta.eql(key.config, profile.config()) or
                !std.meta.eql(key.public_schedule_digest, digest) or schedule.len != prepared.wires.len) return null;
            for (schedule, prepared.wires) |owned, current| if (!std.meta.eql(owned, current)) return null;
            // Authenticate the cached ID/schedule and ALL current public values.
            // Worker.proveAdmitted also rebinds this admission even on same-key hits.
            return try Protocol.Admission.init(key, key_id, schedule, prepared.values);
        }
    };
}

test {
    _ = @import("tests/block_v5_native_recursive_consuming_test.zig");
}
test "native expected setup cache: independently required key rejects mismatch before proof work" {
    const wanted: [32]u8 = @splat(3);
    try requireExpectedKey(null, @splat(4)); // Original opt-in-free APIs.
    try requireExpectedKey(wanted, wanted);
    var changed = wanted;
    changed[0] ^= 1;
    try std.testing.expectError(error.V5NativeSetupCacheExpectedKeyMismatch, requireExpectedKey(wanted, changed));
}
