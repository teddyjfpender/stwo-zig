//! Process-wide Native Metal runtime ownership.
//!
//! Backend calls hold shared leases while using the runtime. Resident objects
//! retain a separate resource count, so explicit shutdown can fail closed
//! instead of invalidating buffers or trees that outlive a call.

const std = @import("std");
const core_aot = @import("core_aot.zig");
const runtime_mod = @import("runtime.zig");

var runtime_lock: std.Thread.RwLock = .{};
var shared_runtime: ?runtime_mod.Runtime = null;
var shared_identity: ?RuntimeIdentity = null;
var runtime_initializations: std.atomic.Value(u64) = .init(0);
var runtime_shutdowns: std.atomic.Value(u64) = .init(0);
var active_call_leases: std.atomic.Value(u64) = .init(0);
var live_resident_resources: std.atomic.Value(u64) = .init(0);

pub const LifecycleSnapshot = struct {
    initialized: bool,
    identity: ?RuntimeIdentity,
    active_call_leases: u64,
    live_resident_resources: u64,
    initialization_count: u64,
    shutdown_count: u64,
};

pub const RuntimeOrigin = enum {
    diagnostic_source_jit,
    authenticated_core_aot,
};

pub const RuntimeIdentity = struct {
    origin: RuntimeOrigin,
    source_sha256: [32]u8,
    manifest_sha256: ?[32]u8 = null,
    metallib_sha256: ?[32]u8 = null,
    metallib_bytes: ?u64 = null,
};

pub const InitializationPolicy = union(enum) {
    source_jit,
    authenticated_aot: struct {
        bundle_path: []const u8,
        manifest_sha256: [32]u8,
        profile: core_aot.Profile = .core_v2,
    },
};

pub const ShutdownError = error{
    RuntimeBusy,
    ResidentResourcesLive,
};

pub const CallLease = struct {
    runtime: *runtime_mod.Runtime,

    pub fn deinit(_: *CallLease) void {
        _ = active_call_leases.fetchSub(1, .monotonic);
        runtime_lock.unlockShared();
    }
};

/// Admits and initializes the process runtime exactly once. A conflicting
/// policy fails closed, and authenticated AOT never falls back to source JIT.
pub fn initialize(allocator: std.mem.Allocator, policy: InitializationPolicy) !void {
    runtime_lock.lock();
    defer runtime_lock.unlock();

    if (shared_runtime != null) {
        if (policyMatchesIdentity(policy, shared_identity.?)) return;
        return error.RuntimePolicyConflict;
    }

    switch (policy) {
        .source_jit => {
            shared_runtime = try runtime_mod.Runtime.init();
            shared_identity = sourceIdentity();
        },
        .authenticated_aot => |aot| {
            var admission = try core_aot.admitForProfile(
                allocator,
                aot.bundle_path,
                aot.manifest_sha256,
                aot.profile,
            );
            defer admission.deinit();
            shared_runtime = try runtime_mod.Runtime.initFromAotAdmission(&admission);
            shared_identity = .{
                .origin = .authenticated_core_aot,
                .source_sha256 = aot.profile.sourceDigest(),
                .manifest_sha256 = aot.manifest_sha256,
                .metallib_sha256 = admission.metallib.sha256,
                .metallib_bytes = admission.metallib.bytes,
            };
        },
    }
    _ = runtime_initializations.fetchAdd(1, .monotonic);
}

pub fn acquire() !CallLease {
    while (true) {
        runtime_lock.lockShared();
        if (shared_runtime) |*active_runtime| {
            _ = active_call_leases.fetchAdd(1, .monotonic);
            return .{ .runtime = active_runtime };
        }
        runtime_lock.unlockShared();

        runtime_lock.lock();
        defer runtime_lock.unlock();
        if (shared_runtime == null) {
            shared_runtime = try runtime_mod.Runtime.init();
            shared_identity = sourceIdentity();
            _ = runtime_initializations.fetchAdd(1, .monotonic);
        }
    }
}

pub fn acquireExisting() error{RuntimeNotInitialized}!CallLease {
    runtime_lock.lockShared();
    const active_runtime = if (shared_runtime) |*value| value else {
        runtime_lock.unlockShared();
        return error.RuntimeNotInitialized;
    };
    _ = active_call_leases.fetchAdd(1, .monotonic);
    return .{ .runtime = active_runtime };
}

/// Retains one resident object created while a call lease is active.
pub fn retainResidentResource() void {
    _ = live_resident_resources.fetchAdd(1, .monotonic);
}

pub fn releaseResidentResource() void {
    const previous = live_resident_resources.fetchSub(1, .monotonic);
    std.debug.assert(previous > 0);
}

pub fn destroyResidentBuffer(handle: *anyopaque) void {
    runtime_mod.ResidentBuffer.destroyOpaque(handle);
    releaseResidentResource();
}

pub fn lifecycleSnapshot() LifecycleSnapshot {
    runtime_lock.lockShared();
    defer runtime_lock.unlockShared();
    return .{
        .initialized = shared_runtime != null,
        .identity = shared_identity,
        .active_call_leases = active_call_leases.load(.monotonic),
        .live_resident_resources = live_resident_resources.load(.monotonic),
        .initialization_count = runtime_initializations.load(.monotonic),
        .shutdown_count = runtime_shutdowns.load(.monotonic),
    };
}

pub fn platformIdentityAlloc(allocator: std.mem.Allocator) ![]u8 {
    var lease = try acquireExisting();
    defer lease.deinit();
    return lease.runtime.platformIdentityAlloc(allocator);
}

/// Releases the runtime only when no calls or backend-owned resident objects
/// can still reference it. A successful shutdown permits a later warmup.
pub fn shutdown() ShutdownError!void {
    if (!runtime_lock.tryLock()) return error.RuntimeBusy;
    defer runtime_lock.unlock();
    if (live_resident_resources.load(.acquire) != 0) {
        return error.ResidentResourcesLive;
    }
    if (shared_runtime) |*active_runtime| {
        active_runtime.deinit();
        shared_runtime = null;
        shared_identity = null;
        _ = runtime_shutdowns.fetchAdd(1, .monotonic);
    }
}

fn sourceIdentity() RuntimeIdentity {
    return .{
        .origin = .diagnostic_source_jit,
        .source_sha256 = core_aot.sourceDigest(),
    };
}

fn policyMatchesIdentity(policy: InitializationPolicy, identity: RuntimeIdentity) bool {
    return switch (policy) {
        .source_jit => identity.origin == .diagnostic_source_jit,
        .authenticated_aot => |aot| identity.origin == .authenticated_core_aot and
            std.meta.eql(identity.source_sha256, aot.profile.sourceDigest()) and
            identity.manifest_sha256 != null and
            std.meta.eql(identity.manifest_sha256.?, aot.manifest_sha256),
    };
}

test "Metal shared runtime lifecycle observation does not initialize a device" {
    const lifecycle = lifecycleSnapshot();
    try std.testing.expect(lifecycle.initialization_count >= lifecycle.shutdown_count);
    try std.testing.expectEqual(
        lifecycle.initialized,
        lifecycle.initialization_count > lifecycle.shutdown_count,
    );
    try std.testing.expectEqual(lifecycle.initialized, lifecycle.identity != null);
}

test "Metal shared runtime policy identity matching is exact" {
    const source = sourceIdentity();
    try std.testing.expect(policyMatchesIdentity(.source_jit, source));
    try std.testing.expect(!policyMatchesIdentity(.{
        .authenticated_aot = .{
            .bundle_path = "/ignored",
            .manifest_sha256 = [_]u8{1} ** 32,
        },
    }, source));

    const aot = RuntimeIdentity{
        .origin = .authenticated_core_aot,
        .source_sha256 = core_aot.Profile.core_v2.sourceDigest(),
        .manifest_sha256 = [_]u8{3} ** 32,
        .metallib_sha256 = [_]u8{4} ** 32,
        .metallib_bytes = 4096,
    };
    try std.testing.expect(policyMatchesIdentity(.{
        .authenticated_aot = .{
            .bundle_path = "/same-authority",
            .manifest_sha256 = [_]u8{3} ** 32,
        },
    }, aot));
    try std.testing.expect(!policyMatchesIdentity(.source_jit, aot));
}

test "Ethereum AOT runtime cannot reuse a core library for a different admitted profile" {
    const identity = RuntimeIdentity{ .origin = .authenticated_core_aot, .source_sha256 = core_aot.Profile.core_v2.sourceDigest(), .manifest_sha256 = .{3} ** 32 };
    try std.testing.expect(!policyMatchesIdentity(.{ .authenticated_aot = .{ .bundle_path = "/same-pin", .manifest_sha256 = .{3} ** 32, .profile = .ethereum_fixed_program_narrow_v1 } }, identity));
}
