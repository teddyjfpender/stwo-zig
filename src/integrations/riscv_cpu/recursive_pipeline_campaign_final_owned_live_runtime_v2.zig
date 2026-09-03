//! Move-style owner for an installed final-campaign lifecycle and runtime.
//!
//! The lifecycle owns the immutable Stage-102 session/provider. The nested
//! epoch owns the final Worker, its typed leases, and the Driver. This owner
//! fixes their destruction order: quiescing destroys the epoch and returns
//! the still-installed lifecycle; full destruction destroys the epoch before
//! uninstalling and releasing the lifecycle. No proof capability is encoded.

const std = @import("std");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const MOVE_STYLE_LIFECYCLE_OWNERSHIP = true;
pub const QUIESCE_RETURNS_INSTALLED_LIFECYCLE = true;
pub const WORKER_AND_LEASES_DESTROYED_BEFORE_LIFECYCLE = true;

pub const Error = error{
    CampaignFinalOwnedLiveRuntimeMismatchV2,
    CampaignFinalOwnedLiveRuntimeUnavailableV2,
};

/// Ownership of `lifecycle` transfers only after `init` succeeds. On error,
/// the caller still owns the exact pointer and provider installation.
pub fn OwnerFor(comptime Epoch: type, comptime Lifecycle: type) type {
    assertTypes(Epoch, Lifecycle);

    return struct {
        const Self = @This();

        pub const available = Epoch.available;
        pub const RuntimeEpochV2 = Epoch;
        pub const LifecycleV4 = Lifecycle;

        allocator: std.mem.Allocator,
        epoch: *Epoch,
        lifecycle: *Lifecycle.OwnedFinalSessionV4,

        pub fn init(
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            store_root: []const u8,
            lifecycle: *Lifecycle.OwnedFinalSessionV4,
        ) !*Self {
            if (comptime !available)
                return error.CampaignFinalOwnedLiveRuntimeUnavailableV2;
            // This validation is deliberately before the owner allocation:
            // a rejection cannot consume or mutate caller ownership.
            try lifecycle.validate(scratch_allocator);
            const epoch = try Epoch.init(
                owner_allocator,
                scratch_allocator,
                store_root,
                lifecycle,
            );
            errdefer epoch.deinit();
            const self = try owner_allocator.create(Self);
            errdefer owner_allocator.destroy(self);
            self.* = .{
                .allocator = owner_allocator,
                .epoch = epoch,
                .lifecycle = lifecycle,
            };
            try self.validate(scratch_allocator);
            return self;
        }

        pub fn validate(
            self: *Self,
            scratch_allocator: std.mem.Allocator,
        ) !void {
            try self.lifecycle.validate(scratch_allocator);
            try self.epoch.validate(scratch_allocator);
            if (self.epoch.lifecycle != self.lifecycle)
                return error.CampaignFinalOwnedLiveRuntimeMismatchV2;
        }

        pub fn epochView(self: *Self) *Epoch {
            return self.epoch;
        }

        /// Failure-atomic while validation fails. On success, destroys the
        /// Worker and every typed lease, destroys this owner, and transfers
        /// the still-installed lifecycle pointer back to the caller.
        pub fn quiesceRuntime(
            self: *Self,
            scratch_allocator: std.mem.Allocator,
        ) !*Lifecycle.OwnedFinalSessionV4 {
            try self.validate(scratch_allocator);
            const allocator = self.allocator;
            const lifecycle = self.lifecycle;
            self.epoch.deinit();
            self.* = undefined;
            allocator.destroy(self);
            return lifecycle;
        }

        /// Full ordered teardown. Worker-owned typed leases are destroyed
        /// before the lifecycle uninstalls its immutable Session provider.
        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.epoch.deinit();
            self.lifecycle.deinit();
            self.* = undefined;
            allocator.destroy(self);
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn assertTypes(comptime Epoch: type, comptime Lifecycle: type) void {
    inline for (.{
        "available",
        "LifecycleV4",
        "init",
        "validate",
        "deinit",
    }) |name| if (!@hasDecl(Epoch, name))
        @compileError("owned live runtime Epoch missing " ++ name);
    inline for (.{"OwnedFinalSessionV4"}) |name|
        if (!@hasDecl(Lifecycle, name))
            @compileError("owned live runtime Lifecycle missing " ++ name);
    if (Epoch.LifecycleV4 != Lifecycle)
        @compileError("owned live runtime Lifecycle type drifted");
    if (!@hasField(Epoch, "lifecycle"))
        @compileError("owned live runtime Epoch lost lifecycle custody");
    rejectCodec(Epoch);
    rejectCodec(Lifecycle.OwnedFinalSessionV4);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("owned live runtime gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !MOVE_STYLE_LIFECYCLE_OWNERSHIP or
        !QUIESCE_RETURNS_INSTALLED_LIFECYCLE or
        !WORKER_AND_LEASES_DESTROYED_BEFORE_LIFECYCLE)
    {
        @compileError("campaign owned live runtime contract drifted");
    }
}
