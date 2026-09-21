//! Lifecycle-aware owner for one final-campaign worker epoch.
//!
//! The sealed Stage-102 lifecycle remains the sole owner of the immutable
//! session and its provider installation. This owner derives that exact
//! session pointer from the lifecycle, owns one Worker and one Driver over
//! it, and destroys every worker-retained typed lease before returning
//! control to the still-installed lifecycle. It has no durable codec and
//! never accepts a caller-supplied Session pointer.

const std = @import("std");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const EXACT_INSTALLED_SESSION_POINTER_REQUIRED = true;
pub const WORKER_AND_LEASES_DESTROYED_BEFORE_LIFECYCLE = true;
pub const STORE_ROOT_EXACT_MATCH_REQUIRED = true;

pub const Error = error{
    CampaignFinalLiveRuntimeEpochMismatchV2,
    CampaignFinalLiveRuntimeEpochUnavailableV2,
};

/// `Worker.AdapterV1` must carry the same Session provider installed by
/// `Lifecycle.OwnedFinalSessionV4`. `Driver` must be the exact immutable
/// Session specialization. The generic form permits a cheap, non-proof test
/// adapter while production remains fail-closed with its adapter flags.
pub fn OwnerFor(
    comptime Worker: type,
    comptime Driver: type,
    comptime Lifecycle: type,
    comptime SessionProvider: type,
) type {
    assertTypes(Worker, Driver, Lifecycle, SessionProvider);

    return struct {
        const Self = @This();

        pub const available = Worker.AdapterV1.available and
            SessionProvider.available;
        pub const WorkerV1 = Worker;
        pub const FinalDriverV2 = Driver;
        pub const LifecycleV4 = Lifecycle;
        pub const SessionProviderV4 = SessionProvider;

        allocator: std.mem.Allocator,
        lifecycle: *Lifecycle.OwnedFinalSessionV4,
        session: *const SessionProvider.SessionV4,
        worker: Worker,
        driver: Driver,

        pub fn init(
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            store_root: []const u8,
            lifecycle: *Lifecycle.OwnedFinalSessionV4,
        ) !*Self {
            if (comptime !available)
                return error.CampaignFinalLiveRuntimeEpochUnavailableV2;
            try lifecycle.validate(scratch_allocator);
            const session: *const SessionProvider.SessionV4 =
                try lifecycle.immutableSession();
            try SessionProvider.requireInstalledSession(session);
            if (!std.mem.eql(u8, store_root, session.store.root_path))
                return error.CampaignFinalLiveRuntimeEpochMismatchV2;

            const self = try owner_allocator.create(Self);
            errdefer owner_allocator.destroy(self);
            self.allocator = owner_allocator;
            self.lifecycle = lifecycle;
            self.session = session;
            self.worker = try Worker.init(owner_allocator, store_root);
            errdefer self.worker.deinit();
            self.driver = try Driver.init(scratch_allocator, session);
            try self.validate(scratch_allocator);
            return self;
        }

        pub fn validate(
            self: *Self,
            scratch_allocator: std.mem.Allocator,
        ) !void {
            try self.lifecycle.validate(scratch_allocator);
            const session: *const SessionProvider.SessionV4 =
                try self.lifecycle.immutableSession();
            try SessionProvider.requireInstalledSession(session);
            try self.driver.validateIdentity(scratch_allocator);
            if (session != self.session or
                self.driver.session != session or
                self.driver.store != session.store or
                !std.mem.eql(
                    u8,
                    self.worker.store.root_path,
                    session.store.root_path,
                ))
            {
                return error.CampaignFinalLiveRuntimeEpochMismatchV2;
            }
        }

        /// Exclusive borrow. Any pointer projected from a retained lease dies
        /// before the next lease-table mutation or this owner's `deinit`.
        pub fn workerView(self: *Self) *Worker {
            return &self.worker;
        }

        pub fn driverView(self: *const Self) *const Driver {
            return &self.driver;
        }

        /// Worker destruction owns lease teardown. The lifecycle/provider is
        /// deliberately left installed for the external owner to validate or
        /// use in a subsequent epoch.
        pub fn deinit(self: *Self) void {
            const allocator = self.allocator;
            self.worker.deinit();
            self.* = undefined;
            allocator.destroy(self);
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn assertTypes(
    comptime Worker: type,
    comptime Driver: type,
    comptime Lifecycle: type,
    comptime SessionProvider: type,
) void {
    inline for (.{ "AdapterV1", "init", "deinit" }) |name|
        if (!@hasDecl(Worker, name))
            @compileError("live runtime epoch Worker missing " ++ name);
    inline for (.{ "SessionProviderV4", "available" }) |name|
        if (!@hasDecl(Worker.AdapterV1, name))
            @compileError("live runtime epoch adapter missing " ++ name);
    inline for (.{ "init", "validateIdentity" }) |name|
        if (!@hasDecl(Driver, name))
            @compileError("live runtime epoch Driver missing " ++ name);
    inline for (.{
        "OwnedFinalSessionV4",
        "ImmutableSessionV4",
        "ReplayProviderV4",
    }) |name| if (!@hasDecl(Lifecycle, name))
        @compileError("live runtime epoch Lifecycle missing " ++ name);
    inline for (.{
        "available",
        "SessionV4",
        "requireInstalledSession",
    }) |name| if (!@hasDecl(SessionProvider, name))
        @compileError("live runtime epoch Provider missing " ++ name);
    if (Worker.AdapterV1.SessionProviderV4 != SessionProvider or
        Lifecycle.ReplayProviderV4 != SessionProvider or
        Lifecycle.ImmutableSessionV4 != SessionProvider.SessionV4)
    {
        @compileError("live runtime epoch provider/session type drifted");
    }
    if (!@hasField(Driver, "store") or
        !@hasField(Driver, "session"))
    {
        @compileError("live runtime epoch Driver custody fields missing");
    }
    rejectCodec(Worker.AdapterV1);
    rejectCodec(Lifecycle.OwnedFinalSessionV4);
    rejectCodec(SessionProvider.SessionV4);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("live runtime epoch gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !EXACT_INSTALLED_SESSION_POINTER_REQUIRED or
        !WORKER_AND_LEASES_DESTROYED_BEFORE_LIFECYCLE or
        !STORE_ROOT_EXACT_MATCH_REQUIRED)
    {
        @compileError("campaign final live runtime epoch contract drifted");
    }
}
