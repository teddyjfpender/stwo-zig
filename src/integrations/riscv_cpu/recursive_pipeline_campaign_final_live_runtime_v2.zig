//! Compile-time assembly for the process-local final-campaign runtime.
//!
//! One immutable Session provider supplies the final remint and execution
//! policy to the real Stage102/103/104 composite. The same composite payload
//! then flows through the generic Worker, live fold-child binder, incremental
//! build executor, committed-receipt adapter, and final Driver. This module
//! adds no route or durable wire; it exists to make nominal custody/type drift
//! across those independently gated pieces a compile error.

const std = @import("std");

const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const composite_mod = @import(
    "recursive_pipeline_worker_campaign_final_composite_v2.zig",
);
const binder_mod = @import(
    "recursive_pipeline_campaign_final_live_fold_child_binder_v2.zig",
);
const plan_mod = @import(
    "recursive_pipeline_campaign_final_live_build_plan_v2.zig",
);
const executor_mod = @import(
    "recursive_pipeline_campaign_final_live_build_executor_v2.zig",
);
const committed_mod = @import(
    "recursive_pipeline_campaign_final_live_committed_stage_v2.zig",
);
const epoch_mod = @import(
    "recursive_pipeline_campaign_final_live_runtime_epoch_v2.zig",
);
const driver_mod = @import("recursive_pipeline_campaign_final_driver_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const ONE_IMMUTABLE_SESSION_PROVIDER_REQUIRED = true;
pub const ONE_FINAL_REMINT_REQUIRED = true;
pub const EXACT_EXECUTION_KEY_POLICY_REQUIRED = true;
pub const LIVE_CHILD_PAYLOAD_REMAINS_WORKER_PRIVATE = true;
pub const WORKER_DESTROYED_BEFORE_SESSION_PROVIDER = true;

pub const Error = error{
    CampaignFinalLiveRuntimeMismatchV2,
    CampaignFinalLiveRuntimeUnavailableV2,
};

/// `FinalWorker` is the exact specialization produced by
/// `recursive_pipeline_campaign_final_worker_transaction_v2.Types`.
/// `SessionProvider` must be its already-installed immutable Stage102
/// provider and execution-policy provider.
pub fn Types(
    comptime FinalWorker: type,
    comptime SessionProvider: type,
) type {
    assertProvider(SessionProvider);
    const Composite = composite_mod.AdapterFor(
        FinalWorker,
        SessionProvider,
    );
    const Worker = worker_mod.Worker(Composite);
    const Binder = binder_mod.BinderFor(Worker);
    const Child = Binder.BorrowedChildV2;
    const Plan = plan_mod.PlanFor(Child, Child);
    const Executor = executor_mod.ExecutorFor(Worker, Plan);
    const Committed = committed_mod.AdapterFor(Executor);
    const Driver = driver_mod.DriverFor(
        SessionProvider.SessionV4,
        Composite,
    );

    return struct {
        pub const available = Composite.available;
        pub const FinalWorkerV2 = FinalWorker;
        pub const SessionProviderV4 = SessionProvider;
        pub const ImmutableSessionV4 = SessionProvider.SessionV4;
        pub const CompositeAdapterV2 = Composite;
        pub const WorkerV1 = Worker;
        pub const FoldChildBinderV2 = Binder;
        pub const BorrowedFoldChildV2 = Child;
        pub const LiveBuildPlanV2 = Plan;
        pub const LiveBuildExecutorV2 = Executor;
        pub const LiveCommittedStageV2 = Committed;
        pub const FinalDriverV2 = Driver;

        /// Binds this exact composite Worker/Driver to the installed
        /// Stage-102 lifecycle without accepting a caller-supplied Session
        /// pointer. The returned epoch remains unavailable while this
        /// production composite is unavailable.
        pub fn LifecycleEpochFor(comptime Lifecycle: type) type {
            return epoch_mod.OwnerFor(
                Worker,
                Driver,
                Lifecycle,
                SessionProvider,
            );
        }

        const Runtime = @This();

        /// Non-owning convenience view. The caller owns the installed Session,
        /// worker, every lease, and their destruction order.
        pub const BorrowedRuntimeV2 = struct {
            worker: *Worker,
            driver: *const Driver,
            binder: Binder,
            executor: Executor,

            pub fn init(
                scratch_allocator: std.mem.Allocator,
                worker: *Worker,
                driver: *const Driver,
            ) !BorrowedRuntimeV2 {
                try driver.validateIdentity(scratch_allocator);
                const result = BorrowedRuntimeV2{
                    .worker = worker,
                    .driver = driver,
                    .binder = Binder.init(worker),
                    .executor = Executor.init(worker),
                };
                try result.validate(scratch_allocator);
                return result;
            }

            pub fn validate(
                self: *const BorrowedRuntimeV2,
                scratch_allocator: std.mem.Allocator,
            ) !void {
                try self.driver.validateIdentity(scratch_allocator);
                if (self.binder.worker != self.worker or
                    self.executor.worker != self.worker)
                {
                    return error.CampaignFinalLiveRuntimeMismatchV2;
                }
            }

            comptime {
                rejectCodec(BorrowedRuntimeV2);
            }
        };

        /// Heap-stable worker/driver epoch. `session` and its provider
        /// installation are borrowed; the owner destroys the worker (and all
        /// remaining typed leases) before it releases that external session.
        pub const OwnedRuntimeV2 = struct {
            allocator: std.mem.Allocator,
            session: *const SessionProvider.SessionV4,
            worker: Worker,
            driver: Driver,

            pub fn init(
                owner_allocator: std.mem.Allocator,
                scratch_allocator: std.mem.Allocator,
                store_root: []const u8,
                session: *const SessionProvider.SessionV4,
            ) !*OwnedRuntimeV2 {
                if (comptime !Runtime.available)
                    return error.CampaignFinalLiveRuntimeUnavailableV2;
                try SessionProvider.requireInstalledSession(session);
                try session.validate(scratch_allocator);
                const final_remint = session.authority.final_remint;
                const namespace = final_remint.shape.campaign_namespace_sha256;
                const provided_final = try SessionProvider
                    .finalRemintForCampaign(namespace);
                const provided_authority = try SessionProvider
                    .authorityForCampaign(namespace);
                if (provided_final != final_remint or
                    provided_authority != session.authority)
                {
                    return error.CampaignFinalLiveRuntimeMismatchV2;
                }

                const self = try owner_allocator.create(OwnedRuntimeV2);
                errdefer owner_allocator.destroy(self);
                self.allocator = owner_allocator;
                self.session = session;
                self.worker = try Worker.init(owner_allocator, store_root);
                errdefer self.worker.deinit();
                self.driver = try Driver.init(scratch_allocator, session);
                try self.validate(scratch_allocator);
                return self;
            }

            pub fn validate(
                self: *OwnedRuntimeV2,
                scratch_allocator: std.mem.Allocator,
            ) !void {
                try SessionProvider.requireInstalledSession(self.session);
                try self.session.validate(scratch_allocator);
                try self.driver.validateIdentity(scratch_allocator);
                const namespace = self.driver.shape
                    .campaign_namespace_sha256;
                if (self.driver.session != self.session or
                    (try SessionProvider.finalRemintForCampaign(namespace)) !=
                        self.driver.final_remint or
                    (try SessionProvider.authorityForCampaign(namespace)) !=
                        self.session.authority or
                    !std.mem.eql(
                        u8,
                        self.worker.store.root_path,
                        self.session.store.root_path,
                    ))
                {
                    return error.CampaignFinalLiveRuntimeMismatchV2;
                }
                const borrowed = try self.borrow(scratch_allocator);
                try borrowed.validate(scratch_allocator);
            }

            pub fn borrow(
                self: *OwnedRuntimeV2,
                scratch_allocator: std.mem.Allocator,
            ) !BorrowedRuntimeV2 {
                return BorrowedRuntimeV2.init(
                    scratch_allocator,
                    &self.worker,
                    &self.driver,
                );
            }

            pub fn deinit(self: *OwnedRuntimeV2) void {
                const allocator = self.allocator;
                self.worker.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            comptime {
                rejectCodec(OwnedRuntimeV2);
            }
        };

        comptime {
            rejectCodec(Runtime);
            if (available or Composite.production or
                Worker.AdapterV1 != Composite or
                Binder.WorkerV1 != Worker or
                Binder.RetainedLeaseProjection !=
                    Composite.RetainedLeaseProjection or
                Executor.WorkerV1 != Worker or
                Executor.LiveBuildPlanV2 != Plan or
                Committed.ExecutorV2 != Executor)
            {
                @compileError("campaign final live runtime type closure drifted");
            }
        }
    };
}

fn assertProvider(comptime Provider: type) void {
    inline for (.{
        "available",
        "SessionV4",
        "requireInstalledSession",
        "authorityForCampaign",
        "finalRemintForCampaign",
        "policyForExecution",
    }) |name| if (!@hasDecl(Provider, name))
        @compileError("campaign final live runtime provider missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign final live runtime gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !ONE_IMMUTABLE_SESSION_PROVIDER_REQUIRED or
        !ONE_FINAL_REMINT_REQUIRED or
        !EXACT_EXECUTION_KEY_POLICY_REQUIRED or
        !LIVE_CHILD_PAYLOAD_REMAINS_WORKER_PRIVATE or
        !WORKER_DESTROYED_BEFORE_SESSION_PROVIDER)
    {
        @compileError("campaign final live runtime contract drifted");
    }
}
