//! Process-local provider slot for a campaign recursive worker.
//!
//! The frozen worker adapter contract uses comptime provider functions, while
//! the authenticated campaign, final remint, Stage-102 admissions, and host
//! execution policy exist only at runtime. This slot bridges those boundaries
//! for exactly one campaign session. Installation must bracket the worker
//! lifetime; the borrowed session remains immutable until the worker and all
//! of its leases are destroyed. Nothing in this module has a durable codec.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const inventory_opener =
    @import("recursive_pipeline_worker_campaign_real_leaf_inventory_opener_v4.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SINGLE_CAMPAIGN_PER_SPECIALIZATION = true;
pub const EXACT_INSTALLED_SESSION_POINTER_REQUIRED = true;

pub const Stage102ColdAdmissionV4 =
    inventory_opener.Stage102ColdAdmissionV4;
pub const FinalRemint = final_mod.CampaignFinalRemintAuthorityV2;
pub const PolicyV2 = policy_mod.PolicyV2;

pub const Error = error{
    CampaignWorkerSessionAlreadyInstalledV4,
    CampaignWorkerSessionNotInstalledV4,
};

/// Session contract:
///
/// - `AuthorityV4: type`;
/// - `validate(allocator) !void`;
/// - `authorityForCampaign(namespace) !*const AuthorityV4`;
/// - `stage102AdmissionForOutput(namespace, ref)
///      !*const Stage102ColdAdmissionV4`;
/// - `finalRemintForCampaign(namespace) !*const FinalRemint`;
/// - `policyForExecution(execution) !PolicyV2`.
/// - `adoptStage102ColdPublication(...) !void` deep-owns every retained
///   request projection before returning.
///
/// The session is an owner-defined process-local bundle. In particular, this
/// provider never derives an authority from an artifact digest or receipt.
pub fn ProviderFor(comptime Session: type) type {
    assertSession(Session);

    return struct {
        const Provider = @This();

        pub const available = true;
        pub const AuthorityV4 = Session.AuthorityV4;
        pub const SessionV4 = Session;

        var mutex: std.Thread.Mutex = .{};
        var active: ?*const Session = null;

        /// Move-only lifecycle token. The caller must destroy the worker and
        /// every lease before calling `deinit`.
        pub const InstalledV4 = struct {
            session: *const Session,
            installed: bool = true,

            pub fn validate(
                self: *const InstalledV4,
                allocator: std.mem.Allocator,
            ) !void {
                if (!self.installed or
                    try Provider.current() != self.session)
                {
                    return error.CampaignWorkerSessionNotInstalledV4;
                }
                try self.session.validate(allocator);
            }

            pub fn deinit(self: *InstalledV4) void {
                Provider.mutex.lock();
                defer Provider.mutex.unlock();
                std.debug.assert(self.installed);
                std.debug.assert(Provider.active == self.session);
                Provider.active = null;
                self.installed = false;
            }
        };

        pub fn install(
            allocator: std.mem.Allocator,
            session: *const Session,
        ) !InstalledV4 {
            try session.validate(allocator);
            mutex.lock();
            defer mutex.unlock();
            if (active != null)
                return error.CampaignWorkerSessionAlreadyInstalledV4;
            active = session;
            return .{ .session = session };
        }

        pub fn isInstalled() bool {
            mutex.lock();
            defer mutex.unlock();
            return active != null;
        }

        /// Requires the caller's borrow to be the exact immutable session
        /// installed in this specialization. A value-identical copy is not a
        /// process-local capability and is rejected.
        pub fn requireInstalledSession(session: *const Session) !void {
            if (try current() != session)
                return error.CampaignWorkerSessionNotInstalledV4;
        }

        pub fn authorityForCampaign(
            namespace: artifact_store.Digest,
        ) !*const AuthorityV4 {
            return (try current()).authorityForCampaign(namespace);
        }

        pub fn stage102AdmissionForOutput(
            namespace: artifact_store.Digest,
            output_ref: artifact_store.BlobRefV1,
        ) !*const Stage102ColdAdmissionV4 {
            return (try current()).stage102AdmissionForOutput(
                namespace,
                output_ref,
            );
        }

        pub fn finalRemintForCampaign(
            namespace: artifact_store.Digest,
        ) !*const FinalRemint {
            return (try current()).finalRemintForCampaign(namespace);
        }

        pub fn policyForExecution(
            execution: artifact_store.ExecutionKeyV1,
        ) !PolicyV2 {
            return (try current()).policyForExecution(execution);
        }

        pub fn adoptStage102ColdPublication(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
        ) !void {
            return (try current()).adoptStage102ColdPublication(
                allocator,
                node,
                semantic,
                execution,
                ordered_inputs,
                output_ref,
                stage_manifest_ref,
                dependency_stage_manifest_refs,
            );
        }

        fn current() !*const Session {
            mutex.lock();
            defer mutex.unlock();
            return active orelse
                error.CampaignWorkerSessionNotInstalledV4;
        }

        comptime {
            rejectCodec(InstalledV4);
            if (!Provider.available)
                @compileError("campaign worker session provider unavailable");
        }
    };
}

fn assertSession(comptime Session: type) void {
    inline for (.{
        "AuthorityV4",
        "validate",
        "authorityForCampaign",
        "stage102AdmissionForOutput",
        "finalRemintForCampaign",
        "policyForExecution",
        "adoptStage102ColdPublication",
    }) |name| if (!@hasDecl(Session, name))
        @compileError("campaign worker session missing " ++ name);
    rejectCodec(Session);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign worker session gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !SINGLE_CAMPAIGN_PER_SPECIALIZATION or
        !EXACT_INSTALLED_SESSION_POINTER_REQUIRED)
    {
        @compileError("campaign worker session provider contract drifted");
    }
}
