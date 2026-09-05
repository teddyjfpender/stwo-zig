//! Process-local live-lease binder for final campaign receipts.
//!
//! `CommittedStageV2` carries an opaque lease selector because the controller
//! may schedule by JSON. Before a receipt enters the final driver, this owner
//! proves that selector still names the exact node/output/StageManifest tuple
//! in the active typed worker. The verifier payload remains private to the
//! worker and no durable projection can mint this authority.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const driver_mod = @import("recursive_pipeline_campaign_final_driver_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const LIVE_TYPED_LEASE_REQUIRED = true;
pub const EXACT_LEASE_IDENTITY_REQUIRED = true;
pub const EXCLUSIVE_WORKER_BORROW_REQUIRED = true;
pub const VALIDATE_BEFORE_AND_AFTER_DRIVER = true;

pub const Error = error{
    CampaignFinalLiveReceiptMismatchV2,
};

pub fn BinderFor(
    comptime Worker: type,
    comptime Driver: type,
    comptime Frontier: type,
) type {
    assertWorker(Worker);
    assertDriver(Driver);
    assertFrontier(Frontier);

    return struct {
        pub const WorkerV1 = Worker;
        pub const DriverV2 = Driver;
        pub const FrontierV4 = Frontier;

        worker: *Worker,
        driver: *const Driver,

        const Self = @This();

        pub fn init(worker: *Worker, driver: *const Driver) Self {
            return .{ .worker = worker, .driver = driver };
        }

        pub const BorrowedRole0ReceiptV2 = struct {
            binder: *const Self,
            frontier: *const Frontier.OwnedFrontierV4,
            receipt: *const driver_mod.CommittedStageV2,
            index: usize,

            pub fn validate(self: BorrowedRole0ReceiptV2) !void {
                const rows = self.frontier.orderedRows();
                if (self.index >= rows.len)
                    return error.CampaignFinalLiveReceiptMismatchV2;
                const row = &rows[self.index];
                try row.role0.validate();
                try self.binder.worker.validateRetainedLeaseIdentity(
                    self.receipt.lease_id,
                    self.receipt.node.node_id,
                    self.receipt.output_ref,
                    self.receipt.stage_manifest_ref,
                );
                if (row.coordinate != @as(u32, @intCast(self.index)) or
                    !artifact_store.BlobRefV1.eql(
                        row.publication.output_ref,
                        self.receipt.output_ref,
                    ) or !artifact_store.BlobRefV1.eql(
                    row.publication.stage_manifest_ref,
                    self.receipt.stage_manifest_ref,
                ) or row.role0.lease.nodeArtifact().coordinate.index !=
                    row.coordinate or
                    row.role0.lease.nodeArtifact().coordinate.height != 0)
                {
                    return error.CampaignFinalLiveReceiptMismatchV2;
                }
            }

            pub fn node(
                self: BorrowedRole0ReceiptV2,
            ) *const protocol.Node {
                return self.receipt.node;
            }

            pub fn outputRef(
                self: BorrowedRole0ReceiptV2,
            ) artifact_store.BlobRefV1 {
                return self.receipt.output_ref;
            }

            pub fn stageManifestRef(
                self: BorrowedRole0ReceiptV2,
            ) artifact_store.BlobRefV1 {
                return self.receipt.stage_manifest_ref;
            }

            pub fn nodeArtifact(
                self: BorrowedRole0ReceiptV2,
            ) *const campaign_artifact.Artifact {
                return self.frontier.orderedRows()[self.index]
                    .role0.lease.nodeArtifact();
            }

            pub fn liveLeaseSelector(
                self: BorrowedRole0ReceiptV2,
            ) []const u8 {
                return self.receipt.lease_id;
            }
        };

        pub const BoundRole0FrontierV2 = struct {
            binder: *const Self,
            frontier: *const Frontier.OwnedFrontierV4,
            receipts: []const driver_mod.CommittedStageV2,

            pub fn validate(
                self: BoundRole0FrontierV2,
                allocator: std.mem.Allocator,
            ) !void {
                try self.binder.validateRole0Frontier(
                    allocator,
                    self.frontier,
                    self.receipts,
                );
            }

            pub fn len(self: BoundRole0FrontierV2) usize {
                return self.receipts.len;
            }

            pub fn role0At(
                self: BoundRole0FrontierV2,
                index: usize,
            ) !BorrowedRole0ReceiptV2 {
                if (index >= self.receipts.len or
                    self.receipts.len != self.frontier.orderedRows().len)
                {
                    return error.CampaignFinalLiveReceiptMismatchV2;
                }
                const result = BorrowedRole0ReceiptV2{
                    .binder = self.binder,
                    .frontier = self.frontier,
                    .receipt = &self.receipts[index],
                    .index = index,
                };
                try result.validate();
                return result;
            }
        };

        /// The caller grants an exclusive worker borrow for the full call.
        /// The second pass pins that driver validation did not accidentally
        /// consume or replace any role-0 lease.
        pub fn validateRole0Frontier(
            self: *const Self,
            allocator: std.mem.Allocator,
            frontier: anytype,
            receipts: []const driver_mod.CommittedStageV2,
        ) !void {
            try self.validateLiveReceipts(receipts);
            try self.driver.validateRole0Frontier(
                allocator,
                frontier,
                receipts,
            );
            try self.validateLiveReceipts(receipts);
        }

        pub fn validateLiveReceipts(
            self: *const Self,
            receipts: []const driver_mod.CommittedStageV2,
        ) !void {
            for (receipts) |receipt| {
                try self.worker.validateRetainedLeaseIdentity(
                    receipt.lease_id,
                    receipt.node.node_id,
                    receipt.output_ref,
                    receipt.stage_manifest_ref,
                );
            }
        }

        pub fn bindRole0Frontier(
            self: *const Self,
            allocator: std.mem.Allocator,
            frontier: *const Frontier.OwnedFrontierV4,
            receipts: []const driver_mod.CommittedStageV2,
        ) !BoundRole0FrontierV2 {
            const result = BoundRole0FrontierV2{
                .binder = self,
                .frontier = frontier,
                .receipts = receipts,
            };
            try result.validate(allocator);
            return result;
        }

        comptime {
            rejectCodec(Self);
            rejectCodec(BorrowedRole0ReceiptV2);
            rejectCodec(BoundRole0FrontierV2);
        }
    };
}

fn assertWorker(comptime Worker: type) void {
    if (!@hasDecl(Worker, "validateRetainedLeaseIdentity"))
        @compileError("final receipt binder worker lacks live lease identity validation");
}

fn assertDriver(comptime Driver: type) void {
    if (!@hasDecl(Driver, "validateRole0Frontier"))
        @compileError("final receipt binder driver lacks role0 frontier validation");
}

fn assertFrontier(comptime Frontier: type) void {
    if (!@hasDecl(Frontier, "OwnedFrontierV4"))
        @compileError("final receipt binder lacks ordered role0 frontier owner");
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("final live receipt authority gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !LIVE_TYPED_LEASE_REQUIRED or
        !EXACT_LEASE_IDENTITY_REQUIRED or
        !EXCLUSIVE_WORKER_BORROW_REQUIRED or
        !VALIDATE_BEFORE_AND_AFTER_DRIVER)
    {
        @compileError("campaign final live receipt binder contract drifted");
    }
}
