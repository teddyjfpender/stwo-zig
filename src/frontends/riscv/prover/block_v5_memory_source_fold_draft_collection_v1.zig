//! Typed draft replay/promotion transaction for the ORIGINAL Job collect loop.
//! A successful Store.Pin remains transport metadata, never proof authority.
const std = @import("std");
const Draft = @import("block_v5_memory_source_fold_draft_pages_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Store = @import("block_v5_memory_source_fold_operand_store_v1.zig");

pub const Collection = struct {
    owner: *Draft.Owner,
    admitted: *const Batch.Admission,
    plan: Protocol.FoldPlan,
    limits: Protocol.Limits,
    reader: Draft.Reader,
    created: u32 = 0,
    raw_planned: u32,
    raw_created: u32 = 0,
    live: bool = true,
    committed: bool = false,
    pub const source_authority = false;

    /// Reject any reused publication owner before taking its reader lease.
    /// The original drafts, plan, source census and limits remain authoritative
    /// only as admission/transport inputs to the genuine PAGE producer.
    pub fn init(owner: *Draft.Owner, admitted: *const Batch.Admission, plan: Protocol.FoldPlan, limits: Protocol.Limits, raw_pages: u32) !Collection {
        try owner.require(admitted, plan, limits);
        if (owner.published != 0) return error.ReusedSourceFoldDraftPublication;
        return .{ .owner = owner, .admitted = admitted, .plan = plan, .limits = limits, .raw_planned = raw_pages, .reader = try Draft.Reader.open(owner, admitted, plan, limits) };
    }
    pub fn next(self: *Collection) !?Fold.Operation {
        if (!self.live or self.committed) return error.ClosedSourceFoldDraftCollection;
        return self.reader.next();
    }
    pub fn requireFinished(self: *const Collection) !void {
        if (!self.live or self.committed) return error.ClosedSourceFoldDraftCollection;
        try self.reader.requireFinished();
    }
    /// Job must call its original actual FoldOwner.require and derive the
    /// independently admitted six-root pin identity before this operation.
    /// Promotion itself checks original header/record/hash/order invariants.
    pub fn promote(self: *Collection, index: u32, page_identity: [32]u8) !Store.Pin {
        if (!self.live or self.committed) return error.ClosedSourceFoldDraftCollection;
        if (index != self.created) return error.InvalidSourceFoldDraftOrder;
        const pin = try self.owner.promote(self.admitted, self.plan, index, page_identity, self.limits);
        self.created += 1; // Immediately after successful exclusive publication.
        return pin;
    }
    /// Original RawOwner.persist publishes exclusively. Record its successful
    /// return immediately, before all later checks, without allocating state.
    /// Job has independently admitted the exact raw roster before this call.
    pub fn recordRaw(self: *Collection, index: u32) void {
        std.debug.assert(self.live and !self.committed and index == self.raw_created and index < self.raw_planned);
        self.raw_created += 1;
    }
    /// Transfer file ownership only after the Job's original root roster,
    /// source epoch, Context and sealed phase have all been constructed.
    pub fn commit(self: *Collection) !void {
        try self.requireFinished();
        if (self.created != self.plan.pages or self.raw_created != self.raw_planned) return error.IncompleteSourceFoldDraftPublication;
        self.committed = true;
    }
    pub fn deinit(self: *Collection) void {
        if (!self.live) return;
        self.reader.deinit();
        self.live = false;
        if (!self.committed) {
            self.owner.failed = true;
            var remaining = self.created;
            while (remaining != 0) {
                remaining -= 1;
                var buffer: [128]u8 = undefined;
                const filename = Draft.path(&buffer, remaining, true) catch continue;
                self.owner.dir.deleteFile(filename) catch {};
            }
            remaining = self.raw_created;
            while (remaining != 0) {
                remaining -= 1;
                var buffer: [128]u8 = undefined;
                const filename = rawPath(&buffer, remaining) catch continue;
                self.owner.dir.deleteFile(filename) catch {};
            }
        }
    }
};
/// Exactly the original Job.name(.raw,index,false) path; shared-source parity
/// is checked by the integration fixture without changing its public API.
pub fn rawPath(buffer: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "source-page-raw-{d}.operands", .{index});
}
