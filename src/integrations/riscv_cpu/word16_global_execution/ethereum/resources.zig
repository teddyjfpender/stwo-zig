//! Operational resource admission; no field selects proof/security authority.
const std = @import("std");
const ReceiverBudget = @import("receiver_budget.zig");
const CaptureOptions = @import("capture_options.zig").Options;
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const Schedule = @import("../services/schedule.zig");
/// Operational admission only. These limits never enter statement authority.
/// The coordinator's accounting is not a complete bound on process RSS.
pub const Resources = struct {
    gkr_bytes: usize,
    global_bytes: usize,
    retained_frontend_bytes: usize,
    disk_bytes: usize,
    /// Explicit operational choice: small inventories may retain MAIN in RAM.
    park_main: bool = true,
    /// Operational cache only; never changes live proof ownership or protocol.
    recycler_cache_bytes: usize = ReceiverBudget.RECYCLER_CACHE_BYTES,
    /// Producer geometry experiment. The default preserves the admitted roster.
    keccak_max_log: u32 = 18,
    one_truth_per_family: bool = false,
    coalesce_truth_families: bool = false,
    checkpoint_above_gkr_bytes: usize = 0,
    defer_local_binding: bool = false,
    capture_options: CaptureOptions = .{},
    stage2_order: []const usize = &.{},
    schedule: Schedule.Policy,
    pub fn validate(self: Resources) !void {
        if (self.gkr_bytes == 0 or self.global_bytes == 0 or self.retained_frontend_bytes == 0 or (self.park_main and self.disk_bytes == 0) or self.schedule.memory_cap_bytes == 0) return error.MissingWideResourceAdmission;
        try self.capture_options.validate();
        try self.schedule.validate();
        if (self.recycler_cache_bytes > ReceiverBudget.RECYCLER_CACHE_BYTES) return error.UnsupportedRecyclerCacheLimit;
        if (self.keccak_max_log < 16 or self.keccak_max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
        try Schedule.validateOrder(self.stage2_order, self.stage2_order.len);
    }
    pub fn jsonStringify(self: Resources, writer: anytype) !void {
        try writer.beginObject();
        inline for (.{ "gkr_bytes", "global_bytes", "retained_frontend_bytes", "disk_bytes", "park_main", "schedule" }) |name| {
            try writer.objectField(name);
            try writer.write(@field(self, name));
        }
        // Preserve historical default report schema; only explicit opt-in emits order.
        if (self.stage2_order.len != 0) {
            try writer.objectField("stage2_order");
            try writer.write(self.stage2_order);
        }
        if (!self.capture_options.isDefault()) {
            try writer.objectField("capture_options");
            try writer.write(self.capture_options);
        }
        if (self.recycler_cache_bytes != ReceiverBudget.RECYCLER_CACHE_BYTES) {
            try writer.objectField("recycler_cache_bytes");
            try writer.write(self.recycler_cache_bytes);
        }
        if (self.coalesce_truth_families) {
            try writer.objectField("coalesce_truth_families");
            try writer.write(true);
        }
        if (self.one_truth_per_family) {
            try writer.objectField("one_truth_per_family");
            try writer.write(true);
        }
        if (self.keccak_max_log != 18) {
            try writer.objectField("keccak_max_log");
            try writer.write(self.keccak_max_log);
        }
        if (self.checkpoint_above_gkr_bytes != 0) {
            try writer.objectField("checkpoint_above_gkr_bytes");
            try writer.write(self.checkpoint_above_gkr_bytes);
        }
        if (self.defer_local_binding) {
            try writer.objectField("defer_local_binding");
            try writer.write(true);
        }
        try writer.endObject();
    }
};
/// Separate operational schema keeps historical control resource/report bytes
/// unchanged. No field in either schema selects a security construction.
pub const CandidateResources = struct {
    /// Geometry-only producer option. Every emitted policy/shape remains bound
    /// by the existing statement and independently rebuilt by the receiver.
    keccak_uniform_throughput: bool = false,
    gkr_bytes: usize,
    global_bytes: usize,
    retained_frontend_bytes: usize,
    disk_bytes: usize,
    fixed_setup_bytes: usize,
    park_main: bool = true,
    recycler_cache_bytes: usize = ReceiverBudget.RECYCLER_CACHE_BYTES,
    /// Producer geometry experiment. The default preserves the admitted roster.
    keccak_max_log: u32 = 18,
    one_truth_per_family: bool = false,
    coalesce_truth_families: bool = false,
    checkpoint_above_gkr_bytes: usize = 0,
    defer_local_binding: bool = false,
    capture_options: CaptureOptions = .{},
    stage2_order: []const usize = &.{},
    schedule: Schedule.Policy,
    pub fn operational(self: CandidateResources) Resources {
        return .{ .gkr_bytes = self.gkr_bytes, .global_bytes = self.global_bytes, .retained_frontend_bytes = self.retained_frontend_bytes, .disk_bytes = self.disk_bytes, .park_main = self.park_main, .recycler_cache_bytes = self.recycler_cache_bytes, .keccak_max_log = self.keccak_max_log, .one_truth_per_family = self.one_truth_per_family, .coalesce_truth_families = self.coalesce_truth_families, .checkpoint_above_gkr_bytes = self.checkpoint_above_gkr_bytes, .defer_local_binding = self.defer_local_binding, .capture_options = self.capture_options, .stage2_order = self.stage2_order, .schedule = self.schedule };
    }
    pub fn validate(self: CandidateResources) !void {
        if (self.fixed_setup_bytes == 0) return error.MissingCandidateFixedSetupAdmission;
        try self.operational().validate();
    }
};

test {
    _ = @import("resources_test.zig");
}
// Worker admission is an operational bound, independent of scheduler threads.
// Parked coefficients and Merkle trees are bounded by explicit byte/disk
// admission. Their roster must fit the existing receiver security envelope.
// No-store retention keeps its smaller resident bound.
pub fn residentWorkerLimit(park_main: bool, count: usize, keccak_max_log: u32) !usize {
    if (park_main) return error.ResidentPipelineCannotParkMain;
    if (keccak_max_log < 16 or keccak_max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
    if (count == 0 or count > Candidate.MAX_PROOFS or count > @import("../services/gkr_local/manifest.zig").MAX_WORKERS) return error.BoundedWideCoordinatorLimit;
    return count;
}
pub fn producerWorkerLimit(park_main: bool, count: usize, keccak_max_log: u32) !usize {
    if (keccak_max_log < 16 or keccak_max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
    const cap: usize = if (park_main) @intCast(Candidate.MAX_PROOFS) else 8;
    if (count == 0 or count > cap or count > @import("../services/gkr_local/manifest.zig").MAX_WORKERS) return error.BoundedWideCoordinatorLimit;
    return if (park_main) @max(@as(usize, 32), count) else 8;
}
