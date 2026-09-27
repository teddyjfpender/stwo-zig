//! Versioned native-v3/OpenV2 staged producer. Ready parents prove every child
//! verifier equation, publish deterministic hash-pinned files, then release
//! dependents. Metadata is provisional; only fresh complete reception promotes
//! a globally closed block. No legacy claim-zero forest admission is accepted.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const engine = @import("stwo_prover_engine");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const normalized = @import("../recursion/block_v5_open_child_frames_v2.zig");
const bus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const protocol = @import("../recursion/block_v5_reusable_open_parent_protocol_v2.zig");
const preparation = @import("../recursion/block_v5_open_parent_preparation_v2.zig");
const exact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
const verified_mod = @import("../recursion/blake3_native_parent_verifier.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const dag_mod = @import("block_v5_open_exact_forest_plan_v1.zig");
const queue_mod = @import("block_v5_open_forest_queue_v1.zig");
const setup_cache = @import("block_v5_open_parent_setup_cache_v1.zig");
const Cache = setup_cache.ForBackend(Cpu);
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const VERSION: u32 = 1;
pub const ParentPin = struct {
    kind: dag_mod.Kind,
    slots: spans.SlotSpan,
    child_slots: [4]spans.SlotSpan,
    node: exact.NodePin,
    file: exact.FilePin,
};
pub const OuterPin = struct { node: exact.NodePin, file: exact.FilePin };
pub const Options = struct {
    profile: parent.protocol.Profile,
    lane_count: usize,
    total_host_limit: usize,
    max_execution_count: u32,
    max_proof_bytes: usize,
    /// Standalone only; shared_pool uses the driver's global helper capacity.
    pool_workers_per_lane: usize = 1,
    setup_cache_entries_per_lane: usize = 1,
    retained_scratch_bytes_per_lane: usize = 0,
    /// Independent coordinators can share one driver's helper pool. Borrowed
    /// through finish/abort; this changes scheduling, never proof admission.
    shared_pool: ?*engine.work_pool.WorkPool = null,
};
pub const Stage = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    execution_count: u32,
    parents: []ParentPin,
    outer: OuterPin,
    public_pins: exact.OuterPins,
    combined_native_open_sum: core.fields.qm31.QM31,
    /// All stage-owned allocations, including retained schedules/pin metadata.
    /// Borrowed native public policy is owned by the caller and excluded.
    stage_owned_peak_bytes: usize,
    setup_cache_stats: setup_cache.Stats = .{},
    budget: *Budget,
    pub fn deinit(self: *Stage) void {
        for (self.parents) |pin| self.a.free(pin.node.schedule);
        self.a.free(self.parents);
        self.a.free(self.outer.node.schedule);
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn leafPath(index: u32, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "block-v5-open-native-leaf-{d}.proof", .{index});
}
pub fn parentPath(index: u32, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "block-v5-open-parent-{d}.proof", .{index});
}
pub const OUTER_FILE = "block-v5-open-exact-outer.proof";
pub fn openPinned(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, pin: exact.FilePin, max_bytes: usize) ![]u8 {
    if (pin.byte_len == 0 or pin.byte_len > max_bytes or std.mem.allEqual(u8, &pin.sha256, 0)) return error.InvalidV5OpenProofFilePin;
    var file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != pin.byte_len) return error.TamperedV5OpenProofFile;
    const bytes = try file.readToEndAlloc(a, @intCast(pin.byte_len));
    errdefer a.free(bytes);
    if (bytes.len != pin.byte_len or !std.meta.eql(hash(bytes), pin.sha256)) return error.TamperedV5OpenProofFile;
    return bytes;
}
pub fn writeProof(dir: std.fs.Dir, name: []const u8, bytes: []const u8, max_bytes: usize) !exact.FilePin {
    if (bytes.len == 0 or bytes.len > max_bytes) return error.InvalidV5OpenProofFileSize;
    var file = try dir.createFile(name, .{ .exclusive = true });
    errdefer dir.deleteFile(name) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
    return .{ .byte_len = bytes.len, .sha256 = hash(bytes) };
}
fn hash(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

/// Explicit typed specialization; NativeV3 remains the public default.
pub const ForLeafAdapter = @import("block_v5_open_forest_stage_impl_v1.zig").ForLeafAdapter;
const Default = ForLeafAdapter(@import("../recursion/block_v5_native_exact_leaf_adapter_v1.zig"));
pub const LeafFile = Default.LeafFile;
pub const Stream = Default.Stream;
pub const prove = Default.prove;
