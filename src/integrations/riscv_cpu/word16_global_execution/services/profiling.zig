//! Optional observations only. Recorder identity never enters proof authority.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const core = @import("stwo_core");
const Profile = @import("stwo_prover_api").stage_profile;
const G = @import("../protocol.zig");
pub const Options = struct {
    commit_batch_columns: u32 = 64,
    schedule: @import("schedule.zig").Policy = .{},
    /// Maximum byte range advised for the current worker only, not an RSS cap.
    prefetch_main_bytes: usize = 0,
    retained_main: ?*@import("../retained_main_store.zig").Store = null,
    recorders: []const ?*Profile.Recorder = &.{},
    directory: ?std.fs.Dir = null,
    /// One-way producer mode: event arrays are freed as owned LS metadata is
    /// constructed. Advice outer headers remain valid and must be deinitialized.
    consume_memory_events: bool = false,
    pub fn validate(self: Options, count: usize) !void {
        try self.schedule.validate();
        if (self.prefetch_main_bytes > 4 << 30 or (self.prefetch_main_bytes != 0 and self.prefetch_main_bytes < std.heap.pageSize())) return error.InvalidRetainedMainPrefetchCap;
        if (self.commit_batch_columns == 0) return error.InvalidStreamingBatchSize;
        if (self.recorders.len != 0 and self.recorders.len != count) return error.InvalidServiceRecorderRoster;
        if (self.directory != null and self.recorders.len == 0) return error.MissingServiceRecorders;
    }
    pub fn recorder(self: Options, index: usize) ?*Profile.Recorder {
        return if (self.recorders.len == 0) null else self.recorders[index];
    }
    pub fn finish(self: Options, a: std.mem.Allocator, index: usize) !void {
        const dir = self.directory orelse return;
        const active = self.recorder(index) orelse return;
        var snapshot = try active.snapshot(a);
        defer snapshot.deinit(a);
        const bytes = try std.json.Stringify.valueAlloc(a, snapshot, .{ .whitespace = .indent_2 });
        defer a.free(bytes);
        var name: [40]u8 = undefined;
        const path = try std.fmt.bufPrint(&name, "physical-{d:0>4}.stages.json", .{index});
        try @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive(dir, path, bytes);
    }
};
pub fn prove(a: std.mem.Allocator, handles: []const engine.air.component_prover.ComponentProver, channel: *G.T.P.Channel, scheme: G.T.Scheme, recorder: ?*Profile.Recorder) !core.proof.StarkProof(G.T.P.Hasher) {
    var extended = try engine.prove.proveExWithRecorder(@import("stwo_cpu_backend").CpuBackend, G.T.P.Hasher, G.T.P.MerkleChannel, a, handles, channel, scheme, false, recorder);
    extended.aux.deinit(a);
    return extended.proof;
}
