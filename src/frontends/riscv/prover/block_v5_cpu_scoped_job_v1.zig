//! Actual driver completion callback: joined durable native/seven-family
//! stores -> exact independently derived roster -> bounded fresh scoped folds.
//! The manifest records proposals only; source/global obligations stay OPEN.
const std = @import("std");
const Sources = @import("block_v5_cpu_scoped_job_sources_v1.zig");
const Fold = @import("block_v5_cpu_scoped_job_fold_v1.zig");
const Publication = @import("block_v5_cpu_recursive_publication_v1.zig");
const Assembly = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(true);
const Forest = @import("block_v5_capacity_open_forest_stage_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
pub const Options = struct {
    source: Sources.Limits = .{},
    fold: Fold.Limits = .{},
    max_manifest_bytes: usize = 16 << 20,
    pub fn validate(self: Options) !void {
        try self.fold.validate();
        if (self.max_manifest_bytes == 0 or self.source.max_owned_bytes == 0 or self.source.max_source_cells == 0 or self.source.max_proof_bytes == 0) return error.InvalidCpuScopedJobOptions;
    }
};
pub const Report = struct {
    physical_leaves: usize,
    parent_files: usize,
    manifest: [32]u8,
    pub const complete_block_authority = false;
    pub const source_authority = false;
};
const PublicationCount = struct {
    next: u32 = 0,
    fn put(raw: *anyopaque, index: u32, pin: Fold.Pin, spec: *const @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig").NodeSpec) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (index != self.next or pin.byte_len == 0 or !std.meta.eql(try spec.key.identity(), spec.expected_id)) return error.InvalidCpuScopedPublicationOrder;
        self.next = try std.math.add(u32, self.next, 1);
    }
};
/// Must run after all leaf/family workers join and after original detached base
/// and original-row template verification. It borrows the same stable Source,
/// caller Catalog, Native.Prepared and writer schedules until teardown below.
/// It does not retain replay/PCS state, constructor captures or another roster.
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, assembly: *const Assembly.Assembly, publication: *Publication.Session, natives: []const Forest.LeafFile, options: Options) !Report {
    try options.validate();
    const source = try Sources.create(a, assembly, publication, natives, options.source);
    defer source.deinit();
    var count = PublicationCount{};
    var result = try Fold.ForBackend(@import("stwo_cpu_backend").CpuBackend).run(a, dir, source, publication.profile, options.fold, .{ .publish = .{ .context = &count, .put_open = PublicationCount.put } });
    defer result.deinit();
    if (count.next != result.files.len) return error.IncompleteCpuScopedNodeFiles;
    const bytes = try std.math.add(usize, 204, try std.math.mul(usize, result.files.len, 76));
    if (bytes > options.max_manifest_bytes) return error.CpuScopedManifestResourceLimit;
    const raw = try a.alloc(u8, bytes);
    defer a.free(raw);
    @memcpy(raw[0..8], "B5SCJOB1");
    std.mem.writeInt(u32, raw[8..12], @intCast(result.files.len), .little);
    var at: usize = 12;
    inline for (.{ result.owner.pins.job, result.owner.pins.coverage, result.owner.pins.source, result.owner.pins.scoped, result.owner.pins.routing, result.owner.pinned_identity }) |digest| {
        @memcpy(raw[at..][0..32], &digest);
        at += 32;
    }
    for (result.files, result.owner.pins.node_ids, 0..) |pin, key, index| {
        std.mem.writeInt(u32, raw[at..][0..4], @intCast(index), .little);
        std.mem.writeInt(u64, raw[at + 4 ..][0..8], pin.byte_len, .little);
        @memcpy(raw[at + 12 ..][0..32], &pin.sha256);
        @memcpy(raw[at + 44 ..][0..32], &key);
        at += 76;
    }
    if (at != raw.len) return error.IncompleteCpuScopedNodeFiles;
    try Files.publish(dir, "block-v5-cpu-scoped-nodes.pins", raw);
    return .{ .physical_leaves = source.coverage.meta.physical.len, .parent_files = result.files.len, .manifest = Files.hash(raw) };
}
