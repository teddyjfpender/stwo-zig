//! Exact successfully published destination inventory. Original inputs and
//! pre-existing destinations are never enrolled. No proof or key authority.
const std = @import("std");
const Fold = @import("block_v5_cpu_scoped_job_fold_v1.zig");
const Page = @import("block_v5_memory_source_page_forest_policy_owner_v1.zig");
const Memory = @import("block_v5_ram_range_forest_policy_owner_v1.zig");
const MemoryManifest = @import("block_v5_ram_range_forest_manifest_v1.zig");
const FinalManifest = @import("block_v5_cpu_final_job_manifest_v1.zig");
pub const Inventory = struct {
    requester_nodes: usize = 0,
    page_leaves: usize = 0,
    page_nodes: usize = 0,
    memory_ram: usize = 0,
    memory_range: usize = 0,
    memory_nodes: usize = 0,
    memory_join: bool = false,
    memory_manifest: bool = false,
    public_root: bool = false,
    final_root: bool = false,
    final_manifest: bool = false,
    pub fn rollback(self: Inventory, dir: std.fs.Dir) void {
        if (self.final_manifest) dir.deleteFile(FinalManifest.NAME) catch {};
        FinalManifest.removePublished(dir, self.public_root, self.final_root);
        if (self.memory_manifest) dir.deleteFile(MemoryManifest.NAME) catch {};
        Memory.removePublished(dir, self.memory_ram, self.memory_range, self.memory_nodes, self.memory_join);
        for (0..self.page_nodes) |index| {
            var path: [128]u8 = undefined;
            dir.deleteFile(Page.nodeFilename(&path, @intCast(index)) catch continue) catch {};
        }
        for (0..self.page_leaves) |index| {
            var path: [128]u8 = undefined;
            dir.deleteFile(Page.leafFilename(&path, @intCast(index)) catch continue) catch {};
        }
        for (0..self.requester_nodes) |index| {
            var path: [128]u8 = undefined;
            dir.deleteFile(Fold.ForRecipe(.requesters).path(&path, @intCast(index)) catch continue) catch {};
        }
    }
};
