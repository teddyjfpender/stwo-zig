//! Only transport files are created here; no guest/proof/receiver is invoked.
const std = @import("std");
const Cleanup = @import("block_v5_cpu_recursive_completion_rollback_v1.zig");
const Fold = @import("block_v5_cpu_scoped_job_fold_v1.zig");
const Page = @import("block_v5_memory_source_page_forest_policy_owner_v1.zig");
const Memory = @import("block_v5_ram_range_forest_policy_owner_v1.zig");
const MemoryManifest = @import("block_v5_ram_range_forest_manifest_v1.zig");
const Final = @import("block_v5_cpu_final_job_manifest_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
fn present(dir: std.fs.Dir, name: []const u8) !void {
    const file = try dir.openFile(name, .{});
    file.close();
}
fn gone(dir: std.fs.Dir, name: []const u8) !void {
    try std.testing.expectError(error.FileNotFound, dir.openFile(name, .{}));
}
test "cpu recursive completion: cross stage rollback preserves originals and unowned destinations at every handoff" {
    for (0..5) |stage| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var inventory = Cleanup.Inventory{};
        const original = "original-native.proof";
        try Files.publish(tmp.dir, original, "original transport input");
        var path: [128]u8 = undefined;
        // Sentinels sit immediately beyond each successfully published prefix.
        try Files.publish(tmp.dir, try Fold.ForRecipe(.requesters).path(&path, 2), "existing requester destination");
        try Files.publish(tmp.dir, try Page.leafFilename(&path, 2), "existing PAGE destination");
        try Files.publish(tmp.dir, try Memory.filename(&path, .ram, 2), "existing RAM destination");
        if (stage >= 1) {
            for (0..2) |i| try Files.publish(tmp.dir, try Fold.ForRecipe(.requesters).path(&path, @intCast(i)), "new requester transport");
            inventory.requester_nodes = 2;
        }
        if (stage >= 2) {
            for (0..2) |i| try Files.publish(tmp.dir, try Page.leafFilename(&path, @intCast(i)), "new PAGE transport");
            try Files.publish(tmp.dir, try Page.nodeFilename(&path, 0), "new PAGE parent transport");
            inventory.page_leaves = 2;
            inventory.page_nodes = 1;
        }
        if (stage >= 3) {
            for (0..2) |i| try Files.publish(tmp.dir, try Memory.filename(&path, .ram, @intCast(i)), "new RAM transport");
            try Files.publish(tmp.dir, try Memory.filename(&path, .range, 0), "new range transport");
            try Files.publish(tmp.dir, try Memory.filename(&path, .node, 0), "new memory parent transport");
            try Files.publish(tmp.dir, try Memory.filename(&path, .join, 0), "new memory root transport");
            try Files.publish(tmp.dir, MemoryManifest.NAME, "new memory manifest transport");
            inventory.memory_ram = 2;
            inventory.memory_range = 1;
            inventory.memory_nodes = 1;
            inventory.memory_join = true;
            inventory.memory_manifest = true;
        }
        if (stage >= 4) {
            try Files.publish(tmp.dir, Final.PUBLIC_PROOF, "new public root transport");
            try Files.publish(tmp.dir, Final.FINAL_PROOF, "new final root transport");
            try Files.publish(tmp.dir, Final.NAME, "new final manifest transport");
            inventory.public_root = true;
            inventory.final_root = true;
            inventory.final_manifest = true;
        }
        inventory.rollback(tmp.dir);
        inventory.rollback(tmp.dir); // Deinit/outer error cleanup may overlap.
        try present(tmp.dir, original);
        try present(tmp.dir, try Fold.ForRecipe(.requesters).path(&path, 2));
        try present(tmp.dir, try Page.leafFilename(&path, 2));
        try present(tmp.dir, try Memory.filename(&path, .ram, 2));
        if (stage >= 1) for (0..2) |i| try gone(tmp.dir, try Fold.ForRecipe(.requesters).path(&path, @intCast(i)));
        if (stage >= 2) {
            for (0..2) |i| try gone(tmp.dir, try Page.leafFilename(&path, @intCast(i)));
            try gone(tmp.dir, try Page.nodeFilename(&path, 0));
        }
        if (stage >= 3) {
            for (0..2) |i| try gone(tmp.dir, try Memory.filename(&path, .ram, @intCast(i)));
            inline for (.{ .range, .node, .join }) |kind| try gone(tmp.dir, try Memory.filename(&path, kind, 0));
            try gone(tmp.dir, MemoryManifest.NAME);
        }
        if (stage >= 4) {
            try gone(tmp.dir, Final.PUBLIC_PROOF);
            try gone(tmp.dir, Final.FINAL_PROOF);
            try gone(tmp.dir, Final.NAME);
        }
    }
}
test "cpu recursive completion: rejected existing manifest and root destinations are never enrolled" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    inline for (.{ Final.NAME, Final.PUBLIC_PROOF, Final.FINAL_PROOF, MemoryManifest.NAME }) |name| {
        try Files.publish(tmp.dir, name, "preexisting transport");
        try std.testing.expectError(error.ExistingV5BundleArtifact, Files.publish(tmp.dir, name, "rejected transport"));
    }
    (Cleanup.Inventory{}).rollback(tmp.dir);
    inline for (.{ Final.NAME, Final.PUBLIC_PROOF, Final.FINAL_PROOF, MemoryManifest.NAME }) |name| try present(tmp.dir, name);
}
