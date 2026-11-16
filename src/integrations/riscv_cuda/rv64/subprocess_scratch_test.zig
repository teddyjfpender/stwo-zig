//! Private request-file ownership laws, without a prover or subprocess.
const std = @import("std");
const Owner = @import("subprocess_scratch.zig");
const a = std.testing.allocator;

fn path(dir: std.fs.Dir, suffix: []const u8) ![]u8 {
    const root = try dir.realpathAlloc(a, ".");
    defer a.free(root);
    return std.fs.path.join(a, &.{ root, suffix });
}

test "hybrid scratch cannot create an unclaimed producer output directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const directory = try path(tmp.dir, "unclaimed/.gpu-hybrid");
    defer a.free(directory);
    try std.testing.expectError(error.FileNotFound, Owner.Request.init(a, directory, .pcs, 0));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access("unclaimed", .{}));
    try std.testing.expectError(error.MissingHybridProducerOutput, Owner.Request.init(a, "", .pcs, 0));
}

test "hybrid scratch owns disjoint role files and cleans success and failure paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const directory = try path(tmp.dir, ".gpu-hybrid");
    defer a.free(directory);
    var pcs = try Owner.Request.init(a, directory, .pcs, 0);
    const input_copy = try a.dupe(u8, pcs.input);
    defer a.free(input_copy);
    var composition = try Owner.Request.init(a, directory, .composition, 0);
    defer composition.deinit(true);
    try std.testing.expect(!std.mem.eql(u8, pcs.input, composition.input));
    try std.testing.expect(!std.mem.eql(u8, pcs.output, composition.output));
    pcs.deinit(true); // the same defer is used after helper spawn/decode errors
    try std.testing.expectError(error.FileNotFound, std.fs.cwd().access(input_copy, .{}));
    try std.fs.cwd().access(composition.input, .{});
}

test "hybrid scratch refuses collisions and never deletes a foreign output" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".gpu-hybrid");
    try tmp.dir.writeFile(.{ .sub_path = ".gpu-hybrid/pcs-0.output", .data = "foreign" });
    const directory = try path(tmp.dir, ".gpu-hybrid");
    defer a.free(directory);
    try std.testing.expectError(error.PathAlreadyExists, Owner.Request.init(a, directory, .pcs, 0));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(".gpu-hybrid/pcs-0.input", .{}));
    const value = try tmp.dir.readFileAlloc(a, ".gpu-hybrid/pcs-0.output", 32);
    defer a.free(value);
    try std.testing.expectEqualStrings("foreign", value);
}

fn exercise(allocator: std.mem.Allocator, directory: []const u8) !void {
    var request = try Owner.Request.init(allocator, directory, .pcs, 1);
    defer request.deinit(true);
}
test "hybrid scratch request construction preserves allocation failure ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const directory = try path(tmp.dir, ".gpu-hybrid");
    defer a.free(directory);
    try std.testing.checkAllAllocationFailures(a, exercise, .{directory});
}
