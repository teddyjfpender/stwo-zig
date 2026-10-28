//! Standalone parent verification. External pinned keys reconstruct every
//! descendant Tree0 before any claims or proof file is opened.
const std = @import("std");
const registry_mod = @import("recursive_segment_v2_detached_parent_key_registry.zig");
const parent_command = @import("stwo_riscv_frontend").recursion.detached_parent_command_v1;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 5 and (std.mem.eql(u8, args[1], "--derive-expected") or
        std.mem.eql(u8, args[1], "--derive-span") or
        std.mem.eql(u8, args[1], "--fold-root") or
        std.mem.eql(u8, args[1], "--fold-span")))
        return parent_command.main();
    const admission_only = args.len == 4 and std.mem.eql(u8, args[1], "--admit-key");
    if (!admission_only and args.len != 5) return error.ExpectedBundleKeyRootAndIndependentKeyRegistry;
    const registry_path = if (admission_only) args[2] else args[4];
    const pin_hex = if (admission_only) args[3] else args[2];
    if (pin_hex.len != 64) return error.ExpectedPinnedParentKeySha256;
    var parent_pin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&parent_pin, pin_hex);
    const registry_bytes = try std.fs.cwd().readFileAlloc(allocator, registry_path, registry_mod.MAX_REGISTRY_BYTES);
    defer allocator.free(registry_bytes);
    const registry = try std.json.parseFromSlice(registry_mod.RegistryV1, allocator, registry_bytes, .{ .allocate = .alloc_always });
    defer registry.deinit();
    var timer = try std.time.Timer.start();
    try registry_mod.admit(allocator, std.fs.path.dirname(registry_path) orelse ".", &registry.value, parent_pin);
    if (admission_only) {
        const result = try std.json.Stringify.valueAlloc(allocator, .{
            .endpoint = "detached_parent_key_only_admission_v3",
            .parent_key_sha256 = parent_pin,
            .fixed_root_admitted = true,
            .proof_loaded = false,
            .admission_ns = timer.read(),
        }, .{});
        defer allocator.free(result);
        try std.fs.File.stdout().writeAll(result);
        try std.fs.File.stdout().writeAll("\n");
        return;
    }
    var receipt = try parent_command.verifyDirectory(allocator, args[1], parent_pin, args[3]);
    receipt.request_ns = timer.read();
    const json = try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
