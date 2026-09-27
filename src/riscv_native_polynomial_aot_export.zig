//! Offline native AIR catalog export. No guest, STARK or device execution.
const std = @import("std");
pub const codegen = struct {
    pub const base = @import("backends/metal/runtime/base_polynomial_codegen.zig");
    pub const lookup = @import("backends/metal/runtime/lookup_polynomial_codegen.zig");
    pub const lookup_v2 = @import("backends/metal/runtime/lookup_polynomial_v2_codegen.zig");
    pub const aot = @import("backends/metal/runtime/riscv_polynomial_aot_codegen.zig");
};
pub const Inventory = @import("frontends/riscv/air/native_polynomial_inventory_v1.zig").Inventory(codegen);

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.InvalidArguments;
    var inventory = try Inventory.init(a);
    defer inventory.deinit();
    const source = try codegen.aot.generateLibrary(a, inventory.base.items, inventory.lookup.items, inventory.lookup_v2.items);
    defer a.free(source);
    try std.fs.cwd().makePath(args[1]);
    var directory = try std.fs.cwd().openDir(args[1], .{});
    defer directory.close();
    try directory.writeFile(.{ .sub_path = "kernels.metal", .data = source });
    const Entry = struct { kind: []const u8, program_id: ?u64, kernel: []u8, columns: usize, equations_or_buses: usize };
    var programs = std.ArrayList(Entry).empty;
    defer {
        for (programs.items) |entry| a.free(entry.kernel);
        programs.deinit(a);
    }
    try programs.ensureTotalCapacity(a, inventory.base.items.len + inventory.lookup.items.len + inventory.lookup_v2.items.len);
    for (inventory.base.items) |entry| programs.appendAssumeCapacity(.{ .kind = "base", .program_id = entry.program_id, .kernel = try codegen.base.kernelName(a, entry.program), .columns = entry.program.column_count, .equations_or_buses = entry.program.roots.len });
    for (inventory.lookup.items) |entry| programs.appendAssumeCapacity(.{ .kind = "lookup", .program_id = entry.program_id, .kernel = try codegen.lookup.kernelName(a, entry.program), .columns = entry.program.column_count, .equations_or_buses = entry.program.entries.len });
    for (inventory.lookup_v2.items) |*entry| programs.appendAssumeCapacity(.{ .kind = "lookup_v2", .program_id = null, .kernel = try codegen.lookup_v2.kernelName(a, &entry.program), .columns = entry.program.layout.column_count, .equations_or_buses = entry.program.entries.len });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    const manifest = try std.json.Stringify.valueAlloc(a, .{
        .version = 1,
        .source_file = "kernels.metal",
        .source_sha256 = std.fmt.bytesToHex(digest, .lower),
        .programs = programs.items,
        .canonical_x0_activation = false,
        .guest_executed = false,
        .stark_proved = false,
        .device_executed = false,
        .performance_measured = false,
    }, .{ .whitespace = .indent_2 });
    defer a.free(manifest);
    try directory.writeFile(.{ .sub_path = "source_manifest.json", .data = manifest });
}
