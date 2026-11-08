//! Generate native CPU evaluators for one SHA-authenticated `STWZEVA/1`
//! bundle (the circuit AIR's recorded programs), with the same C writer as
//! the Cairo AIR library's kernels.
//!
//! `bundle-main BUNDLE SHA256 PREFIX EXPECTED_PROGRAMS OUT_DIR`: writes
//! `{PREFIX}_{i}.c` per distinct program identity and `registry.zig`, whose
//! `executor()` resolves an identity to its kernel. The registry imports the
//! evaluator ABI from `stwo_cairo_frontend`.
const std = @import("std");
const frontend = @import("stwo_cairo").frontends.cairo;
const program_identity = frontend.witness.eval_program_identity;
const composition = frontend.witness.composition_bundle;
const c_writer = @import("c_writer.zig");
const om31_writer = @import("om31_writer.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 6) return error.InvalidArguments;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, args[1], 64 << 20);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), args[2])) return error.BundleDigestMismatch;
    const prefix = args[3];
    const expected = try std.fmt.parseInt(usize, args[4], 10);
    var bundle = try composition.Bundle.parse(allocator, bytes);
    defer bundle.deinit();

    try std.fs.cwd().makePath(args[5]);
    var directory = try std.fs.cwd().openDir(args[5], .{});
    defer directory.close();
    var registry = try directory.createFile("registry.zig", .{});
    defer registry.close();
    var buffer: [65536]u8 = undefined;
    var file_writer = registry.writer(&buffer);
    const w = &file_writer.interface;
    try w.writeAll("const std=@import(\"std\");\nconst native=@import(\"stwo_cairo_frontend\").proving.air.native_evaluator;\npub fn executor() native.Executor {return .{.resolve=resolve};}\nfn resolve(identity:[32]u8) ?native.Kernel {\n");
    var seen = std.AutoHashMap([32]u8, void).init(allocator);
    defer seen.deinit();
    var count: usize = 0;
    var identities: std.ArrayList([32]u8) = .empty;
    defer identities.deinit(allocator);
    for (bundle.components) |component| for (component.parts) |part| {
        const identity = program_identity.identity(part.program);
        const entry = try seen.getOrPut(identity);
        if (entry.found_existing) continue;
        const name = try std.fmt.allocPrint(allocator, "{s}_{d}.c", .{ prefix, count });
        var file = try directory.createFile(name, .{});
        defer file.close();
        var c_buffer: [65536]u8 = undefined;
        var writer = file.writer(&c_buffer);
        var source: std.Io.Writer.Allocating = .init(allocator);
        try c_writer.generate(allocator, part.program, count, &source.writer);
        // The C writer names every kernel `cairo_cpu_air_{i}`; this bundle's
        // kernels link next to the Cairo library's, so rename them.
        const renamed = try std.mem.replaceOwned(u8, allocator, source.written(), "cairo_cpu_air_", try std.fmt.allocPrint(allocator, "{s}_", .{prefix}));
        try writer.interface.writeAll(renamed);
        try writer.interface.flush();
        const wide_name = try std.fmt.allocPrint(allocator, "{s}_om31_{d}.c", .{ prefix, count });
        var wide_file = try directory.createFile(wide_name, .{});
        defer wide_file.close();
        var wide_buffer: [65536]u8 = undefined;
        var wide_file_writer = wide_file.writer(&wide_buffer);
        var wide_source: std.Io.Writer.Allocating = .init(allocator);
        try om31_writer.generate(allocator, part.program, count, &wide_source.writer);
        const wide_renamed = try std.mem.replaceOwned(u8, allocator, wide_source.written(), "cairo_cpu_air_", try std.fmt.allocPrint(allocator, "{s}_", .{prefix}));
        try wide_file_writer.interface.writeAll(wide_renamed);
        try wide_file_writer.interface.flush();
        try w.writeAll("if(std.mem.eql(u8,&identity,&[_]u8{");
        for (identity) |value| try w.print("{d},", .{value});
        try w.print("}}))return {s}_{d};\n", .{ prefix, count });
        try identities.append(allocator, identity);
        count += 1;
    };
    // The build graph declares the bundle's program cardinality explicitly.
    if (count != expected) {
        std.debug.print("bundle has {d} distinct programs, build expects {d}\n", .{ count, expected });
        return error.BundleCardinalityChanged;
    }
    try w.print("return null;\n}}\npub const generated_program_count={d};\n", .{count});
    for (0..count) |index| try w.print("extern fn {s}_{d}(*const native.Range) callconv(.c) void;\n", .{ prefix, index });
    try w.writeAll("pub fn om31Executor() native.Om31.Executor {return .{.resolve=resolveOm31};}\nfn resolveOm31(identity:[32]u8) ?native.Om31.Kernel {\n");
    for (identities.items, 0..) |id, index| {
        try w.writeAll("if(std.mem.eql(u8,&identity,&[_]u8{");
        for (id) |value| try w.print("{d},", .{value});
        try w.print("}}))return {s}_om31_{d};\n", .{ prefix, index });
    }
    try w.writeAll("return null;\n}\n");
    for (0..count) |index| try w.print("extern fn {s}_om31_{d}(*const native.Om31.Range) callconv(.c) void;\n", .{ prefix, index });
    try w.flush();
}
