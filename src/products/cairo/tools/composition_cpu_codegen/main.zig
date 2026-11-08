//! Generate native evaluators from the pinned, SHA-authenticated AIR library.
const std = @import("std");
const frontend = @import("stwo_cairo").frontends.cairo;
const program_identity = frontend.witness.eval_program_identity;
const c_writer = @import("c_writer.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len != 3) return error.InvalidArguments;
    var library = try frontend.air.template_library.Library.readFile(allocator, args[1]);
    defer library.deinit();
    try std.fs.cwd().makePath(args[2]);
    var directory = try std.fs.cwd().openDir(args[2], .{});
    defer directory.close();
    var registry = try directory.createFile("registry.zig", .{});
    defer registry.close();
    var buffer: [65536]u8 = undefined;
    var file_writer = registry.writer(&buffer);
    const w = &file_writer.interface;
    try w.writeAll("const std=@import(\"std\");\nconst native=@import(\"stwo_cairo\").frontends.cairo.proving.air.native_evaluator;\npub fn executor() native.Executor {return .{.resolve=resolve};}\nfn resolve(identity:[32]u8) ?native.Kernel {\n");
    var seen = std.AutoHashMap([32]u8, void).init(allocator);
    defer seen.deinit();
    var count: usize = 0;
    for (library.sources) |source| for (source.bundle.components) |component| for (component.parts) |part| {
        const digest = program_identity.identity(part.program);
        const entry = try seen.getOrPut(digest);
        if (entry.found_existing) continue;
        const name = try std.fmt.allocPrint(allocator, "air_{d}.c", .{count});
        var file = try directory.createFile(name, .{});
        defer file.close();
        var c_buffer: [65536]u8 = undefined;
        var writer = file.writer(&c_buffer);
        try c_writer.generate(allocator, part.program, count, &writer.interface);
        try writer.interface.flush();
        try w.writeAll("if(std.mem.eql(u8,&identity,&[_]u8{");
        for (digest) |value| try w.print("{d},", .{value});
        try w.print("}}))return cairo_cpu_air_{d};\n", .{count});
        count += 1;
    };
    // Build graph declares this authenticated library cardinality explicitly.
    if (count != 69) return error.AirLibraryCardinalityChanged;
    try w.print("return null;\n}}\npub const generated_program_count={d};\n", .{count});
    for (0..count) |index| try w.print("extern fn cairo_cpu_air_{d}(*const native.Range) callconv(.c) void;\n", .{index});
    try w.flush();
    std.debug.print("generated {d} authenticated CPU AIR kernels\n", .{count});
}
