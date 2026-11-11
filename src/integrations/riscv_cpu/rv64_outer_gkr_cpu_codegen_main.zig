//! Build-time generation only. Reads the same pinned source as the receiver.
const std = @import("std");
const CPU = @import("stwo_circuit_cpu_integration");
const H = @import("outer_gkr/hybrid_air.zig");
const Lower = @import("outer_gkr/cpu_lowering.zig");
const Inputs = @import("outer_gkr/cpu_inputs.zig");
const Writer = @import("hybrid_cpu_emitter");
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len != 3) return error.ExpectedHybridAirAndOutput;
    const bytes = try std.fs.cwd().readFileAlloc(a, args[1], 64 << 20);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), CPU.air.bundle_sha256)) return error.HybridSourceDigestMismatch;
    var bundle = try CPU.air.parse(a, bytes);
    defer bundle.deinit();
    if (bundle.components.len != 11) return error.HybridSourceCardinality;
    try std.fs.cwd().makePath(args[2]);
    var directory = try std.fs.cwd().openDir(args[2], .{});
    defer directory.close();
    var registry_file = try directory.createFile("registry.zig", .{});
    defer registry_file.close();
    var registry_buffer: [65536]u8 = undefined;
    var registry_writer = registry_file.writer(&registry_buffer);
    const registry = &registry_writer.interface;
    try registry.writeAll("const std=@import(\"std\");\nconst N=@import(\"stwo_cairo_frontend\").proving.air.native_evaluator.Om31;\npub fn executor() N.Executor{return .{.resolve=resolve};}\nfn resolve(id:[32]u8) ?N.Kernel {\n");
    for (bundle.components, 0..) |*component, index| {
        var artifact = try H.record(a, component, @enumFromInt(index));
        defer artifact.deinit();
        const kinds = try a.alloc(Inputs.Kind, artifact.program.inputs.len);
        for (kinds, artifact.program.inputs) |*kind, input| kind.* = Inputs.expected(artifact.component, input);
        var lower = try Lower.Plan.init(a, &artifact.program, kinds);
        defer lower.deinit();
        const name = try std.fmt.allocPrint(a, "hybrid_{d}.c", .{index});
        const file = try directory.createFile(name, .{});
        defer file.close();
        var buffer: [65536]u8 = undefined;
        var writer = file.writer(&buffer);
        try Writer.generate(a, &artifact.program, &lower, index, &writer.interface);
        try writer.interface.flush();
        try registry.writeAll("if(std.mem.eql(u8,&id,&[_]u8{");
        for (artifact.program.identity) |byte| try registry.print("{d},", .{byte});
        try registry.print("}}))return rv64_hybrid_air_{d};\n", .{index});
    }
    try registry.writeAll("return null;\n}\npub const generated_program_count=11;\n");
    for (0..11) |index| try registry.print("extern fn rv64_hybrid_air_{d}(*const N.Range) callconv(.c) void;\n", .{index});
    try registry.flush();
}
