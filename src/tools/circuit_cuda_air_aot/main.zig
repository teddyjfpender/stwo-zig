//! Generate circuit CUDA AIR sources from the pinned recorded bundle.
const std = @import("std");
const circuit_cuda = @import("stwo_circuit_cuda_integration");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3) return error.ExpectedCircuitAirAndOutputDirectory;
    const encoded = try std.fs.cwd().readFileAlloc(allocator, args[1], 16 << 20);
    defer allocator.free(encoded);
    var catalog = try circuit_cuda.air_aot.build(allocator, encoded);
    defer catalog.deinit();
    try std.fs.cwd().makePath(args[2]);
    var directory = try std.fs.cwd().openDir(args[2], .{});
    defer directory.close();

    const ManifestBody = struct {
        abi_schema: []const u8 = "cairo_eval_part_v1",
        cache_key: [16]u8,
        filename: []const u8,
        kernel_name: []const u8,
        normalized_program_identity: [64]u8,
        source_identity: [64]u8,
        constant_count: u32,
    };
    const bodies = try allocator.alloc(ManifestBody, catalog.bodies.len);
    defer allocator.free(bodies);
    var initialized: usize = 0;
    defer for (bodies[0..initialized]) |entry| allocator.free(entry.filename);
    for (catalog.bodies, bodies) |body, *entry| {
        const filename = try std.fmt.allocPrint(allocator, "circuit_eval_{s}.cu", .{&std.fmt.bytesToHex(body.source_identity, .lower)});
        defer allocator.free(filename);
        try directory.writeFile(.{ .sub_path = filename, .data = body.source });
        entry.* = .{
            .cache_key = std.fmt.bytesToHex(std.mem.toBytes(std.mem.nativeToBig(u64, body.cache_key)), .lower),
            .filename = try allocator.dupe(u8, filename),
            .kernel_name = body.kernel_name,
            .normalized_program_identity = std.fmt.bytesToHex(body.normalized_program_identity, .lower),
            .source_identity = std.fmt.bytesToHex(body.source_identity, .lower),
            .constant_count = body.constant_count,
        };
        initialized += 1;
    }
    var json = std.Io.Writer.Allocating.init(allocator);
    defer json.deinit();
    try std.json.Stringify.value(.{
        .schema = "stwo-circuit-cuda-air-aot-v1",
        .bundle_sha256 = circuit_cuda.air_aot.bundle_sha256,
        .bodies = bodies,
        .occurrences = catalog.occurrences,
    }, .{ .whitespace = .indent_2 }, &json.writer);
    try directory.writeFile(.{ .sub_path = "manifest.json", .data = json.written() });
    std.debug.print("circuit CUDA AIR: {} unique kernels, {} placements\n", .{ bodies.len, catalog.occurrences.len });
}
