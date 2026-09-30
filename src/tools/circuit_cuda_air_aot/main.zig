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
    const ProductOccurrence = struct { component_index: u32, part_index: u32 };
    const ProductBody = struct {
        kind: []const u8 = "constraint",
        label: []const u8,
        abi_schema: []const u8 = "cairo_eval_part_v1",
        kernel_name: []const u8,
        cache_key: [16]u8,
        semantic_hash: [16]u8,
        program_identity: [64]u8,
        file: []const u8,
        module_globals: []const u8 = "none",
        catalog_identity: [64]u8,
        codegen_version: u32 = 6,
        identity_scheme: []const u8 = "sha256-circuit-eval-parametric-source-v6",
        occurrences: []ProductOccurrence,
        source_sha256: [64]u8,
    };
    const bodies = try allocator.alloc(ManifestBody, catalog.bodies.len);
    defer allocator.free(bodies);
    const products = try allocator.alloc(ProductBody, catalog.bodies.len);
    defer allocator.free(products);
    var initialized: usize = 0;
    defer for (bodies[0..initialized], products[0..initialized]) |entry, product| {
        allocator.free(entry.filename);
        allocator.free(product.label);
        allocator.free(product.occurrences);
    };
    for (catalog.bodies, bodies, products, 0..) |body, *entry, *product, body_index| {
        const prefix = "stwo_cairo_cuda_eval_v6_";
        if (!std.mem.startsWith(u8, body.kernel_name, prefix) or body.kernel_name.len != prefix.len + 16)
            return error.InvalidCircuitAotKernelName;
        const semantic = body.kernel_name[prefix.len..];
        const label = try std.fmt.allocPrint(allocator, "circuit_eval_{s}", .{semantic});
        errdefer allocator.free(label);
        const key = std.fmt.bytesToHex(std.mem.toBytes(std.mem.nativeToBig(u64, body.cache_key)), .lower);
        const filename = try std.fmt.allocPrint(allocator, "constraint_{s}_{s}.cu", .{ label, &key });
        defer allocator.free(filename);
        try directory.writeFile(.{ .sub_path = filename, .data = body.source });
        var occurrences = std.ArrayList(ProductOccurrence).empty;
        errdefer occurrences.deinit(allocator);
        for (catalog.occurrences) |occurrence| {
            if (occurrence.body_index == body_index) try occurrences.append(allocator, .{
                .component_index = occurrence.component_index,
                .part_index = occurrence.part_index,
            });
        }
        if (occurrences.items.len == 0) return error.UnusedCircuitAotBody;
        entry.* = .{
            .cache_key = key,
            .filename = try allocator.dupe(u8, filename),
            .kernel_name = body.kernel_name,
            .normalized_program_identity = std.fmt.bytesToHex(body.normalized_program_identity, .lower),
            .source_identity = std.fmt.bytesToHex(body.source_identity, .lower),
            .constant_count = body.constant_count,
        };
        product.* = .{
            .label = label,
            .kernel_name = body.kernel_name,
            .cache_key = key,
            .semantic_hash = semantic[0..16].*,
            .program_identity = std.fmt.bytesToHex(body.normalized_program_identity, .lower),
            .file = entry.filename,
            .catalog_identity = std.fmt.bytesToHex(sha256Bundle(encoded), .lower),
            .occurrences = try occurrences.toOwnedSlice(allocator),
            .source_sha256 = std.fmt.bytesToHex(body.source_identity, .lower),
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
    std.mem.sort(ProductBody, products, {}, struct {
        fn lessThan(_: void, left: ProductBody, right: ProductBody) bool {
            return std.mem.lessThan(u8, left.label, right.label);
        }
    }.lessThan);
    var product_json = std.Io.Writer.Allocating.init(allocator);
    defer product_json.deinit();
    try std.json.Stringify.value(products, .{ .whitespace = .indent_2 }, &product_json.writer);
    try directory.writeFile(.{ .sub_path = "aot_manifest.json", .data = product_json.written() });
    std.debug.print("circuit CUDA AIR: {} unique kernels, {} placements\n", .{ bodies.len, catalog.occurrences.len });
}

fn sha256Bundle(encoded: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    return digest;
}
