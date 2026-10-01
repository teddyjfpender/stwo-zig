//! Fully resident CUDA proving for a verified Cairo PIE, its leaf wrap, and
//! the recursive fold tree. The host builds verifier circuits and checks
//! published proofs; every Cairo and circuit STARK is proved on CUDA.
const std = @import("std");
const cairo_app = @import("cairo_cuda_app");
const circuit_app = @import("circuit_recursion_app");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const circuit_cuda = @import("stwo_circuit_cuda_integration");
const wire = @import("stwo_circuit_recursion_wire");
const sink = @import("verified_sink.zig");

const max_file = 64 << 20;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 2) return error.MissingCommand;
    if (std.mem.eql(u8, args[1], "leaf-wrap")) return leafWrap(allocator, args[2..]);
    if (std.mem.eql(u8, args[1], "leaf-wrap-batch")) return leafWrapBatch(allocator, args[2..]);
    if (std.mem.eql(u8, args[1], "fold-tree")) return foldTree(allocator, args[2..]);
    return error.UnknownCommand;
}

fn leafWrap(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var wall = try std.time.Timer.start();
    const registry = try flag(args, "--registry");
    const program = try flag(args, "--program");
    const input = try flag(args, "--input");
    const leaf_path = try flag(args, "--output");
    const cairo_proof = try flag(args, "--cairo-proof");
    const cairo_report = try flag(args, "--cairo-report");
    var catalog = try circuit_cuda.air_aot.build(allocator, try circuit_app.authenticatedAirPrograms());
    defer catalog.deinit();
    const catalog_ns = wall.lap();
    var backend = circuit_cuda.recursion_source.Context{ .catalog = &catalog };
    var receiver = sink.Context{
        .allocator = allocator,
        .request = .{
            .registry_path = registry,
            .program_path = program,
            .prover_input_path = input,
            .source = backend.source(),
        },
        .output_path = leaf_path,
    };
    var total = try std.time.Timer.start();
    try cairo_app.proveWithSink(allocator, .{
        .input = input,
        .output = cairo_proof,
        .report_out = cairo_report,
        .repeat = 1,
        .circuit_registry = registry,
    }, receiver.sink());
    if (!receiver.delivered) return error.MissingVerifiedCairoLeaf;
    std.debug.print("circuit-cuda leaf-wrap total_ns={} wrap_ns={} proof={s}\n", .{ total.read(), receiver.wrap_ns, leaf_path });
    std.debug.print("circuit-cuda leaf-wrap setup_ns={} execution_ns={}\n", .{ catalog_ns, wall.lap() });
}

const BatchManifestItem = struct {
    registry: []const u8,
    program: []const u8,
    input: []const u8,
    output: []const u8,
    cairo_proof: []const u8,
    cairo_report: []const u8,
};

fn leafWrapBatch(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var wall = try std.time.Timer.start();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const manifest_path = try flag(args, "--manifest");
    const parsed = try std.json.parseFromSlice([]BatchManifestItem, a, try readFile(a, manifest_path), .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    if (parsed.value.len == 0 or parsed.value.len > 256) return error.InvalidBatchSize;
    var catalog = try circuit_cuda.air_aot.build(allocator, try circuit_app.authenticatedAirPrograms());
    defer catalog.deinit();
    var backend = circuit_cuda.recursion_source.Context{ .catalog = &catalog };
    const first = parsed.value[0];
    for (parsed.value[1..]) |entry| {
        if (!std.mem.eql(u8, entry.registry, first.registry) or
            !std.mem.eql(u8, entry.program, first.program))
            return error.MixedLeafPrograms;
    }
    var shared = try circuit_app.VerifiedLeafSession.init(allocator, .{
        .registry_path = first.registry,
        .program_path = first.program,
        .prover_input_path = first.input,
        .source = backend.source(),
    });
    defer shared.deinit();
    const setup_ns = wall.lap();
    const receivers = try a.alloc(sink.Context, parsed.value.len);
    const items = try a.alloc(cairo_app.BatchItem, parsed.value.len);
    for (parsed.value, receivers, items) |entry, *receiver, *item| {
        receiver.* = .{
            .allocator = allocator,
            .request = .{
                .registry_path = entry.registry,
                .program_path = entry.program,
                .prover_input_path = entry.input,
                .source = backend.source(),
            },
            .output_path = entry.output,
            .shared_session = &shared,
        };
        item.* = .{
            .request = .{
                .input = entry.input,
                .output = entry.cairo_proof,
                .report_out = entry.cairo_report,
                .repeat = 1,
                .circuit_registry = entry.registry,
            },
            .sink = receiver.sink(),
        };
    }
    var total = try std.time.Timer.start();
    try cairo_app.proveBatchWithSinks(allocator, items);
    for (receivers, 0..) |receiver, index| {
        if (!receiver.delivered) return error.MissingVerifiedCairoLeaf;
        std.debug.print("circuit-cuda batch-leaf index={} wrap_ns={} proof={s}\n", .{
            index, receiver.wrap_ns, receiver.output_path,
        });
    }
    std.debug.print("circuit-cuda leaf-wrap-batch leaves={} total_ns={}\n", .{ receivers.len, total.read() });
    std.debug.print("circuit-cuda leaf-wrap-batch setup_ns={} execution_ns={} cache_hits={} cache_misses={}\n", .{
        setup_ns, wall.lap(), shared.cache.stats.hits, shared.cache.stats.misses,
    });
}

fn foldTree(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var wall = try std.time.Timer.start();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const registry_path = try flag(args, "--registry");
    const manifest_path = try flag(args, "--manifest");
    const proof_path = try flag(args, "--proof");
    const outputs_path = try flag(args, "--outputs");
    const packed_path = try flag(args, "--packed");
    const parsed_registry = try wire.registry.parseRegistry(a, try readFile(a, registry_path));
    const manifest = try wire.leaf_proof_json.parseLeavesManifest(a, try readFile(a, manifest_path));
    const leaves = try a.alloc(wire.leaf_proof_json.LeafInput, manifest.value.len);
    for (leaves, manifest.value) |*leaf, path| {
        const parsed = try wire.leaf_proof_json.parseLeafInput(a, try readFile(a, path));
        leaf.* = parsed.value;
    }
    const parse_ns = wall.lap();
    var catalog = try circuit_cuda.air_aot.build(allocator, try circuit_app.authenticatedAirPrograms());
    defer catalog.deinit();
    const catalog_ns = wall.lap();
    var backend = circuit_cuda.recursion_source.Context{ .catalog = &catalog };
    var timer = try std.time.Timer.start();
    var files = try circuit_app.foldTreeWithSource(
        allocator,
        parsed_registry.registry,
        leaves,
        &circuit_cpu.prove.cpu_provers,
        null,
        backend.source(),
    );
    defer files.deinit();
    const fold_ns = timer.read();
    try std.fs.cwd().writeFile(.{ .sub_path = proof_path, .data = files.proof.written() });
    try std.fs.cwd().writeFile(.{ .sub_path = outputs_path, .data = files.outputs.written() });
    try std.fs.cwd().writeFile(.{ .sub_path = packed_path, .data = files.packed_tree.written() });
    std.debug.print("circuit-cuda fold-tree leaves={} reductions={} prove_ns={} proof_bytes={}\n", .{
        files.stats.n_leaves, files.stats.n_pair_reductions, fold_ns, files.proof.written().len,
    });
    std.debug.print("circuit-cuda fold-tree parse_ns={} catalog_ns={} fold_ns={} publish_ns={}\n", .{
        parse_ns, catalog_ns, fold_ns, wall.lap() - fold_ns,
    });
}

fn flag(args: []const []const u8, name: []const u8) ![]const u8 {
    if (args.len % 2 != 0) return error.InvalidArguments;
    for (0..args.len / 2) |index| {
        const key = args[index * 2];
        if (std.mem.eql(u8, key, name)) return args[index * 2 + 1];
    }
    return error.MissingArgument;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, max_file);
}

test "resident pipeline command requires an explicit source" {
    try std.testing.expectError(error.MissingArgument, flag(&.{ "--input", "x" }, "--registry"));
}
