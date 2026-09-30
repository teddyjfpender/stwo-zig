//! Recursive-tree wall time on the committed R9 workload (design §9.1, §9.2
//! item 6): `n` copies of the upstream golden leaf
//! (`four_leaves/leaf.json`) folded under the recursive-tree test registry,
//! as `circuit-parity-r9` does, with the prover's stage profile per
//! reduction and the process CPU utilisation (CPU seconds over wall
//! seconds). The root files are checked before any number is printed: for
//! four leaves against the upstream goldens byte for byte, otherwise against
//! the R9 checkpoint's `root.proof` SHA-256. Not a test:
//! `zig build bench-fold -- [n_leaves] [repeats]`, default `4 1`.

const std = @import("std");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");

const recursion = circuit_cpu.recursion;
const stage_profile = prover.stage_profile;

const registry_path = "vectors/circuit/official/registries/recursive_tree_test.json";
const leaf_path = "vectors/circuit/official/recursive_tree/four_leaves/leaf.json";
const goldens_dir = "vectors/circuit/official/recursive_tree/four_leaves";
const checkpoint_path = "vectors/circuit/r9/fold_tree.json";
const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

pub fn main() !void {
    const gpa = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);
    const n_leaves: usize = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 4;
    const repeats: usize = if (args.len > 2) try std.fmt.parseInt(usize, args[2], 10) else 1;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var setup_timer = try std.time.Timer.start();
    var registry = try wire.registry.parseRegistry(gpa, try std.fs.cwd().readFileAlloc(arena, registry_path, 1 << 20));
    defer registry.deinit();
    var projection = try circuit.air_eval.projection.parse(gpa, try std.fs.cwd().readFileAlloc(arena, projection_path, 8 << 20));
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(gpa, &projection);
    defer table.deinit();
    var bundle = try circuit_cpu.air.parse(gpa, try std.fs.cwd().readFileAlloc(arena, circuit_cpu.air.bundle_path, 1 << 20));
    defer bundle.deinit();
    var canonical = try recursion.CanonicalCircuit.build(gpa, &table, registry.registry);
    defer canonical.deinit(gpa);
    var leaf = try wire.leaf_proof_json.parseLeafInput(gpa, try std.fs.cwd().readFileAlloc(arena, leaf_path, 8 << 20));
    defer leaf.deinit();
    std.debug.print("setup (canonical circuit, cold): {d:.2} s\n", .{seconds(setup_timer.read())});

    const expected_sha = try expectedRootSha(arena, n_leaves);

    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    std.debug.print("pool workers {d}, leaves {d}, repeats {d}\n", .{ pool.workerCount(), n_leaves, repeats });

    const leaves = try arena.alloc(wire.leaf_proof_json.LeafInput, n_leaves);
    @memset(leaves, leaf.value);

    for (0..repeats) |repeat| {
        var recorder = stage_profile.Recorder.initWithOptions(gpa, "cpu", "fold-tree", .{ .capture_tasks = false });
        defer recorder.deinit();
        var packed_arena = std.heap.ArenaAllocator.init(gpa);
        defer packed_arena.deinit();
        const fold: recursion.Fold = .{
            .canonical = &canonical,
            .table = &table,
            .bundle = &bundle,
            .options = .{ .compact_polynomial_min_log = 18, .recorder = &recorder },
            .packed_allocator = packed_arena.allocator(),
        };

        const cpu_before = cpuSeconds();
        var timer = try std.time.Timer.start();
        var folded = try recursion.tree.foldLeaves(gpa, &fold, leaves);
        defer folded.root.deinit();
        const wall = seconds(timer.read());
        const cpu = cpuSeconds() - cpu_before;

        var proof: std.Io.Writer.Allocating = .init(gpa);
        defer proof.deinit();
        var outputs: std.Io.Writer.Allocating = .init(gpa);
        defer outputs.deinit();
        var packed_tree: std.Io.Writer.Allocating = .init(gpa);
        defer packed_tree.deinit();
        try recursion.tree.writeRootOutputs(&folded.root, &proof.writer, &outputs.writer, &packed_tree.writer);
        const actual_sha = sha256Hex(proof.written());
        if (!std.mem.eql(u8, &expected_sha, &actual_sha)) {
            std.debug.print("root.proof sha256 {s}, expected {s}\n", .{ actual_sha, expected_sha });
            return error.RootProofMismatch;
        }

        var profile = try recorder.snapshot(gpa);
        defer profile.deinit(gpa);
        std.debug.print("run {d}: tree {d:.2} s wall, {d:.1} CPU s, utilisation {d:.1}/{d} workers; root.proof matches upstream\n", .{
            repeat, wall, cpu, cpu / wall, pool.workerCount(),
        });
        for (profile.stages) |node| printNode(node, 1);
    }
}

/// The upstream `root.proof` SHA-256 for `n` golden leaves.
fn expectedRootSha(arena: std.mem.Allocator, n: usize) ![64]u8 {
    if (n == 4) return sha256Hex(try std.fs.cwd().readFileAlloc(arena, goldens_dir ++ "/root.proof", 8 << 20));
    const document = try std.json.parseFromSliceLeaky(std.json.Value, arena, try std.fs.cwd().readFileAlloc(arena, checkpoint_path, 1 << 20), .{});
    const body = document.object.get("body") orelse return error.BadCheckpoint;
    const trees = (body.object.get("trees") orelse return error.MissingTree).array.items;
    for (trees) |tree| {
        if (tree.object.get("n_leaves").?.integer != n) continue;
        const sha = tree.object.get("root_proof").?.object.get("sha256").?.string;
        if (sha.len != 64) return error.BadCheckpoint;
        return sha[0..64].*;
    }
    return error.MissingTree;
}

fn printNode(node: stage_profile.StageNode, depth: usize) void {
    if (node.seconds < 0.005) return;
    for (0..depth) |_| std.debug.print("  ", .{});
    std.debug.print("{s:<40} {d:>8.3} s\n", .{ node.id, node.seconds });
    if (depth >= 4) return;
    if (node.children) |children| for (children) |child| printNode(child, depth + 1);
}

fn cpuSeconds() f64 {
    const usage = std.posix.getrusage(std.posix.rusage.SELF);
    const user = @as(f64, @floatFromInt(usage.utime.sec)) + @as(f64, @floatFromInt(usage.utime.usec)) / 1e6;
    const system = @as(f64, @floatFromInt(usage.stime.sec)) + @as(f64, @floatFromInt(usage.stime.usec)) / 1e6;
    return user + system;
}

fn seconds(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
