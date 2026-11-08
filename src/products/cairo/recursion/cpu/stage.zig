//! One bounded recursive fold stage, with an internal checkpoint or terminal
//! root. The app owns the canonical circuit and backend; this module owns the
//! mixed entry conversion and lossless publication.
const std = @import("std");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const recursion = circuit_cpu.recursion;

pub const Input = union(enum) {
    leaf: wire.leaf_proof_json.LeafInput,
    checkpoint: wire.checkpoint.Node,
};

const ManifestEntry = struct {
    kind: []const u8,
    path: []const u8,
};

const Manifest = struct { entries: []const ManifestEntry };

/// The input arena stays live through the proof and checkpoint render.
pub fn loadInputs(allocator: std.mem.Allocator, path: []const u8) ![]Input {
    const manifest = try std.fs.cwd().readFileAlloc(allocator, path, 64 << 20);
    const parsed = try std.json.parseFromSlice(Manifest, allocator, manifest, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    if (parsed.value.entries.len == 0 or parsed.value.entries.len > 256) return error.InvalidFoldStageSize;
    const inputs = try allocator.alloc(Input, parsed.value.entries.len);
    for (parsed.value.entries, inputs) |entry, *input| {
        const bytes = try std.fs.cwd().readFileAlloc(allocator, entry.path, 64 << 20);
        input.* = if (std.mem.eql(u8, entry.kind, "leaf"))
            .{ .leaf = (try wire.leaf_proof_json.parseLeafInput(allocator, bytes)).value }
        else if (std.mem.eql(u8, entry.kind, "checkpoint"))
            .{ .checkpoint = (try wire.checkpoint.parse(allocator, bytes)).node }
        else
            return error.InvalidFoldStageEntry;
    }
    return inputs;
}

pub const Files = struct {
    checkpoint: std.Io.Writer.Allocating,
    proof: std.Io.Writer.Allocating,
    outputs: std.Io.Writer.Allocating,
    packed_tree: std.Io.Writer.Allocating,
    stats: recursion.Stats,

    pub fn deinit(self: *Files) void {
        self.checkpoint.deinit();
        self.proof.deinit();
        self.outputs.deinit();
        self.packed_tree.deinit();
        self.* = undefined;
    }
};

pub fn run(
    gpa: std.mem.Allocator,
    fold: *const recursion.Fold,
    inputs: []const Input,
    jobs: usize,
    terminal_root: bool,
    stage_timer: *std.time.Timer,
    setup_ns: u64,
) !Files {
    const entries = try gpa.alloc(recursion.LayerEntry, inputs.len);
    defer gpa.free(entries);
    var loaded: usize = 0;
    errdefer for (entries[0..loaded]) |*entry| entry.deinit();
    for (inputs, entries) |input, *entry| {
        entry.* = switch (input) {
            .leaf => |leaf| try recursion.LayerEntry.fromLeaf(gpa, fold, leaf),
            .checkpoint => |node| try recursion.LayerEntry.fromCheckpoint(gpa, fold, node),
        };
        loaded += 1;
    }
    loaded = 0;
    const decode_ns = stage_timer.lap();
    var folded = try recursion.tree.foldEntriesBoundedProfile(gpa, fold, entries, jobs, terminal_root);
    defer folded.root.deinit();
    const reductions_ns = stage_timer.lap();
    var files: Files = .{
        .checkpoint = .init(gpa),
        .proof = .init(gpa),
        .outputs = .init(gpa),
        .packed_tree = .init(gpa),
        .stats = folded.stats,
    };
    errdefer files.deinit();
    if (terminal_root) {
        try recursion.tree.writeRootOutputs(&folded.root, &files.proof.writer, &files.outputs.writer, &files.packed_tree.writer);
    } else {
        try recursion.tree.writeCheckpoint(gpa, fold, &folded.root, &files.checkpoint.writer);
    }
    std.debug.print("circuit-fold-checkpoint mode={s} entries={} reductions={} setup_ns={} decode_ns={} reductions_ns={} render_ns={}\n", .{
        if (terminal_root) "root" else "internal", inputs.len, folded.stats.n_pair_reductions,
        setup_ns,                                  decode_ns,  reductions_ns,
        stage_timer.lap(),
    });
    return files;
}
