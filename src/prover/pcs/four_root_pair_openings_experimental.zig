//! Honest prover for the experimental four-root Gate source-pair custody
//! slice. Four independent production-profile plain Merkle trees are used;
//! the caller still owns the transcript epochs, OOD roster, and FRI proof.
const std = @import("std");
const core = @import("stwo_core");
const source = core.pcs.four_root_pair_openings_experimental;
const MerkleProver = @import("../vcs_lifted/prover.zig").MerkleProverLifted(source.H);

const M31 = core.fields.m31.M31;

pub const Input = struct {
    /// FRI-extended words, ordered fixed/main/interaction/composition.
    columns: [source.root_count][]const []const M31,
    lifting_log_size: u32,
    raw_queries: []const usize,
};

pub const OwnedProof = struct {
    arena: std.heap.ArenaAllocator,
    expected: source.Expected,
    openings: [source.root_count]source.TreeOpening,

    pub fn deinit(self: *OwnedProof) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn prove(allocator: std.mem.Allocator, input: Input) !OwnedProof {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    if (input.columns[3].len != source.composition_columns)
        return error.InvalidFourRootPairShape;
    const positions = try source.pairPositions(a, input.raw_queries, input.lifting_log_size);
    var roots: [source.root_count]source.H.Hash = undefined;
    var logs: [source.root_count][]const u32 = undefined;
    var openings: [source.root_count]source.TreeOpening = undefined;
    for (input.columns, 0..) |columns, i| {
        if (columns.len == 0) return error.InvalidFourRootPairShape;
        const tree_logs = try a.alloc(u32, columns.len);
        for (columns, tree_logs) |column, *log| {
            if (column.len < 2 or !std.math.isPowerOfTwo(column.len))
                return error.InvalidFourRootPairShape;
            log.* = @intCast(std.math.log2_int(usize, column.len));
            if (log.* > input.lifting_log_size)
                return error.InvalidFourRootPairShape;
        }
        const tree = try MerkleProver.commitLifted(a, columns, input.lifting_log_size);
        roots[i] = tree.root();
        logs[i] = tree_logs;
        const opened = try tree.decommit(a, positions, columns);
        openings[i] = .{
            .queried_values = opened.queried_values,
            .hash_witness = opened.decommitment.decommitment.hash_witness,
        };
    }
    return .{
        .arena = arena,
        .expected = .{
            .roots = roots,
            .column_log_sizes = logs,
            .lifting_log_size = input.lifting_log_size,
            .raw_queries = try a.dupe(usize, input.raw_queries),
        },
        .openings = openings,
    };
}
