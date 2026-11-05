//! Format compact resident PCS readback into native proof containers. This
//! module derives no challenge and performs no prover arithmetic or hashing.
const std = @import("std");
const core = @import("stwo_core");
const F = @import("fri.zig");
const T = @import("trace.zig");
const O = F.O;
const M = core.fields.m31.M31;
const H = F.H;
const P = core.pcs.ForField(O);
const TV = core.pcs.TreeVec;
const Decommitment = core.vcs_lifted.verifier.MerkleDecommitmentLifted(H);
pub const Tree = struct {
    coefficient_logs: []const u32,
    sorted_to_original: []const u32,
    sample_counts: []const u32,
};
pub const Shape = struct { config: core.pcs.PcsConfig, degree_log: u32, trees: []const Tree };
pub const Input = struct { raw_queries: []const u32, samples: []const u32, trace: []const T.Readback, fri: []const F.LayerReadback, terminal: [8]u32, nonce: u64 };
pub fn assemble(a: std.mem.Allocator, shape: Shape, data: Input) !P.CommitmentSchemeProof(H) {
    const plan = try F.Plan.init(shape.degree_log, shape.config.fri_config);
    if (shape.trees.len == 0 or shape.trees.len > 4 or data.trace.len != shape.trees.len or data.raw_queries.len != plan.queries) return error.InvalidPcsReadback;
    var sample_count: usize = 0;
    for (shape.trees) |tree| {
        if (tree.coefficient_logs.len == 0 or tree.coefficient_logs.len > 65536 or tree.sorted_to_original.len != tree.coefficient_logs.len or tree.sample_counts.len != tree.coefficient_logs.len) return error.InvalidPcsShape;
        for (tree.coefficient_logs, tree.sample_counts) |log, count| {
            if (log < 1 or log > 28 - shape.config.fri_config.log_blowup_factor or count > 5 or (count != 0 and log > shape.degree_log)) return error.InvalidPcsShape;
            sample_count = try std.math.add(usize, sample_count, count);
        }
    }
    if (data.samples.len != try std.math.mul(usize, sample_count, 8)) return error.InvalidPcsReadback;
    const openings = try a.alloc(T.Opening, shape.trees.len);
    defer a.free(openings);
    var opened: usize = 0;
    var own_openings = true;
    defer if (own_openings) {
        for (openings[0..opened]) |*p| p.deinit(a);
    };
    for (shape.trees, data.trace, openings) |tree, readback, *opening| {
        const logs = try a.alloc(u32, tree.coefficient_logs.len);
        defer a.free(logs);
        for (tree.sorted_to_original, logs) |order, *log| {
            if (order >= tree.coefficient_logs.len) return error.InvalidPcsShape;
            log.* = tree.coefficient_logs[order] + shape.config.fri_config.log_blowup_factor;
        }
        opening.* = try T.assemble(a, .{ .tree_log = std.mem.max(u32, logs), .lifting_log = plan.initial_log, .column_logs = logs, .column_order = tree.sorted_to_original }, data.raw_queries, readback);
        opened += 1;
    }
    var fri = try F.assemble(a, plan, data.raw_queries, data.fri, &data.terminal);
    var own_fri = true;
    defer if (own_fri) fri.deinit(a);
    const roots = try a.alloc(H.Hash, shape.trees.len);
    errdefer a.free(roots);
    for (openings, roots) |opening, *root| root.* = opening.root;
    const samples = try a.alloc([][]O, shape.trees.len);
    errdefer a.free(samples);
    var completed: usize = 0;
    errdefer for (samples[0..completed]) |tree| {
        for (tree) |column| a.free(column);
        a.free(tree);
    };
    var cursor: usize = 0;
    for (shape.trees, samples) |tree, *columns| {
        columns.* = try a.alloc([]O, tree.sample_counts.len);
        var done: usize = 0;
        errdefer {
            for (columns.*[0..done]) |column| a.free(column);
            a.free(columns.*);
        }
        for (tree.sample_counts, columns.*) |count, *column| {
            column.* = try a.alloc(O, count);
            done += 1;
            for (column.*) |*value| {
                var coords: [8]M = undefined;
                for (&coords) |*v| {
                    const word = data.samples[cursor];
                    cursor += 1;
                    if (word >= core.fields.m31.Modulus) return error.NoncanonicalPcsReadback;
                    v.* = M.fromCanonical(word);
                }
                value.* = O.fromM31Array(coords);
            }
        }
        completed += 1;
    }
    const queried = try a.alloc([][]M, shape.trees.len);
    errdefer a.free(queried);
    const decommitments = try a.alloc(Decommitment, shape.trees.len);
    errdefer a.free(decommitments);
    for (openings, queried, decommitments) |opening, *q, *d| {
        q.* = opening.queried_values;
        d.* = opening.decommitment;
    }
    own_openings = false;
    own_fri = false;
    return .{ .config = shape.config, .commitments = TV(H.Hash).initOwned(roots), .sampled_values = TV([][]O).initOwned(samples), .decommitments = TV(Decommitment).initOwned(decommitments), .queried_values = TV([][]M).initOwned(queried), .proof_of_work = data.nonce, .fri_proof = fri };
}
