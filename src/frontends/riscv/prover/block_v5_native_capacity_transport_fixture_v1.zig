//! Structurally valid literal postcard envelopes, never generated STARK proofs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Statement = @import("../air/statement.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Codec = @import("block_v5_native_capacity_codec_v1.zig");
const Legacy = @import("block_v5_native_codec_v3.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const suite = core.proof_suites.Blake3;
pub const config: core.pcs.PcsConfig = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .n_queries = 2, .log_last_layer_degree_bound = 0, .fold_step = 1 } };
pub fn shape(rows: u32) Statement.Blake3ExecutionStatement {
    var result = std.mem.zeroes(Statement.Blake3ExecutionStatement);
    result.initializeDescriptorStorage();
    result.n_components = 1;
    result.component_descs[0] = .{ .family = .base_alu_imm, .log_size = @max(1, std.math.log2_int_ceil(u32, rows)), .n_rows = rows, .n_columns = @intCast(@import("../runner/trace.zig").nColumnsForFamily(.base_alu_imm)) };
    result.total_steps = rows;
    result.public_data = .{ .initial_pc = 0, .final_pc = 0, .clock = rows, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(3) }, .initial_rw_root = null, .final_rw_root = null, .completion = @import("../air/public_data.zig").Completion.canonicalSelfLoop(0), .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} } };
    return result;
}
pub fn expected(source: *const Statement.Blake3ExecutionStatement) !Codec.Expected {
    return .{ .shape = source, .external_retirements = 0, .config = config, .template_id = @splat(7), .instance_id = @splat(8), .capacity_digest = try Protocol.capacityDigest(source, 0) };
}
pub fn legacyExpected(source: *const Statement.Blake3ExecutionStatement) Legacy.Expected {
    return .{ .shape = source, .external_retirements = 0, .config = config, .template_id = @splat(7), .instance_id = @splat(8) };
}
pub const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    stark: suite.Proof,
    claims: *Statement.RiscVInteractionClaim,
    pub fn init(a: std.mem.Allocator, source: *const Statement.Blake3ExecutionStatement, comptime capacity_mode: bool) !Fixture {
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const scratch = arena.allocator();
        const claims = try scratch.create(Statement.RiscVInteractionClaim);
        claims.initZeroInto();
        claims.n_components = source.n_components;
        claims.n_infra = source.n_infra;
        const T = if (capacity_mode) Protocol else @import("block_v5_native_template_protocol_v3.zig");
        const counts = [_]usize{
            (try T.columnLogs(scratch, source, 0, .fixed)).len,
            (try T.columnLogs(scratch, source, 0, .main)).len,
            (try T.columnLogs(scratch, source, 0, .interaction)).len,
            core.verifier_types.compositionColumnCount(core.verifier_types.COMPOSITION_LOG_SPLIT, core.fields.qm31.SECURE_EXTENSION_DEGREE).?,
        };
        const samples = try scratch.alloc([][]Q, 4);
        const queries = try scratch.alloc([][]M, 4);
        const Decommit = core.vcs_lifted.verifier.MerkleDecommitmentLifted(suite.Hasher);
        const decommits = try scratch.alloc(Decommit, 4);
        for (counts, 0..) |count, tree| {
            samples[tree] = try scratch.alloc([]Q, count);
            queries[tree] = try scratch.alloc([]M, count);
            for (samples[tree], queries[tree], 0..) |*sample, *query, i| {
                sample.* = try scratch.dupe(Q, &.{Q.fromBase(M.fromCanonical(@intCast(17 + tree + i)))});
                query.* = try scratch.alloc(M, 0);
            }
            decommits[tree] = .{ .hash_witness = try scratch.alloc(suite.Hasher.Hash, 0) };
        }
        const max_log = if (capacity_mode) try Codec.maximumProofColumnLog(try expected(source)) else try T.maximumProofColumnLog(source, 0);
        const layers = try scratch.alloc(core.fri.FriLayerProof(suite.Hasher), max_log - 1);
        const first = core.fri.FriLayerProof(suite.Hasher){ .fri_witness = try scratch.alloc(Q, 0), .decommitment = .{ .hash_witness = try scratch.alloc(suite.Hasher.Hash, 0) }, .commitment = @splat(11) };
        for (layers) |*layer| layer.* = .{ .fri_witness = try scratch.alloc(Q, 0), .decommitment = .{ .hash_witness = try scratch.alloc(suite.Hasher.Hash, 0) }, .commitment = @splat(12) };
        return .{ .arena = arena, .claims = claims, .stark = .{ .commitment_scheme_proof = .{
            .config = config,
            .commitments = .{ .items = try scratch.dupe(suite.Hasher.Hash, &.{ @splat(1), @splat(2), @splat(3), @splat(4) }) },
            .sampled_values = .{ .items = samples },
            .queried_values = .{ .items = queries },
            .decommitments = .{ .items = decommits },
            .proof_of_work = 0,
            .fri_proof = .{ .first_layer = first, .inner_layers = layers, .last_layer_poly = core.poly.line.LinePoly.initOwned(try scratch.dupe(Q, &.{Q.one()})) },
        } } };
    }
    pub fn deinit(self: *Fixture) void {
        self.arena.deinit();
    }
    pub fn native(self: *const Fixture) @import("block_v5_native_execution_proof_v3.zig").Proof {
        return .{ .stark = self.stark, .claims = self.claims, .template_id = @splat(7), .instance_id = @splat(8) };
    }
    pub fn capacity(self: *const Fixture) @import("block_v5_native_capacity_proof_v1.zig").Proof {
        return .{ .stark = self.stark, .claims = self.claims, .template_id = @splat(7), .instance_id = @splat(8) };
    }
};
