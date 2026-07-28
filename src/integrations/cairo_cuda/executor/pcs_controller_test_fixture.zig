const std = @import("std");
const arena = @import("../../../backends/cuda/runtime/arena.zig");
const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const fixed_table = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const semantic_authority = @import("stwo_cairo_frontend").proof_plan.semantic_authority;
const proof_ir = @import("stwo_backend_contracts").proof_program;
const resident_plan = @import("resident_plan.zig");
const resident_test = @import("resident_plan_test_support.zig");
const plan_fixture = @import("resident_plan_test.zig");

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
    fixed: fixed_table.Bundle,
    preprocessed_logs: []u32,
    protocol: compact.CompactProtocolV1,
    program: proof_ir.ProofProgram,
    plan: resident_plan.Plan,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        var bundle = try composition.Bundle.readFile(
            allocator,
            "vectors/cairo/sn_pie_2_composition.bin",
        );
        errdefer bundle.deinit();
        var fixed = try fixed_table.Bundle.readFile(
            allocator,
            "vectors/cairo/cairo_fixed_tables.bin",
        );
        errdefer fixed.deinit();
        const logs = try semantic_authority.preprocessedLogs(
            allocator,
            fixed,
        );
        errdefer allocator.free(logs);
        const protocol = try plan_fixture.sn2Protocol(bundle, logs.len);
        var provisional_program = try plan_fixture.sn2Program(
            allocator,
            bundle,
            protocol,
            logs,
        );
        defer provisional_program.deinit(allocator);
        var program = try authenticatedProgram(
            allocator,
            provisional_program,
            protocol,
        );
        errdefer program.deinit(allocator);
        const plan = try resident_plan.Plan.init(
            allocator,
            program,
            protocol,
            bundle,
            try resident_test.geometry(program, bundle),
        );
        return .{
            .allocator = allocator,
            .bundle = bundle,
            .fixed = fixed,
            .preprocessed_logs = logs,
            .protocol = protocol,
            .program = program,
            .plan = plan,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.plan.deinit(self.allocator);
        self.program.deinit(self.allocator);
        self.allocator.free(self.preprocessed_logs);
        self.fixed.deinit();
        self.bundle.deinit();
        self.* = undefined;
    }
};

pub const Provider = struct {
    plan: *const resident_plan.Plan,

    pub fn slot(self: Provider, id: arena.SlotId) !common.Words {
        var cursor: usize = 0;
        for (self.plan.slots) |descriptor| {
            cursor = std.mem.alignForward(
                usize,
                cursor,
                descriptor.alignment_words,
            );
            if (descriptor.id == id) {
                return .{
                    .address = 0x1_0000_0000 + cursor * @sizeOf(u32),
                    .len = descriptor.words,
                    .owner = 91,
                    .generation = 17,
                };
            }
            cursor = std.math.add(
                usize,
                cursor,
                descriptor.words,
            ) catch return error.SizeOverflow;
        }
        return error.ArenaSlotMissing;
    }
};

pub fn same(left: anytype, right: anytype) bool {
    return left.address == right.address and
        left.len == right.len and
        left.owner == right.owner and
        left.generation == right.generation;
}

fn authenticatedProgram(
    allocator: std.mem.Allocator,
    source: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !proof_ir.ProofProgram {
    const nodes = [_]proof_ir.Node{
        graphNode(0, .trace_generation, .trace_generation, 0, 0),
        graphNode(1, .commitment, .trace_commit, 0, 0),
        graphNode(2, .commitment, .trace_commit, 0, 2),
        graphNode(3, .pow, .trace_commit, 2, 1),
        graphNode(4, .constraint_evaluation, .trace_commit, 3, 1),
        graphNode(5, .commitment, .trace_commit, 4, 1),
        graphNode(6, .constraint_evaluation, .constraint_evaluation, 5, 1),
        graphNode(7, .commitment, .constraint_evaluation, 6, 1),
        graphNode(8, .oods, .oods, 7, 1),
        graphNode(9, .quotient, .quotient, 8, 1),
        graphNode(10, .fri_commit, .fri_commit, 9, 1),
        graphNode(11, .pow, .pow, 10, 1),
        graphNode(12, .decommit, .decommit, 11, 1),
    };
    const dependencies = [_]u32{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    };
    const barriers = try canonicalBarriers(allocator, protocol);
    defer allocator.free(barriers);
    return proof_ir.ProofProgram.init(allocator, .{
        .identity = source.identity,
        .native_air_contract = source.native_air_contract,
        .trace_columns = source.trace_columns,
        .constraints = source.constraints,
        .commitments = source.commitments,
        .transcript = barriers,
        .quotient = source.quotient,
        .fri_layers = source.fri_layers,
        .buffers = source.buffers,
        .nodes = &nodes,
        .dependency_ids = &dependencies,
    });
}

fn canonicalBarriers(
    allocator: std.mem.Allocator,
    protocol: compact.CompactProtocolV1,
) ![]proof_ir.TranscriptBarrier {
    const barriers = try allocator.alloc(
        proof_ir.TranscriptBarrier,
        16 + protocol.fri_tree_count * 2,
    );
    var cursor: usize = 0;
    const prefix_kinds = [_]proof_ir.TranscriptKind{
        .mix,
        .mix,
        .mix,
        .mix,
        .pow,
        .challenge,
        .mix,
        .mix,
        .challenge,
        .mix,
        .challenge,
        .mix,
        .challenge,
    };
    const prefix_counts = [_]u32{
        1,
        1,
        1,
        1,
        1,
        2,
        protocol.interaction_sum_count,
        1,
        1,
        1,
        1,
        protocol.sampled_value_words / 4,
        1,
    };
    const prefix_nodes = [_]u32{
        2, 2, 2, 2, 3, 3, 5, 5, 5, 7, 7, 8, 8,
    };
    for (prefix_kinds, prefix_counts, prefix_nodes) |
        kind,
        count,
        node_id,
    | {
        barriers[cursor] = graphBarrier(
            barriers[0..cursor],
            node_id,
            kind,
            count,
        );
        cursor += 1;
    }
    for (0..protocol.fri_tree_count) |_| {
        barriers[cursor] = graphBarrier(
            barriers[0..cursor],
            10,
            .mix,
            1,
        );
        cursor += 1;
        barriers[cursor] = graphBarrier(
            barriers[0..cursor],
            10,
            .challenge,
            1,
        );
        cursor += 1;
    }
    const suffix_kinds = [_]proof_ir.TranscriptKind{
        .mix,
        .pow,
        .queries,
    };
    const suffix_counts = [_]u32{
        protocol.final_line_coefficient_count,
        1,
        protocol.query_count,
    };
    const suffix_nodes = [_]u32{ 10, 11, 11 };
    for (suffix_kinds, suffix_counts, suffix_nodes) |
        kind,
        count,
        node_id,
    | {
        barriers[cursor] = graphBarrier(
            barriers[0..cursor],
            node_id,
            kind,
            count,
        );
        cursor += 1;
    }
    std.debug.assert(cursor == barriers.len);
    return barriers;
}

fn graphBarrier(
    previous: []const proof_ir.TranscriptBarrier,
    node_id: u32,
    kind: proof_ir.TranscriptKind,
    count: u32,
) proof_ir.TranscriptBarrier {
    var phase: u32 = 0;
    if (previous.len != 0 and previous[previous.len - 1].node == node_id)
        phase = previous[previous.len - 1].phase + 1;
    return .{
        .ordinal = @intCast(previous.len),
        .node = node_id,
        .phase = phase,
        .kind = kind,
        .value_count = count,
    };
}

fn graphNode(
    id: u32,
    kind: proof_ir.OperationKind,
    stage: proof_ir.Stage,
    dependency_first: u32,
    dependency_count: u32,
) proof_ir.Node {
    return .{
        .id = id,
        .kind = kind,
        .stage = stage,
        .dependencies = .{
            .first = dependency_first,
            .count = dependency_count,
        },
        .parallelism = .coordination,
        .graph_candidate = false,
        .work = .{
            .bytes_read = 1,
            .bytes_written = 1,
            .field_operations = 1,
            .hash_compressions = 0,
            .minimum_launches = 1,
        },
    };
}
