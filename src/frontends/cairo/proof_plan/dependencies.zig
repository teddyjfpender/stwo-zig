//! Canonical data-flow dependencies between official Cairo witness writers.

const std = @import("std");

pub const ProducerEdge = struct {
    producer: []const u8,
    word_base: u32,
    words_per_instance: u32,
    instances: u32,
};

pub const CapacityFeed = struct {
    producer: []const u8,
    instances: u32,
};

const edge_blake_round = [_]ProducerEdge{.{ .producer = "blake_compress_opcode", .word_base = 110, .words_per_instance = 19, .instances = 10 }};
const edge_blake_g = [_]ProducerEdge{.{ .producer = "blake_round", .word_base = 81, .words_per_instance = 6, .instances = 8 }};
const edge_triple_xor = [_]ProducerEdge{.{ .producer = "blake_compress_opcode", .word_base = 300, .words_per_instance = 3, .instances = 8 }};
const edge_partial_w18 = [_]ProducerEdge{.{ .producer = "pedersen_aggregator_window_bits_18", .word_base = 7, .words_per_instance = 72, .instances = 28 }};
const edge_partial_ec_generic = [_]ProducerEdge{.{ .producer = "ec_op_builtin", .word_base = 16, .words_per_instance = 125, .instances = 252 }};
const edge_cube = [_]ProducerEdge{
    .{ .producer = "poseidon_aggregator", .word_base = 282, .words_per_instance = 10, .instances = 2 },
    .{ .producer = "poseidon_3_partial_rounds_chain", .word_base = 1, .words_per_instance = 10, .instances = 3 },
    .{ .producer = "poseidon_full_round_chain", .word_base = 0, .words_per_instance = 10, .instances = 3 },
};
const edge_range_252 = [_]ProducerEdge{
    .{ .producer = "poseidon_aggregator", .word_base = 262, .words_per_instance = 10, .instances = 2 },
    .{ .producer = "poseidon_3_partial_rounds_chain", .word_base = 61, .words_per_instance = 10, .instances = 3 },
};
const edge_poseidon_full = [_]ProducerEdge{.{ .producer = "poseidon_aggregator", .word_base = 6, .words_per_instance = 32, .instances = 8 }};
const edge_poseidon_partial = [_]ProducerEdge{.{ .producer = "poseidon_aggregator", .word_base = 342, .words_per_instance = 42, .instances = 27 }};
const compact_verify_edges = [_]ProducerEdge{
    .{ .producer = "add_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "add_opcode_small", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "add_ap_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "assert_eq_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "assert_eq_opcode_imm", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "assert_eq_opcode_double_deref", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "blake_compress_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "call_opcode_abs", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "call_opcode_rel_imm", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "generic_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jnz_opcode_non_taken", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jnz_opcode_taken", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jump_opcode_abs", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jump_opcode_double_deref", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jump_opcode_rel", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "jump_opcode_rel_imm", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "mul_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "mul_opcode_small", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "qm_31_add_mul_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
    .{ .producer = "ret_opcode", .word_base = 0, .words_per_instance = 7, .instances = 1 },
};
const compact_pedersen_edges = [_]ProducerEdge{.{ .producer = "pedersen_builtin", .word_base = 3, .words_per_instance = 3, .instances = 1 }};
const compact_poseidon_edges = [_]ProducerEdge{.{ .producer = "poseidon_builtin", .word_base = 6, .words_per_instance = 6, .instances = 1 }};

const capacity_blake_round = [_]CapacityFeed{.{ .producer = "blake_compress_opcode", .instances = 10 }};
const capacity_blake_g = [_]CapacityFeed{.{ .producer = "blake_round", .instances = 8 }};
const capacity_triple_xor = [_]CapacityFeed{.{ .producer = "blake_compress_opcode", .instances = 8 }};
const capacity_partial_w18 = [_]CapacityFeed{.{ .producer = "pedersen_aggregator_window_bits_18", .instances = 28 }};
const capacity_partial_ec_generic = [_]CapacityFeed{.{ .producer = "ec_op_builtin", .instances = 252 }};
const capacity_cube = [_]CapacityFeed{
    .{ .producer = "poseidon_aggregator", .instances = 2 },
    .{ .producer = "poseidon_3_partial_rounds_chain", .instances = 3 },
    .{ .producer = "poseidon_full_round_chain", .instances = 3 },
};
const capacity_range_252 = [_]CapacityFeed{
    .{ .producer = "poseidon_aggregator", .instances = 2 },
    .{ .producer = "poseidon_3_partial_rounds_chain", .instances = 3 },
};
const capacity_poseidon_full = [_]CapacityFeed{.{ .producer = "poseidon_aggregator", .instances = 8 }};
const capacity_poseidon_partial = [_]CapacityFeed{.{ .producer = "poseidon_aggregator", .instances = 27 }};
const capacity_verify = [_]CapacityFeed{
    .{ .producer = "add_opcode", .instances = 1 },
    .{ .producer = "add_opcode_small", .instances = 1 },
    .{ .producer = "add_ap_opcode", .instances = 1 },
    .{ .producer = "assert_eq_opcode", .instances = 1 },
    .{ .producer = "assert_eq_opcode_imm", .instances = 1 },
    .{ .producer = "assert_eq_opcode_double_deref", .instances = 1 },
    .{ .producer = "blake_compress_opcode", .instances = 1 },
    .{ .producer = "call_opcode_abs", .instances = 1 },
    .{ .producer = "call_opcode_rel_imm", .instances = 1 },
    .{ .producer = "generic_opcode", .instances = 1 },
    .{ .producer = "jnz_opcode_non_taken", .instances = 1 },
    .{ .producer = "jnz_opcode_taken", .instances = 1 },
    .{ .producer = "jump_opcode_abs", .instances = 1 },
    .{ .producer = "jump_opcode_double_deref", .instances = 1 },
    .{ .producer = "jump_opcode_rel", .instances = 1 },
    .{ .producer = "jump_opcode_rel_imm", .instances = 1 },
    .{ .producer = "mul_opcode", .instances = 1 },
    .{ .producer = "mul_opcode_small", .instances = 1 },
    .{ .producer = "qm_31_add_mul_opcode", .instances = 1 },
    .{ .producer = "ret_opcode", .instances = 1 },
};
const capacity_pedersen = [_]CapacityFeed{.{ .producer = "pedersen_builtin", .instances = 1 }};
const capacity_poseidon = [_]CapacityFeed{.{ .producer = "poseidon_builtin", .instances = 1 }};

/// Producer slabs gathered without sorting into one consumer witness input.
pub fn gatheredProducerEdges(component: []const u8) ?[]const ProducerEdge {
    if (std.mem.eql(u8, component, "blake_round")) return &edge_blake_round;
    if (std.mem.eql(u8, component, "blake_g")) return &edge_blake_g;
    if (std.mem.eql(u8, component, "triple_xor_32")) return &edge_triple_xor;
    if (std.mem.eql(u8, component, "partial_ec_mul_window_bits_18")) return &edge_partial_w18;
    if (std.mem.eql(u8, component, "partial_ec_mul_generic")) return &edge_partial_ec_generic;
    if (std.mem.eql(u8, component, "cube_252")) return &edge_cube;
    if (std.mem.eql(u8, component, "range_check_252_width_27")) return &edge_range_252;
    if (std.mem.eql(u8, component, "poseidon_full_round_chain")) return &edge_poseidon_full;
    if (std.mem.eql(u8, component, "poseidon_3_partial_rounds_chain")) return &edge_poseidon_partial;
    return null;
}

/// Geometry for producer tuples that must be gathered, sorted, and compacted.
pub const CompactGeometry = struct {
    edges: []const ProducerEdge,
    tuple_words: u32,
    key_words: u32,
    enabler_slot: u32,
    iota_slot: u32,
    multiplicity_slot: u32,
};

pub fn compactGeometry(component: []const u8) ?CompactGeometry {
    if (std.mem.eql(u8, component, "verify_instruction")) return .{ .edges = &compact_verify_edges, .tuple_words = 7, .key_words = 1, .enabler_slot = 7, .iota_slot = 8, .multiplicity_slot = 9 };
    if (std.mem.eql(u8, component, "pedersen_aggregator_window_bits_18")) return .{ .edges = &compact_pedersen_edges, .tuple_words = 3, .key_words = 2, .enabler_slot = 3, .iota_slot = 4, .multiplicity_slot = 5 };
    if (std.mem.eql(u8, component, "poseidon_aggregator")) return .{ .edges = &compact_poseidon_edges, .tuple_words = 6, .key_words = 3, .enabler_slot = 6, .iota_slot = 7, .multiplicity_slot = 8 };
    return null;
}

pub fn canonicalProducerEdges(component: []const u8) []const ProducerEdge {
    if (gatheredProducerEdges(component)) |edges| return edges;
    if (compactGeometry(component)) |geometry| return geometry.edges;
    return &.{};
}

pub fn canonicalCapacityFeeds(component: []const u8) []const CapacityFeed {
    if (std.mem.eql(u8, component, "blake_round")) return &capacity_blake_round;
    if (std.mem.eql(u8, component, "blake_g")) return &capacity_blake_g;
    if (std.mem.eql(u8, component, "triple_xor_32")) return &capacity_triple_xor;
    if (std.mem.eql(u8, component, "partial_ec_mul_window_bits_18")) return &capacity_partial_w18;
    if (std.mem.eql(u8, component, "partial_ec_mul_generic")) return &capacity_partial_ec_generic;
    if (std.mem.eql(u8, component, "cube_252")) return &capacity_cube;
    if (std.mem.eql(u8, component, "range_check_252_width_27")) return &capacity_range_252;
    if (std.mem.eql(u8, component, "poseidon_full_round_chain")) return &capacity_poseidon_full;
    if (std.mem.eql(u8, component, "poseidon_3_partial_rounds_chain")) return &capacity_poseidon_partial;
    if (std.mem.eql(u8, component, "verify_instruction")) return &capacity_verify;
    if (std.mem.eql(u8, component, "pedersen_aggregator_window_bits_18")) return &capacity_pedersen;
    if (std.mem.eql(u8, component, "poseidon_aggregator")) return &capacity_poseidon;
    return &.{};
}
