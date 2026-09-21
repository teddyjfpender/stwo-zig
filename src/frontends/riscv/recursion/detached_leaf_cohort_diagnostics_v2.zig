//! Observational diagnostics for the canonical leaf cohort; no authority is minted.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const tuple_diagnostic = @import("detached_leaf_tuple_diagnostic_v2.zig");
const relation_interaction = @import("air/relation_interaction.zig");
const RED_TUPLE_DOMAIN_MASK = tuple_diagnostic.RED_DOMAIN_MASK;

/// Diagnostic-only inventory of the actual materialized Tree 0 and all
/// lowering constants, including unused graph constants. No new authority
/// is minted. Invocation order distinguishes producer Tree 0 from the
/// subsequent verifier reconstruction in the engine's surrounding phases.
pub fn printCircuitCensus(self: anytype, columns: []const []const M31, circuit_census_sequence: *std.atomic.Value(u64)) void {
    const invocation = circuit_census_sequence.fetchAdd(1, .monotonic);
    std.debug.print("SEGMENT_V2_CIRCUIT_CENSUS phase=outer_tree0_filled invocation={d} prepared_sha256={s} manifest_sha256={s}\n", .{
        invocation,
        std.fmt.bytesToHex(self.prepared_identity, .lower),
        std.fmt.bytesToHex(self.complete_manifest.seal, .lower),
    });
    for (self.complete_manifest.roster_rows[0..self.complete_manifest.roster_count]) |row| {
        const placement = self.complete_manifest.placements[row].?;
        const offset: usize = placement.preprocessed_offset;
        const count: usize = placement.geometry.preprocessed_columns;
        var values = std.crypto.hash.sha2.Sha256.init(.{});
        var words: usize = 0;
        for (columns[offset..][0..count]) |column| {
            censusHashU64(&values, column.len);
            for (column) |word| censusHashM31(&values, word);
            words += column.len;
        }
        std.debug.print("SEGMENT_V2_CIRCUIT_CENSUS phase=outer_tree0_filled invocation={d} row={d} log_size={d} columns={d} words={d} values_sha256={s}\n", .{
            invocation, row, placement.geometry.log_size, count, words, std.fmt.bytesToHex(values.finalResult(), .lower),
        });
    }
    for (self.core.authority.arithmetic_reference.lanes, 0..) |lane, lane_index| {
        var edges = std.crypto.hash.sha2.Sha256.init(.{});
        var constants = std.crypto.hash.sha2.Sha256.init(.{});
        var coordinates = std.crypto.hash.sha2.Sha256.init(.{});
        var public_values = std.crypto.hash.sha2.Sha256.init(.{});
        var input_count: usize = 0;
        var constant_count: usize = 0;
        var term_count: usize = 0;
        censusHashU64(&edges, lane.graph.nodes.len);
        for (lane.graph.nodes, 0..) |node, node_index| {
            censusHashU64(&edges, @intFromEnum(node.op));
            switch (node.op) {
                .input => input_count += 1,
                .constant => |value| {
                    constant_count += 1;
                    censusHashU64(&constants, node_index);
                    for (value) |word| censusHashM31(&constants, M31.fromCanonical(word));
                },
                .add, .sub, .mul => |operands| {
                    censusHashU64(&edges, operands.lhs);
                    censusHashU64(&edges, operands.rhs);
                },
                .neg, .inverse => |operand| censusHashU64(&edges, operand),
            }
        }
        censusHashU64(&edges, lane.graph.outputs.len);
        for (lane.graph.outputs) |output| censusHashU64(&edges, output);
        for (self.core.authority.lowering_plan.public_terms) |term| {
            if (term.lane != lane_index) continue;
            term_count += 1;
            censusHashU64(&coordinates, term.lane);
            censusHashU64(&coordinates, @intFromEnum(term.active_in));
            censusHashU64(&coordinates, @intFromEnum(term.role));
            censusHashU64(&coordinates, term.circuit_id);
            censusHashU64(&coordinates, term.node_id);
            censusHashU64(&coordinates, term.multiplicity);
            for (term.value.toM31Array()) |word| censusHashM31(&public_values, word);
        }
        std.debug.print("SEGMENT_V2_CIRCUIT_CENSUS phase=lowering_after_tree0 invocation={d} lane={d} circuit_id={d} mode={s} nodes={d} inputs={d} constants={d} outputs={d} public_terms={d} node_edges_sha256={s} constant_values_sha256={s} public_coordinates_sha256={s} public_values_sha256={s} graph_sha256={s}\n", .{
            invocation,                                      lane_index,                                          lane.circuit_id,                                       @tagName(lane.active_in),                                lane.graph.nodes.len,                                   input_count, constant_count, lane.graph.outputs.len, term_count,
            std.fmt.bytesToHex(edges.finalResult(), .lower), std.fmt.bytesToHex(constants.finalResult(), .lower), std.fmt.bytesToHex(coordinates.finalResult(), .lower), std.fmt.bytesToHex(public_values.finalResult(), .lower), std.fmt.bytesToHex(lane.graph.identity_digest, .lower),
        });
    }
}

fn censusHashU64(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}

fn censusHashM31(hash: *std.crypto.hash.sha2.Sha256, value: M31) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value.toU32(), .little);
    hash.update(&bytes);
}

pub fn diagnoseRedTupleClosure(
    self: anytype,
    allocator: std.mem.Allocator,
) !tuple_diagnostic.Report {
    var ledger = relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try self.noncore.appendTupleContributions(
        &ledger,
        RED_TUPLE_DOMAIN_MASK,
    );
    try self.core.appendTupleContributions(
        allocator,
        &ledger,
        RED_TUPLE_DOMAIN_MASK,
    );
    return tuple_diagnostic.classify(
        allocator,
        &ledger,
        RED_TUPLE_DOMAIN_MASK,
    );
}
