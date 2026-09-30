//! Strict one-read circuit proof reconstruction. The SWPC envelope is a
//! transport format; the returned words use the verifier's canonical order.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const canonical = @import("stwo_cairo_frontend").witness.proof_bundle;
const shared = @import("stwo_native_cuda_integration").common.proof_bundle;
const terminal = @import("resident_terminal_bundle.zig");

pub const MeasuredRead = struct {
    operations: u64,
    bytes: u64,
    runtime_compile_attempts: u64,
    cpu_fallback_attempts: u64,

    pub fn validate(self: MeasuredRead, expected_words: usize) !void {
        if (self.operations != 1 or self.bytes != try shared.mul(expected_words, 4))
            return error.InvalidTerminalRead;
        if (self.runtime_compile_attempts != 0 or self.cpu_fallback_attempts != 0)
            return error.NonresidentCircuitProof;
    }
};

pub const Proof = struct {
    words: []u32,
    decoded: canonical.ProofBundle,
    read: MeasuredRead,

    pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
        self.decoded.deinit(allocator);
        allocator.free(self.words);
        self.* = undefined;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        layout: terminal.Layout,
        decommit: terminal.Decommit,
        transport: []const u32,
        read: MeasuredRead,
    ) !Proof {
        var descriptor = try terminal.Bundle.init(allocator, layout, decommit);
        defer descriptor.deinit(allocator);
        try descriptor.validate(decommit.capacity_words);
        try read.validate(descriptor.total_words);
        try validateEnvelope(descriptor, transport);
        const claim_words = try shared.mul(circuit.common.component_list.N_COMPONENTS, 4);
        const wire_layout = try canonical.Layout.initRuntime(
            4,
            claim_words,
            try shared.mul(layout.sampled_values, 4),
            layout.fri_roots,
            try shared.mul(layout.final_coefficients, 4),
            decommit.capacity_words,
        );
        const words = try allocator.alloc(u32, wire_layout.total_words);
        errdefer allocator.free(words);
        try reorder(descriptor, transport, wire_layout, words);
        var decoded = try canonical.ProofBundle.decode(allocator, words, wire_layout);
        errdefer decoded.deinit(allocator);
        if (decoded.decommitment.raw_queries.len != layout.query_count or
            decoded.decommitment.trees.len != 4 + layout.fri_roots)
            return error.InvalidCircuitDecommitment;
        const capacity = words[wire_layout.decommitment.start..wire_layout.decommitment.end];
        for (capacity[decoded.decommitment.words.len..]) |word|
            if (word != 0) return error.NonzeroCircuitDecommitmentTail;
        return .{ .words = words, .decoded = decoded, .read = read };
    }
};

fn validateEnvelope(descriptor: terminal.Bundle, transport: []const u32) !void {
    if (transport.len != descriptor.total_words or transport.len < shared.header_words)
        return error.InvalidCircuitTerminalHeader;
    for (descriptor.static_header, 0..) |expected, index| {
        const finalized = if (index == 15) @as(u32, 0) else expected;
        if (transport[index] != finalized)
            return if (index == 15) error.InvalidFriDegree else error.InvalidCircuitTerminalHeader;
    }
}

fn reorder(
    descriptor: terminal.Bundle,
    transport: []const u32,
    layout: canonical.Layout,
    output: []u32,
) !void {
    if (output.len != layout.total_words) return error.InvalidCircuitTerminalLength;
    const roots_and_claims = section(descriptor, transport, .trace_commitments);
    const commitments = layout.commitments.end - layout.commitments.start;
    const claims = layout.interaction_claim.end - layout.interaction_claim.start;
    if (roots_and_claims.len != commitments + claims)
        return error.InvalidCircuitTerminalHeader;
    @memcpy(output[layout.commitments.start..layout.commitments.end], roots_and_claims[0..commitments]);
    @memcpy(output[layout.interaction_claim.start..layout.interaction_claim.end], roots_and_claims[commitments..]);
    const pow = section(descriptor, transport, .proof_of_work);
    if (pow.len != 4) return error.InvalidCircuitTerminalHeader;
    @memcpy(output[layout.interaction_pow.start..layout.interaction_pow.end], pow[0..2]);
    @memcpy(output[layout.query_pow.start..layout.query_pow.end], pow[2..4]);
    @memcpy(output[layout.sampled_values.start..layout.sampled_values.end], section(descriptor, transport, .sampled_values));
    @memcpy(output[layout.fri_commitments.start..layout.fri_commitments.end], section(descriptor, transport, .fri_commitments));
    @memcpy(output[layout.final_line_poly.start..layout.final_line_poly.end], section(descriptor, transport, .fri_last_layer));
    @memcpy(output[layout.decommitment.start..layout.decommitment.end], section(descriptor, transport, .decommitment));
}

fn section(descriptor: terminal.Bundle, words: []const u32, kind: shared.SectionKind) []const u32 {
    const part = descriptor.section(kind);
    return words[part.offset_words .. part.offset_words + part.words];
}

test "resident circuit decoder rejects an unmeasured or poisoned terminal" {
    const allocator = std.testing.allocator;
    const layout = terminal.Layout{
        .sampled_values = 1,
        .fri_roots = 1,
        .final_coefficients = 1,
        .query_count = 1,
        .query_pow_bits = 1,
        .blowup = 1,
        .fold_step = 4,
        .max_log_degree_bound = 3,
    };
    const decommit = terminal.Decommit{ .capacity_words = 64 };
    var descriptor = try terminal.Bundle.init(allocator, layout, decommit);
    defer descriptor.deinit(allocator);
    const words = try allocator.dupe(u32, descriptor.static_header);
    defer allocator.free(words);
    const read = MeasuredRead{ .operations = 0, .bytes = words.len * 4, .runtime_compile_attempts = 0, .cpu_fallback_attempts = 0 };
    try std.testing.expectError(error.InvalidTerminalRead, Proof.decode(allocator, layout, decommit, words, read));
    const measured = MeasuredRead{ .operations = 1, .bytes = descriptor.total_words * 4, .runtime_compile_attempts = 0, .cpu_fallback_attempts = 0 };
    try std.testing.expectError(error.InvalidCircuitTerminalHeader, Proof.decode(allocator, layout, decommit, words, measured));
}
