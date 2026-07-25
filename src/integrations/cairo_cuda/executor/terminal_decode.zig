//! Strict reconstruction of the Rust-accepted Cairo proof payload from SWPC.
//!
//! The CUDA proof finalizer writes one self-describing SWPC allocation. This
//! decoder treats its header as untrusted, checks it against caller-authenticated
//! protocol geometry, and reorders the two PoW nonces into the canonical
//! `resident_sn2_bundle_v1` wire order.

const builtin = @import("builtin");
const std = @import("std");
const compact = @import("../../../frontends/cairo/compact_verifier_interchange.zig");
const proof_bundle = @import("../../../frontends/cairo/witness/proof_bundle.zig");
const decommit_bundle = @import(
    "../../../backends/cuda/runtime/proof_assembly/decommit_bundle.zig",
);
const common = @import("../../native_cuda/common/proof_bundle.zig");
const terminal = @import("terminal_bundle.zig");

pub const Error = error{
    CpuFallbackObserved,
    GeometryOverflow,
    IncompleteTerminalReadEvidence,
    InvalidCanonicalProofLength,
    InvalidDecommitment,
    InvalidTerminalHeader,
    NonzeroDecommitmentTail,
    RuntimeCompilationObserved,
    TerminalReadLengthMismatch,
    TerminalReadOperationMismatch,
    UnsupportedProtocol,
};

/// Runtime counters supplied by the proof session after the stream completes.
///
/// There is no default "good" state: the route can claim one terminal D2H and
/// zero fallback/runtime compilation only from an explicitly measured record.
pub const MeasuredTerminalRead = struct {
    measured: bool = false,
    d2h_proof_operations: u64 = 0,
    d2h_proof_bytes: u64 = 0,
    runtime_compile_attempts: u64 = 0,
    cpu_fallback_attempts: u64 = 0,

    pub fn validate(self: MeasuredTerminalRead, expected_bytes: usize) Error!void {
        if (!self.measured) return error.IncompleteTerminalReadEvidence;
        if (self.d2h_proof_operations != 1)
            return error.TerminalReadOperationMismatch;
        if (self.d2h_proof_bytes != expected_bytes)
            return error.TerminalReadLengthMismatch;
        if (self.runtime_compile_attempts != 0)
            return error.RuntimeCompilationObserved;
        if (self.cpu_fallback_attempts != 0)
            return error.CpuFallbackObserved;
    }
};

/// Host-owned canonical proof payload. `structural` borrows `words`.
pub const CanonicalProof = struct {
    protocol: compact.CompactProtocolV1,
    words: []u32,
    structural: proof_bundle.ProofBundle,
    terminal_read: MeasuredTerminalRead,

    pub fn decode(
        allocator: std.mem.Allocator,
        protocol: compact.CompactProtocolV1,
        transport_words: []const u32,
        terminal_read: MeasuredTerminalRead,
    ) !CanonicalProof {
        try protocol.validate();
        var descriptor = try terminal.Bundle.init(
            allocator,
            .{ .protocol = protocol },
            .{ .capacity_words = protocol.decommitment_capacity_words },
        );
        defer descriptor.deinit(allocator);
        try descriptor.validate(protocol.decommitment_capacity_words);

        const transport_bytes = try checkedMul(transport_words.len, @sizeOf(u32));
        try terminal_read.validate(transport_bytes);
        try validateTransport(descriptor, transport_words);

        const canonical_word_count = try protocol.proofWordCount();
        const words = try allocator.alloc(u32, canonical_word_count);
        errdefer allocator.free(words);
        try reconstructCanonical(descriptor, transport_words, words, protocol);
        var structural = try proof_bundle.ProofBundle.decode(
            allocator,
            words,
            try canonicalLayout(protocol),
        );
        errdefer structural.deinit(allocator);
        try validateDecommitment(allocator, protocol, structural);
        return .{
            .protocol = protocol,
            .words = words,
            .structural = structural,
            .terminal_read = terminal_read,
        };
    }

    pub fn deinit(self: *CanonicalProof, allocator: std.mem.Allocator) void {
        self.structural.deinit(allocator);
        allocator.free(self.words);
        self.* = undefined;
    }

    /// Exact little-endian bytes accepted by `CompactProtocolV1`.
    pub fn bytes(self: CanonicalProof) []const u8 {
        if (comptime builtin.cpu.arch.endian() != .little) {
            @compileError("Cairo CUDA canonical proof bytes require a little-endian host");
        }
        return std.mem.sliceAsBytes(self.words);
    }

    pub fn sha256(self: CanonicalProof) [32]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.bytes(), &digest, .{});
        return digest;
    }
};

pub fn transportWordCount(
    allocator: std.mem.Allocator,
    protocol: compact.CompactProtocolV1,
) !usize {
    var descriptor = try terminal.Bundle.init(
        allocator,
        .{ .protocol = protocol },
        .{ .capacity_words = protocol.decommitment_capacity_words },
    );
    defer descriptor.deinit(allocator);
    return descriptor.total_words;
}

fn canonicalLayout(
    protocol: compact.CompactProtocolV1,
) !proof_bundle.Layout {
    return proof_bundle.Layout.initRuntime(
        protocol.commitment_count,
        try checkedMul(protocol.interaction_sum_count, 4),
        protocol.sampled_value_words,
        protocol.fri_tree_count,
        try checkedMul(protocol.final_line_coefficient_count, 4),
        protocol.decommitment_capacity_words,
    );
}

fn validateTransport(
    descriptor: terminal.Bundle,
    transport: []const u32,
) !void {
    if (transport.len != descriptor.total_words or
        transport.len < common.header_words)
    {
        return error.InvalidTerminalHeader;
    }
    for (descriptor.static_header, 0..) |expected, index| {
        const finalized = if (index == common.fixed_header_words - 1)
            @as(u32, 0)
        else
            expected;
        if (transport[index] != finalized)
            return error.InvalidTerminalHeader;
    }
}

fn reconstructCanonical(
    descriptor: terminal.Bundle,
    transport: []const u32,
    canonical: []u32,
    protocol: compact.CompactProtocolV1,
) !void {
    const layout = try canonicalLayout(protocol);
    if (canonical.len != layout.total_words)
        return error.InvalidCanonicalProofLength;
    const trace = source(descriptor, transport, .trace_commitments);
    const commitment_words = try checkedMul(protocol.commitment_count, 8);
    const interaction_words = try checkedMul(protocol.interaction_sum_count, 4);
    if (trace.len != commitment_words + interaction_words)
        return error.InvalidTerminalHeader;
    @memcpy(canonical[layout.commitments.start..layout.commitments.end], trace[0..commitment_words]);
    @memcpy(
        canonical[layout.interaction_claim.start..layout.interaction_claim.end],
        trace[commitment_words..],
    );

    const pow = source(descriptor, transport, .proof_of_work);
    if (pow.len != 4) return error.InvalidTerminalHeader;
    @memcpy(canonical[layout.interaction_pow.start..layout.interaction_pow.end], pow[0..2]);
    @memcpy(canonical[layout.query_pow.start..layout.query_pow.end], pow[2..4]);
    @memcpy(
        canonical[layout.sampled_values.start..layout.sampled_values.end],
        source(descriptor, transport, .sampled_values),
    );
    @memcpy(
        canonical[layout.fri_commitments.start..layout.fri_commitments.end],
        source(descriptor, transport, .fri_commitments),
    );
    @memcpy(
        canonical[layout.final_line_poly.start..layout.final_line_poly.end],
        source(descriptor, transport, .fri_last_layer),
    );
    @memcpy(
        canonical[layout.decommitment.start..layout.decommitment.end],
        source(descriptor, transport, .decommitment),
    );
}

fn validateDecommitment(
    allocator: std.mem.Allocator,
    protocol: compact.CompactProtocolV1,
    structural: proof_bundle.ProofBundle,
) !void {
    const capacity = structural.words[structural.layout.decommitment.start..structural.layout.decommitment.end];
    var decoded = decommit_bundle.Bundle.decodeBorrowed(
        allocator,
        @constCast(capacity),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidDecommitment,
    };
    defer decoded.deinit(allocator);
    if (decoded.raw_query_count != protocol.query_count or
        decoded.trees.len != protocol.decommitment_record_count)
    {
        return error.InvalidDecommitment;
    }
    for (decoded.trees, 0..) |tree, index| {
        const expected_kind: decommit_bundle.TreeKind =
            if (index < protocol.commitment_count) .trace else .fri;
        if (tree.kind != expected_kind or tree.role != index)
            return error.InvalidDecommitment;
    }
    for (capacity[decoded.used_words..]) |word| {
        if (word != 0) return error.NonzeroDecommitmentTail;
    }
}

fn source(
    descriptor: terminal.Bundle,
    transport: []const u32,
    kind: common.SectionKind,
) []const u32 {
    const section = descriptor.section(kind);
    return transport[section.offset_words .. section.offset_words + section.words];
}

fn checkedMul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}
