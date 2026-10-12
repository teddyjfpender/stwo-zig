//! Exact diagnostic projection from an authenticated SegmentV2 sparse boundary.
//!
//! This adapter deliberately cannot authorize a recursive proof. SegmentV2
//! retains a Poseidon continuation snapshot, whereas the available
//! `blake3_memory_boundary` AIR opens a different tree. Pairing that AIR with
//! the V3 byte bridge would allow a detached word to impersonate native
//! memory. The projection below records the real V2 word and its canonical
//! wire position so the eventual source AIR can consume row-11 words. A
//! caller still needs a fresh native proof capture and a proof-visible source
//! relation before any V3 root may be published.

const std = @import("std");
const public_data = @import("../air/public_data_v2.zig");
const wire = @import("segment_statement_v2.zig");
const binding = @import("segment_public_io_binding_v1.zig");
const ingress = @import("segment_public_io_ingress_v2.zig");
const bridge = @import("air/v3_public_io_word_bridge_v1.zig");

pub const PROOF_ACTIVATION = false;
pub const Word = struct {
    role: bridge.Role,
    address: u32,
    /// Canonical four-u16 retained tuple; absent zero words are rejected.
    retained_wire_offset: usize,
    bridge_row: bridge.Row,
};

pub const Projection = struct {
    allocator: std.mem.Allocator,
    words: []Word,
    wire_id: wire.Digest,
    coverage: binding.Coverage,

    pub fn deinit(self: *Projection) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }

    /// A host-side authenticated wire, even one from a freshly verified
    /// native capture, cannot stand in for a source relation in the outer AIR.
    pub fn requireProofVisibleSource(_: *const Projection) error{V3MemorySourceAirUnavailable}!void {
        return error.V3MemorySourceAirUnavailable;
    }
};

/// Diagnostic only: `data` is reauthenticated and checked against an owned,
/// verifier-supplied ABI and expected bytes. Do not construct a proof roster
/// from this projection; `retained_wire_offset` is witness data, not a key.
pub fn projectAuthenticatedWire(
    allocator: std.mem.Allocator,
    data: *const public_data.PublicDataV2,
    policy: *const ingress.VerifierExpectedIo,
    source_circuit: u32,
) !Projection {
    const expected = binding.Expected{
        .input_start = policy.input_start,
        .input = policy.input,
        .output_len_addr = policy.output_len_addr,
        .output_data_addr = policy.output_data_addr,
        .output = policy.output,
    };
    const coverage = try binding.validateAuthenticatedWire(data, expected);
    const view = try data.authenticatedView();
    var rows: std.ArrayList(Word) = .empty;
    errdefer rows.deinit(allocator);
    if (coverage.input) try appendRange(allocator, &rows, &view, view.entry_snapshot, policy, .input, policy.input_start, policy.input.len, source_circuit);
    if (coverage.output) {
        try appendOne(allocator, &rows, &view, view.exit_snapshot, policy, .output_length, policy.output_len_addr, source_circuit);
        try appendRange(allocator, &rows, &view, view.exit_snapshot, policy, .output, policy.output_data_addr, policy.output.len, source_circuit);
    }
    return .{ .allocator = allocator, .words = try rows.toOwnedSlice(allocator), .wire_id = view.wire_id, .coverage = coverage };
}

fn appendRange(
    allocator: std.mem.Allocator,
    rows: *std.ArrayList(Word),
    view: *const wire.CanonicalWireViewV2,
    section: wire.RetainedSectionV2,
    policy: *const ingress.VerifierExpectedIo,
    role: bridge.Role,
    start: u32,
    length: usize,
    source_circuit: u32,
) !void {
    if (length == 0) return;
    const end = @as(u64, start) + length;
    var address = start & ~@as(u32, 3);
    while (@as(u64, address) < end) : (address += 4)
        try appendOne(allocator, rows, view, section, policy, role, address, source_circuit);
}

fn appendOne(
    allocator: std.mem.Allocator,
    rows: *std.ArrayList(Word),
    view: *const wire.CanonicalWireViewV2,
    section: wire.RetainedSectionV2,
    policy: *const ingress.VerifierExpectedIo,
    role: bridge.Role,
    address: u32,
    source_circuit: u32,
) !void {
    var low: usize = 0;
    var high: usize = section.count;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (view.sparseEntry(section, middle).address < address) low = middle + 1 else high = middle;
    }
    // A zero word is absent from V2's canonical sparse section. The dormant
    // relation has no absence proof, so no host-synthesized zero source is
    // permitted here even when the expected byte is zero.
    if (low == section.count or view.sparseEntry(section, low).address != address)
        return error.ZeroWordRequiresAbsenceProof;
    const value = view.sparseEntry(section, low).value;
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    const row = try bridge.logicalRow(policy, role, address, source_circuit, bytes);
    try rows.append(allocator, .{
        .role = role,
        .address = address,
        .retained_wire_offset = section.payload_start + low * wire.RETAINED_ENTRY_WORDS,
        .bridge_row = row,
    });
}
