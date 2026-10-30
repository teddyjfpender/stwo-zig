//! Metal source for the authenticated recursive framework polynomial contract.
//!
//! No AIR is transcribed here: direct roots and relation tuple expressions come
//! from the shared program. This generator owns only the versioned framework
//! recurrence and its resident-buffer ABI. Runtime integration/device parity
//! are separate gates; emitting source is not evidence of GPU execution.
const std = @import("std");
const component = @import("stwo_prover_engine").air.component_prover;
const field_codegen = @import("lookup_polynomial_codegen.zig");
const Program = component.OwnedFrameworkPolynomialProgramV1;
const lowering = @import("stwo_prover_engine").air.framework_polynomial_emitter_v1;

pub const codegen_version: u16 = 3;
pub const identity_domain = "stwo/metal/framework-polynomial-codegen/v3\x00";
// Codegen v3 retains the v1 buffer ABI; layout selects the claim payload. Exact emitter/helper bytes additionally
// invalidate cached kernels when a source change accidentally omits a bump.
const emitter_source = @embedFile("framework_polynomial_codegen.zig");

pub const Entry = struct {
    program: *const Program,
    tree_column_counts: []const usize,
};

/// Cold admission checks actual tree geometry and the immutable program seal.
/// Invocation offsets still must be checked against actual resident buffers.
pub fn validate(entry: Entry) !void {
    try entry.program.validate(entry.tree_column_counts);
    for (entry.program.inputs) |input| switch (input) {
        .trace_column => |column| if (column.tree_index > 2) return error.UnsupportedFrameworkPolynomialTree,
        .profile_parameter => {},
    };
    for (entry.program.interaction_columns) |column|
        if (column.tree_index > 2) return error.UnsupportedFrameworkPolynomialTree;
}

/// Kernel identity binds executable equations, not their physical placement.
/// emitKernel still validates the complete placement-bound program before
/// producing the canonical body. The original program seal remains unchanged
/// and must be retained separately by runtime job admission.
pub fn codegenIdentity(allocator: std.mem.Allocator, entry: Entry) ![32]u8 {
    var canonical = std.ArrayList(u8).empty;
    defer canonical.deinit(allocator);
    try emitKernel(allocator, canonical.writer(allocator), "stwo_framework_canonical", entry);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    hash.update(&lowering.fingerprint());
    var version: [2]u8 = undefined;
    std.mem.writeInt(u16, &version, codegen_version, .little);
    hash.update(&version);
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(emitter_source, &source_digest, .{});
    hash.update(&source_digest);
    std.crypto.hash.sha2.Sha256.hash(field_codegen.preamble, &source_digest, .{});
    hash.update(&source_digest);
    std.crypto.hash.sha2.Sha256.hash(canonical.items, &source_digest, .{});
    hash.update(&source_digest);
    return hash.finalResult();
}

pub fn kernelName(allocator: std.mem.Allocator, entry: Entry) ![]u8 {
    return nameForIdentity(allocator, try codegenIdentity(allocator, entry));
}

fn nameForIdentity(allocator: std.mem.Allocator, identity: [32]u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "stwo_zig_framework_poly_v1_{s}", .{
        std.fmt.bytesToHex(identity, .lower),
    });
}

pub fn generateLibrary(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    if (entries.len == 0) return error.InvalidFrameworkPolynomialProgram;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    var emitted = std.AutoHashMap([32]u8, void).init(allocator);
    defer emitted.deinit();
    const writer = source.writer(allocator);
    try writer.writeAll(field_codegen.preamble);
    for (entries) |entry| {
        // Admission precedes deduplication: an invalid relocated entry cannot
        // borrow admission from another job with the same executable body.
        const identity = try codegenIdentity(allocator, entry);
        const slot = try emitted.getOrPut(identity);
        if (slot.found_existing) continue;
        const name = try nameForIdentity(allocator, identity);
        defer allocator.free(name);
        try emitKernel(allocator, writer, name, entry);
    }
    return source.toOwnedSlice(allocator);
}

/// Resident ABI, all offsets measured in M31 words:
/// 0..2: already expanded PCS tree arenas; 3: u64 column offsets in program
/// input order followed by interaction-column order (parameter slots unused);
/// 4: profile M31 parameters; 5: relation QM31 words, followed by the derived
/// claimedSumShift() for same-row-prefix or per-batch claims for independent
/// prefixes; 6: QM31 coefficient powers for this whole component;
/// 7: additive secure output; 8..10: evaluation rows and vanishing inverses.
///
/// Runtime must bind parameters.trace_log_size to admitted geometry, derive the
/// shift, validate every offset/extent and supply the correctly shifted global
/// coefficient window. Values and parameters never enter kernel identity.
pub fn emitKernel(allocator: std.mem.Allocator, writer: anytype, name: []const u8, entry: Entry) !void {
    try validate(entry);
    const program = entry.program;
    try writer.print(
        \\kernel void {s}(
        \\    device const uint *tree0 [[buffer(0)]],
        \\    device const uint *tree1 [[buffer(1)]],
        \\    device const uint *tree2 [[buffer(2)]],
        \\    device const ulong *column_offsets [[buffer(3)]],
        \\    device const uint *profile_parameters [[buffer(4)]],
        \\    device const uint *relation_parameters [[buffer(5)]],
        \\    device const uint *powers [[buffer(6)]],
        \\    device uint *output [[buffer(7)]],
        \\    constant uint &row_count [[buffer(8)]],
        \\    constant uint *denominator_inverses [[buffer(9)]],
        \\    constant uint &denominator_count [[buffer(10)]],
        \\    uint row [[thread_position_in_grid]]) {{
        \\    if (row >= row_count) return;
        \\    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
        \\    RiscvQm31 folded = {{ 0u, 0u, 0u, 0u }};
        \\
    , .{name});
    try lowering.emitBody(allocator, writer, program);
}

pub const emitLookupTerms = lowering.emitLookupTerms;
pub const emitWideFraction = lowering.emitWideFraction;
