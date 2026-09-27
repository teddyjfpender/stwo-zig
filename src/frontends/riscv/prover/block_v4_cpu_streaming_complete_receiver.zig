//! Complete block-v4 receiver over staged CPU artifacts. Fresh core admission
//! happens inside this call, one execution proof at a time; only then may the
//! recursive leaf, dyadic forest, and exact outer root issue authority.
const std = @import("std");
const batch = @import("block_memory_batch_verify_v2.zig");
const pins_mod = @import("block_memory_complete_receiver_v3.zig");
const incremental = @import("block_v4_cpu_incremental_core_receiver.zig");
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");
const recursive = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");
const span = @import("../recursion/span_statement_blake3.zig");

pub const RecursionPins = pins_mod.RecursionPins;
pub const RecursionBytes = pins_mod.RecursionBytes;

/// Production authority requires q70/PoW26. Public policy must supply the
/// trusted job, native keys, outer key, forest digest and every parent pin
/// independently of the proof files before invoking this function.
pub fn verifyCanonical(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, recursion_pins: RecursionPins, recursion_bytes: RecursionBytes) !batch.CompleteBlock {
    try verifyProfile(a, product, trusted, recursion_pins, recursion_bytes, .csp_q70_pow26);
    return .complete_block_verified;
}

/// Test-only authority tier; never returns `CompleteBlock`.
pub fn verifyDiagnostic(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, recursion_pins: RecursionPins, recursion_bytes: RecursionBytes) !void {
    try verifyProfile(a, product, trusted, recursion_pins, recursion_bytes, .diagnostic_q8_pow0);
}

fn verifyProfile(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, recursion_pins: RecursionPins, recursion_bytes: RecursionBytes, profile: parent.Profile) !void {
    const config = profile.config();
    const complete = try preflight(product, trusted, recursion_pins, recursion_bytes, profile);
    var verified = try incremental.verify(a, product, trusted, config);
    defer verified.deinit(a);
    const count = trusted.native_key_ids.len;
    if (verified.leaves.len != count or verified.public_data.len != count or
        verified.core.executions.len != count or
        verified.core.summary.event_count != product.statement.expected_events)
        return error.IncompleteStreamingCoreReceipt;

    const descriptor_count = count + recursion_pins.dyadic.len;
    const descriptors = try a.alloc(recursive.Descriptor, descriptor_count);
    defer a.free(descriptors);
    for (recursion_pins.leaf, recursion_bytes.leaf, descriptors[0..count], 0..) |pin, bytes, *descriptor, index| {
        const receipt = &verified.core.executions[index];
        descriptor.* = try recursive.verifyLeafBytes(a, bytes, pin.admission, pin.expected_key_id, verified.leaves[index], &verified.public_data[index].data, config, product.statement.seal, trusted.native_key_ids[index], receipt.native_roots, receipt.witness_root, receipt);
    }
    for (recursion_pins.dyadic, recursion_bytes.dyadic, 0..) |pin, bytes, index| {
        descriptors[count + index] = try recursive.verifyDyadicBytes(a, bytes, pin.proof.admission, pin.proof.expected_key_id, descriptors[pin.left_index], descriptors[pin.right_index]);
    }
    const roots = try a.alloc(recursive.Descriptor, recursion_pins.root_indices.len);
    defer a.free(roots);
    for (recursion_pins.root_indices, roots) |index, *root| root.* = descriptors[index];
    const digest = try recursive.verifiedForestDigest(complete.expected_job, roots);
    if (!std.mem.eql(u8, &digest, &complete.forest_roster_digest))
        return error.UntrustedBlockForestRoster;
    var outer = if (profile == .diagnostic_q8_pow0)
        try recursive.verifyDiagnosticExactBytes(a, recursion_bytes.outer, recursion_pins.outer.admission, recursion_pins.outer.expected_key_id, complete.expected_job, roots)
    else
        try recursive.verifyExactBytes(a, recursion_bytes.outer, recursion_pins.outer.admission, recursion_pins.outer.expected_key_id, complete.expected_job, roots);
    defer outer.deinit();
    _ = try outer.root();
}

/// Run every key, count and tree-edge check before the receiver opens proof
/// bytes. The pins are caller policy, not declarations read from the bundle.
fn preflight(product: product_mod.Product, trusted: trusted_mod.Trusted, pins: RecursionPins, bytes: RecursionBytes, profile: parent.Profile) !batch.CompletePins {
    const count = trusted.native_key_ids.len;
    if (count == 0 or count != product.first.entries.len or
        pins.leaf.len != count or bytes.leaf.len != count or
        pins.dyadic.len != bytes.dyadic.len or
        pins.root_indices.len == 0 or pins.root_indices.len > span.MAX_SLOT_HEIGHT + 1)
        return error.InvalidBlockRecursiveProofCensus;
    const complete = try product.statement.requireCompletePins(product.public.pin.initial_rw_root.bytes);
    if (!std.meta.eql(complete.expected_job, trusted.job) or
        !std.meta.eql(complete.outer_recursive_key_id, trusted.outer_key_id) or
        !std.meta.eql(complete.forest_roster_digest, trusted.forest_roster_digest) or
        !std.meta.eql(complete.expected_job.complete.protocol_id, @import("../recursion/blake3_block_execution_span_v3.zig").protocolIdentity(profile.config())))
        return error.UntrustedStreamingCompletePins;
    const roots_expected: usize = @popCount(trusted.job.segment_count);
    if (pins.root_indices.len != roots_expected or
        pins.dyadic.len != count - roots_expected)
        return error.InvalidBlockRecursiveProofCensus;
    if (pins.outer.admission.key.profile != profile or
        !std.mem.eql(u8, &pins.outer.expected_key_id, &trusted.outer_key_id))
        return error.UntrustedBlockOuterKey;
    try pins.outer.admission.validate();
    if (!std.mem.eql(u8, &pins.outer.admission.expected_id, &pins.outer.expected_key_id))
        return error.UntrustedBlockOuterKey;
    for (pins.leaf) |pin| {
        if (pin.admission.key.profile != profile) return error.ExpectedBlockRecursiveSecurity;
        try pin.admission.validate();
        if (!std.mem.eql(u8, &pin.admission.expected_id, &pin.expected_key_id))
            return error.UntrustedBlockLeafKey;
    }
    for (pins.dyadic, 0..) |pin, i| {
        if (pin.proof.admission.key.profile != profile) return error.ExpectedBlockRecursiveSecurity;
        try pin.proof.admission.validate();
        if (!std.mem.eql(u8, &pin.proof.admission.expected_id, &pin.proof.expected_key_id))
            return error.UntrustedBlockDyadicKey;
        const current = count + i;
        if (pin.left_index >= current or pin.right_index >= current or pin.left_index == pin.right_index)
            return error.InvalidBlockRecursiveTreeEdge;
    }
    for (pins.root_indices) |index| if (index >= count + pins.dyadic.len)
        return error.InvalidBlockRecursiveRootIndex;
    return complete;
}
