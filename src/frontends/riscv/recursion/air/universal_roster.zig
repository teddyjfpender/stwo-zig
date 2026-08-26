//! Pinned 36-entry universal-recursion protocol roster.
//!
//! Order is commitment, claimed-sum, and composition order at Stark-V commit
//! `59172a201bd01f2f4b699bc2f7d4442d8ee81597`. Status is deliberately split:
//! typed logical admission does not imply concrete adapter or real proof gates.

const std = @import("std");

pub const COMPONENT_COUNT: usize = 36;

pub const Component = enum(u8) {
    control = 0,
    transcript_air = 1,
    transcript_binding = 2,
    transcript_state = 3,
    transcript_word = 4,
    transcript_payload = 5,
    pow_check = 6,
    pow_frame = 7,
    relation_challenge = 8,
    verifier_randomness = 9,
    statement_input = 10,
    statement_semantics_input = 11,
    vm_public_claim_input = 12,
    vm_public_claim_hash = 13,
    vm_public_io_hash = 14,
    vm_public_claim_semantics_input = 15,
    vm_public_logup_input = 16,
    vm_public_logup_control = 17,
    vm_air_composition_input = 18,
    vm_air_composition_control = 19,
    query_bits = 20,
    query_mapping = 21,
    merkle_root = 22,
    trace_merkle = 23,
    pcs_deep_input = 24,
    fri_merkle_leaf = 25,
    fri_merkle_node = 26,
    fri_merkle_anchor = 27,
    fri_verifier_control = 28,
    fri_verifier_input = 29,
    qm31_mul = 30,
    qm31_inv = 31,
    linear_ops = 32,
    merkle_path = 33,
    poseidon2 = 34,
    range_check_8_8 = 35,
};

pub const Status = enum(u8) {
    open = 0,
    shared_primitive_only = 1,
    typed_logical = 2,
    /// The roster row is closed by a separately owned, authenticated native
    /// provider.  It participates in the universal manifest and proof gate,
    /// but deliberately has no second recursion-local equation owner.
    authenticated_shared_provider = 3,
};

pub const Descriptor = struct {
    component: Component,
    name: []const u8,
    reference_owner: []const u8,
    status: Status,
    concrete_adapter: bool,
    real_proof_gate: bool,
};

pub const DESCRIPTORS = [COMPONENT_COUNT]Descriptor{
    admittedDescriptor(.control, "control", "control_air.rs", .typed_logical),
    adapterDescriptor(.transcript_air, "transcript_air", "transcript_air.rs"),
    adapterDescriptor(.transcript_binding, "transcript_binding", "transcript_binding_air.rs"),
    adapterDescriptor(.transcript_state, "transcript_state", "transcript_state_air.rs"),
    adapterDescriptor(.transcript_word, "transcript_word", "transcript_word_air.rs"),
    adapterDescriptor(.transcript_payload, "transcript_payload", "transcript_payload_air.rs"),
    adapterDescriptor(.pow_check, "pow_check", "pow.rs"),
    adapterDescriptor(.pow_frame, "pow_frame", "pow.rs"),
    adapterDescriptor(.relation_challenge, "relation_challenge", "relation_challenge_air.rs"),
    adapterDescriptor(.verifier_randomness, "verifier_randomness", "verifier_randomness_air.rs"),
    adapterDescriptor(.statement_input, "statement_input", "statement_input_air.rs"),
    adapterDescriptor(.statement_semantics_input, "statement_semantics_input", "statement_semantics_input_air.rs"),
    adapterDescriptor(.vm_public_claim_input, "vm_public_claim_input", "vm_public_claim_input_air.rs"),
    adapterDescriptor(.vm_public_claim_hash, "vm_public_claim_hash", "vm_public_claim_hash_air.rs"),
    adapterDescriptor(.vm_public_io_hash, "vm_public_io_hash", "vm_public_io_hash_air.rs"),
    adapterDescriptor(.vm_public_claim_semantics_input, "vm_public_claim_semantics_input", "vm_public_claim_semantics_input_air.rs"),
    adapterDescriptor(.vm_public_logup_input, "vm_public_logup_input", "vm_public_logup_input_air.rs"),
    adapterDescriptor(.vm_public_logup_control, "vm_public_logup_control", "vm_public_logup_control_air.rs"),
    provenDescriptor(.vm_air_composition_input, "vm_air_composition_input", "vm_air_composition_input_air.rs"),
    provenDescriptor(.vm_air_composition_control, "vm_air_composition_control", "vm_air_composition_control_air.rs"),
    adapterDescriptor(.query_bits, "query_bits", "query_position_air.rs"),
    adapterDescriptor(.query_mapping, "query_mapping", "query_position_air.rs"),
    adapterDescriptor(.merkle_root, "merkle_root", "merkle_root_air.rs"),
    adapterDescriptor(.trace_merkle, "trace_merkle", "trace_merkle_air.rs"),
    provenDescriptor(.pcs_deep_input, "pcs_deep_input", "pcs_deep_input_air.rs"),
    adapterDescriptor(.fri_merkle_leaf, "fri_merkle_leaf", "fri_merkle_air.rs"),
    adapterDescriptor(.fri_merkle_node, "fri_merkle_node", "fri_merkle_air.rs"),
    adapterDescriptor(.fri_merkle_anchor, "fri_merkle_anchor", "fri_merkle_air.rs"),
    adapterDescriptor(.fri_verifier_control, "fri_verifier_control", "fri_verifier_control_air.rs"),
    provenDescriptor(.fri_verifier_input, "fri_verifier_input", "fri_verifier_input_air.rs"),
    adapterDescriptor(.qm31_mul, "qm31_mul", "qm31_mul.rs"),
    adapterDescriptor(.qm31_inv, "qm31_inv", "qm31_inv.rs"),
    adapterDescriptor(.linear_ops, "linear_ops", "linear_ops.rs"),
    provenDescriptor(.merkle_path, "merkle_path", "merkle_path.rs"),
    providerDescriptor(.poseidon2, "poseidon2", "crates/air/src/poseidon2.rs"),
    providerDescriptor(.range_check_8_8, "range_check_8_8", "crates/air/src/schema.rs"),
};

pub fn typedLogicalCount() usize {
    var count: usize = 0;
    for (DESCRIPTORS) |item| count += @intFromBool(item.status == .typed_logical);
    return count;
}

pub fn concreteAdapterCount() usize {
    var count: usize = 0;
    for (DESCRIPTORS) |item| count += @intFromBool(item.concrete_adapter);
    return count;
}

pub fn authenticatedSharedProviderCount() usize {
    var count: usize = 0;
    for (DESCRIPTORS) |item| count += @intFromBool(
        item.status == .authenticated_shared_provider,
    );
    return count;
}

/// Protocol-row closure counts both recursion-local typed equations and an
/// authenticated delegation to an existing concrete provider.  Keeping this
/// separate from `typedLogicalCount` prevents provider reuse from being
/// reported as duplicate AIR authorship.
pub fn universalClosureCount() usize {
    return typedLogicalCount() + authenticatedSharedProviderCount();
}

pub fn realProofGateCount() usize {
    var count: usize = 0;
    for (DESCRIPTORS) |item| count += @intFromBool(item.real_proof_gate);
    return count;
}

comptime {
    if (@typeInfo(Component).@"enum".fields.len != COMPONENT_COUNT)
        @compileError("universal recursion roster count drifted");
    for (DESCRIPTORS, 0..) |item, index| {
        if (@intFromEnum(item.component) != index)
            @compileError("universal recursion roster order drifted");
    }
}

fn descriptor(
    component: Component,
    name: []const u8,
    reference_owner: []const u8,
    status: Status,
) Descriptor {
    return .{
        .component = component,
        .name = name,
        .reference_owner = reference_owner,
        .status = status,
        .concrete_adapter = false,
        .real_proof_gate = false,
    };
}

/// A row earns these gates only after its authenticated typed programs drive a
/// concrete native component through real PCS/FRI prove and independent
/// verification. This does not imply universal relation closure.
fn admittedDescriptor(
    component: Component,
    name: []const u8,
    reference_owner: []const u8,
    status: Status,
) Descriptor {
    var result = descriptor(component, name, reference_owner, status);
    result.concrete_adapter = true;
    result.real_proof_gate = true;
    return result;
}

fn adapterDescriptor(
    component: Component,
    name: []const u8,
    reference_owner: []const u8,
) Descriptor {
    var result = descriptor(component, name, reference_owner, .typed_logical);
    result.concrete_adapter = true;
    return result;
}

fn provenDescriptor(
    component: Component,
    name: []const u8,
    reference_owner: []const u8,
) Descriptor {
    var result = adapterDescriptor(component, name, reference_owner);
    result.real_proof_gate = true;
    return result;
}

fn providerDescriptor(
    component: Component,
    name: []const u8,
    reference_owner: []const u8,
) Descriptor {
    var result = descriptor(
        component,
        name,
        reference_owner,
        .authenticated_shared_provider,
    );
    result.concrete_adapter = true;
    return result;
}

test "R-012 universal roster pins exact order and honest completion layers" {
    try std.testing.expectEqual(@as(usize, 36), DESCRIPTORS.len);
    try std.testing.expectEqual(@as(usize, 34), typedLogicalCount());
    try std.testing.expectEqual(@as(usize, 2), authenticatedSharedProviderCount());
    try std.testing.expectEqual(@as(usize, 36), universalClosureCount());
    try std.testing.expectEqual(@as(usize, 36), concreteAdapterCount());
    try std.testing.expectEqual(@as(usize, 6), realProofGateCount());
    try std.testing.expectEqualStrings("control", DESCRIPTORS[0].name);
    try std.testing.expect(DESCRIPTORS[0].concrete_adapter);
    try std.testing.expect(DESCRIPTORS[0].real_proof_gate);
    try std.testing.expectEqualStrings("vm_air_composition_input", DESCRIPTORS[18].name);
    try std.testing.expectEqualStrings("range_check_8_8", DESCRIPTORS[35].name);
}

test "R-012 no universal row remains unresolved" {
    for (DESCRIPTORS) |item|
        try std.testing.expect(item.status != .shared_primitive_only);
}

test "R-012 authenticated providers close rows without duplicate typed ownership" {
    for ([_]Component{ .poseidon2, .range_check_8_8 }) |component| {
        const item = DESCRIPTORS[@intFromEnum(component)];
        try std.testing.expectEqual(
            Status.authenticated_shared_provider,
            item.status,
        );
        try std.testing.expect(item.concrete_adapter);
        try std.testing.expect(!item.real_proof_gate);
    }
}
