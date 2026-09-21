//! Path-free description of one immutable campaign Stage-102 inventory.
//!
//! The input Session has already cold-opened and authenticated every role-0
//! wrapper.  This module revalidates that live Session and emits only its
//! durable controller projection: exact nodes, Zig keys, CAS references, and
//! campaign/execution identities.  Admission pointers, proof captures, live
//! lease selectors, and verifier capabilities never enter the document.

const std = @import("std");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

pub const FORMAT =
    "stwo.recursive-pipeline.campaign-stage102-immutable-inventory.v4";
pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SERIALIZABLE_LIVE_LEASE_SELECTOR = false;
pub const EXACT_ORDERED_SESSION_PROJECTION = true;

pub const Error = error{
    CampaignStage102InventoryDescriptionMismatchV4,
};

/// `Session` is the immutable value returned by
/// `recursive_pipeline_worker_campaign_stage102_inventory_v4.SessionFor`.
/// The generic boundary avoids importing a concrete role-0 backend while
/// still requiring the Session's full live validation before any bytes exist.
pub fn DescriptionFor(comptime Session: type) type {
    assertSession(Session);
    return struct {
        pub fn encodeCanonicalJsonAlloc(
            allocator: std.mem.Allocator,
            session: *const Session,
        ) ![]u8 {
            try session.validate(allocator);
            const final_remint = session.authority.final_remint;
            const shape = final_remint.shape;
            const registry = try final_remint.registryAuthority();
            const expected_count = std.math.cast(
                usize,
                shape.real_leaf_count,
            ) orelse return error.CampaignStage102InventoryDescriptionMismatchV4;
            if (session.entries.len != expected_count)
                return error.CampaignStage102InventoryDescriptionMismatchV4;

            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const temporary = arena.allocator();
            var root = protocol.jsonObject(temporary);
            try protocol.put(&root, "format", protocol.string(FORMAT));
            try protocol.put(
                &root,
                "format_version",
                protocol.integer(FORMAT_VERSION),
            );
            try protocol.put(
                &root,
                "schema_version",
                protocol.integer(SCHEMA_VERSION),
            );
            try protocol.put(&root, "production", .{ .bool = false });
            try protocol.putDigest(
                temporary,
                &root,
                "campaign_namespace_sha256",
                shape.campaign_namespace_sha256,
            );
            try protocol.putDigest(
                temporary,
                &root,
                "campaign_inventory_identity_sha256",
                shape.inventory_identity_sha256,
            );
            try protocol.putDigest(
                temporary,
                &root,
                "campaign_shape_identity_sha256",
                shape.identity_sha256,
            );
            try protocol.putDigest(
                temporary,
                &root,
                "final_remint_binding_identity_sha256",
                final_remint.binding_identity_sha256,
            );
            try protocol.putDigest(
                temporary,
                &root,
                "registry_identity_sha256",
                registry.identity_sha256,
            );
            try protocol.putDigest(
                temporary,
                &root,
                "host_execution_identity_sha256",
                session.policy.host.identity_sha256,
            );
            try protocol.putDigest(
                temporary,
                &root,
                "worker_policy_identity_sha256",
                session.policy.worker_policy_identity,
            );
            try protocol.putDigest(
                temporary,
                &root,
                "memory_policy_identity_sha256",
                session.policy.memory_policy_identity,
            );
            try putShapeAndPolicy(temporary, &root, session);

            var rows = protocol.array(temporary);
            for (session.entries, 0..) |*entry, index| {
                const retained = try session.stage102AdmissionForOutput(
                    shape.campaign_namespace_sha256,
                    entry.output_ref,
                );
                if (retained != &entry.admission)
                    return error.CampaignStage102InventoryDescriptionMismatchV4;
                const expected_index = std.math.cast(
                    u32,
                    index,
                ) orelse return error.CampaignStage102InventoryDescriptionMismatchV4;

                var row = protocol.jsonObject(temporary);
                var coordinate = protocol.jsonObject(temporary);
                // Session.validate cold-opens every entry and proves that
                // slot i is exactly the height-zero campaign coordinate i.
                try protocol.put(
                    &coordinate,
                    "height",
                    protocol.integer(0),
                );
                try protocol.put(
                    &coordinate,
                    "index",
                    protocol.integer(expected_index),
                );
                try protocol.put(&row, "coordinate", coordinate);
                try protocol.put(
                    &row,
                    "node",
                    try protocol.nodeValue(temporary, retained.node.*),
                );
                try protocol.put(
                    &row,
                    "semantic_key",
                    try protocol.semanticProjection(
                        temporary,
                        retained.semantic.*,
                    ),
                );
                try protocol.put(
                    &row,
                    "execution_key",
                    try protocol.executionProjection(
                        temporary,
                        retained.execution.*,
                    ),
                );
                try protocol.put(
                    &row,
                    "ordered_inputs",
                    try protocol.inputRefsValue(
                        temporary,
                        retained.ordered_inputs[0..],
                    ),
                );
                try protocol.put(
                    &row,
                    "output_ref",
                    try protocol.blobRefValue(temporary, entry.output_ref),
                );
                try protocol.put(
                    &row,
                    "stage_manifest_ref",
                    try protocol.blobRefValue(
                        temporary,
                        retained.stage_manifest_ref,
                    ),
                );
                var dependency_manifests = protocol.array(temporary);
                try protocol.append(
                    &dependency_manifests,
                    try protocol.blobRefValue(
                        temporary,
                        retained.dependency_stage_manifest_ref,
                    ),
                );
                try protocol.put(
                    &row,
                    "dependency_stage_manifest_refs",
                    dependency_manifests,
                );
                try protocol.append(&rows, row);
            }
            try protocol.put(&root, "rows", rows);

            // This digest is an identity for the complete validated Session
            // projection, not a replacement for any role-specific authority.
            const authority_identity = try protocol.canonicalDigest(
                temporary,
                root,
            );
            try protocol.putDigest(
                temporary,
                &root,
                "authority_identity_sha256",
                authority_identity,
            );
            try protocol.sealObject(temporary, &root);
            return protocol.canonicalAlloc(allocator, root, false);
        }
    };
}

fn putShapeAndPolicy(
    allocator: std.mem.Allocator,
    root: *protocol.Json,
    session: anytype,
) !void {
    const shape = session.authority.final_remint.shape;
    const policy = session.policy;
    inline for (.{
        .{ "real_leaf_count", shape.real_leaf_count },
        .{ "padded_leaf_count", shape.padded_leaf_count },
        .{ "empty_leaf_count", shape.empty_leaf_count },
        .{ "fold_count", shape.fold_count },
        .{ "root_height", shape.root_height },
        .{ "total_cpu_tokens", policy.total_cpu_tokens },
        .{ "cpu_tokens_per_node", policy.cpu_tokens_per_node },
        .{ "proof_worker_count", policy.proof_worker_count },
        .{ "maximum_parallel_nodes", policy.maximum_parallel_nodes },
    }) |field| try protocol.put(
        root,
        field[0],
        protocol.integer(field[1]),
    );
    try protocol.put(
        root,
        "total_rss_bytes",
        try protocol.integerU64(allocator, policy.total_rss_bytes),
    );
    try protocol.put(
        root,
        "rss_bytes_per_node",
        try protocol.integerU64(allocator, policy.rss_bytes_per_node),
    );
}

fn assertSession(comptime Session: type) void {
    inline for (.{
        "validate",
        "stage102AdmissionForOutput",
    }) |name| if (!@hasDecl(Session, name))
        @compileError("Stage102 inventory description Session missing " ++ name);
    inline for (.{ "store", "authority", "entries", "policy" }) |name|
        if (!@hasField(Session, name))
            @compileError("Stage102 inventory description Session field missing " ++ name);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        SERIALIZABLE_LIVE_LEASE_SELECTOR or
        !EXACT_ORDERED_SESSION_PROJECTION)
    {
        @compileError("Stage102 immutable inventory description drifted");
    }
}
