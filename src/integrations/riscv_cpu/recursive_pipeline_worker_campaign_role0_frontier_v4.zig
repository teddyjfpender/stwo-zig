//! Canonically ordered role-0 frontier for the final campaign driver.
//!
//! Expected output/StageManifest refs are custody inputs, not proof authority.
//! Every row is reopened through the sealed-session bridge and therefore owns
//! a verifier-minted role-0 lease before it enters this ordered view.  The
//! exact immutable-session policy pointer and both ExecutionKey policy
//! identities are rechecked for every runtime campaign coordinate.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const RUNTIME_COUNT_ORDERED = true;
pub const EXACT_POLICY_POINTER_REQUIRED = true;
pub const COLD_ROLE0_LEASE_REQUIRED = true;

pub const Error = error{
    CampaignRole0FrontierMismatchV4,
};

pub const ExpectedPublicationV4 = struct {
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,

    pub fn validate(self: ExpectedPublicationV4) !void {
        try campaign_cas.validate(self.output_ref, .recursion_node);
        try campaign_cas.validate(self.stage_manifest_ref, .stage_manifest);
    }
};

pub fn FrontierFor(comptime Bridge: type) type {
    assertBridge(Bridge);
    const Policy = Bridge.PolicyV2;
    const Role0Final = Bridge.Role0FinalV4;

    return struct {
        pub const BridgeV4 = Bridge;
        pub const PolicyV2 = Policy;

        pub const RowV4 = struct {
            coordinate: u32,
            publication: ExpectedPublicationV4,
            role0: Role0Final,
        };

        pub const OwnedFrontierV4 = struct {
            allocator: std.mem.Allocator,
            bridge: Bridge,
            policy: *const Policy,
            rows: []RowV4,

            pub fn init(
                allocator: std.mem.Allocator,
                scratch_allocator: std.mem.Allocator,
                bridge: Bridge,
                policy: *const Policy,
                expected: []const ExpectedPublicationV4,
            ) !OwnedFrontierV4 {
                try bridge.validate(scratch_allocator);
                const session = try bridge.lifecycle.immutableSession();
                if (session.policy != policy or
                    expected.len != session.entries.len or
                    expected.len != @as(
                        usize,
                        @intCast(
                            bridge.assembly.finalRemint().shape.real_leaf_count,
                        ),
                    ))
                {
                    return error.CampaignRole0FrontierMismatchV4;
                }
                try policy.validate();
                const rows = try allocator.alloc(RowV4, expected.len);
                errdefer allocator.free(rows);
                for (expected, session.entries, 0..) |
                    publication,
                    entry,
                    index,
                | {
                    try publication.validate();
                    if (!artifact_store.BlobRefV1.eql(
                        publication.output_ref,
                        entry.output_ref,
                    ) or !artifact_store.BlobRefV1.eql(
                        publication.stage_manifest_ref,
                        entry.admission.stage_manifest_ref,
                    )) return error.CampaignRole0FrontierMismatchV4;
                    for (expected[0..index]) |earlier| {
                        if (artifact_store.BlobRefV1.eql(
                            earlier.output_ref,
                            publication.output_ref,
                        ) or artifact_store.BlobRefV1.eql(
                            earlier.stage_manifest_ref,
                            publication.stage_manifest_ref,
                        )) return error.CampaignRole0FrontierMismatchV4;
                    }
                    const role0 = try bridge.role0ForOutput(
                        scratch_allocator,
                        publication.output_ref,
                    );
                    const artifact = role0.lease.nodeArtifact();
                    try policy.validateAgainstExecution(
                        role0.admission.execution.*,
                    );
                    if (artifact.coordinate.height != 0 or
                        artifact.coordinate.index !=
                            @as(u32, @intCast(index)) or
                        role0.admission.node.cpu_tokens !=
                            @as(u64, policy.cpu_tokens_per_node) or
                        role0.admission.node.rss_tokens !=
                            policy.rss_bytes_per_node)
                    {
                        return error.CampaignRole0FrontierMismatchV4;
                    }
                    rows[index] = .{
                        .coordinate = @intCast(index),
                        .publication = publication,
                        .role0 = role0,
                    };
                }
                const result = OwnedFrontierV4{
                    .allocator = allocator,
                    .bridge = bridge,
                    .policy = policy,
                    .rows = rows,
                };
                try result.validate(scratch_allocator);
                return result;
            }

            pub fn validate(
                self: *const OwnedFrontierV4,
                scratch_allocator: std.mem.Allocator,
            ) !void {
                try self.bridge.validate(scratch_allocator);
                try self.policy.validate();
                const session = try self.bridge.lifecycle.immutableSession();
                if (session.policy != self.policy or
                    self.rows.len != session.entries.len)
                {
                    return error.CampaignRole0FrontierMismatchV4;
                }
                for (self.rows, 0..) |row, index| {
                    const entry = &session.entries[index];
                    try row.publication.validate();
                    try row.role0.validate();
                    try self.policy.validateAgainstExecution(
                        row.role0.admission.execution.*,
                    );
                    const artifact = row.role0.lease.nodeArtifact();
                    if (row.coordinate != @as(u32, @intCast(index)) or
                        artifact.coordinate.height != 0 or
                        artifact.coordinate.index != row.coordinate or
                        row.role0.session != session or
                        row.role0.admission != &entry.admission or
                        !artifact_store.BlobRefV1.eql(
                            row.publication.output_ref,
                            entry.output_ref,
                        ) or !artifact_store.BlobRefV1.eql(
                        row.publication.stage_manifest_ref,
                        entry.admission.stage_manifest_ref,
                    )) {
                        return error.CampaignRole0FrontierMismatchV4;
                    }
                }
            }

            pub fn orderedRows(
                self: *const OwnedFrontierV4,
            ) []const RowV4 {
                return self.rows;
            }

            pub fn deinit(self: *OwnedFrontierV4) void {
                self.allocator.free(self.rows);
                self.* = undefined;
            }
        };

        comptime {
            rejectCodec(RowV4);
            rejectCodec(OwnedFrontierV4);
        }
    };
}

fn assertBridge(comptime Bridge: type) void {
    inline for (.{
        "LifecycleV4",
        "PolicyV2",
        "Role0FinalV4",
        "validate",
        "role0ForOutput",
    }) |name| if (!@hasDecl(Bridge, name))
        @compileError("campaign role0 frontier bridge missing " ++ name);
    const Lifecycle = Bridge.LifecycleV4;
    if (!@hasDecl(Lifecycle, "OwnedFinalSessionV4"))
        @compileError("campaign role0 frontier lifecycle missing final session");
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign role0 frontier gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !RUNTIME_COUNT_ORDERED or
        !EXACT_POLICY_POINTER_REQUIRED or !COLD_ROLE0_LEASE_REQUIRED)
    {
        @compileError("campaign role0 frontier contract drifted");
    }
}
