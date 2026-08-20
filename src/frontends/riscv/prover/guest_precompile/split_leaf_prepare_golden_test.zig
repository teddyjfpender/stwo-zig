//! Parallel ownership, manifest-barrier, and failure evidence for R-008.
//! Core split-leaf preparation and barrier tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const opcode_trace = @import("../opcode_trace.zig");
const aggregation_fixture = @import("../../aggregation/test_fixture.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const split_leaf_statement = @import("split_leaf_statement.zig");
const subject = @import("split_leaf_prepare.zig");

const Authorities = struct {
    accepted: aggregation_types.AcceptedProtocolV1,
    caller: subject.CallerPrepareAuthorityV1,
    provider: subject.ProviderPrepareAuthorityV1,
};

fn authorities(
    call_count: u32,
    job_marker: u8,
    protocol_marker: u8,
) !Authorities {
    const accepted = aggregation_types.AcceptedProtocolV1{
        .proof_protocol_digest = aggregation_fixture.digest(protocol_marker),
        .relation_registry_digest = aggregation_fixture.digest(
            protocol_marker +% 1,
        ),
    };
    return .{
        .accepted = accepted,
        .caller = try subject.CallerPrepareAuthorityV1.canonical(
            accepted,
            aggregation_fixture.digest(job_marker),
            aggregation_fixture.digest(0xc1),
            call_count,
        ),
        .provider = try subject.ProviderPrepareAuthorityV1.canonical(
            accepted,
            aggregation_fixture.digest(job_marker),
            aggregation_fixture.digest(0xc2),
            call_count,
        ),
    };
}

fn callerIdentities(
    prepared: *const subject.PreparedCallerLeafV1,
) !split_leaf_statement.VerifierOwnedLeafIdentitiesV1 {
    return .{
        .protocol = try split_leaf_statement.VerifierOwnedProtocolIdentityV1.canonical(
            prepared.authority.accepted_protocol,
        ),
        .artifact = .{
            .role = .core_request,
            .air_artifact_digest = prepared.authority.air_artifact_digest,
            .preprocessed_root = prepared.descriptor.preprocessed_root,
            .component = prepared.authority.component,
        },
    };
}

fn providerIdentities(
    prepared: *const subject.PreparedProviderLeafV1,
) !split_leaf_statement.VerifierOwnedLeafIdentitiesV1 {
    return .{
        .protocol = try split_leaf_statement.VerifierOwnedProtocolIdentityV1.canonical(
            prepared.authority.accepted_protocol,
        ),
        .artifact = .{
            .role = .poseidon2_provider,
            .air_artifact_digest = prepared.authority.air_artifact_digest,
            .preprocessed_root = prepared.descriptor.preprocessed_root,
            .component = prepared.authority.component,
        },
    };
}

const CallerRunner = struct {
    allocator: std.mem.Allocator,
    authority: subject.CallerPrepareAuthorityV1,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    logs: *const support.OwnedLogs,
    result: ?subject.PreparedCallerLeafV1 = null,
    failure: ?anyerror = null,

    fn run(self: *CallerRunner) void {
        self.result = subject.prepareCaller(
            self.allocator,
            self.authority,
            self.core,
            self.extension,
            &self.logs.calls,
            &self.logs.rows,
        ) catch |err| {
            self.failure = err;
            return;
        };
    }
};

const ProviderRunner = struct {
    allocator: std.mem.Allocator,
    authority: subject.ProviderPrepareAuthorityV1,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    logs: *const support.OwnedLogs,
    result: ?subject.PreparedProviderLeafV1 = null,
    failure: ?anyerror = null,

    fn run(self: *ProviderRunner) void {
        self.result = subject.prepareProvider(
            self.allocator,
            self.authority,
            self.core,
            self.extension,
            &self.logs.calls,
            &self.logs.rows,
        ) catch |err| {
            self.failure = err;
            return;
        };
    }
};

fn expectGolden(label: []const u8, expected: Digest, actual: Digest) !void {
    if (!aggregation_hash.eql(expected, actual)) {
        const hex = std.fmt.bytesToHex(actual, .lower);
        std.debug.print("{s}={s}\n", .{ label, &hex });
    }
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

const Digest = aggregation_hash.Digest;
fn goldenDigest(comptime hex: []const u8) Digest {
    var result: Digest = undefined;
    _ = std.fmt.hexToBytes(&result, hex) catch
        @compileError("invalid R-008 golden digest");
    return result;
}

fn independentHashInt(
    hasher: *aggregation_hash.Blake2s256,
    comptime Int: type,
    value: Int,
) void {
    var bytes: [@sizeOf(Int)]u8 = undefined;
    std.mem.writeInt(Int, &bytes, value, .little);
    hasher.update(&bytes);
}

fn independentOrderedCallCommitment(
    records: []const call_buffer.Record,
) Digest {
    if (records.len == 0) return aggregation_hash.emptyCallCommitment();
    var hasher = aggregation_hash.Blake2s256.init(.{});
    hasher.update(subject.ordered_call_domain);
    independentHashInt(&hasher, u32, subject.format_version);
    independentHashInt(&hasher, u32, @intCast(call_buffer.lane_count));
    independentHashInt(&hasher, u64, @intCast(records.len));
    for (records, 0..) |record, index| {
        independentHashInt(&hasher, u64, @intCast(index));
        for (record.input) |word| independentHashInt(&hasher, u32, word);
        for (record.output) |word| independentHashInt(&hasher, u32, word);
    }
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

fn independentColumnSeal(
    domain: []const u8,
    log_size: u32,
    n_rows: u32,
    first: []const M31,
    active: []const M31,
) Digest {
    std.debug.assert(first.len == active.len);
    var hasher = aggregation_hash.Blake2s256.init(.{});
    hasher.update(domain);
    hasher.update(subject.shadow_commitment_profile);
    independentHashInt(&hasher, u32, subject.format_version);
    independentHashInt(&hasher, u32, log_size);
    independentHashInt(&hasher, u32, n_rows);
    independentHashInt(&hasher, u32, @intCast(subject.selector_column_count));
    independentHashInt(&hasher, u64, @intCast(first.len));
    for (first) |value| hasher.update(&value.toBytesLe());
    for (active) |value| hasher.update(&value.toBytesLe());
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

fn independentDeclaration(
    role: aggregation_types.LeafRole,
    descriptor: aggregation_types.LeafDescriptorV1,
    component: component_registry.Descriptor,
) Digest {
    var hasher = aggregation_hash.Blake2s256.init(.{});
    hasher.update(switch (role) {
        .core_request => subject.caller_declaration_domain,
        .poseidon2_provider => subject.provider_declaration_domain,
    });
    hasher.update(subject.shadow_commitment_profile);
    independentHashInt(&hasher, u32, subject.format_version);
    independentHashInt(&hasher, u32, descriptor.leaf_index);
    independentHashInt(&hasher, u32, descriptor.pair_index);
    hasher.update(&.{@intFromEnum(descriptor.role)});
    hasher.update(&.{descriptor.flags});
    independentHashInt(&hasher, u16, descriptor.reserved);
    hasher.update(&descriptor.job_digest);
    // The field being defined is intentionally absent from this independent
    // preimage as well.
    hasher.update(&descriptor.leaf_air_artifact_digest);
    hasher.update(&descriptor.preprocessed_root);
    hasher.update(&descriptor.main_root);
    hasher.update(&descriptor.guest_call_commitment);
    independentHashInt(&hasher, u64, descriptor.guest_call_count);
    hasher.update(&descriptor.proof_protocol_digest);
    independentHashInt(&hasher, u16, descriptor.execution_profile_id);
    independentHashInt(&hasher, u16, descriptor.relation_schema_version);
    hasher.update(&descriptor.execution_semantic_digest);
    hasher.update(&descriptor.relation_registry_digest);
    independentHashInt(&hasher, u32, descriptor.relation_schema_id);
    independentHashInt(&hasher, u16, descriptor.relation_arity);
    independentHashInt(&hasher, u16, descriptor.reserved_tail);
    independentHashInt(&hasher, u32, @intFromEnum(component.slot));
    independentHashInt(&hasher, u32, @intFromEnum(component.kind));
    independentHashInt(&hasher, u16, component.version);
    independentHashInt(&hasher, u32, component.n_rows);
    independentHashInt(&hasher, u32, component.log_size);
    independentHashInt(&hasher, u16, component.preprocessed_columns);
    independentHashInt(&hasher, u16, component.main_columns);
    independentHashInt(&hasher, u16, component.interaction_columns);
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

const ordered_call_17 = goldenDigest(
    "c887aa5cf1d7ab32070e4fa0df7e29a217b5ea698ccf2ebd9ff89d5c24f6b6b9",
);
const caller_selectors_17 = goldenDigest(
    "789b53a754ba7b33210e6395a2f67ae0249a1ba0e3476086b717599ef8b5684a",
);
const provider_selectors_17 = goldenDigest(
    "ba131f33fc38dde9f600cbe2c8dfe77eccfd84e4f84fecbccc0bbf686ef6efe2",
);
const caller_main_17 = goldenDigest(
    "93a6cb829e1fcaf026e83e92630e551edcd2f0f30296a61435f6108820cec7ae",
);
const provider_main_17 = goldenDigest(
    "62291f5181b0bbd9bb8d496bf3081b6b78b3d69de1f75d6f619a001930f6577b",
);
const caller_declaration_17 = goldenDigest(
    "b0eaced8eb351a4755dcf88c2f3efb905b05881a8ddf32fe792e5f3a9e501059",
);
const provider_declaration_17 = goldenDigest(
    "8b3850b8161af4138493e4345503a60bfdcc20256d95b42a623fb4f513427f0d",
);
const session_17 = goldenDigest(
    "89f3151bc56adf87e2b6d49230087a83b4daf67225a8439460855d8abc972e7f",
);

test "pre-session role commitments declarations and barrier are golden" {
    var core = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    const authority = try authorities(17, 0x18, 0xa1);
    var caller = try subject.prepareCaller(
        std.testing.allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer caller.deinit();
    var provider = try subject.prepareProvider(
        std.testing.allocator,
        authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer provider.deinit();
    const barrier = try subject.ManifestBarrierV1.create(
        std.testing.allocator,
        authority.accepted,
        &caller,
        &provider,
    );
    defer barrier.deinit();

    const first = try opcode_trace.generateIsFirst(
        std.testing.allocator,
        caller.authority.component.log_size,
    );
    defer std.testing.allocator.free(first);
    const active = try opcode_trace.generateIsActive(
        std.testing.allocator,
        caller.authority.component.log_size,
        caller.authority.component.n_rows,
    );
    defer std.testing.allocator.free(active);
    try std.testing.expectEqualSlices(M31, first, caller.selectors.column(0));
    try std.testing.expectEqualSlices(M31, active, caller.selectors.column(1));
    try std.testing.expectEqualSlices(M31, first, provider.selectors.column(0));
    try std.testing.expectEqualSlices(M31, active, provider.selectors.column(1));
    try std.testing.expectEqualSlices(
        u8,
        &caller.guest_call_commitment,
        &independentOrderedCallCommitment(logs.calls.records()),
    );
    try std.testing.expectEqualSlices(
        u8,
        &caller.descriptor.preprocessed_root,
        &independentColumnSeal(
            subject.caller_selector_domain,
            caller.selectors.log_size,
            caller.selectors.n_rows,
            first,
            active,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &provider.descriptor.preprocessed_root,
        &independentColumnSeal(
            subject.provider_selector_domain,
            provider.selectors.log_size,
            provider.selectors.n_rows,
            first,
            active,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &caller.descriptor.leaf_statement_digest,
        &independentDeclaration(
            .core_request,
            caller.descriptor,
            caller.authority.component,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &provider.descriptor.leaf_statement_digest,
        &independentDeclaration(
            .poseidon2_provider,
            provider.descriptor,
            provider.authority.component,
        ),
    );

    try expectGolden("ordered call", ordered_call_17, caller.guest_call_commitment);
    try expectGolden("caller selectors", caller_selectors_17, caller.descriptor.preprocessed_root);
    try expectGolden("provider selectors", provider_selectors_17, provider.descriptor.preprocessed_root);
    try expectGolden("caller main", caller_main_17, caller.descriptor.main_root);
    try expectGolden("provider main", provider_main_17, provider.descriptor.main_root);
    try expectGolden("caller declaration", caller_declaration_17, caller.descriptor.leaf_statement_digest);
    try expectGolden("provider declaration", provider_declaration_17, provider.descriptor.leaf_statement_digest);
    try expectGolden("session", session_17, barrier.session.session_digest);
}

comptime {
    if (component_registry.preprocessed_columns != subject.selector_column_count)
        @compileError("R-008 prepare test selector geometry drifted");
}
