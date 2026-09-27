//! End-to-end, hostile-mutation, OOM, and cost gates for segment row 35.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const public_data_mod = @import("../air/public_data.zig");
const lookup_counter = @import("../air/lookups/tables/counter.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const statement_air = @import("air/statement_semantics_input.zig");
const statement_relation = @import("air/statement_semantics_input_relation.zig");
const statement_witness = @import("air/statement_semantics_input_witness.zig");
const claim_air = @import("air/vm_public_claim_input.zig");
const claim_relation = @import("air/vm_public_claim_input_relation.zig");
const claim_witness = @import("air/vm_public_claim_input_witness.zig");
const leaf_owner = @import("segment_leaf_authority.zig");
const claim = @import("vm_public_claim.zig");
const owner = @import("segment_range_authority.zig");

const BINDING_COUNT: usize = 6;
const BINDINGS = [BINDING_COUNT]statement_witness.InputBinding{
    .{
        .node_id = 1,
        .use_count = 2,
        .source = .{ .statement = .{
            .scope = 0,
            .index = 20,
            .active_kinds = .SEGMENT,
        } },
    },
    .{
        .node_id = 2,
        .use_count = 1,
        .source = .{ .statement = .{
            .scope = 0,
            .index = 21,
            .active_kinds = .SEGMENT,
        } },
    },
    // Deliberate duplicate circuit input: relation multiplicity is per row,
    // not per distinct statement word or wire use count.
    .{
        .node_id = 3,
        .use_count = 4,
        .source = .{ .statement = .{
            .scope = 0,
            .index = 20,
            .active_kinds = .SEGMENT,
        } },
    },
    .{
        .node_id = 4,
        .use_count = 1,
        .source = .{ .statement = .{
            .scope = 0,
            .index = 0,
            .active_kinds = .SEGMENT,
        } },
    },
    .{
        .node_id = 5,
        .use_count = 1,
        .source = .{ .selector = .segment_leaf },
    },
    // This row belongs to the binary verifier and must contribute neither a
    // segment value nor a range request.
    .{
        .node_id = 6,
        .use_count = 1,
        .source = .{ .statement = .{
            .scope = 1,
            .index = 20,
            .active_kinds = .BINARY,
        } },
    },
};

test "R-012 segment range authority pins the complete two-source ledger" {
    const authority = owner.SourceAuthority.pinned();
    try authority.validate();
    try std.testing.expectEqual(@as(usize, 2), authority.sources.len);
    try std.testing.expectEqual(
        @import("air/universal_roster.zig").Component.statement_semantics_input,
        authority.sources[0].component,
    );
    try std.testing.expectEqual(@as(u8, 2), authority.sources[0].event_ordinal);
    try std.testing.expectEqual(
        @import("../air/lang/relation.zig").Role.request,
        authority.sources[0].role,
    );
    try std.testing.expectEqual(
        @import("air/universal_roster.zig").Component.vm_public_claim_input,
        authority.sources[1].component,
    );
    try std.testing.expectEqual(@as(u8, 5), authority.sources[1].event_ordinal);

    var statement_definition = try statement_air.build(std.testing.allocator);
    defer statement_definition.deinit();
    const statement_plan = try statement_relation.authenticate(&statement_definition);
    try std.testing.expectEqual(
        @import("../air/lang/relation.zig").Domain.range_check_8_8,
        statement_plan.events[authority.sources[0].event_ordinal].domain,
    );
    try std.testing.expectEqual(
        @import("../air/lang/relation.zig").Role.request,
        statement_plan.events[authority.sources[0].event_ordinal].role,
    );

    var claim_definition = try claim_air.build(std.testing.allocator);
    defer claim_definition.deinit();
    const claim_plan = try claim_relation.authenticate(&claim_definition);
    try std.testing.expectEqual(
        @import("../air/lang/relation.zig").Domain.range_check_8_8,
        claim_plan.events[authority.sources[1].event_ordinal].domain,
    );
    try std.testing.expectEqual(
        @import("../air/lang/relation.zig").Role.request,
        claim_plan.events[authority.sources[1].event_ordinal].role,
    );

    var mutated = authority;
    mutated.sources[1].event_ordinal = 4;
    try std.testing.expectError(error.InvalidSourceAuthority, mutated.validate());
}

test "R-012 segment range authority derives exact signed multiplicities" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var workspace = try owner.Workspace.init(std.testing.allocator);
    defer workspace.deinit(std.testing.allocator);

    const sources = fixture.sources();
    const counts = try workspace.derive(sources);
    try std.testing.expectEqual(@as(u64, 3), counts.statement);
    try std.testing.expectEqual(
        countClaimU16(&fixture.leaf_preprocessing.claim_input),
        counts.vm_claim,
    );

    var reference = try referenceCounter(std.testing.allocator, sources);
    defer reference.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        M31,
        reference.values,
        workspace.counter.values,
    );
    try std.testing.expect(
        workspace.counter.signedTotal().eql(
            M31.zero().sub(M31.fromU64(try counts.total())),
        ),
    );

    var prepared = try owner.Prepared.init(
        std.testing.allocator,
        &workspace,
        sources,
    );
    defer prepared.deinit();
    try prepared.validateAgainst(&workspace, sources);
    try prepared.provider().validateAgainstSource(&reference);
    try std.testing.expectEqualSlices(
        M31,
        reference.values,
        prepared.provider().counter.values,
    );
}

test "R-012 segment range authority rejects mutations before workspace stores" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var workspace = try owner.Workspace.init(std.testing.allocator);
    defer workspace.deinit(std.testing.allocator);
    _ = try workspace.derive(fixture.sources());

    const before = counterDigest(&workspace.counter);
    const saved_statement = fixture.statement_values[0];
    fixture.statement_values[0] = saved_statement.add(M31.one());
    try std.testing.expectError(
        error.StatementAuthorityMismatch,
        workspace.derive(fixture.sources()),
    );
    try std.testing.expectEqual(before, counterDigest(&workspace.counter));
    fixture.statement_values[0] = saved_statement;

    fixture.statement_preprocessing.rows[0].integer = false;
    try std.testing.expectError(
        error.AuthorityMismatch,
        workspace.derive(fixture.sources()),
    );
    try std.testing.expectEqual(before, counterDigest(&workspace.counter));
    fixture.statement_preprocessing.rows[0].integer = true;

    const claim_index = firstClaimU16(&fixture.leaf_preprocessing.claim_input);
    const saved_byte = fixture.leaf.claim_input.rows[claim_index].low_byte;
    fixture.leaf.claim_input.rows[claim_index].low_byte = saved_byte.add(M31.one());
    try std.testing.expectError(
        error.IntegerWordOutOfRange,
        workspace.derive(fixture.sources()),
    );
    try std.testing.expectEqual(before, counterDigest(&workspace.counter));
    fixture.leaf.claim_input.rows[claim_index].low_byte = saved_byte;

    // A valid row-11 value slice may still not borrow the destination table.
    @memcpy(workspace.counter.values[0..BINDING_COUNT], &fixture.statement_values);
    const aliased_before = counterDigest(&workspace.counter);
    var aliased = fixture.sources();
    aliased.statement.values = workspace.counter.values[0..BINDING_COUNT];
    try std.testing.expectError(error.AliasedWorkspace, workspace.derive(aliased));
    try std.testing.expectEqual(aliased_before, counterDigest(&workspace.counter));
}

test "R-012 segment range prepared snapshot rejects detached authority" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var workspace = try owner.Workspace.init(std.testing.allocator);
    defer workspace.deinit(std.testing.allocator);
    var prepared = try owner.Prepared.init(
        std.testing.allocator,
        &workspace,
        fixture.sources(),
    );
    defer prepared.deinit();

    prepared.request_counts.statement += 1;
    try std.testing.expectError(
        error.RequestCountMismatch,
        prepared.validateAgainst(&workspace, fixture.sources()),
    );
    prepared.request_counts.statement -= 1;

    prepared.source_authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        prepared.validateAgainst(&workspace, fixture.sources()),
    );
    prepared.source_authority_digest[0] ^= 1;

    const saved = prepared.range_check.counter.values[0];
    prepared.range_check.counter.values[0] = saved.sub(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        prepared.validateAgainst(&workspace, fixture.sources()),
    );
}

test "R-012 segment range workspace is allocation-free and snapshots once" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var workspace = try owner.Workspace.init(measured.allocator());
        defer workspace.deinit(measured.allocator());
        try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);

        const before_derive = measured.alloc_index;
        _ = try workspace.derive(fixture.sources());
        try std.testing.expectEqual(before_derive, measured.alloc_index);

        var prepared = try owner.Prepared.init(
            measured.allocator(),
            &workspace,
            fixture.sources(),
        );
        defer prepared.deinit();
        try std.testing.expectEqual(before_derive + 1, measured.alloc_index);

        const before_validate = measured.alloc_index;
        try prepared.validateAgainst(&workspace, fixture.sources());
        try std.testing.expectEqual(before_validate, measured.alloc_index);
        try std.testing.expectEqual(
            @as(usize, 1) << range_bridge.LOG_SIZE,
            prepared.provider().counter.values.len,
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
}

test "R-012 segment range construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        workspaceFailureCase,
        .{},
    );

    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var workspace = try owner.Workspace.init(std.testing.allocator);
    defer workspace.deinit(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preparedFailureCase,
        .{ &workspace, fixture.sources() },
    );
}

const Fixture = struct {
    data: public_data_mod.PublicData,
    leaf_preprocessing: leaf_owner.Preprocessing,
    leaf: leaf_owner.Prepared,
    statement_preprocessing: statement_witness.Preprocessed,
    statement_values: [BINDING_COUNT]M31,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const data = testPublicData();
        var leaf_preprocessing = try leaf_owner.Preprocessing.init(
            allocator,
            try claim.Shape.init(3, 3),
        );
        errdefer leaf_preprocessing.deinit();
        var leaf = try leaf_owner.Prepared.init(
            allocator,
            &leaf_preprocessing,
            &data,
        );
        errdefer leaf.deinit();
        var statement_preprocessing = try statement_witness.Preprocessed.init(
            allocator,
            0x51,
            &BINDINGS,
        );
        errdefer statement_preprocessing.deinit();
        var result = Fixture{
            .data = data,
            .leaf_preprocessing = leaf_preprocessing,
            .leaf = leaf,
            .statement_preprocessing = statement_preprocessing,
            .statement_values = undefined,
        };
        for (
            &result.statement_values,
            result.statement_preprocessing.rows,
        ) |*value, row| {
            const active = row.active_kinds.contains(.segment_leaf);
            value.* = switch (row.source) {
                .statement => if (active)
                    result.leaf.statement.words[row.word_index]
                else
                    M31.zero(),
                .selector => M31.fromU64(@intFromBool(active)),
                .private => M31.fromCanonical(17),
            };
        }
        _ = try result.sources().validate();
        return result;
    }

    fn deinit(self: *Fixture) void {
        self.statement_preprocessing.deinit();
        self.leaf.deinit();
        self.leaf_preprocessing.deinit();
        self.* = undefined;
    }

    fn sources(self: *Fixture) owner.Sources {
        return .{
            .data = &self.data,
            .leaf_preprocessing = &self.leaf_preprocessing,
            .leaf = &self.leaf,
            .statement = .{
                .preprocessing = &self.statement_preprocessing,
                .values = &self.statement_values,
            },
        };
    }
};

fn referenceCounter(
    allocator: std.mem.Allocator,
    sources: owner.Sources,
) !lookup_counter.Counter {
    _ = try sources.validate();
    var result = try lookup_counter.Counter.init(allocator, .range_check_8_8);
    errdefer result.deinit(allocator);
    for (
        sources.statement.preprocessing.rows,
        sources.statement.values,
    ) |row, value| {
        if (row.integer and row.active_kinds.contains(.segment_leaf)) {
            try result.registerRaw(QM31.one().neg(), &.{
                QM31.fromBase(M31.fromCanonical(value.toU32() & 0xff)),
                QM31.fromBase(M31.fromCanonical(value.toU32() >> 8)),
            });
        }
    }
    for (
        sources.leaf_preprocessing.claim_input.rows,
        sources.leaf.claim_input.rows,
    ) |metadata, row| {
        if (std.meta.activeTag(metadata.kind) == .u16) {
            try result.registerRaw(QM31.one().neg(), &.{
                QM31.fromBase(row.low_byte),
                QM31.fromBase(row.high_byte),
            });
        }
    }
    return result;
}

fn countClaimU16(preprocessing: *const claim_witness.Preprocessed) u64 {
    var count: u64 = 0;
    for (preprocessing.rows) |row|
        count += @intFromBool(std.meta.activeTag(row.kind) == .u16);
    return count;
}

fn firstClaimU16(preprocessing: *const claim_witness.Preprocessed) usize {
    for (preprocessing.rows, 0..) |row, index|
        if (std.meta.activeTag(row.kind) == .u16) return index;
    unreachable;
}

fn counterDigest(counter: *const lookup_counter.Counter) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (counter.values) |value| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value.v, .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}

fn workspaceFailureCase(allocator: std.mem.Allocator) !void {
    var workspace = try owner.Workspace.init(allocator);
    defer workspace.deinit(allocator);
}

fn preparedFailureCase(
    allocator: std.mem.Allocator,
    workspace: *owner.Workspace,
    sources: owner.Sources,
) !void {
    var prepared = try owner.Prepared.init(allocator, workspace, sources);
    defer prepared.deinit();
    try prepared.validateAgainst(workspace, sources);
}

const test_input_words = [_]u32{ 0x4433_2211, 0x55 };
const test_output_words = [_]public_data_mod.OutputWord{
    .{ .addr = 0x10_0004, .value = 4, .clock = 5 },
    .{ .addr = 0x10_0008, .value = 0x8877_6655, .clock = 6 },
};

fn testPublicData() public_data_mod.PublicData {
    var initial_regs = [_]u32{0} ** 32;
    initial_regs[1] = 0x8000_0001;
    var final_regs = initial_regs;
    final_regs[2] = 9;
    var reg_last_clock = [_]u32{0} ** 32;
    reg_last_clock[2] = 7;
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 8,
        .initial_regs = initial_regs,
        .final_regs = final_regs,
        .reg_last_clock = reg_last_clock,
        .program_root = 1,
        .initial_rw_root = 11,
        .final_rw_root = 21,
        .completion = public_data_mod.Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{
            .input_start = 0x20_0000,
            .input_len = 5,
            .input_words = &test_input_words,
            .output_len = 4,
            .output_len_addr = 0x10_0004,
            .output_data_addr = 0x10_0008,
            .output_words = &test_output_words,
        },
    };
}
