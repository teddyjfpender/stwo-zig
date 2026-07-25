const std = @import("std");
const compact = @import("../../frontends/cairo/compact_verifier_interchange.zig");
const compact_geometry = @import("../../frontends/cairo/compact_protocol_geometry.zig");
const proof_plan = @import("../../frontends/cairo/proof_plan.zig");
const staged = @import("../../frontends/cairo/staged_arena_planner.zig");
const statement = @import("../../frontends/cairo/statement_bootstrap.zig");
const composition = @import("../../frontends/cairo/witness/composition_bundle.zig");
const source_semantic_pack = @import("../../frontends/cairo/witness/source_semantic_pack.zig");
const subject = @import("program.zig");
const identities = @import("identity.zig");

test {
    std.testing.refAllDecls(source_semantic_pack);
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    proof: proof_plan.CairoProofPlan,
    statement_bytes: []u8,
    preprocessed_logs: []u32,
    protocol: compact.CompactProtocolV1,
    pack: identities.PackIdentity,
    buffers: [4]subject.BufferDescription,

    fn init(allocator: std.mem.Allocator, bundle: *const composition.Bundle) !Fixture {
        const parts = try allocator.alloc(proof_plan.TracePart, bundle.components.len);
        defer allocator.free(parts);
        const components = try allocator.alloc(proof_plan.Component, bundle.components.len);
        defer allocator.free(components);
        var dependency: [1]proof_plan.ProducerEdge = undefined;
        if (bundle.components.len > 1) dependency[0] = .{
            .producer = bundle.components[0].label,
            .word_base = 0,
            .words_per_instance = 1,
            .instances = 1,
        };
        for (bundle.components, parts, components, 0..) |component, *part, *planned, index| {
            const rows = @as(u32, 1) << @intCast(component.trace_log_size);
            part.* = .{ .id = .main, .rows = .{ .real_rows = rows, .padded_rows = rows } };
            planned.* = .{
                .name = component.label,
                .canonical_ordinal = @intCast(index),
                .writer = .recorded_aot,
                .trace_parts = parts[index .. index + 1],
                .producer_edges = if (index == 1) &dependency else &.{},
                .capacity_feeds = &.{},
            };
        }
        var proof = try proof_plan.CairoProofPlan.init(allocator, components);
        errdefer proof.deinit();
        const statement_bytes = try testStatement(allocator, bundle);
        errdefer allocator.free(statement_bytes);

        const verifier_log = try bundle.verifierMaxLogDegreeBound();
        var protocol_geometry = compact.RuntimeProtocolGeometryV1.sn2();
        protocol_geometry.max_log_degree_bound = verifier_log;
        protocol_geometry.fri_tree_count =
            1 + (verifier_log - 1) / protocol_geometry.fri_fold_step;
        protocol_geometry.decommitment_record_count =
            protocol_geometry.commitment_count + protocol_geometry.fri_tree_count;
        const widths = [4]u32{
            161,
            finalSpanEnd(bundle, 1),
            finalSpanEnd(bundle, 2),
            8,
        };
        const capacity = try compact_geometry.minimumDecommitmentWords(
            protocol_geometry.decommitment_record_count,
            protocol_geometry.query_count,
        );
        const protocol = try (compact.CompactProofLayoutV1{
            .interaction_claim_words = @intCast(bundle.components.len * 4),
            .sampled_value_words = 4,
            .decommitment_capacity_words = capacity,
        }).protocolRuntime(7, protocol_geometry, widths);
        const preprocessed_logs = try allocator.alloc(u32, widths[0]);
        errdefer allocator.free(preprocessed_logs);
        for (preprocessed_logs, 0..) |*log_rows, index|
            log_rows.* = 4 + @as(u32, @intCast(index % 3));

        return .{
            .allocator = allocator,
            .proof = proof,
            .statement_bytes = statement_bytes,
            .preprocessed_logs = preprocessed_logs,
            .protocol = protocol,
            .pack = testPack(bundle, verifier_log),
            .buffers = .{
                .{
                    .staged = .{
                        .logical_id = 10,
                        .component_index = 0,
                        .role = .producer_slab,
                        .size_bytes = 256,
                        .alignment = 64,
                    },
                },
                .{
                    .staged = .{
                        .logical_id = 11,
                        .component_index = 1,
                        .role = .base_coefficients,
                        .size_bytes = 512,
                        .alignment = 64,
                    },
                },
                .{
                    .staged = .{
                        .logical_id = 12,
                        .component_index = 0,
                        .role = .interaction_coefficients,
                        .size_bytes = 1024,
                        .alignment = 64,
                    },
                },
                .{
                    .staged = .{
                        .logical_id = 13,
                        .component_index = null,
                        .role = .protocol_persistent,
                        .size_bytes = 128,
                        .alignment = 32,
                    },
                },
            },
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.free(self.preprocessed_logs);
        self.allocator.free(self.statement_bytes);
        self.proof.deinit();
        self.* = undefined;
    }

    fn authority(
        self: *Fixture,
        bundle: *const composition.Bundle,
    ) subject.testing.TestAuthority {
        return .{
            .proof = &self.proof,
            .pack = self.pack,
            .composition = bundle,
            .preprocessed_logs = self.preprocessed_logs,
            .compact_statement = self.statement_bytes,
            .protocol = self.protocol,
            .buffers = &self.buffers,
        };
    }
};

test "Cairo development emitter describes the complete heterogeneous proof program deterministically" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(allocator, "vectors/cairo/sn_pie_2_composition.bin");
    defer bundle.deinit();
    var fixture = try Fixture.init(allocator, &bundle);
    defer fixture.deinit();

    var first = try subject.testing.emit(allocator, fixture.authority(&bundle));
    defer first.deinit(allocator);
    var second = try subject.testing.emit(allocator, fixture.authority(&bundle));
    defer second.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &first.program_digest, &second.program_digest);
    try std.testing.expectEqualSlices(u8, &first.semantic_digest, &second.semantic_digest);
    try std.testing.expectEqual(@as(usize, 4), first.commitments.len);
    try std.testing.expectEqual(bundle.components.len, first.constraints.len);
    for (bundle.components, first.constraints) |component, constraint| {
        try std.testing.expectEqual(component.n_constraints, constraint.constraint_count);
        try std.testing.expectEqual(
            component.evaluation_log_size - component.trace_log_size,
            constraint.max_degree_log,
        );
    }
    inline for ([_]@import("stwo_backend_contracts").proof_program.CommitmentRole{
        .preprocessed,
        .main,
        .interaction,
        .composition,
    }, 0..) |role, index| try std.testing.expectEqual(role, first.commitments[index].role);
    try std.testing.expectEqual(fixture.protocol.fri_tree_count, first.fri_layers.len);
    try std.testing.expectEqual(@as(usize, 4), first.buffers.len);
    try std.testing.expectEqual(.trace_commit, first.buffers[2].live_from);
    try std.testing.expectEqual(.decommit, first.buffers[2].live_through);
    try std.testing.expectEqual(.ingress, first.buffers[3].live_from);
    try std.testing.expectEqual(.proof_assembly, first.buffers[3].live_through);
    try std.testing.expect(first.trace_columns[0].log_rows != first.trace_columns[1].log_rows);
    var dependent_trace_nodes: usize = 0;
    for (first.nodes[0..bundle.components.len]) |node| {
        if (node.dependencies.count == 0) continue;
        dependent_trace_nodes += 1;
        try std.testing.expectEqual(@as(u32, 1), node.dependencies.count);
        try std.testing.expectEqual(@as(u32, 0), first.dependency_ids[node.dependencies.first]);
    }
    try std.testing.expectEqual(@as(usize, 1), dependent_trace_nodes);
    for (first.nodes) |node| try std.testing.expect(!node.graph_candidate);
    var pow_barriers: usize = 0;
    for (first.transcript) |barrier| if (barrier.kind == .pow) {
        pow_barriers += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), pow_barriers);
    try std.testing.expectEqual(.queries, first.transcript[first.transcript.len - 1].kind);
}

test "Cairo identities and complete program digest reject semantic mutations" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(allocator, "vectors/cairo/sn_pie_2_composition.bin");
    defer bundle.deinit();
    var fixture = try Fixture.init(allocator, &bundle);
    defer fixture.deinit();
    var baseline = try subject.testing.emit(allocator, fixture.authority(&bundle));
    defer baseline.deinit(allocator);

    fixture.statement_bytes[16] ^= 1;
    var statement_mutation = try subject.testing.emit(allocator, fixture.authority(&bundle));
    defer statement_mutation.deinit(allocator);
    try expectDifferent(baseline.program_digest, statement_mutation.program_digest);
    fixture.statement_bytes[16] ^= 1;

    fixture.protocol.channel_salt += 1;
    var protocol_mutation = try subject.testing.emit(allocator, fixture.authority(&bundle));
    defer protocol_mutation.deinit(allocator);
    try expectDifferent(baseline.program_digest, protocol_mutation.program_digest);
    fixture.protocol.channel_salt -= 1;

    fixture.pack.manifest[0] ^= 1;
    var pack_mutation = try subject.testing.emit(allocator, fixture.authority(&bundle));
    defer pack_mutation.deinit(allocator);
    try expectDifferent(baseline.program_digest, pack_mutation.program_digest);
    fixture.pack.manifest[0] ^= 1;

    const original_hash = bundle.components[0].parts[0].semantic_hash;
    bundle.components[0].parts[0].semantic_hash ^= 1;
    bundle.components[0].parts[0].program.header.semantic_hash ^= 1;
    var component_mutation = try subject.testing.emit(allocator, fixture.authority(&bundle));
    defer component_mutation.deinit(allocator);
    try expectDifferent(
        baseline.constraints[0].expression,
        component_mutation.constraints[0].expression,
    );
    bundle.components[0].parts[0].semantic_hash = original_hash;
    bundle.components[0].parts[0].program.header.semantic_hash = original_hash;
}

test "Cairo emitter fails closed on geometry drift and remains development only" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(allocator, "vectors/cairo/sn_pie_2_composition.bin");
    defer bundle.deinit();
    var fixture = try Fixture.init(allocator, &bundle);
    defer fixture.deinit();

    var authority = fixture.authority(&bundle);
    authority.pack.provenance = .source_derived;
    try std.testing.expectError(
        subject.Error.DevelopmentSemanticsRequired,
        subject.testing.emit(allocator, authority),
    );

    authority = fixture.authority(&bundle);
    authority.protocol.trace_columns[1] += 1;
    try std.testing.expectError(
        subject.Error.InvalidCompositionGeometry,
        subject.testing.emit(allocator, authority),
    );

    const last = fixture.statement_bytes.len - 4;
    fixture.statement_bytes[last] ^= 1;
    try std.testing.expectError(
        subject.Error.InvalidStatementEncoding,
        subject.testing.emit(allocator, fixture.authority(&bundle)),
    );
    fixture.statement_bytes[last] ^= 1;

    try std.testing.expect(!subject.production_ready);
}

test "Cairo production admission uses configured source authority and exact proof plan" {
    const allocator = std.testing.allocator;
    const directory = try std.fs.cwd().realpathAlloc(
        allocator,
        "vectors/cairo/source_semantics/v3",
    );
    defer allocator.free(directory);
    const manifest_path = try std.fs.cwd().realpathAlloc(
        allocator,
        "vectors/cairo/source_semantics/v3/manifest.json",
    );
    defer allocator.free(manifest_path);
    var source_pack = try source_semantic_pack.loadDirectory(
        allocator,
        .{
            .path = manifest_path,
            .sha256 = decodeDigest("cfbeff3da13461d0d9cf2df2a215d951df713698db18036f4882ddf1f857bd3a"),
        },
        directory,
    );
    defer source_pack.deinit();

    const parts = [_]proof_plan.TracePart{.{
        .id = .main,
        .rows = .{ .real_rows = 16, .padded_rows = 16 },
    }};
    const components = [_]proof_plan.Component{.{
        .name = "add_opcode_small",
        .canonical_ordinal = 0,
        .writer = .recorded_aot,
        .trace_parts = &parts,
        .producer_edges = &.{},
        .capacity_feeds = &.{},
    }};
    var plan = try proof_plan.CairoProofPlan.init(allocator, &components);
    defer plan.deinit();
    try subject.authenticateSourceComponentPlan(&source_pack, &plan);
}

fn decodeDigest(value: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, value) catch unreachable;
    return digest;
}

fn testStatement(
    allocator: std.mem.Allocator,
    bundle: *const composition.Bundle,
) ![]u8 {
    var flat = try statement.deriveFlatClaimGeometry(allocator, bundle);
    defer flat.deinit();
    const total = statement.compact_statement_header_bytes +
        @as(usize, 20) * @import("../../frontends/cairo/adapter/mod.zig").N_PUBLIC_SEGMENTS +
        4 * (flat.component_enable_bits.len + flat.component_log_sizes.len);
    const encoded = try allocator.alloc(u8, total);
    @memset(encoded, 0);
    @memcpy(encoded[0..8], &statement.compact_statement_magic);
    std.mem.writeInt(u16, encoded[8..10], statement.compact_statement_version, .little);
    std.mem.writeInt(u16, encoded[10..12], statement.compact_statement_header_bytes, .little);
    std.mem.writeInt(u32, encoded[56..60], @intCast(flat.component_enable_bits.len), .little);
    std.mem.writeInt(u32, encoded[60..64], @intCast(flat.component_log_sizes.len), .little);
    std.mem.writeInt(
        u32,
        encoded[64..68],
        @import("../../frontends/cairo/adapter/mod.zig").N_PUBLIC_SEGMENTS,
        .little,
    );
    std.mem.writeInt(
        u32,
        encoded[68..72],
        statement.compact_statement_memory_entry_words,
        .little,
    );
    var cursor = statement.compact_statement_header_bytes +
        @as(usize, 20) * @import("../../frontends/cairo/adapter/mod.zig").N_PUBLIC_SEGMENTS;
    for (flat.component_enable_bits) |enabled| {
        std.mem.writeInt(u32, encoded[cursor..][0..4], @intFromBool(enabled), .little);
        cursor += 4;
    }
    for (flat.component_log_sizes) |log_size| {
        std.mem.writeInt(u32, encoded[cursor..][0..4], log_size, .little);
        cursor += 4;
    }
    return encoded;
}

fn testPack(bundle: *const composition.Bundle, verifier_log: u32) identities.PackIdentity {
    return .{
        .provenance = .proof_derived,
        .manifest = repeatedDigest(1),
        .composition_projection = repeatedDigest(2),
        .composition = repeatedDigest(3),
        .witness_programs = repeatedDigest(4),
        .multiplicity_feeds = repeatedDigest(5),
        .relation_templates = repeatedDigest(6),
        .fixed_tables = repeatedDigest(7),
        .preprocessed_coefficients = repeatedDigest(8),
        .verifier_max_log_degree_bound = verifier_log,
        .composition_plan_hash = bundle.plan_hash,
    };
}

fn repeatedDigest(value: u8) [32]u8 {
    return [_]u8{value} ** 32;
}

fn finalSpanEnd(bundle: *const composition.Bundle, tree: u32) u32 {
    const component = bundle.components[bundle.components.len - 1];
    for (component.trace_spans) |span| if (span.tree == tree) return span.end;
    unreachable;
}

fn expectDifferent(left: [32]u8, right: [32]u8) !void {
    try std.testing.expect(!std.mem.eql(u8, &left, &right));
}
