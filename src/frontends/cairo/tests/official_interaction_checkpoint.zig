//! Official Stwo-Cairo interaction-trace differential checks.

const std = @import("std");
const cairo = @import("cairo_frontend");

const Fixture = struct {
    input_path: []const u8,
    base_path: []const u8,
    interaction_path: []const u8,
    producer_count: usize,
    fixed_count: usize,
    include_pedersen: bool,
};

const all_opcodes = Fixture{
    .input_path = "vectors/cairo/official/all_opcodes.prover_input.json",
    .base_path = "vectors/cairo/official/all_opcodes.base_trace_checkpoint.json",
    .interaction_path = "vectors/cairo/official/all_opcodes.interaction_trace_checkpoint.json",
    .producer_count = 24,
    .fixed_count = 18,
    .include_pedersen = false,
};

const all_builtins = Fixture{
    .input_path = "vectors/cairo/official/all_builtins.prover_input.json",
    .base_path = "vectors/cairo/official/all_builtins.base_trace_checkpoint.json",
    .interaction_path = "vectors/cairo/official/all_builtins.interaction_trace_checkpoint.json",
    .producer_count = 26,
    .fixed_count = 19,
    .include_pedersen = true,
};

test "official Cairo all-opcodes interactions match Rust" {
    try runFixture(all_opcodes);
}

test "official Cairo all-builtins interactions match Rust" {
    try runFixture(all_builtins);
}

fn runFixture(fixture: Fixture) !void {
    const digest = try inputDigest(std.testing.allocator, fixture.input_path);
    var input = try cairo.adapter.official_input.readFile(
        std.testing.allocator,
        fixture.input_path,
    );
    defer input.deinit(std.testing.allocator);
    var bundle = try cairo.witness.bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/official/witness_programs_v1.bin",
    );
    defer bundle.deinit();
    var topology = try cairo.witness.feed_topology.readOfficial(
        std.testing.allocator,
        "vectors/cairo/official/witness_feed_topology_v1.json",
    );
    defer topology.deinit();
    var base = try cairo.conformance.receipt.readFile(
        std.testing.allocator,
        fixture.base_path,
        .{
            .input_sha256 = digest,
            .authority = .{
                .stwo_cairo_revision = cairo.claim_registry.source_revision.stwo_cairo,
                .stwo_revision = cairo.claim_registry.source_revision.stwo,
            },
        },
    );
    defer base.deinit();
    var interaction = try cairo.conformance.interaction_receipt.readFile(
        std.testing.allocator,
        fixture.interaction_path,
        .{
            .input_sha256 = digest,
            .authority = cairo.conformance.interaction_receipt.official_authority,
            .challenge_derivation = cairo.conformance.interaction_receipt.official_challenge_derivation,
        },
    );
    defer interaction.deinit();

    var execution = try cairo.conformance.recorded_trace.execute(
        std.testing.allocator,
        &input,
        &bundle,
        base.components,
    );
    defer execution.deinit();
    try std.testing.expect(execution.mismatch == null);
    try std.testing.expectEqual(fixture.producer_count, execution.producers.len);

    for (execution.producers) |producer| {
        const expected = findComponent(interaction.components, producer.label) orelse
            return error.MissingInteractionReceipt;
        const component = topology.find(expected.label) orelse
            return error.MissingInteractionTopology;
        const mismatch = try cairo.conformance.recorded_interaction.compareComponent(
            std.testing.allocator,
            component,
            producer,
            expected,
            interaction.challenge.z_m31,
            interaction.challenge.alpha_powers_m31,
        );
        if (mismatch) |failure| printMismatch(failure);
        try std.testing.expect(mismatch == null);
    }

    var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();
    var relations = try cairo.witness.relation_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();
    var multiplicities = try cairo.conformance.fixed_trace.populateTopology(
        std.testing.allocator,
        &input,
        topology,
        execution.producers,
        &fixed,
        base.components,
    );
    defer multiplicities.deinit();
    var pedersen: cairo.preprocessed.pedersen_table.Table = undefined;
    var pedersen_initialized = false;
    defer if (pedersen_initialized) pedersen.deinit();
    if (fixture.include_pedersen) {
        pedersen = try cairo.preprocessed.pedersen_table.Table.init(
            std.testing.allocator,
            .standard,
        );
        pedersen_initialized = true;
    }
    var fixed_matches: usize = 0;
    for (fixed.entries) |entry| {
        if (std.mem.eql(u8, entry.component, "verify_bitwise_xor_12")) continue;
        if (!fixture.include_pedersen and
            std.mem.startsWith(u8, entry.component, "pedersen_points_table_"))
            continue;
        const expected = findComponent(interaction.components, entry.component) orelse continue;
        const trace = (relations.find(entry.component) orelse
            return error.MissingRelationTemplate).traces[0];
        var source = cairo.witness.fixed_lookup_words.Source{
            .entry = entry,
            .tables = &multiplicities,
            .pedersen = if (pedersen_initialized) &pedersen else null,
        };
        const view = try cairo.witness.interaction_trace.SourceView.lookupWords(
            try source.lookupColumns(),
            entry.row_count,
        );
        try view.validateDeclaration(trace.layout, trace.layout_arg);
        const mismatch = try cairo.conformance.recorded_interaction.compareTrace(
            std.testing.allocator,
            trace.descriptors,
            view,
            expected,
            interaction.challenge.z_m31,
            interaction.challenge.alpha_powers_m31,
        );
        if (mismatch) |failure| printMismatch(failure);
        try std.testing.expect(mismatch == null);
        fixed_matches += 1;
    }
    try std.testing.expectEqual(fixture.fixed_count, fixed_matches);

    if (findComponent(interaction.components, "verify_bitwise_xor_12")) |xor_expected| {
        const xor_entry = fixed.find("verify_bitwise_xor_12") orelse
            return error.MissingFixedTable;
        var xor_columns = try cairo.witness.implicit_interaction_sources.fixedMultiplicities(
            std.testing.allocator,
            xor_entry,
            &multiplicities,
        );
        defer xor_columns.deinit();
        const xor_template = relations.find("verify_bitwise_xor_12") orelse
            return error.MissingRelationTemplate;
        const xor_trace = xor_template.traces[0];
        const xor_view = try xor_columns.xor12View();
        try xor_view.validateDeclaration(xor_trace.layout, xor_trace.layout_arg);
        try expectTraceMatches(
            xor_trace.descriptors,
            xor_view,
            xor_expected,
            interaction,
        );
    }

    var memory_counts = try cairo.witness.cpu_memory_multiplicity.collectTopology(
        std.testing.allocator,
        &input,
        topology,
        execution.producers,
    );
    defer memory_counts.deinit();
    var address = try cairo.witness.implicit_interaction_sources.memoryAddress(
        std.testing.allocator,
        &input,
        &memory_counts,
    );
    defer address.deinit();
    const address_trace = (relations.find("memory_address_to_id") orelse
        return error.MissingRelationTemplate).traces[0];
    const address_view = try address.addressView();
    try address_view.validateDeclaration(address_trace.layout, address_trace.layout_arg);
    try expectTraceMatches(
        address_trace.descriptors,
        address_view,
        findComponent(interaction.components, "memory_address_to_id") orelse
            return error.MissingInteractionReceipt,
        interaction,
    );

    const memory_template = relations.find("memory_id_to_big") orelse
        return error.MissingRelationTemplate;
    var big = try cairo.witness.implicit_interaction_sources.memoryBig(
        std.testing.allocator,
        &input,
        &memory_counts,
        0,
    );
    defer big.deinit();
    const big_trace = findTrace(memory_template.traces, .each_memory_big) orelse
        return error.MissingRelationTrace;
    const big_view = try big.bigView(0);
    try big_view.validateDeclaration(big_trace.layout, big_trace.layout_arg);
    try expectTraceMatches(
        big_trace.descriptors,
        big_view,
        findComponent(interaction.components, "memory_id_to_big[0]") orelse
            return error.MissingInteractionReceipt,
        interaction,
    );

    var small = try cairo.witness.implicit_interaction_sources.memorySmall(
        std.testing.allocator,
        &input,
        &memory_counts,
    );
    defer small.deinit();
    const small_trace = findTrace(memory_template.traces, .memory_small) orelse
        return error.MissingRelationTrace;
    const small_view = try small.smallView();
    try small_view.validateDeclaration(small_trace.layout, small_trace.layout_arg);
    try expectTraceMatches(
        small_trace.descriptors,
        small_view,
        findComponent(interaction.components, "memory_id_to_small") orelse
            return error.MissingInteractionReceipt,
        interaction,
    );
}

fn inputDigest(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const encoded = try std.fs.cwd().readFileAlloc(allocator, path, 2 * 1024 * 1024);
    defer allocator.free(encoded);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    return digest;
}

fn findComponent(
    components: []const cairo.conformance.interaction_checkpoint.Component,
    label: []const u8,
) ?cairo.conformance.interaction_checkpoint.Component {
    for (components) |component| {
        if (std.mem.eql(u8, component.label, label)) return component;
    }
    return null;
}

fn printMismatch(failure: cairo.conformance.recorded_interaction.Mismatch) void {
    std.debug.print(
        "interaction mismatch kind={s} component={s} column={?}\n",
        .{ @tagName(failure.kind), failure.component_label, failure.column_ordinal },
    );
    if (failure.expected_digest) |digest| {
        const expected_hex = std.fmt.bytesToHex(digest, .lower);
        std.debug.print("  expected={s}\n", .{&expected_hex});
    }
    if (failure.actual_digest) |digest| {
        const actual_hex = std.fmt.bytesToHex(digest, .lower);
        std.debug.print("  actual={s}\n", .{&actual_hex});
    }
}

fn findTrace(
    traces: []const cairo.witness.relation_bundle.Trace,
    part: cairo.witness.relation_bundle.TracePart,
) ?cairo.witness.relation_bundle.Trace {
    for (traces) |trace| if (trace.part == part) return trace;
    return null;
}

fn expectTraceMatches(
    descriptors: []const u32,
    source: cairo.witness.interaction_trace.SourceView,
    expected: cairo.conformance.interaction_checkpoint.Component,
    interaction: cairo.conformance.interaction_receipt.Loaded,
) !void {
    const mismatch = try cairo.conformance.recorded_interaction.compareTrace(
        std.testing.allocator,
        descriptors,
        source,
        expected,
        interaction.challenge.z_m31,
        interaction.challenge.alpha_powers_m31,
    );
    if (mismatch) |failure| printMismatch(failure);
    try std.testing.expect(mismatch == null);
}
