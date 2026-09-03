//! Exact fourteen-component Ethereum AIR replay for ProgramV2.
//!
//! Component order, masks, and counts come from the cold geometry authority;
//! expressions are evaluated by the production generic evaluators over the
//! canonical recording scalar.

const logup = @import("../air/logup.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const keccak_direct = @import("../air/guest_precompile/keccakf_direct.zig");
const keccak_interaction =
    @import("../air/guest_precompile/keccakf_interaction_plan.zig");
const keccak_relations =
    @import("../air/guest_precompile/keccakf_relations.zig");
const keccak_table =
    @import("../air/guest_precompile/keccakf_table_component.zig");
const keccak_tables = @import("../air/guest_precompile/keccakf_tables.zig");
const keccak_trace = @import("../air/guest_precompile/keccakf_trace.zig");
const keccak_witness = @import("../air/guest_precompile/keccakf_witness.zig");
const secp_bundle =
    @import("../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_config =
    @import("../air/guest_precompile/secp256k1_component_config.zig");
const secp_trace =
    @import("../air/guest_precompile/secp256k1_component_trace.zig");

const geometry_mod =
    @import("ethereum_composition_extension_geometry_v2.zig");
const relations_mod = @import("ethereum_composition_relations_v2.zig");
const support = @import("ethereum_vm_composition_graph_support_v2.zig");

const Scalar = support.Scalar;
const SampleLayout = support.SampleLayoutV2;

pub const Result = struct {
    accumulation: Scalar,
    instruction_count: u32,
    claim_count: u32,
};

pub fn record(
    geometry: *const geometry_mod.GeometryV2,
    layout: *const SampleLayout,
    claims: []const Scalar,
    relations: *const relations_mod.RelationsV2,
    point: anytype,
    composition_randomness: Scalar,
    denominators: *[31]?Scalar,
    initial_accumulation: Scalar,
) !Result {
    try geometry.validate();
    if (claims.len != geometry.detailed_claim_count)
        return error.InvalidClaimCount;
    var result = Result{
        .accumulation = initial_accumulation,
        .instruction_count = 0,
        .claim_count = 0,
    };

    try recordKeccak(
        geometry.components[0],
        layout,
        claims,
        &relations.keccak,
        point,
        composition_randomness,
        denominators,
        &result,
    );
    try recordKeccakTable(
        .chi,
        geometry.components[1],
        layout,
        claims,
        &relations.keccak,
        point,
        composition_randomness,
        denominators,
        &result,
    );
    try recordKeccakTable(
        .xor5,
        geometry.components[2],
        layout,
        claims,
        &relations.keccak,
        point,
        composition_randomness,
        denominators,
        &result,
    );
    inline for (.{
        secp_bundle.ProductBase,
        secp_bundle.ProductScalar,
        secp_bundle.LinearBase,
        secp_bundle.LinearScalar,
        secp_config.Point,
        secp_config.Split,
        secp_config.ScalarProgram,
        secp_config.Table,
        secp_config.Recovery,
        secp_config.ByteTable,
        secp_config.RecoveryCaller,
    }, 3..) |Config, index| try recordSecp(
        Config,
        geometry.components[index],
        layout,
        claims,
        &relations.secp,
        point,
        composition_randomness,
        denominators,
        &result,
    );

    if (result.instruction_count != geometry.air_instruction_count) {
        return error.InvalidInstructionCount;
    }
    if (result.claim_count != geometry.detailed_claim_count)
        return error.InvalidClaimCount;
    return result;
}

fn recordKeccak(
    component: geometry_mod.ComponentV2,
    layout: *const SampleLayout,
    claims: []const Scalar,
    relations: anytype,
    point: anytype,
    randomness: Scalar,
    denominators: *[31]?Scalar,
    result: *Result,
) !void {
    const instruction_before = result.instruction_count;
    if (component.kind != .keccak_shard_v1 or
        component.direct_constraint_count != keccak_direct.constraint_count or
        component.interaction_batch_count != keccak_interaction.batch_count)
    {
        return error.InvalidComponentGeometry;
    }
    const denominator = support.quotientDenominator(
        component.log_size,
        layout.extension.max_log_degree_bound,
        point,
        denominators,
    );
    const pp = component.spans[0].offset;
    const main_offset = component.spans[1].offset;
    const interaction_offset = component.spans[2].offset;
    var main: [keccak_trace.Layout.main_columns]Scalar = undefined;
    for (&main, 0..) |*value, column| value.* = try layout.atExtension(
        1,
        main_offset + column,
        0,
    );
    var previous_io: [2 * keccak_relations.io_arity]Scalar = undefined;
    for (&previous_io, 0..) |*value, field| value.* = try layout.atExtension(
        1,
        main_offset + keccak_trace.Layout.io_a + field,
        -1,
    );
    var minus_two: [keccak_witness.state_cell_count]Scalar = undefined;
    var minus_one: [keccak_witness.state_cell_count]Scalar = undefined;
    var plus_one: [keccak_witness.state_cell_count]Scalar = undefined;
    var plus_two: [keccak_witness.state_cell_count]Scalar = undefined;
    var plus_twenty_seven: [keccak_witness.state_cell_count]Scalar = undefined;
    for (0..keccak_witness.state_cell_count) |cell| {
        const column = main_offset + keccak_trace.Layout.state + cell;
        minus_two[cell] = try layout.atExtension(1, column, -2);
        minus_one[cell] = try layout.atExtension(1, column, -1);
        plus_one[cell] = try layout.atExtension(1, column, 1);
        plus_two[cell] = try layout.atExtension(1, column, 2);
        plus_twenty_seven[cell] = try layout.atExtension(1, column, 27);
    }
    var selectors: [keccak_witness.row_count]Scalar = undefined;
    for (&selectors, 0..) |*value, group| value.* = try layout.atExtension(
        0,
        pp + keccak_trace.Layout.row_group + group,
        0,
    );
    const second_active = try layout.atExtension(
        0,
        pp + keccak_trace.Layout.second_active,
        0,
    );
    var sink = Sink{
        .result = result,
        .randomness = randomness,
        .denominator = denominator,
    };
    try keccak_direct.evaluateGeneric(
        Scalar,
        &main,
        &previous_io,
        &minus_two,
        &minus_one,
        &plus_one,
        &plus_two,
        &selectors,
        second_active,
        &sink,
    );
    const pairs = try keccak_interaction.rowPairsGeneric(
        Scalar,
        &main,
        &plus_one,
        &plus_twenty_seven,
        &selectors,
        relations,
    );
    const is_first = try layout.atExtension(
        0,
        pp + keccak_trace.Layout.is_first,
        0,
    );
    try appendPairs(
        pairs,
        interaction_offset,
        is_first,
        layout,
        claims,
        randomness,
        denominator,
        result,
    );
    const expected = component.direct_constraint_count +
        component.interaction_batch_count;
    if (result.instruction_count - instruction_before != expected)
        return error.InvalidInstructionCount;
}

fn recordKeccakTable(
    kind: keccak_tables.Kind,
    component: geometry_mod.ComponentV2,
    layout: *const SampleLayout,
    claims: []const Scalar,
    relations: anytype,
    point: anytype,
    randomness: Scalar,
    denominators: *[31]?Scalar,
    result: *Result,
) !void {
    const instruction_before = result.instruction_count;
    const expected_kind: ethereum_statement.Kind = switch (kind) {
        .chi => .keccak_chi_table_v2,
        .xor5 => .keccak_xor5_table_v2,
    };
    if (component.kind != expected_kind or
        component.direct_constraint_count != 0 or
        component.interaction_batch_count != 1)
    {
        return error.InvalidComponentGeometry;
    }
    const denominator = support.quotientDenominator(
        component.log_size,
        layout.extension.max_log_degree_bound,
        point,
        denominators,
    );
    const pp = component.spans[0].offset;
    var tuple: [keccak_tables.arity]Scalar = undefined;
    for (&tuple, 0..) |*value, field| value.* = try layout.atExtension(
        0,
        pp + 1 + field,
        0,
    );
    const multiplicity = try layout.atExtension(
        1,
        component.spans[1].offset,
        0,
    );
    const current = try layout.sampledExtensionSecure(
        component.spans[2].offset,
        0,
    );
    const previous = try layout.sampledExtensionSecure(
        component.spans[2].offset,
        -1,
    );
    const is_first = try layout.atExtension(0, pp, 0);
    if (result.claim_count >= claims.len) return error.InvalidClaimCount;
    const constraint = try keccak_table.evaluateRowGeneric(
        Scalar,
        kind,
        &tuple,
        multiplicity,
        current,
        previous,
        is_first,
        claims[@intCast(result.claim_count)],
        relations,
    );
    append(result, randomness, denominator, constraint);
    result.claim_count += 1;
    const expected = component.direct_constraint_count +
        component.interaction_batch_count;
    if (result.instruction_count - instruction_before != expected)
        return error.InvalidInstructionCount;
}

fn recordSecp(
    comptime Config: type,
    component: geometry_mod.ComponentV2,
    layout: *const SampleLayout,
    claims: []const Scalar,
    relations: anytype,
    point: anytype,
    randomness: Scalar,
    denominators: *[31]?Scalar,
    result: *Result,
) !void {
    const instruction_before = result.instruction_count;
    if (component.direct_constraint_count != Config.direct_constraint_count or
        component.interaction_batch_count != Config.batch_count)
    {
        return error.InvalidComponentGeometry;
    }
    const denominator = support.quotientDenominator(
        component.log_size,
        layout.extension.max_log_degree_bound,
        point,
        denominators,
    );
    var main: [Config.main_column_count]Scalar = undefined;
    var previous: [Config.main_column_count]Scalar = undefined;
    var next: [Config.main_column_count]Scalar = undefined;
    for (&main, &previous, &next, 0..) |*current, *prior, *following, column| {
        const global = component.spans[1].offset + column;
        current.* = try layout.atExtension(1, global, 0);
        prior.* = try layout.atExtension(1, global, -1);
        following.* = try layout.atExtension(1, global, 1);
    }
    const pp = component.spans[0].offset;
    const is_first = try layout.atExtension(
        0,
        pp + secp_trace.logup_first_column,
        0,
    );
    const group_first = try layout.atExtension(
        0,
        pp + secp_trace.group_first_column,
        0,
    );
    const group_last = try layout.atExtension(
        0,
        pp + secp_trace.group_last_column,
        0,
    );
    var sink = Sink{
        .result = result,
        .randomness = randomness,
        .denominator = denominator,
    };
    Config.evaluate(
        Scalar,
        &main,
        &previous,
        &next,
        group_first,
        group_last,
        relations,
        &sink,
    );
    const pairs = Config.rowPairs(
        Scalar,
        &main,
        &previous,
        &next,
        relations,
    );
    try appendPairs(
        pairs,
        component.spans[2].offset,
        is_first,
        layout,
        claims,
        randomness,
        denominator,
        result,
    );
    const expected = component.direct_constraint_count +
        component.interaction_batch_count;
    if (result.instruction_count - instruction_before != expected)
        return error.InvalidInstructionCount;
}

fn appendPairs(
    pairs: anytype,
    interaction_offset: usize,
    is_first: Scalar,
    layout: *const SampleLayout,
    claims: []const Scalar,
    randomness: Scalar,
    denominator: Scalar,
    result: *Result,
) !void {
    if (@as(usize, result.claim_count) + pairs.len > claims.len)
        return error.InvalidClaimCount;
    for (pairs, 0..) |pair, batch| {
        const current = try layout.sampledExtensionSecure(
            interaction_offset + 4 * batch,
            0,
        );
        const previous = try layout.sampledExtensionSecure(
            interaction_offset + 4 * batch,
            -1,
        );
        const constraint = logup.pairConstraintGeneric(
            Scalar,
            current,
            previous,
            is_first,
            claims[@as(usize, result.claim_count) + batch],
            pair,
        );
        append(result, randomness, denominator, constraint);
    }
    result.claim_count += @intCast(pairs.len);
}

const Sink = struct {
    result: *Result,
    randomness: Scalar,
    denominator: Scalar,

    pub fn add(self: *Sink, constraint: Scalar, _: u8) void {
        append(
            self.result,
            self.randomness,
            self.denominator,
            constraint,
        );
    }
};

fn append(
    result: *Result,
    randomness: Scalar,
    denominator: Scalar,
    constraint: Scalar,
) void {
    support.accumulate(&result.accumulation, randomness, constraint, denominator);
    result.instruction_count += 1;
}

comptime {
    if (ethereum_statement.component_count != 14)
        @compileError("Ethereum extension component inventory drifted");
}
