const std = @import("std");
const core = @import("stwo_core");

const public_data_v2 = @import("../air/public_data_v2.zig");
const public_support = @import("../air/public_data_v2_test_support.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const router_air = @import("air/ethereum_leaf_child_field_router_v1.zig");
const program_mod = @import("ethereum_leaf_child_field_program_v1.zig");
const witness_mod = @import("ethereum_leaf_child_field_witness_v1.zig");
const leaf_v2 = @import("segment_leaf_authority_v2.zig");
const leaf_contract = @import("segment_leaf_authority_v2_contract.zig");

const M31 = core.fields.m31.M31;

const components = [_]statement_v1.FamilyComponentDesc{.{
    .family = .base_alu_imm,
    .log_size = 4,
    .n_rows = 3,
    .n_columns = 10,
}};
const infra = [_]statement_v1.InfraComponentDesc{.{
    .kind = .program,
    .log_size = 4,
    .n_rows = 3,
    .n_columns = 4,
}};

pub fn run() !void {
    const actual = try router_air.computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqual(router_air.SEMANTIC_DIGEST, actual);
    var definition = try router_air.build(std.testing.allocator);
    defer definition.deinit();
    _ = try router_air.authenticate(&definition);
    try runPinnedTests();
}

test "Ethereum child-field router semantic digest is pinned" {
    try std.testing.expectEqual(
        router_air.SEMANTIC_DIGEST,
        try router_air.computeSemanticDigest(std.testing.allocator),
    );
}

test "Ethereum child emitters derive local identities and retain Tree0" {
    try runPinnedTests();
}

pub fn runPinnedTests() !void {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var program = try program_mod.ProgramV1.init(
        std.testing.allocator,
        &components,
        &infra,
    );
    defer program.deinit();
    try std.testing.expectEqual(
        @as(usize, program_mod.BASE_ROUTER_ROW_COUNT + 16),
        program.router_rows.len,
    );
    try std.testing.expectEqual(@as(usize, 5), program.authority_hash.rows.len);
    try std.testing.expectEqual(@as(usize, 9), program.receipt_hash.rows.len);

    const input = fixture.input();
    var witness = try witness_mod.WitnessV1.init(
        std.testing.allocator,
        &program,
        input,
    );
    defer witness.deinit();
    try witness.validateAgainst(&program, input);
    try std.testing.expectEqual(
        fixture.receipt.authority_id,
        witness.local_authority_digest,
    );
    try std.testing.expectEqual(
        fixture.receipt.wire_id,
        witness.local_wire_digest,
    );
    try std.testing.expectEqual(
        fixture.receipt.identity,
        witness.local_receipt_digest,
    );
    try std.testing.expectEqual(fixture.tree0_root, witness.tree0_root);
    _ = try witness.authorityHashLogicalRow(&program, 0);
    _ = try witness.receiptHashLogicalRow(&program, 0);
    try std.testing.expectError(
        error.EthereumLeafWrapperAuthorityUnavailable,
        program.requireCompleteWrapperAuthority(),
    );

    witness.router_rows[0][0] = witness.router_rows[0][0].add(M31.one());
    try std.testing.expectError(
        error.InvalidEthereumChildFieldWitness,
        witness.validateAgainst(&program, input),
    );

    var program_mutation = try program_mod.ProgramV1.init(
        std.testing.allocator,
        &components,
        &infra,
    );
    defer program_mutation.deinit();
    program_mutation.router_rows[0].raw_a_index += 1;
    try std.testing.expectError(
        error.InvalidEthereumChildFieldProgram,
        program_mutation.validateAgainst(&components, &infra),
    );

    var wrong_tree_input = input;
    wrong_tree_input.tree0_root[0] +%= 1;
    try std.testing.expectError(
        error.InvalidEthereumChildFieldWitness,
        witness.validateAgainst(&program, wrong_tree_input),
    );
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    data: public_data_v2.PublicDataV2,
    context: leaf_v2.NativeTemporalContextV2,
    receipt: statement_v2.VerifiedReceipt,
    tree0_root: [8]u32,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const source_fixture = try public_support.Fixture.init();
        const source = source_fixture.rightSource();
        const words = try public_support.encode(allocator, &source);
        errdefer allocator.free(words);
        const data = try public_data_v2.PublicDataV2.authenticate(words);
        const keys = try leaf_v2.VerifierKeyAuthorityV2.init(
            public_support.id("child-field-local-program"),
            public_support.id("child-field-parent-program"),
        );
        const manifest = try leaf_v2.ManifestV2.init(words.len);
        const metadata = try data.metadata();
        const context = try leaf_contract.nativeContext(
            &metadata,
            &keys,
            &manifest,
        );
        const receipt = try verifiedReceipt(&data);
        return .{
            .allocator = allocator,
            .words = words,
            .data = data,
            .context = context,
            .receipt = receipt,
            .tree0_root = public_support.id("child-field-tree0"),
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }

    fn input(self: *const Fixture) witness_mod.InputsV1 {
        return .{
            .public_data = &self.data,
            .context = &self.context,
            .receipt = &self.receipt,
            .tree0_root = self.tree0_root,
            .component_descs = &components,
            .infra_descs = &infra,
        };
    }
};

fn verifiedReceipt(
    data: *const public_data_v2.PublicDataV2,
) !statement_v2.VerifiedReceipt {
    var all_components: [statement_v1.MAX_COMPONENTS]statement_v1.FamilyComponentDesc =
        undefined;
    @memcpy(all_components[0..components.len], &components);
    var all_infra: [statement_v1.MAX_INFRA_COMPONENTS]statement_v1.InfraComponentDesc =
        undefined;
    @memcpy(all_infra[0..infra.len], &infra);
    const public = try statement_v2.canonicalCorePublicData(data);
    const core_statement = statement_v1.RiscVStatement{
        .n_components = components.len,
        .component_descs = all_components,
        .initial_pc = public.initial_pc,
        .final_pc = public.final_pc,
        .total_steps = public.clock,
        .public_data = public,
        .n_infra = infra.len,
        .infra_descs = all_infra,
    };
    const statement = try statement_v2.RiscVStatementV2.init(
        core_statement,
        data.*,
    );
    return statement.verifiedReceipt();
}
