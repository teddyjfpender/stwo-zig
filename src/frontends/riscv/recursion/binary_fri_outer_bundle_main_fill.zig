//! Transactional main-tree generation for the binary FRI bundle.

const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");
const source_mod = @import("binary_fri_outer_source.zig");

pub fn fill(
    self: anytype,
    manifest: anytype,
    destination: [][]M31,
    comptime manifest_contract: type,
    comptime MAIN_COLUMN_COUNT: usize,
    comptime MAIN_COLUMNS_PER_ROW: anytype,
    comptime bundleLogSizes: anytype,
    comptime bindOwnedColumns: anytype,
    comptime preflightFreshColumns: anytype,
    comptime clearColumns: anytype,
    comptime finalizePendingSharedSchedule: anytype,
    comptime providerCallsPrepared: anytype,
    comptime captureSharedProviderOutputs: anytype,
    comptime validate: anytype,
) !void {
    try validate(self);
    const logs = bundleLogSizes(self);
    var columns = try bindOwnedColumns(
        manifest_contract,
        manifest_contract.MAIN_TREE_INDEX,
        MAIN_COLUMN_COUNT,
        MAIN_COLUMNS_PER_ROW,
        logs,
        manifest,
        destination,
    );
    try preflightFreshColumns(&columns);
    errdefer clearColumns(&columns);

    const composition_end = source_mod.COMPOSITION_MAIN_COLUMN_COUNT;
    const fri_end = composition_end + source_mod.MAIN_COLUMN_COUNT;
    const arithmetic_end = fri_end + source_mod.ARITHMETIC_MAIN_COLUMN_COUNT;
    const merkle_end = arithmetic_end + source_mod.MERKLE_PATH_MAIN_COLUMN_COUNT;
    try self.source.fillCompositionMainPreparedInto(
        &self.source_authority,
        &self.composition_workspace,
        columns[0..composition_end],
    );
    try self.source.fillFriMainPreparedInto(
        &self.source_authority,
        &self.fri_workspace,
        columns[composition_end..fri_end],
    );
    try self.source.fillArithmeticMainPreparedInto(
        &self.source_authority,
        &self.arithmetic_workspace,
        columns[fri_end..arithmetic_end],
    );
    try self.source.prepareMerkleWorkspacePrepared(
        &self.source_authority,
        &self.fri_workspace,
        &self.merkle_workspace,
    );
    try self.source.fillMerkleMainPreparedInto(
        &self.source_authority,
        &self.fri_workspace,
        &self.merkle_workspace,
        columns[arithmetic_end..merkle_end],
    );
    const core_calls = try self.source.merklePoseidonCallsPrepared(
        &self.source_authority,
        &self.fri_workspace,
        &self.merkle_workspace,
    );
    try finalizePendingSharedSchedule(self, core_calls);
    const calls = try providerCallsPrepared(self);
    var provider: [poseidon_air.N_MAIN_COLUMNS][]M31 = undefined;
    @memcpy(&provider, columns[merkle_end..][0..poseidon_air.N_MAIN_COLUMNS]);
    try self.poseidon_authority.executor.generateMainInto(
        &provider,
        calls,
        logs[16],
    );
    try self.source.prepareRelationRowsPrepared(
        &self.source_authority,
        &self.composition_workspace,
        &self.fri_workspace,
        &self.arithmetic_workspace,
        &self.merkle_workspace,
        &self.relation_rows,
    );
    try self.interaction_workspace.bindRows(
        self.source,
        &self.relation_rows,
    );
    try captureSharedProviderOutputs(self, &provider);
    self.main_prepared = true;
    try validate(self);
}
