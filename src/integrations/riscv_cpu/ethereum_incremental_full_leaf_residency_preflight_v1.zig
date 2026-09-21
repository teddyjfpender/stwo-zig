//! Ethereum prepared-leaf lower bound before Engine/PCS allocation. Geometry
//! helpers are shared with native commitment construction. Passing this bound
//! is not a process-memory guarantee: Merkle/FRI/quotient/twiddle storage and
//! witness owners are excluded. Source columns are reported, not all assumed
//! simultaneously live.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const engine = @import("stwo_prover_engine");
const residency = engine.pcs.residency_estimate;
const ethereum = frontend.prover_mod.guest_precompile;
const bridge = frontend.prover_mod.incremental_bridge_external_v3;
const lookup = frontend.air.lookup_physical_manifest_v2;
const View = @import("ethereum_incremental_full_leaf_prepared_proof_transaction_v4.zig").ProofViewV4;

pub const EstimateV1 = struct {
    retained_lde_bytes: u64 = 0,
    source_column_bytes: u64 = 0,
    columns: u64 = 0,

    fn add(self: *EstimateV1, value: residency.Estimate) !void {
        self.retained_lde_bytes = try std.math.add(u64, self.retained_lde_bytes, value.minimum_resident_bytes);
        self.source_column_bytes = try std.math.add(u64, self.source_column_bytes, value.source_bytes);
        self.columns = try std.math.add(u64, self.columns, value.column_count);
    }

    pub fn requireWithin(self: EstimateV1, budget: u64) !void {
        if (self.retained_lde_bytes > budget) return error.PcsResidentBudgetExceeded;
    }
};

pub fn check(allocator: std.mem.Allocator, view: View, budget: usize) !void {
    const core = &view.workspace.statement;
    var manifest = lookup.Manifest.native();
    const authenticated = try lookup.AuthenticatedStatement.init(core, &manifest);
    const tree0 = try ethereum.ethereum_preprocessed.logSizes(allocator, core, view.extension);
    defer allocator.free(tree0);
    const tree1 = try ethereum.ethereum_main.logSizes(allocator, core, view.extension);
    defer allocator.free(tree1);
    const tree2 = try ethereum.ethereum_interaction.logSizesAuthenticatedLookupV2(allocator, core, view.extension, &manifest, &authenticated);
    defer allocator.free(tree2);
    const blowup = (try view.profile.pcsConfig()).fri_config.log_blowup_factor;
    var estimate = EstimateV1{};
    inline for (.{ tree0, tree1, tree2 }) |logs| try estimate.add(try residency.estimate(logs, blowup, .never));
    if (view.profile.circuitProfile().programPolicy() == .fixed_decoded_table_v1) {
        try estimate.add(try residency.estimateUniform(
            frontend.air.program.fixed_table_v1.COLUMN_COUNT,
            core.infra_descs[0].log_size,
            blowup,
            .never,
        ));
    }
    try estimate.add(try residency.estimateUniform(
        bridge.PREPROCESSED_COLUMNS + bridge.MAIN_COLUMNS + bridge.INTERACTION_COLUMNS,
        view.profile.bridge_geometry.log_size,
        blowup,
        .never,
    ));
    std.debug.print(
        "INCREMENTAL_FULL_LEAF_PREFLIGHT_V1 retained_lde_lower_bound_bytes={} source_column_bytes={} columns={} blowup_log={} budget_bytes={} excludes=merkle,fri,quotient,twiddles,witness,allocator\n",
        .{ estimate.retained_lde_bytes, estimate.source_column_bytes, estimate.columns, blowup, budget },
    );
    if (estimate.retained_lde_bytes > budget) {
        var detailed = EstimateV1{};
        for (core.component_descs[0..core.n_components], 0..) |descriptor, index| {
            const columns = try std.math.add(u64, 2 + @as(u64, descriptor.n_columns), manifest.entryForFamily(descriptor.family).interaction_column_count);
            try detailed.add(try reportComponent("core", @tagName(descriptor.family), index, descriptor.n_rows, descriptor.log_size, columns, blowup));
        }
        for (core.infra_descs[0..core.n_infra], 0..) |descriptor, index| {
            const statement = frontend.air.statement;
            const columns = try std.math.add(u64, @as(u64, statement.nPreprocessedColumnsForInfra(descriptor.kind)) + descriptor.n_columns, statement.nInteractionColsForInfra(descriptor.kind));
            try detailed.add(try reportComponent("infra", @tagName(descriptor.kind), index, descriptor.n_rows, descriptor.log_size, columns, blowup));
            if (index == 0 and view.profile.circuitProfile().programPolicy() == .fixed_decoded_table_v1)
                try detailed.add(try reportComponent("program_admission", "fixed_decoded_table", index, descriptor.n_rows, descriptor.log_size, frontend.air.program.fixed_table_v1.COLUMN_COUNT, blowup));
        }
        for (view.extension.components, 0..) |descriptor, index| {
            const columns = try std.math.add(u64, @as(u64, descriptor.preprocessed_columns) + descriptor.main_columns, descriptor.interaction_columns);
            try detailed.add(try reportComponent("ethereum", @tagName(descriptor.kind), index, descriptor.n_rows, descriptor.log_size, columns, blowup));
        }
        try detailed.add(try reportComponent("bridge", "incremental", 0, view.profile.bridge_geometry.n_rows, view.profile.bridge_geometry.log_size, bridge.PREPROCESSED_COLUMNS + bridge.MAIN_COLUMNS + bridge.INTERACTION_COLUMNS, blowup));
        if (!std.meta.eql(detailed, estimate)) return error.IncrementalLeafResourceGeometryMismatch;
    }
    try estimate.requireWithin(budget);
}

fn reportComponent(group: []const u8, kind: []const u8, index: usize, rows: u32, log_size: u32, columns: u64, blowup: u32) !residency.Estimate {
    const estimate = try residency.estimateUniform(std.math.cast(usize, columns) orelse return error.IncrementalLeafResourceGeometryOverflow, log_size, blowup, .never);
    std.debug.print("INCREMENTAL_FULL_LEAF_COMPONENT_PREFLIGHT_V1 group={s} kind={s} index={} rows={} log_size={} columns={} source_bytes={} retained_lde_bytes={}\n", .{ group, kind, index, rows, log_size, columns, estimate.source_bytes, estimate.minimum_resident_bytes });
    return estimate;
}

test "retained leaf PCS lower bound sums mixed geometry and rejects insufficient budget" {
    var estimate = EstimateV1{};
    try estimate.add(try residency.estimate(&.{ 2, 3 }, 1, .never));
    try estimate.add(try residency.estimateUniform(2, 4, 1, .never));
    try std.testing.expectEqual(@as(u64, (4 + 8 + 2 * 16) * 8), estimate.retained_lde_bytes);
    try std.testing.expectEqual(@as(u64, (4 + 8 + 2 * 16) * 4), estimate.source_column_bytes);
    try estimate.requireWithin(estimate.retained_lde_bytes);
    try std.testing.expectError(error.PcsResidentBudgetExceeded, estimate.requireWithin(estimate.retained_lde_bytes - 1));
}

test "retained real leaf PCS decision uses separate budget and actual retention" {
    // Exact mixed Tree0/1/2 geometry retained from real segment9 replay v3.
    // The same shared decision runs again on Tree1 with the scheme's policy.
    const counted = [_]struct { log: u32, columns: usize }{
        .{ .log = 5, .columns = 141 },
        .{ .log = 7, .columns = 1451 },
        .{ .log = 8, .columns = 260 },
        .{ .log = 9, .columns = 1355 },
        .{ .log = 10, .columns = 12 },
        .{ .log = 12, .columns = 176 },
        .{ .log = 13, .columns = 396 },
        .{ .log = 14, .columns = 8486 },
        .{ .log = 15, .columns = 149 },
        .{ .log = 16, .columns = 2539 },
        .{ .log = 17, .columns = 1355 },
        .{ .log = 18, .columns = 23 },
        .{ .log = 19, .columns = 28 },
        .{ .log = 20, .columns = 44 },
        .{ .log = 22, .columns = 479 },
    };
    var logs: [16894]u32 = undefined;
    var offset: usize = 0;
    for (counted) |entry| {
        @memset(logs[offset..][0..entry.columns], entry.log);
        offset += entry.columns;
    }
    try std.testing.expectEqual(logs.len, offset);
    const checkTree = ethereum.ethereum_segment_orchestration.requireTree1ResidencyWithPolicy;
    const accepted = try checkTree(&logs, 1, 24 * 1024 * 1024 * 1024, .never);
    try std.testing.expectEqual(@as(u64, 20550093056), accepted.minimum_resident_bytes);
    try std.testing.expectError(error.PcsResidentBudgetExceeded, checkTree(&logs, 1, 16 * 1024 * 1024 * 1024, .never));
    try std.testing.expectError(error.PcsResidentBudgetExceeded, checkTree(&logs, 1, 24 * 1024 * 1024 * 1024, .always));
}
