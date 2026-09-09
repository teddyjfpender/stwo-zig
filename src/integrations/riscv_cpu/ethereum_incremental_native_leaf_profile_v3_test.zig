const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const profile_mod = @import("ethereum_incremental_native_leaf_profile_v3.zig");
const artifact_v3 = @import("ethereum_incremental_boundary_artifact_v3.zig");
const artifact_v2 = @import("ethereum_incremental_boundary_artifact_v2.zig");
const authority_v1 = @import("ethereum_incremental_boundary_authority_v1.zig");
const boundary_v3 = @import("ethereum_incremental_boundary_authority_v3.zig");
const support =
    @import("ethereum_incremental_boundary_artifact_v3_test_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const statement = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const public_data = frontend.air.public_data;
const memory_state = frontend.runner.memory_state;

const input_words = [_]u32{11};

test "incremental native leaf profile is cold-derived and q193 exact" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator);
    defer case.deinit();

    const profile = try case.mint();
    try profile.validateAgainstStatement(&case.base_statement);
    try profile.validateAgainstInputs(
        allocator,
        &case.artifact,
        &case.wire.data,
        case.publicAuthority(),
        &case.base_statement,
        artifact_v3.default_limits,
    );
    try std.testing.expectEqual(
        boundary_v3.StatementFamilyV3.segment_full_state_v3,
        profile.statement_family,
    );
    try std.testing.expectEqual(
        boundary_v3.BoundaryPolicyV3.full_state_split_memory_multiplicity,
        profile.boundary_policy,
    );
    try std.testing.expectEqual(@as(u32, 193), profile.protocol.pcs.query_count);
    try std.testing.expectEqual(@as(u32, 16), profile.protocol.pcs.pow_bits);
    try std.testing.expectEqual(@as(u32, 4), profile.protocol.pcs.fold_step);
    try std.testing.expectEqual(@as(u32, 209), profile.protocol.pcs.configured_security_bits);
    try std.testing.expectEqual(@as(usize, 1), frontend.prover_mod.incremental_bridge_external_v3.COMPONENT_COUNT);
    try std.testing.expect(profile.bridge_geometry.n_rows != 0);
    try std.testing.expectEqual(
        profile.bridge_geometry.total_interaction_columns,
        profile.totalTreeColumns()[2],
    );
    try std.testing.expect(!profile.production_active);
    try std.testing.expect(!profile.proof_admissible);
    try std.testing.expect(!profile.fresh_verification_available);
}

test "incremental native leaf profile rejects field, geometry, and protocol drift" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator);
    defer case.deinit();
    const canonical = try case.mint();

    var changed = canonical;
    changed.coordinate.segment_index += 1;
    try expectStatementReject(&changed, &case.base_statement);
    changed = canonical;
    changed.continuation_roots.exit ^= 1;
    try expectStatementReject(&changed, &case.base_statement);
    changed = canonical;
    changed.segment_public_wire_id[0] +%= 1;
    try expectStatementReject(&changed, &case.base_statement);
    changed = canonical;
    changed.bridge_geometry.n_rows += 1;
    try expectStatementReject(&changed, &case.base_statement);
    changed = canonical;
    changed.bridge_geometry.placement.interaction_col_offset += 1;
    try expectStatementReject(&changed, &case.base_statement);
    changed = canonical;
    changed.base_geometry.physical_tree_columns[2] += 1;
    try expectStatementReject(&changed, &case.base_statement);
    changed = canonical;
    changed.protocol.pcs.query_count = 192;
    try expectStatementReject(&changed, &case.base_statement);
    changed = canonical;
    changed.protocol.protocol_id[0] +%= 1;
    try expectStatementReject(&changed, &case.base_statement);
    changed = canonical;
    changed.boundary_artifact_content_sha256[0] ^= 1;
    changed.identity_sha256 = canonical.identity_sha256;
    try expectStatementReject(&changed, &case.base_statement);
}

test "incremental native leaf profile reopens artifact and exact base wire" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator);
    defer case.deinit();
    const canonical = try case.mint();

    var changed_statement = case.base_statement;
    changed_statement.core.component_descs[0].n_rows += 1;
    try expectStatementReject(&canonical, &changed_statement);

    var changed = canonical;
    changed.boundary_artifact_content_sha256[0] ^= 1;
    changed.identity_sha256 = profile_mod.testing.authorityIdentity(&changed);
    try std.testing.expectError(
        error.IncrementalNativeLeafInputMismatch,
        changed.validateAgainstInputs(
            allocator,
            &case.artifact,
            &case.wire.data,
            case.publicAuthority(),
            &case.base_statement,
            artifact_v3.default_limits,
        ),
    );
}

test "incremental native leaf transcript order is exact before both trees" {
    const allocator = std.testing.allocator;
    var case = try Case.init(allocator);
    defer case.deinit();
    const profile = try case.mint();

    var pre = Recorder{};
    try profile.mixPreTree0(&case.base_statement, &pre);
    // fold_step=4 makes PcsConfig emit two QM31 values (eight base limbs).
    try std.testing.expectEqualSlices(u32, &.{ 16, 1, 193, 0, 4, 0, 0, 0 }, pre.slice()[0..8]);
    const wire = case.wire.data.words();
    const profile_at = 8 + 4 + 8 + wire.len + physicalActivationWordCount();
    try std.testing.expectEqualSlices(
        u32,
        &profile_mod.PRE_TREE0_DOMAIN_WORDS,
        pre.slice()[profile_at..][0..profile_mod.PRE_TREE0_DOMAIN_WORDS.len],
    );

    var base_prefix = Recorder{};
    const main_claim = case.base_statement.core.canonicalMainClaim();
    main_claim.mixInto(&base_prefix);
    case.base_statement.core.mixShardManifest(&base_prefix);
    var post = Recorder{};
    try profile.mixPostTree1(&case.base_statement, &post);
    try std.testing.expectEqualSlices(
        u32,
        base_prefix.slice(),
        post.slice()[0..base_prefix.len],
    );
    try std.testing.expectEqualSlices(
        u32,
        &profile_mod.POST_TREE1_DOMAIN_WORDS,
        post.slice()[base_prefix.len..][0..profile_mod.POST_TREE1_DOMAIN_WORDS.len],
    );
}

fn expectStatementReject(
    profile: *const profile_mod.AuthorityV3,
    base: *const statement_v2.RiscVStatementV2,
) !void {
    var rejected = false;
    profile.validateAgainstStatement(base) catch {
        rejected = true;
    };
    try std.testing.expect(rejected);
}

fn physicalActivationWordCount() usize {
    // header(7) + three SHA identities encoded as eight u32 limbs each.
    return 7 + 3 * 8;
}

const Recorder = struct {
    words: [4096]u32 = .{0} ** 4096,
    len: usize = 0,

    pub fn mixU32s(self: *Recorder, values: []const u32) void {
        std.debug.assert(self.len + values.len <= self.words.len);
        @memcpy(self.words[self.len..][0..values.len], values);
        self.len += values.len;
    }

    pub fn mixFelts(self: *Recorder, values: []const QM31) void {
        for (values) |value| {
            for (value.toM31Array()) |limb| self.mixU32s(&.{limb.toU32()});
        }
    }

    pub fn mixU64(self: *Recorder, value: u64) void {
        self.mixU32s(&.{
            @truncate(value),
            @truncate(value >> 32),
        });
    }

    fn slice(self: *const Recorder) []const u32 {
        return self.words[0..self.len];
    }
};

const Case = struct {
    allocator: std.mem.Allocator,
    wire: support.OwnedWire,
    transition_bytes: []u8,
    artifact_bytes: []u8,
    artifact: artifact_v3.OwnedArtifactV3,
    retained_public_data: public_data.PublicData,
    layout: memory_state.MemoryLayout,
    base_statement: statement_v2.RiscVStatementV2,

    fn init(allocator: std.mem.Allocator) !Case {
        var fixture = try support.Fixture.init();
        const source = fixture.leftSource();
        var wire = try support.OwnedWire.init(allocator, &source);
        errdefer wire.deinit();
        const metadata = try wire.data.metadata();
        const initial = [_]authority_v1.SparseWordV1{
            .{ .address = 0x2000, .value = 11 },
        };
        const touched = [_]authority_v1.TouchedWordV1{.{
            .address = 0x2000,
            .old_word = 11,
            .new_word = 12,
            .final_clock = 3,
        }};
        var session = try authority_v1.SessionTree.init(
            allocator,
            [_]u8{0x73} ** 32,
            metadata.segment_index,
            &initial,
            try artifact_v2.testing.fullRoot(allocator, &initial),
        );
        defer session.deinit();
        var transition = try session.apply(metadata.segment_index, &touched);
        defer transition.deinit();
        const transition_bytes = try artifact_v2.encodeAlloc(
            allocator,
            &transition,
            artifact_v2.default_limits,
        );
        errdefer allocator.free(transition_bytes);
        const artifact_bytes = try artifact_v3.encodeAlloc(
            allocator,
            transition_bytes,
            &wire.data,
            artifact_v3.default_limits,
        );
        errdefer allocator.free(artifact_bytes);
        var decoded = try artifact_v3.decodeAlloc(
            allocator,
            artifact_bytes,
            artifact_v3.default_limits,
        );
        errdefer decoded.deinit();
        const retained = retainedPublicData(metadata);
        const base = try baseStatement(&wire.data);
        return .{
            .allocator = allocator,
            .wire = wire,
            .transition_bytes = transition_bytes,
            .artifact_bytes = artifact_bytes,
            .artifact = decoded,
            .retained_public_data = retained,
            .layout = memoryLayout(),
            .base_statement = base,
        };
    }

    fn deinit(self: *Case) void {
        self.artifact.deinit();
        self.allocator.free(self.artifact_bytes);
        self.allocator.free(self.transition_bytes);
        self.wire.deinit();
        self.* = undefined;
    }

    fn publicAuthority(self: *const Case) boundary_v3.SegmentPublicAuthorityV3 {
        const metadata = self.wire.data.metadata() catch unreachable;
        return .{
            .coordinate = .{
                .segment_index = metadata.segment_index,
                .segment_count = metadata.segment_count,
            },
            .segment_role = .{
                .is_first = metadata.is_first,
                .is_last = metadata.is_final,
            },
            .layout = self.layout,
            .public_data = &self.retained_public_data,
            .continuation_roots = .{
                .entry = metadata.entry_continuation_root,
                .exit = metadata.exit_continuation_root,
            },
        };
    }

    fn mint(self: *const Case) !profile_mod.AuthorityV3 {
        return profile_mod.mint(
            self.allocator,
            &self.artifact,
            &self.wire.data,
            self.publicAuthority(),
            &self.base_statement,
            artifact_v3.default_limits,
        );
    }
};

fn baseStatement(
    wire: *const frontend.air.public_data_v2.PublicDataV2,
) !statement_v2.RiscVStatementV2 {
    const core_public = try statement_v2.canonicalCorePublicData(wire);
    var core: statement.RiscVStatement = undefined;
    core.n_components = 1;
    core.component_descs[0] = .{
        .family = .base_alu_reg,
        .log_size = 4,
        .n_rows = core_public.clock,
        .n_columns = frontend.runner.trace.nColumnsForFamily(.base_alu_reg),
    };
    core.initial_pc = core_public.initial_pc;
    core.final_pc = core_public.final_pc;
    core.total_steps = core_public.clock;
    core.public_data = core_public;
    core.n_infra = 10;
    core.infra_descs[0] = .{
        .kind = .program,
        .log_size = 1,
        .n_rows = 1,
        .n_columns = frontend.air.program.commitment.N_MAIN_COLUMNS,
    };
    core.infra_descs[1] = .{
        .kind = .merkle,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = frontend.air.memory_commitment.merkle_node.N_MAIN_COLUMNS,
    };
    core.infra_descs[2] = .{
        .kind = .poseidon2,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = frontend.air.memory_commitment.poseidon2_air.N_MAIN_COLUMNS,
    };
    core.infra_descs[3] = .{
        .kind = .clock_update,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = frontend.infra_trace.CLOCK_UPDATE_COLS,
    };
    for (frontend.air.component_order.lookupTables(), 0..) |kind, index| {
        core.infra_descs[4 + index] = .{
            .kind = statement.infraKindForTable(kind),
            .log_size = frontend.air.lookups.tables.schema.logSize(kind),
            .n_rows = @intCast(frontend.air.lookups.tables.schema.size(kind)),
            .n_columns = 1,
        };
    }
    return statement_v2.RiscVStatementV2.init(core, wire.*);
}

fn retainedPublicData(
    metadata: frontend.air.public_data_v2.Metadata,
) public_data.PublicData {
    return .{
        .initial_pc = metadata.entry_cpu.pc,
        .final_pc = metadata.exit_cpu.pc,
        .clock = metadata.global_cycle_end - metadata.global_cycle_start,
        .initial_regs = metadata.entry_cpu.registers,
        .final_regs = metadata.exit_cpu.registers,
        .reg_last_clock = metadata.exit_cpu.predecessor_clocks,
        .program_root = metadata.program[0],
        .initial_rw_root = metadata.entry_continuation_root,
        .final_rw_root = metadata.exit_continuation_root,
        .completion = public_data.Completion.canonicalSelfLoop(
            metadata.exit_cpu.pc,
        ),
        .io_entries = .{
            .input_start = 0x2000,
            .input_len = 4,
            .input_words = &input_words,
            .output_len = 0,
            .output_len_addr = 0x2100,
            .output_data_addr = 0x2104,
            .output_words = &.{},
        },
    };
}

fn memoryLayout() memory_state.MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x2200,
        .stack_bottom = 0x3000,
        .stack_top = 0x4000,
        .io_base = 0x2000,
        .io_end = 0x2200,
        .input_base = 0x2000,
        .input_end = 0x2004,
        .output_len_addr = 0x2100,
        .output_data_addr = 0x2104,
        .output_base = 0x2100,
        .output_end = 0x2200,
    };
}
