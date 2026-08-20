const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const pcs = core.pcs;
const component_order = @import("../../air/component_order.zig");
const artifact_identity = @import("../../air/guest_precompile/artifact_identity.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const lookup_table_schema = @import("../../air/lookups/tables/schema.zig");
const merkle_node = @import("../../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const opcode_entries = @import("../../air/lookups/opcode_entries.zig");
const access_clock = @import("../../access_clock.zig");
const public_data = @import("../../air/public_data.zig");
const base_statement = @import("../../air/statement.zig");
const base_types = @import("../types.zig");
const profile_types = @import("types.zig");
const subject = @import("proof_artifact.zig");

const test_config = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

test "guest proof artifact round trips every fresh-process verifier input canonically" {
    const allocator = std.testing.allocator;
    var input_words = [_]u32{0x0033_2211};
    var output_words = [_]public_data.OutputWord{
        .{ .addr = 0x4000, .value = 5, .clock = access_clock.encode(1, .first) },
        .{ .addr = 0x5000, .value = 0x0403_0201, .clock = access_clock.encode(1, .second) },
        .{ .addr = 0x5004, .value = 0x0000_0005, .clock = access_clock.encode(1, .third) },
    };
    var statement = admittedCore(1);
    statement.public_data.io_entries = .{
        .input_start = 0x3000,
        .input_len = 3,
        .input_words = &input_words,
        .output_len = 5,
        .output_len_addr = 0x4000,
        .output_data_addr = 0x5000,
        .output_words = &output_words,
    };
    try statement.public_data.validate();
    const extension = try guest_statement.ExtensionStatement.canonical(&statement, 1);
    const identity = try artifact_identity.Identity.canonical(&statement, &extension);
    const claim = try zeroClaim(allocator, &statement, &extension, 37);
    defer claim.destroy(allocator);
    const shape = try subject.proofPreflightShape(
        test_config,
        &statement,
        &extension,
        .{},
    );
    var proof = try syntheticProof(allocator, test_config, shape);
    defer proof.deinit(allocator);

    const encoded = try subject.encodeAlloc(allocator, .{
        .pcs_config = test_config,
        .statement = &statement,
        .extension = &extension,
        .artifact = identity,
        .interaction_claim = claim,
        .proof = &proof,
    });
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, &subject.magic, encoded[0..subject.magic.len]);
    try std.testing.expectEqual(@as(u64, encoded.len), readInt(u64, encoded, subject.HeaderOffset.total_bytes));

    var decoded = try subject.decodeAllocForConfig(
        allocator,
        encoded,
        test_config,
        .{},
    );
    defer decoded.deinit(allocator);
    try std.testing.expect(subject.pcsConfigsEqual(test_config, decoded.pcs_config));
    try expectStatementEqual(&statement, &decoded.statement);
    try std.testing.expect(std.meta.eql(extension, decoded.extension));
    try std.testing.expect(std.meta.eql(identity, decoded.artifact));
    try decoded.interaction_claim.validate(&decoded.statement, &decoded.extension);
    try std.testing.expectEqual(@as(u64, 37), decoded.interaction_claim.interactionPow());
    try std.testing.expectEqualSlices(u32, &input_words, decoded.input_words);
    try std.testing.expectEqualSlices(public_data.OutputWord, &output_words, decoded.output_words);

    const reencoded = try subject.encodeAlloc(allocator, .{
        .pcs_config = decoded.pcs_config,
        .statement = &decoded.statement,
        .extension = &decoded.extension,
        .artifact = decoded.artifact,
        .interaction_claim = decoded.interaction_claim,
        .proof = &decoded.proof,
    });
    defer allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
}

test "guest proof artifact rejects framing truncation trailing bytes and allocation bombs" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    const encoded = try fixture.encode(allocator);
    defer allocator.free(encoded);

    for ([_]usize{ 0, subject.header_size - 1, subject.header_size, encoded.len - 1 }) |length| {
        try expectDecodeFailure(encoded[0..length]);
    }
    const trailing = try allocator.alloc(u8, encoded.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..encoded.len], encoded);
    trailing[encoded.len] = 0;
    try expectDecodeFailure(trailing);

    var mutation = try allocator.dupe(u8, encoded);
    defer allocator.free(mutation);
    mutation[0] ^= 1;
    try std.testing.expectError(
        error.InvalidArtifactMagic,
        subject.decodeAlloc(allocator, mutation),
    );
    @memcpy(mutation, encoded);
    writeInt(u16, mutation, subject.HeaderOffset.version, subject.format_version + 1);
    try std.testing.expectError(
        error.UnsupportedArtifactVersion,
        subject.decodeAlloc(allocator, mutation),
    );
    @memcpy(mutation, encoded);
    writeInt(u32, mutation, subject.HeaderOffset.statement_length, std.math.maxInt(u32));
    try expectDecodeFailure(mutation);

    // An attacker-selected query count is rejected in the fixed header before
    // public-I/O, claim, or proof allocation.
    @memcpy(mutation, encoded);
    writeInt(u64, mutation, subject.HeaderOffset.n_queries, 1025);
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.ProofResourceLimitExceeded,
        subject.decodeAlloc(failing.allocator(), mutation),
    );
    try std.testing.expect(!failing.has_induced_failure);

    // I/O byte policy is checked against scalar lengths before the first word
    // allocation, independently of the outer byte-size cap.
    failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var limits = subject.Limits{};
    limits.max_input_bytes = 0;
    try std.testing.expectError(
        error.IoResourceLimitExceeded,
        subject.decodeAllocWithLimits(failing.allocator(), encoded, limits),
    );
    try std.testing.expect(!failing.has_induced_failure);

    var wrong_config = test_config;
    wrong_config.pow_bits = 1;
    failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.PcsConfigMismatch,
        subject.decodeAllocForConfig(
            failing.allocator(),
            encoded,
            wrong_config,
            .{},
        ),
    );
    try std.testing.expect(!failing.has_induced_failure);
}

test "guest proof artifact rejects statement extension claim and proof mutations" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    const encoded = try fixture.encode(allocator);
    defer allocator.free(encoded);
    const sections = sectionOffsets(encoded);
    var mutation = try allocator.dupe(u8, encoded);
    defer allocator.free(mutation);

    writeInt(
        u32,
        mutation,
        sections.statement,
        base_statement.MAX_COMPONENTS + 1,
    );
    try std.testing.expectError(
        error.InvalidComponentCount,
        subject.decodeAlloc(allocator, mutation),
    );

    @memcpy(mutation, encoded);
    writeInt(u16, mutation, sections.extension, 0);
    try std.testing.expectError(
        error.ProfileMismatch,
        subject.decodeAlloc(allocator, mutation),
    );

    @memcpy(mutation, encoded);
    mutation[sections.identity + 24] ^= 1;
    try expectDecodeFailure(mutation);

    const caller = sections.claim + callerClaimOffset(&fixture.statement);
    @memcpy(mutation, encoded);
    writeInt(u32, mutation, caller + descriptorNRowsOffset(), 2);
    try std.testing.expectError(
        error.ClaimDescriptorMismatch,
        subject.decodeAlloc(allocator, mutation),
    );

    @memcpy(mutation, encoded);
    const caller_count = caller + descriptorEncodedSize();
    writeInt(u16, mutation, caller_count, profile_types.caller_batch_count - 1);
    try std.testing.expectError(
        error.InvalidClaimCount,
        subject.decodeAlloc(allocator, mutation),
    );

    @memcpy(mutation, encoded);
    const caller_first_sum = caller_count + @sizeOf(u16);
    writeInt(u32, mutation, caller_first_sum, core.fields.m31.Modulus);
    try std.testing.expectError(
        error.NonCanonicalM31,
        subject.decodeAlloc(allocator, mutation),
    );

    @memcpy(mutation, encoded);
    const caller_aggregate = caller_first_sum + profile_types.caller_batch_count * qm31EncodedSize();
    writeInt(u32, mutation, caller_aggregate, 1);
    try std.testing.expectError(
        error.ComponentClaimMismatch,
        subject.decodeAlloc(allocator, mutation),
    );

    @memcpy(mutation, encoded);
    const provider = caller_aggregate + qm31EncodedSize();
    writeInt(u16, mutation, provider, @intFromEnum(@import("../../air/guest_precompile/component_registry.zig").Slot.caller));
    try std.testing.expectError(
        error.ComponentSlotMismatch,
        subject.decodeAlloc(allocator, mutation),
    );

    @memcpy(mutation, encoded);
    mutation[sections.proof] ^= 1; // postcard pow_bits, header remains zero.
    try std.testing.expectError(
        error.InvalidProofConfig,
        subject.decodeAlloc(allocator, mutation),
    );
}

test "guest proof artifact rolls back owned metadata on early allocation failures" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    const encoded = try fixture.encode(allocator);
    defer allocator.free(encoded);

    // Input words, output words, and the fixed-capacity detailed claim are the
    // first three non-zero allocations.  Failure at each boundary must return
    // without retaining an earlier owner; the testing allocator catches leaks.
    for (0..3) |failure_index| {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = failure_index },
        );
        try std.testing.expectError(
            error.OutOfMemory,
            subject.decodeAlloc(failing.allocator(), encoded),
        );
        try std.testing.expect(failing.has_induced_failure);
    }
}

const Fixture = struct {
    statement: base_statement.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    identity: artifact_identity.Identity,
    claim: *profile_types.InteractionClaim,
    proof: base_types.Proof,
    input_words: [1]u32,
    output_words: [3]public_data.OutputWord,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var result: Fixture = undefined;
        result.input_words = .{0x0033_2211};
        result.output_words = .{
            .{ .addr = 0x4000, .value = 5, .clock = access_clock.encode(1, .first) },
            .{ .addr = 0x5000, .value = 0x0403_0201, .clock = access_clock.encode(1, .second) },
            .{ .addr = 0x5004, .value = 5, .clock = access_clock.encode(1, .third) },
        };
        result.statement = admittedCore(1);
        // These slices are rebound after the value reaches its final address;
        // returning a statement that points into a moved temporary would make
        // the fresh-process ownership test meaningless.
        result.statement.public_data.io_entries = .{
            .input_start = 0x3000,
            .input_len = 3,
            .input_words = &result.input_words,
            .output_len = 5,
            .output_len_addr = 0x4000,
            .output_data_addr = 0x5000,
            .output_words = &result.output_words,
        };
        result.extension = try guest_statement.ExtensionStatement.canonical(
            &result.statement,
            1,
        );
        result.identity = try artifact_identity.Identity.canonical(
            &result.statement,
            &result.extension,
        );
        result.claim = try zeroClaim(
            allocator,
            &result.statement,
            &result.extension,
            37,
        );
        errdefer result.claim.destroy(allocator);
        const shape = try subject.proofPreflightShape(
            test_config,
            &result.statement,
            &result.extension,
            .{},
        );
        result.proof = try syntheticProof(allocator, test_config, shape);
        return result;
    }

    fn rebind(self: *Fixture) void {
        self.statement.public_data.io_entries.input_words = &self.input_words;
        self.statement.public_data.io_entries.output_words = &self.output_words;
    }

    fn encode(self: *Fixture, allocator: std.mem.Allocator) ![]u8 {
        self.rebind();
        // Recompute the two statement-dependent identities after rebind. Slice
        // addresses are not hashed, but doing so keeps this helper honest if
        // public-data identity ever changes representation.
        self.extension = try guest_statement.ExtensionStatement.canonical(&self.statement, 1);
        self.identity = try artifact_identity.Identity.canonical(&self.statement, &self.extension);
        return subject.encodeAlloc(allocator, .{
            .pcs_config = test_config,
            .statement = &self.statement,
            .extension = &self.extension,
            .artifact = self.identity,
            .interaction_claim = self.claim,
            .proof = &self.proof,
        });
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        self.claim.destroy(allocator);
        self.* = undefined;
    }
};

fn admittedCore(n_guest: u32) base_statement.RiscVStatement {
    var statement = support.coreFixture(n_guest);
    statement.public_data.completion = public_data.Completion.canonicalSelfLoop(
        statement.final_pc,
    );
    const clock_update = statement.infra_descs[2];
    statement.infra_descs[2] = .{
        .kind = .merkle,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    statement.infra_descs[3] = .{
        .kind = .poseidon2,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    statement.infra_descs[4] = clock_update;
    var index: usize = 5;
    for (component_order.lookupTables()) |kind| {
        statement.infra_descs[index] = .{
            .kind = base_statement.infraKindForTable(kind),
            .log_size = lookup_table_schema.logSize(kind),
            .n_rows = @intCast(lookup_table_schema.size(kind)),
            .n_columns = 1,
        };
        index += 1;
    }
    statement.n_infra = @intCast(index);
    return statement;
}

fn zeroClaim(
    allocator: std.mem.Allocator,
    statement: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    interaction_pow: u64,
) !*profile_types.InteractionClaim {
    const claim = try profile_types.InteractionClaim.initBaseInto(
        allocator,
        statement,
        extension,
    );
    errdefer claim.destroy(allocator);
    claim.base.initZeroInto();
    claim.base.n_components = statement.n_components;
    claim.base.n_infra = statement.n_infra;
    claim.base.interaction_pow = interaction_pow;
    const caller = [_]QM31{QM31.zero()} ** profile_types.caller_batch_count;
    const provider = [_]QM31{QM31.zero()} ** profile_types.provider_batch_count;
    try claim.finishCanonical(statement, extension, &caller, &provider);
    return claim;
}

fn syntheticProof(
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    shape: @import("interop_postcard").proof_preflight.Shape,
) !base_types.Proof {
    const commitments_slice = try allocator.alloc(base_types.Hasher.Hash, 4);
    errdefer allocator.free(commitments_slice);
    @memset(commitments_slice, .{0} ** @sizeOf(base_types.Hasher.Hash));
    const commitments = pcs.TreeVec(base_types.Hasher.Hash).initOwned(commitments_slice);

    const sampled_values = try sampledTrees(allocator, shape.tree_columns);
    errdefer {
        var owned = sampled_values;
        owned.deinitDeep(allocator);
    }
    const decommitments = try emptyDecommitments(allocator);
    errdefer {
        var owned = decommitments;
        for (owned.items) |*value| value.deinit(allocator);
        owned.deinit(allocator);
    }
    const queried_values = try queriedTrees(allocator, shape.tree_columns);
    errdefer {
        var owned = queried_values;
        owned.deinitDeep(allocator);
    }
    const fri_proof = try syntheticFriProof(allocator, config, shape.max_column_log_size);

    return .{ .commitment_scheme_proof = .{
        .config = config,
        .commitments = commitments,
        .sampled_values = sampled_values,
        .decommitments = decommitments,
        .queried_values = queried_values,
        .proof_of_work = 0,
        .fri_proof = fri_proof,
    } };
}

fn sampledTrees(
    allocator: std.mem.Allocator,
    counts: [4]u32,
) !pcs.TreeVec([][]QM31) {
    const trees = try allocator.alloc([][]QM31, counts.len);
    errdefer allocator.free(trees);
    var initialized_trees: usize = 0;
    errdefer for (trees[0..initialized_trees]) |columns| {
        for (columns) |column| allocator.free(column);
        allocator.free(columns);
    };
    for (counts, 0..) |count, tree_index| {
        const columns = try allocator.alloc([]QM31, count);
        errdefer allocator.free(columns);
        var initialized_columns: usize = 0;
        errdefer for (columns[0..initialized_columns]) |column| allocator.free(column);
        for (columns) |*column| {
            column.* = try allocator.dupe(QM31, &.{QM31.zero()});
            initialized_columns += 1;
        }
        trees[tree_index] = columns;
        initialized_trees += 1;
    }
    return pcs.TreeVec([][]QM31).initOwned(trees);
}

fn queriedTrees(
    allocator: std.mem.Allocator,
    counts: [4]u32,
) !pcs.TreeVec([][]M31) {
    const trees = try allocator.alloc([][]M31, counts.len);
    errdefer allocator.free(trees);
    var initialized_trees: usize = 0;
    errdefer for (trees[0..initialized_trees]) |columns| {
        for (columns) |column| allocator.free(column);
        allocator.free(columns);
    };
    for (counts, 0..) |count, tree_index| {
        const columns = try allocator.alloc([]M31, count);
        errdefer allocator.free(columns);
        var initialized_columns: usize = 0;
        errdefer for (columns[0..initialized_columns]) |column| allocator.free(column);
        for (columns) |*column| {
            column.* = try allocator.alloc(M31, 0);
            initialized_columns += 1;
        }
        trees[tree_index] = columns;
        initialized_trees += 1;
    }
    return pcs.TreeVec([][]M31).initOwned(trees);
}

fn emptyDecommitments(
    allocator: std.mem.Allocator,
) !pcs.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(base_types.Hasher)) {
    const T = core.vcs_lifted.verifier.MerkleDecommitmentLifted(base_types.Hasher);
    const values = try allocator.alloc(T, 4);
    errdefer allocator.free(values);
    var initialized: usize = 0;
    errdefer for (values[0..initialized]) |*value| value.deinit(allocator);
    for (values) |*value| {
        value.* = .{ .hash_witness = try allocator.alloc(base_types.Hasher.Hash, 0) };
        initialized += 1;
    }
    return pcs.TreeVec(T).initOwned(values);
}

fn syntheticFriProof(
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    max_log_size: u32,
) !core.fri.FriProof(base_types.Hasher) {
    const Layer = core.fri.FriLayerProof(base_types.Hasher);
    var first = try emptyFriLayer(allocator);
    errdefer first.deinit(allocator);
    const after_first = max_log_size - config.fri_config.fold_step;
    const remaining = after_first - config.fri_config.log_last_layer_degree_bound;
    const inner_count = try std.math.divCeil(
        u32,
        remaining,
        config.fri_config.fold_step,
    );
    const inner = try allocator.alloc(Layer, inner_count);
    errdefer allocator.free(inner);
    var initialized: usize = 0;
    errdefer for (inner[0..initialized]) |*layer| layer.deinit(allocator);
    for (inner) |*layer| {
        layer.* = try emptyFriLayer(allocator);
        initialized += 1;
    }
    const coefficient_count = @as(usize, 1) <<
        @intCast(config.fri_config.log_last_layer_degree_bound);
    const coefficients = try allocator.alloc(QM31, coefficient_count);
    @memset(coefficients, QM31.zero());
    return .{
        .first_layer = first,
        .inner_layers = inner,
        .last_layer_poly = core.poly.line.LinePoly.initOwned(coefficients),
    };
}

fn emptyFriLayer(allocator: std.mem.Allocator) !core.fri.FriLayerProof(base_types.Hasher) {
    const witness = try allocator.alloc(QM31, 0);
    errdefer allocator.free(witness);
    const hashes = try allocator.alloc(base_types.Hasher.Hash, 0);
    return .{
        .fri_witness = witness,
        .decommitment = .{ .hash_witness = hashes },
        .commitment = .{0} ** @sizeOf(base_types.Hasher.Hash),
    };
}

fn expectStatementEqual(
    expected: *const base_statement.RiscVStatement,
    actual: *const base_statement.RiscVStatement,
) !void {
    try std.testing.expectEqual(expected.n_components, actual.n_components);
    try std.testing.expectEqualSlices(
        base_statement.FamilyComponentDesc,
        expected.component_descs[0..expected.n_components],
        actual.component_descs[0..actual.n_components],
    );
    try std.testing.expectEqual(expected.initial_pc, actual.initial_pc);
    try std.testing.expectEqual(expected.final_pc, actual.final_pc);
    try std.testing.expectEqual(expected.total_steps, actual.total_steps);
    try std.testing.expectEqual(expected.n_infra, actual.n_infra);
    try std.testing.expectEqualSlices(
        base_statement.InfraComponentDesc,
        expected.infra_descs[0..expected.n_infra],
        actual.infra_descs[0..actual.n_infra],
    );
    try std.testing.expectEqualSlices(u32, expected.public_data.io_entries.input_words, actual.public_data.io_entries.input_words);
    try std.testing.expectEqualSlices(public_data.OutputWord, expected.public_data.io_entries.output_words, actual.public_data.io_entries.output_words);
    var expected_without_io = expected.public_data;
    var actual_without_io = actual.public_data;
    expected_without_io.io_entries.input_words = &.{};
    expected_without_io.io_entries.output_words = &.{};
    actual_without_io.io_entries.input_words = &.{};
    actual_without_io.io_entries.output_words = &.{};
    try std.testing.expect(std.meta.eql(expected_without_io, actual_without_io));
}

const SectionOffsets = struct { statement: usize, extension: usize, identity: usize, claim: usize, proof: usize };

fn sectionOffsets(bytes: []const u8) SectionOffsets {
    const statement = subject.header_size;
    const extension = statement + readInt(u32, bytes, subject.HeaderOffset.statement_length);
    const identity = extension + readInt(u32, bytes, subject.HeaderOffset.extension_length);
    const claim = identity + readInt(u32, bytes, subject.HeaderOffset.identity_length);
    const proof = claim + readInt(u32, bytes, subject.HeaderOffset.claim_length);
    return .{ .statement = statement, .extension = extension, .identity = identity, .claim = claim, .proof = proof };
}

fn callerClaimOffset(statement: *const base_statement.RiscVStatement) usize {
    var offset: usize = 1 + @sizeOf(u32);
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        offset += @sizeOf(@typeInfo(@TypeOf(descriptor.family)).@"enum".tag_type) + @sizeOf(u16) +
            opcode_entries.batchCount(descriptor.family) * qm31EncodedSize();
    }
    offset += @sizeOf(u32);
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        offset += @sizeOf(u32) + @sizeOf(u16) +
            base_statement.nClaimedSumsForInfra(descriptor.kind) * qm31EncodedSize();
    }
    return offset + @sizeOf(u64);
}

fn descriptorEncodedSize() usize {
    return 2 + 4 + 2 + 4 + 4 + 2 + 2 + 2;
}

fn descriptorNRowsOffset() usize {
    return 2 + 4 + 2;
}

fn qm31EncodedSize() usize {
    return 4 * @sizeOf(u32);
}

fn readInt(comptime T: type, bytes: []const u8, offset: usize) T {
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

fn writeInt(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

fn expectDecodeFailure(bytes: []const u8) !void {
    if (subject.decodeAlloc(std.testing.allocator, bytes)) |*decoded| {
        var owned = decoded.*;
        owned.deinit(std.testing.allocator);
        return error.ExpectedDecodeFailure;
    } else |_| {}
}
