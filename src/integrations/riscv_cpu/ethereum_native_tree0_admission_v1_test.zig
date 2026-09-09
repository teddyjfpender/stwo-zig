const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const subject = @import("ethereum_native_tree0_admission_v1.zig");
const extension_mod = frontend.air.guest_precompile.ethereum_statement;
const bridge = frontend.prover_mod.incremental_bridge_external_v3;
const BaseEngine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
const Engine = struct {
    pub const Hasher = BaseEngine.Hasher;
    pub const Channel = BaseEngine.Channel;
    pub const Scheme = BaseEngine.Scheme;
    pub const init = BaseEngine.init;
    pub const deinit = BaseEngine.deinit;
    var commits: usize = 0;
    pub fn commit(scheme: *Scheme, allocator: std.mem.Allocator, columns: []@import("stwo_prover_engine").pcs.ColumnEvaluation, recorder: anytype, channel: *Channel) !void {
        commits += 1;
        try BaseEngine.commit(scheme, allocator, columns, recorder, channel);
    }
};
const PCS: core.pcs.PcsConfig = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };

fn fixture() !struct { native: frontend.air.statement.RiscVStatement, extension: extension_mod.Statement, geometry: bridge.GeometryV3, prefix: bridge.PrefixColumnsV3 } {
    const native = frontend.testing.guest_precompile_main_trace_support.coreFixture(0);
    const empty: extension_mod.Shape = .{ .log_size = 1, .n_rows = 0 };
    const extension = try extension_mod.Statement.canonical(&native, 0, 0, .{ .product_base = empty, .product_scalar = empty, .linear_base = empty, .linear_scalar = empty, .point = empty, .split = empty, .scalar = empty, .table = empty, .recovery = empty, .byte = .{ .log_size = 8, .n_rows = 256 }, .recovery_caller = empty });
    const manifest = frontend.air.lookup_physical_manifest_v2.Manifest.native();
    const authenticated = try frontend.air.lookup_physical_manifest_v2.AuthenticatedStatement.init(&native, &manifest);
    var prefix: bridge.PrefixColumnsV3 = .{ .preprocessed = native.nPreprocessedColumns(), .main = native.nMainColumns(), .interaction = @intCast(try authenticated.totalInteractionColumns(&native, &manifest)) };
    for (extension.components) |descriptor| {
        prefix.preprocessed += descriptor.preprocessed_columns;
        prefix.main += descriptor.main_columns;
        prefix.interaction += descriptor.interaction_columns;
    }
    return .{ .native = native, .extension = extension, .geometry = try bridge.GeometryV3.canonicalAfterPrefix(1, prefix), .prefix = prefix };
}

test "Ethereum native Tree0 admission derives once and rejects fixed shape mutations" {
    const allocator = std.testing.allocator;
    var source = try fixture();
    Engine.commits = 0;
    const owner = try subject.NativeTree0AdmissionV1.create(Engine, allocator, &source.native, &source.extension, &source.geometry, PCS);
    defer owner.deinit();
    const expected = owner.root().*;
    const identity = owner.shapeIdentity();
    try std.testing.expectEqual(@as(usize, 1), Engine.commits);
    for (0..100) |_| {
        try owner.validateShape(&source.native, &source.extension, &source.geometry, PCS);
        try std.testing.expectEqualDeep(expected, owner.root().*);
        try std.testing.expectEqualDeep(identity, owner.shapeIdentity());
    }
    try std.testing.expectEqual(@as(usize, 1), Engine.commits);
    var bad_native = source.native;
    bad_native.component_descs[0].n_rows += 1;
    try std.testing.expectError(error.InvalidEthereumNativeTree0Shape, owner.validateShape(&bad_native, &source.extension, &source.geometry, PCS));
    var bad_extension = source.extension;
    bad_extension.counts.keccak_calls += 1;
    try std.testing.expectError(error.InvalidEthereumNativeTree0Shape, owner.validateShape(&source.native, &bad_extension, &source.geometry, PCS));
    const other_geometry = try bridge.GeometryV3.canonicalAfterPrefix(2, source.prefix);
    try std.testing.expectError(error.InvalidEthereumNativeTree0Shape, owner.validateShape(&source.native, &source.extension, &other_geometry, PCS));
    var bad_pcs = PCS;
    bad_pcs.pow_bits += 1;
    try std.testing.expectError(error.InvalidEthereumNativeTree0Shape, owner.validateShape(&source.native, &source.extension, &source.geometry, bad_pcs));
    // Boundary values are deliberately dynamic and have separate AIR routes.
    source.native.initial_pc ^= 4;
    source.native.public_data.initial_regs[1] ^= 1;
    source.extension.admission.memory_relation_terms += 1;
    try owner.validateShape(&source.native, &source.extension, &source.geometry, PCS);
    source = undefined;
    try std.testing.expectEqualDeep(expected, owner.root().*);
    try std.testing.expectEqual(@as(usize, 1), Engine.commits);
}

test "Ethereum native Tree0 fixed bridge selectors change actual PCS commitment" {
    const allocator = std.testing.allocator;
    const source = try fixture();
    const owner = try subject.NativeTree0AdmissionV1.create(Engine, allocator, &source.native, &source.extension, &source.geometry, PCS);
    defer owner.deinit();
    const independently_derived = try frontend.prover_mod.deriveIncrementalEthereumPreprocessedRootV4(Engine, allocator, &source.native, &source.extension, &source.geometry, PCS);
    try std.testing.expectEqualDeep(independently_derived, owner.root().*);
    const other_geometry = try bridge.GeometryV3.canonicalAfterPrefix(2, source.prefix);
    const other = try subject.NativeTree0AdmissionV1.create(Engine, allocator, &source.native, &source.extension, &other_geometry, PCS);
    defer other.deinit();
    try std.testing.expect(!std.meta.eql(owner.root().*, other.root().*));
    try std.testing.expect(!std.meta.eql(owner.shapeIdentity(), other.shapeIdentity()));
}

test "Ethereum fixed program recursive Tree0 admission binds whole ELF beyond identical roots" {
    const allocator = std.testing.allocator;
    const program_mod = @import("ethereum_fixed_program_admission_v1.zig");
    const elf = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig").programElf();
    var expected_sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &expected_sha, .{});
    const program = try program_mod.OwnedV1.createFromElf(allocator, &elf, expected_sha);
    defer program.deinit();
    const changed_elf = try allocator.alloc(u8, elf.len + 1);
    defer allocator.free(changed_elf);
    @memcpy(changed_elf[0..elf.len], &elf);
    changed_elf[elf.len] = 0x5a;
    std.crypto.hash.sha2.Sha256.hash(changed_elf, &expected_sha, .{});
    const other_program = try program_mod.OwnedV1.createFromElf(allocator, changed_elf, expected_sha);
    defer other_program.deinit();
    var source = try fixture();
    source.native.infra_descs[0].n_rows = program.descriptor().row_count;
    source.native.infra_descs[0].log_size = @max(1, std.math.log2_int_ceil(u32, program.descriptor().row_count));
    const empty: extension_mod.Shape = .{ .log_size = 1, .n_rows = 0 };
    source.extension = try extension_mod.Statement.canonical(&source.native, 0, 0, .{ .product_base = empty, .product_scalar = empty, .linear_base = empty, .linear_scalar = empty, .point = empty, .split = empty, .scalar = empty, .table = empty, .recovery = empty, .byte = .{ .log_size = 8, .n_rows = 256 }, .recovery_caller = empty });
    source.prefix.preprocessed += frontend.air.program.fixed_table_v1.COLUMN_COUNT;
    source.geometry = try bridge.GeometryV3.canonicalAfterPrefix(1, source.prefix);
    Engine.commits = 0;
    const owner = try subject.NativeTree0AdmissionV1.createWithProgram(Engine, allocator, &source.native, &source.extension, &source.geometry, PCS, program);
    defer owner.deinit();
    const other = try subject.NativeTree0AdmissionV1.createWithProgram(Engine, allocator, &source.native, &source.extension, &source.geometry, PCS, other_program);
    defer other.deinit();
    try std.testing.expectEqualDeep(owner.root().*, other.root().*);
    try std.testing.expect(!std.meta.eql(owner.shapeIdentity(), other.shapeIdentity()));
    for (0..3) |_| try owner.validateShapeWithProgram(&source.native, &source.extension, &source.geometry, PCS, program);
    try std.testing.expectEqual(@as(usize, 2), Engine.commits);
    try std.testing.expectError(error.EthereumFixedProgramAdmissionMismatch, owner.validateShapeWithProgram(&source.native, &source.extension, &source.geometry, PCS, other_program));
    try std.testing.expectError(error.InvalidEthereumNativeTree0Shape, owner.validateShape(&source.native, &source.extension, &source.geometry, PCS));
}
