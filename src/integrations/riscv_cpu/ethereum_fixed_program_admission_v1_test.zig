const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const admission = @import("ethereum_fixed_program_admission_v1.zig");
const fixture = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
fn sha(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

test "Ethereum fixed program admission pins whole ELF independently of compatibility root" {
    const allocator = std.testing.allocator;
    const elf = fixture.programElf();
    const owner = blk: {
        const source = try allocator.dupe(u8, &elf);
        defer allocator.free(source);
        const value = try admission.OwnedV1.createFromElf(allocator, source, sha(&elf));
        source[0] ^= 1;
        break :blk value;
    };
    defer owner.deinit();
    try owner.validateDescriptor(owner.descriptor());
    const descriptor = owner.descriptor();
    const words = try descriptor.canonicalWords();
    try std.testing.expectEqualDeep(descriptor, try admission.DescriptorV1.fromCanonicalWords(words));
    var noncanonical = words;
    noncanonical[4] = 65536;
    try std.testing.expectError(error.InvalidFixedProgramDescriptor, admission.DescriptorV1.fromCanonicalWords(noncanonical));
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, descriptor.row_count, descriptor.compatibility_root }, words[0..4]);
    for (0..16) |index| {
        try std.testing.expectEqual(std.mem.readInt(u16, descriptor.elf_sha256[2 * index ..][0..2], .little), words[4 + index]);
        try std.testing.expectEqual(std.mem.readInt(u16, descriptor.decoded_table_sha256[2 * index ..][0..2], .little), words[20 + index]);
    }

    try std.testing.expectError(error.EthereumFixedProgramSourceMismatch, admission.OwnedV1.createFromElf(allocator, &elf, .{0} ** 32));
    const extended = try allocator.alloc(u8, elf.len + 1);
    defer allocator.free(extended);
    @memcpy(extended[0..elf.len], &elf);
    extended[elf.len] = 0x5a;
    const other = try admission.OwnedV1.createFromElf(allocator, extended, sha(extended));
    defer other.deinit();
    try std.testing.expectEqualDeep(try owner.rows(), try other.rows());
    try std.testing.expectEqual(owner.descriptor().compatibility_root, other.descriptor().compatibility_root);
    var transcript_a = frontend.recursion.poseidon2_channel.Channel{};
    var transcript_b = frontend.recursion.poseidon2_channel.Channel{};
    transcript_a.mixU32s(&try owner.descriptor().canonicalWords());
    transcript_b.mixU32s(&try other.descriptor().canonicalWords());
    try std.testing.expect(!std.meta.eql(transcript_a.digestWords(), transcript_b.digestWords()));
    try std.testing.expectError(error.EthereumFixedProgramAdmissionMismatch, owner.validateDescriptor(other.descriptor()));
    var changed = owner.descriptor();
    changed.decoded_table_sha256[0] ^= 1;
    try std.testing.expectError(error.EthereumFixedProgramAdmissionMismatch, owner.validateDescriptor(changed));
    changed = owner.descriptor();
    changed.compatibility_root +%= 1;
    try std.testing.expectError(error.EthereumFixedProgramAdmissionMismatch, owner.validateDescriptor(changed));
}

fn root(columns: *const frontend.air.program.fixed_table_v1.ColumnsV1) !frontend.recursion.poseidon2_channel.Digest {
    const allocator = std.testing.allocator;
    const Engine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    var scheme = try Engine.init(allocator, .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } });
    defer Engine.deinit(&scheme, allocator);
    const values = try allocator.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, columns.values.len);
    var initialized: usize = 0;
    var owned = true;
    errdefer if (owned) {
        for (values[0..initialized]) |value| allocator.free(@constCast(value.values));
        allocator.free(values);
    };
    for (columns.values, values) |column, *value| {
        value.* = .{ .log_size = columns.log_size, .values = try allocator.dupe(core.fields.m31.M31, column) };
        initialized += 1;
    }
    var channel = Engine.Channel{};
    owned = false;
    try Engine.commit(&scheme, allocator, values, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    return scheme.trees.items[0].root();
}

test "Ethereum fixed program table binds actual PCS root and preserves decoded columns" {
    const allocator = std.testing.allocator;
    const elf = fixture.programElf();
    const owner = try admission.OwnedV1.createFromElf(allocator, &elf, sha(&elf));
    defer owner.deinit();
    const rows = try owner.rows();
    const log: u32 = @max(4, std.math.log2_int_ceil(usize, rows.len));
    var columns = try owner.fixedColumns(allocator, log);
    defer columns.deinit(allocator);
    var main = try frontend.air.program.commitment.generateMain(allocator, rows, log);
    defer main.deinit(allocator);
    for (frontend.air.program.interaction.FIXED_MAIN_INDICES, columns.values) |index, column| try std.testing.expectEqualSlices(core.fields.m31.M31, main.values[index], column);
    const expected = try root(&columns);
    for (&columns.values) |*column| {
        const before = column.*[0];
        column.*[0] = before.add(core.fields.m31.M31.one());
        try std.testing.expect(!std.meta.eql(expected, try root(&columns)));
        column.*[0] = before;
    }
    try std.testing.expectEqualDeep(expected, try root(&columns));
}
