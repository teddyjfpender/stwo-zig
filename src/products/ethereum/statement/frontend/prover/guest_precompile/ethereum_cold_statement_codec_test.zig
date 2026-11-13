//! Product statement codec against the canonical native immutable public-data authority.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const public_data_v2 = @import("stwo_riscv_rv32").air.public_data_v2;
const support = @import("stwo_riscv_rv32").testing.air.public_data_test_support;

test "public data V2 cold statement codec retains immutable admission and rejects altered authority" {
    const allocator = std.testing.allocator;
    const wire = @import("ethereum_segment_artifact_statement_wire.zig");
    const native_v1 = @import("stwo_riscv_rv32").air.statement;
    const native_v2 = @import("stwo_riscv_rv32").air.statement_v2;
    var fixture = try support.Fixture.init();
    const source = fixture.leftSource();
    const words = try support.encode(allocator, &source);
    defer allocator.free(words);
    const data = try public_data_v2.PublicDataV2.authenticate(words);
    var core: native_v1.RiscVStatement = undefined;
    core.initializeDescriptorStorage();
    core.n_components = 1;
    core.component_descs[0] = .{ .family = .branch_eq, .log_size = 4, .n_rows = 3, .n_columns = 8 };
    core.n_infra = 0;
    core.public_data = try native_v2.canonicalCorePublicData(&data);
    core.initial_pc = core.public_data.initial_pc;
    core.final_pc = core.public_data.final_pc;
    core.total_steps = core.public_data.clock;
    const statement = try native_v2.RiscVStatementV2.init(core, data);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try wire.encode(encoded.writer(allocator), &statement, 1024 * 1024);
    var counters = public_data_v2.PublicDataV2.ValidationCountersV2{};
    var decoded = try wire.decodeWithColdLease(allocator, encoded.items, 1024 * 1024, &counters);
    defer decoded.deinit();
    for (0..8) |_| try decoded.value.validate();
    try std.testing.expectEqualDeep(statement.authority_id, decoded.value.authority_id);
    try std.testing.expectEqualSlices(M31, words, decoded.lease.ownedWords());
    // The transport is still externally mutable. Its altered authority cannot
    // change the admitted owner or mint a second one.
    encoded.items[encoded.items.len - 4] ^= 1;
    try decoded.value.validate();
    try std.testing.expectError(error.StatementAuthorityMismatch, wire.decodeWithColdLease(allocator, encoded.items, 1024 * 1024, null));
    try std.testing.expectEqual(@as(u64, 1), counters.snapshot().legacy_full_authentications);
}
