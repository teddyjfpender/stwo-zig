//! Export current typed encoding facts without executing or proving a guest.
//! This metadata supports work accounting, never proof/key admission.
const std = @import("std");
const Manifest = @import("frontends/riscv/air/lang/opcode_composition_manifest.zig");
const Tables = @import("frontends/riscv/air/lookups/tables/schema.zig");
const ReadAlias = @import("frontends/riscv/air/lang/typed_register_read_alias_candidate_v1.zig");
const TwoReadAlias = @import("frontends/riscv/air/lang/typed_two_read_register_alias_candidate_v1.zig");
const SelectorAlias = @import("frontends/riscv/air/lang/typed_load_store_selector_alias_candidate_v1.zig");

test "export typed RISC-V encoding work metadata" {
    const output = std.posix.getenv("STWO_RISCV_ENCODING_CENSUS_OUTPUT") orelse return error.SkipZigTest;
    const Family = struct {
        name: []const u8,
        authority_digest: [64]u8,
        main_columns: usize,
        direct_constraints: usize,
        lookup_events: usize,
        compatibility_interaction_columns: usize,
        /// Isolated source candidates only; production does not select them.
        candidate_main_columns: usize,
    };
    var families: [Manifest.FAMILY_COUNT]Family = undefined;
    for (Manifest.BY_FAMILY, &families) |descriptor, *family| family.* = .{
        .name = @tagName(descriptor.family),
        .authority_digest = std.fmt.bytesToHex(descriptor.authority_digest, .lower),
        .main_columns = descriptor.main_columns,
        .direct_constraints = descriptor.direct_constraints,
        .lookup_events = descriptor.lookup_events,
        .compatibility_interaction_columns = descriptor.interaction_columns,
        .candidate_main_columns = switch (descriptor.family) {
            .base_alu_imm => ReadAlias.profile(.base_alu_imm).main_column_count,
            .branch_eq => ReadAlias.profile(.branch_eq).main_column_count,
            .branch_lt => ReadAlias.profile(.branch_lt).main_column_count,
            .lt_reg => TwoReadAlias.profile(.lt_reg).main_column_count,
            .mul => TwoReadAlias.profile(.mul).main_column_count,
            .mulh => TwoReadAlias.profile(.mulh).main_column_count,
            .load_store => SelectorAlias.main_column_count,
            else => descriptor.main_columns,
        },
    };
    const Table = struct { name: []const u8, log_size: u32, arity: usize };
    var tables: [Tables.KIND_COUNT]Table = undefined;
    for (&tables, 0..) |*table, i| {
        const kind: Tables.Kind = @enumFromInt(i);
        table.* = .{ .name = @tagName(kind), .log_size = Tables.logSize(kind), .arity = Tables.arity(kind) };
    }
    const a = std.testing.allocator;
    const bytes = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo.riscv.typed-encoding-work-metadata.v1",
        .proof_authority = false,
        .manifest_version = Manifest.FORMAT_VERSION,
        .maximum_native_components = @import("frontends/riscv/air/statement_geometry.zig").MAX_COMPONENTS,
        .families = families,
        .tables = tables,
    }, .{});
    defer a.free(bytes);
    const file = try std.fs.cwd().createFile(output, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(bytes);
    try file.writeAll("\n");
}
