//! Shared Ethereum prefix followed by SHA columns in canonical AIR order.
const std = @import("std");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const sha = @import("../../air/guest_precompile/sha256_component_profile.zig");
const Statement = @import("../blake3_ethereum_sha_statement.zig").Statement;
const ethereum_main = @import("ethereum_main_columns.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const sha_interaction = @import("sha256_interaction.zig");

pub fn preprocessed(a: std.mem.Allocator, statement: *const Statement) ![]Column {
    try statement.sha.validateForRecipe(statement.sha.call_count, statement.ethereum.localZeroCustody());
    var columns = std.ArrayList(Column).fromOwnedSlice(try @import("ethereum_preprocessed.zig").generateExtension(a, &statement.ethereum));
    errdefer free(a, &columns);
    try @import("../../air/guest_precompile/sha256_preprocessed.zig").append(a, statement.sha.call_count, true, &columns);
    return columns.toOwnedSlice(a);
}
pub const Main = struct {
    columns: []Column,
    ethereum: ethereum_main.Generated,
    sha_columns: std.ArrayList(Column),
    pub fn deinit(self: *Main, a: std.mem.Allocator) void {
        a.free(self.columns);
        self.ethereum.deinit(a);
        free(a, &self.sha_columns);
        self.* = undefined;
    }
};
pub fn main(a: std.mem.Allocator, witness: anytype) !Main {
    var ethereum = try ethereum_main.generate(a, &witness.extension);
    errdefer ethereum.deinit(a);
    var columns: std.ArrayList(Column) = .empty;
    errdefer free(a, &columns);
    const rows = witness.sha_rows.tuple();
    inline for (sha.AirsForRecipe(@TypeOf(witness.sha_rows).local_zero_custody), 0..) |Air, i| try @import("../../recursion/air/blake3_row_columns.zig").project(Air, a, rows[i], witness.sha_rows.geometry.logs[i], 1, &columns);
    return .{ .columns = try join(a, ethereum.columns, columns.items), .ethereum = ethereum, .sha_columns = columns };
}
pub const Interaction = struct {
    columns: []Column,
    ethereum: ethereum_interaction.Generated,
    sha_columns: sha_interaction.Generated,
    claim: @import("ethereum_sha_types.zig").ExtensionClaim,
    pub fn deinit(self: *Interaction, a: std.mem.Allocator) void {
        a.free(self.columns);
        self.ethereum.deinit(a);
        self.sha_columns.deinit(a);
        self.* = undefined;
    }
};
pub fn interactions(a: std.mem.Allocator, witness: anytype, relations: *const @import("ethereum_sha_relations.zig").Relations, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !Interaction {
    var ethereum = try ethereum_interaction.generate(a, &witness.extension, &relations.ethereum, pool);
    errdefer ethereum.deinit(a);
    var sha_columns = try sha_interaction.generate(a, &witness.sha_rows, &relations.sha);
    errdefer sha_columns.deinit(a);
    return .{ .columns = try join(a, ethereum.columns, sha_columns.columns), .ethereum = ethereum, .sha_columns = sha_columns, .claim = .{ .ethereum = ethereum.claim, .sha = sha_columns.claims } };
}
fn join(a: std.mem.Allocator, prefix: []const Column, suffix: []const Column) ![]Column {
    const result = try a.alloc(Column, try std.math.add(usize, prefix.len, suffix.len));
    @memcpy(result[0..prefix.len], prefix);
    @memcpy(result[prefix.len..], suffix);
    return result;
}
fn free(a: std.mem.Allocator, columns: *std.ArrayList(Column)) void {
    for (columns.items) |column| a.free(column.values);
    columns.deinit(a);
}
