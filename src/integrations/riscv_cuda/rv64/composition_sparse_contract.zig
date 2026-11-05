//! Pure allocation contract of the exact source-bound selected implementation.
//! Selection is supplied only after Runtime has bound the complete source/plan
//! identity to the loaded addon. It is not authority for external source owners.
const std = @import("std");
fn hex(comptime value: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, value) catch unreachable;
    return out;
}
pub const source = hex("0e888de1c14c0b10cf9fa622543e9c2fa737d33068f21d7406ce213ebe198c2a");
pub const plan = hex("d69b50e5c882403b008f9be4bb64bcebe4782ea06e001066b92d541f8756dd90");
pub const cache_words: u64 = 1024 * (1 << 20);
pub const scratch_words: u64 = 978470;
pub const Selection = struct {
    source: [32]u8,
    plan: [32]u8,
    pub fn validate(self: @This()) !void {
        if (!std.mem.eql(u8, &self.source, &source) or !std.mem.eql(u8, &self.plan, &plan)) return error.UnqualifiedSparseCompositionCost;
    }
};
