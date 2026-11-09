//! Exact old-suite control for the shared row/kernel/payload extractions.
const std = @import("std");
const core = @import("stwo_core");
const T = @import("../pure_p2_truth_worker.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const M = @import("../pure_p2_manifest.zig");
const Hook = struct {
    pub fn run(a: std.mem.Allocator, _: *const T.Key, truth: R.Truth, _: M.Expected, _: *const M.Pending, proof: *const T.Encoded, _: anytype) !void {
        const bytes = try T.encode(a, proof);
        defer a.free(bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        try std.testing.expectEqualStrings(if (truth == .keccak) "7d016c87d09fa24ddfe2516b80840025c3c16cd01430e3be5e1ec9458542ec38" else "057eb42d0bfeba92f06f7d6135b73f2b84ca3af0e77ebce4cc08bbd548e0f3c6", &std.fmt.bytesToHex(digest, .lower));
        std.debug.print("OP_TRUTH_CLASSIC_PARITY kind={s} bytes={d} sha256={s}\n", .{ @tagName(truth), bytes.len, std.fmt.bytesToHex(digest, .lower) });
    }
};
test "OP truth classic extraction exact bytes control" {
    const a = std.testing.allocator;
    var keccak = try @import("../../word16_global_execution/keccak/shared/roster.zig").TruthSetup.init(a, 5);
    defer keccak.deinit();
    try @import("../pure_p2_truth_catalog_test.zig").runWithHook(.{ .keccak = .{ .setup = &keccak, .first_id = 3, .calls = 2 } }, Hook);
    const S = @import("stwo_riscv_frontend").rv64_air.crypto.secp256k1;
    const logs = [2]u32{ try S.layout.logSize(.product, S.program.get(.add), 1), try S.layout.logSize(.linear, S.program.get(.add), 1) };
    var secp = try @import("../../word16_global_execution/secp/roster.zig").TruthSetup.init(a, .add, logs);
    defer secp.deinit();
    try @import("../pure_p2_truth_catalog_test.zig").runWithHook(.{ .secp = .{ .setup = &secp, .first_id = 5, .calls = 1 } }, Hook);
}
