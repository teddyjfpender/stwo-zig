//! Concrete entry-root binding for the existing relocated delegation suites/tools.
//! Zig file imports stay within the owning integration package. This selects
//! only already-registered source files and never accepts a caller-supplied path.
const std = @import("std");
pub const Kind = enum { test_root, cli };
pub const Id = enum { keccak_test, keccak_cpu_test, keccak_quartet_test, secp_test, division_test, multiplication_test, borrowed_test, keccak_fixture, keccak_verify, secp_fixture, division_verify, multiplication_verify };
pub const Selection = struct { root: []const u8, id: Id };
const PREFIX = "src/integrations/riscv_cpu/";
const Entry = struct { path: []const u8, kind: Kind, id: Id };
const entries = [_]Entry{
    .{ .path = "delegations/keccak/test_root.zig", .kind = .test_root, .id = .keccak_test },
    .{ .path = "delegations/keccak/cpu_test_root.zig", .kind = .test_root, .id = .keccak_cpu_test },
    .{ .path = "delegations/keccak/quartet_test_root.zig", .kind = .test_root, .id = .keccak_quartet_test },
    .{ .path = "delegations/secp256k1/test_root.zig", .kind = .test_root, .id = .secp_test },
    .{ .path = "delegations/division/test_root.zig", .kind = .test_root, .id = .division_test },
    .{ .path = "delegations/multiplication/test_root.zig", .kind = .test_root, .id = .multiplication_test },
    .{ .path = "delegations/common/borrowed_test_root.zig", .kind = .test_root, .id = .borrowed_test },
    .{ .path = "delegations/keccak/fixture_main.zig", .kind = .cli, .id = .keccak_fixture },
    .{ .path = "delegations/keccak/verify_main.zig", .kind = .cli, .id = .keccak_verify },
    .{ .path = "delegations/secp256k1/fixture_main.zig", .kind = .cli, .id = .secp_fixture },
    .{ .path = "delegations/division/verify_main.zig", .kind = .cli, .id = .division_verify },
    .{ .path = "delegations/multiplication/verify_main.zig", .kind = .cli, .id = .multiplication_verify },
};
pub fn select(source: []const u8, kind: Kind) ?Selection {
    if (!std.mem.startsWith(u8, source, PREFIX ++ "delegations/")) return null;
    const relative = source[PREFIX.len..];
    for (entries) |entry| if (std.mem.eql(u8, entry.path, relative) and entry.kind == kind) {
        return .{
            .root = if (kind == .test_root) PREFIX ++ "delegation_test_root.zig" else PREFIX ++ "delegation_main.zig",
            .id = entry.id,
        };
    };
    std.debug.panic("unregistered delegation {s} entry: {s}", .{ @tagName(kind), source });
}
pub fn bind(b: *std.Build, module: *std.Build.Module, selection: Selection) void {
    const options = b.addOptions();
    options.addOption(Id, "id", selection.id);
    module.addOptions("delegation_entry", options);
}
