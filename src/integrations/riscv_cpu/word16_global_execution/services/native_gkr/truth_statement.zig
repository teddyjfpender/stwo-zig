//! Direct compact truth segment statement for native-GKR only. Every public
//! span and signed mass shares one native/circuit visitor, before FS draws.
const std = @import("std");
const Canon = @import("../native_schema/canonical.zig");
const CPU = @import("cpu_statement.zig");
const Mass = @import("../gkr_local/mass_authority.zig");
const Wire = @import("../wire.zig");
pub const DOMAIN = "rv64/native-gkr/truth-publics/v2";
pub const Header = CPU.Header;
pub const Metadata = struct { ordinal: u32, execution: [32]u8, mass: Mass.Globals, relations: u32, family: u32, first_id: u32, calls: u32, logs: [2]u32 };
pub fn domainDigest() [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(DOMAIN, &out, .{});
    return out;
}
pub fn emit(header: anytype, metadata: anytype, h: anytype) void {
    h.digest(header.domain);
    inline for (.{ "class_key", "program", "config_identity", "fixed_identity", "fixed_root" }) |name| h.digest(@field(header, name));
    h.word(metadata.ordinal);
    h.digest(metadata.execution);
    h.words(&.{ metadata.family, metadata.first_id, metadata.calls });
    h.words(&metadata.logs);
    inline for (.{ "ram", "kio", "wire" }) |name| {
        h.int64(@field(metadata.mass, name).positive);
        h.int64(@field(metadata.mass, name).negative);
    }
    h.word(metadata.relations);
}
pub fn digest(header: Header, metadata: Metadata) ![32]u8 {
    if (!std.mem.eql(u8, &header.domain, &domainDigest())) return error.NativeGkrStatementDomain;
    var h = Canon.Hasher.init(.stmt);
    emit(header, metadata, &h);
    return h.final();
}
pub fn metadataFor(d: Wire.TruthDeclaration, ordinal: u32, execution: [32]u8, relations: u32) !Metadata {
    return .{ .ordinal = ordinal, .execution = execution, .mass = try Mass.truth(d), .relations = relations, .family = @intFromEnum(Canon.Family.truth(d.family)), .first_id = d.first_id, .calls = d.calls, .logs = d.logs };
}
test "compact truth statement authenticates span and both signed mass halves" {
    const header = Header{ .domain = domainDigest(), .class_key = @splat(1), .program = @splat(2), .config_identity = @splat(3), .fixed_identity = @splat(4), .fixed_root = @splat(5) };
    var metadata = Metadata{ .ordinal = 7, .execution = @splat(8), .mass = .{ .wire = .{ .positive = 12, .negative = 4 } }, .relations = 4, .family = 19, .first_id = 1, .calls = 3, .logs = .{ 10, 0 } };
    const expected = try digest(header, metadata);
    metadata.calls += 1;
    try std.testing.expect(!std.mem.eql(u8, &expected, &try digest(header, metadata)));
    metadata.calls -= 1;
    metadata.mass.wire.negative += @as(u64, 1) << 32;
    try std.testing.expect(!std.mem.eql(u8, &expected, &try digest(header, metadata)));
    var wrong = header;
    wrong.domain = CPU.domainDigest();
    try std.testing.expectError(error.NativeGkrStatementDomain, digest(wrong, metadata));
}
