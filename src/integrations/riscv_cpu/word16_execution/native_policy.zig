//! Native protocol version policy (stream native-format, M6). One selector
//! for the producer AND the receiver: `STWO_RV64_NATIVE_VERSION`.
//!
//!   unset / "" / "v1-flat"           historical flat manifest digest (M5 default bytes)
//!   "m5-chi-chain-v1"                canon-native v1 chain (A1-flawed; diagnostic only)
//!   "m6-native-v2-strict"            rv64-m6-native/v2, profile v2-strict (strict roster + chain)
//!   "m6-native-v2-gkr"               rv64-m6-native/v2, profile v2-gkr (not implemented: refused)
//!
//! Unknown values are a clean error (negative corpus P03 counts an abort as a
//! FAIL). Spec: /workspace/m3/M6-INTERFACES.md section native-format and
//! design/riscv-proving-stack/rv64-m6-native-v2.md.
const std = @import("std");

pub const ENV = "STWO_RV64_NATIVE_VERSION";
pub const Version = enum {
    flat,
    m5_chain_v1,
    m6_v2_strict,
    m6_v2_gkr,
    pub fn chained(v: Version) bool {
        return v != .flat;
    }
    /// v2: every segment's declared component vector equals its class rung
    /// vector; rung components a segment does not use are committed as
    /// all-padding instances (presence is a class constant, not a count).
    pub fn strictRoster(v: Version) bool {
        return v == .m6_v2_strict or v == .m6_v2_gkr;
    }
};
pub const V1_NAME = "rv64-m5-native-chi-chain/v1";
pub const V2_NAME = "rv64-m6-native/v2";

pub fn parse(value: ?[]const u8) error{ UnknownNativeVersion, NativeVersionNotImplemented }!Version {
    const v = value orelse return .flat;
    if (v.len == 0 or std.mem.eql(u8, v, "v1-flat")) return .flat;
    if (std.mem.eql(u8, v, V1_NAME) or std.mem.eql(u8, v, "m5-chi-chain-v1")) return .m5_chain_v1;
    if (std.mem.eql(u8, v, "m6-native-v2-strict") or std.mem.eql(u8, v, "rv64-m6-native/v2/v2-strict")) return .m6_v2_strict;
    // The v2-gkr profile is specified (M6-INTERFACES NF4) but no prover,
    // receiver or leaf implements it yet: refuse it instead of silently
    // proving something else under its name.
    if (std.mem.eql(u8, v, "m6-native-v2-gkr") or std.mem.eql(u8, v, "rv64-m6-native/v2/v2-gkr")) return error.NativeVersionNotImplemented;
    return error.UnknownNativeVersion;
}
pub fn current() error{ UnknownNativeVersion, NativeVersionNotImplemented }!Version {
    return parse(std.posix.getenv(ENV));
}
/// Admission relaxation switch (presence of a component is a class constant
/// under the strict roster). An invalid selector reads as "not strict" here;
/// every entry point refuses it through `current()` first.
pub fn strictRoster() bool {
    const v = current() catch return false;
    return v.strictRoster();
}

test "native version selector" {
    try std.testing.expectEqual(Version.flat, try parse(null));
    try std.testing.expectEqual(Version.flat, try parse("v1-flat"));
    try std.testing.expectEqual(Version.m5_chain_v1, try parse("m5-chi-chain-v1"));
    try std.testing.expectEqual(Version.m6_v2_strict, try parse("m6-native-v2-strict"));
    try std.testing.expectError(error.NativeVersionNotImplemented, parse("m6-native-v2-gkr"));
    try std.testing.expectError(error.UnknownNativeVersion, parse("M6-NATIVE-V2-STRICT"));
    try std.testing.expect((try parse("m6-native-v2-strict")).strictRoster());
    try std.testing.expect(!(try parse("m5-chi-chain-v1")).strictRoster());
}
