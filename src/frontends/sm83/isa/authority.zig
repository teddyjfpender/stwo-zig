//! Immutable SM83 conformance authorities.

const std = @import("std");

pub const opcode_repository = "https://github.com/gbdev/gb-opcodes";
pub const opcode_revision = "376f61c86fdac2048f7ce5fe838ae756b306017e";
pub const opcode_json_url = "https://gbdev.io/gb-opcodes/Opcodes.json";
pub const opcode_json_sha256 = "e7e3cd657d8e87b44570474eb3a6ed735501c9a00520f3d6937881203c823bc5";

pub const pandocs_repository = "https://github.com/gbdev/pandocs";
pub const pandocs_revision = "fe246067b695b5404a4a6a47efb4fd6d921ececb";

pub const single_step_repository = "https://github.com/SingleStepTests/sm83";
pub const single_step_revision = "f9c30210245dd691661db39f5ace022c465ecc2f";
/// SHA-256 of the 500 JSON files concatenated in base-opcode then CB-opcode
/// order. This pins content even when the corpus checkout is dirty.
pub const single_step_v1_sha256 = "f4116a3776c2c5e25bfffa75d41b0b4af78fb75b4e8cfd9785efd76a9abeca0a";

pub const sameboy_repository = "https://github.com/LIJI32/SameBoy";
pub const sameboy_revision = "213a12ce93d66b105a113debd9396306066a7cfc";

pub const blargg_repository = "https://github.com/retrio/gb-test-roms";
pub const blargg_revision = "c240dd7d700e5c0b00a7bbba52b53e4ee67b5f15";

pub const mooneye_repository = "https://github.com/Gekkio/mooneye-test-suite";
pub const mooneye_revision = "31510e12eea6286d36eea060a6adde755e1067aa";
pub const mooneye_wla_revision = "89a90a56be5c2b8cf19a9afa3e1b32384ddb1a97";
pub const mooneye_release = "mts-20260714-0944-31510e1";
pub const mooneye_release_sha256 = "6d4fdda2f1d8d2f5f51b0ff3f6f3cc2fbae047aa395a39c82bda3a0e7cbd2641";

fn isLowerHex(value: []const u8, expected_len: usize) bool {
    if (value.len != expected_len) return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

test "SM83 authorities are exact immutable revisions" {
    try std.testing.expect(isLowerHex(opcode_revision, 40));
    try std.testing.expect(isLowerHex(opcode_json_sha256, 64));
    try std.testing.expect(isLowerHex(pandocs_revision, 40));
    try std.testing.expect(isLowerHex(single_step_revision, 40));
    try std.testing.expect(isLowerHex(single_step_v1_sha256, 64));
    try std.testing.expect(isLowerHex(sameboy_revision, 40));
    try std.testing.expect(isLowerHex(blargg_revision, 40));
    try std.testing.expect(isLowerHex(mooneye_revision, 40));
    try std.testing.expect(isLowerHex(mooneye_wla_revision, 40));
    try std.testing.expect(isLowerHex(mooneye_release_sha256, 64));
}
