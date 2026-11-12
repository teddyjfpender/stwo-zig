//! Canonical tape, statement and immutable ROM compatibility.
const rv = @import("stwo_riscv_frontend").rv64;
const Full = @import("rv64_full.zig");
/// A v3 tape runs under the v2-decoded ROM authority (identical ISA effects);
/// every other profile must match exactly. In particular a v3_zbb tape (which
/// may retire Zbb BINARY instructions) needs a v3_zbb authority: its ROM is
/// the only one that decodes them, so this deliberately does not use isV3.
pub fn tapeMatches(tape: rv.execution_profile.Profile, authority: rv.execution_profile.Profile) bool {
    return tape == authority or (tape == .ethereum_services_v3 and authority == .ethereum_services_v2);
}
/// Legacy native statement + execution ROM admission of a tape (native batch,
/// packet writer and Word16 packet reader). Without a separate execution ROM
/// this is exactly `tapeMatches`. The Zbb route (v2-decoded statement, v3_zbb
/// ROM) admits only v3_zbb tapes, and a v3_zbb tape is admitted only there.
pub fn tapeAdmits(tape: rv.execution_profile.Profile, statement: rv.execution_profile.Profile, rom: rv.execution_profile.Profile) bool {
    if (rom == statement) return tapeMatches(tape, statement);
    return statement == .ethereum_services_v2 and rom == .ethereum_services_v3_zbb and tape == .ethereum_services_v3_zbb;
}
pub fn tapeAdmitted(tape: rv.execution_profile.Profile, authority: *const Full.ProgramAuthority) bool {
    return tapeAdmits(tape, authority.profile, authority.rom_profile);
}
