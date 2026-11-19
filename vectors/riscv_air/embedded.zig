//! Test-only bridge that keeps the reviewed design artifacts authoritative.

pub const m2_production_shadow_machine =
    @embedFile("m2-production-shadow-report-v1.tsv");
pub const m2_production_shadow_markdown =
    @embedFile("m2-production-shadow-report-v1.md");

pub const p002_native_family_static_profile_machine =
    @embedFile("p002-native-family-static-profile-v1/profiles-v1.tsv");
pub const p002_native_family_static_profile_readable =
    @embedFile("p002-native-family-static-profile-v1/profiles-v1.md");

pub const m3_compat_v1_index =
    @embedFile("m3-compat-v1/index-v1.tsv");

/// Production `OpcodeFamily` order. Keeping the embed list literal makes a
/// missing reviewed artifact a compile error rather than a runtime skip.
pub const m3_compat_v1_manifests = [_][]const u8{
    @embedFile("m3-compat-v1/base_alu_reg.stwairc"),
    @embedFile("m3-compat-v1/base_alu_imm.stwairc"),
    @embedFile("m3-compat-v1/shifts_reg.stwairc"),
    @embedFile("m3-compat-v1/shifts_imm.stwairc"),
    @embedFile("m3-compat-v1/lt_reg.stwairc"),
    @embedFile("m3-compat-v1/lt_imm.stwairc"),
    @embedFile("m3-compat-v1/branch_eq.stwairc"),
    @embedFile("m3-compat-v1/branch_lt.stwairc"),
    @embedFile("m3-compat-v1/lui.stwairc"),
    @embedFile("m3-compat-v1/auipc.stwairc"),
    @embedFile("m3-compat-v1/jalr.stwairc"),
    @embedFile("m3-compat-v1/jal.stwairc"),
    @embedFile("m3-compat-v1/load_store.stwairc"),
    @embedFile("m3-compat-v1/mul.stwairc"),
    @embedFile("m3-compat-v1/mulh.stwairc"),
    @embedFile("m3-compat-v1/div.stwairc"),
    @embedFile("m3-compat-v1/fence.stwairc"),
};
