//! Concrete register-only Word16 CPU protocol. No legacy RV64 profile selects
//! this module. A local proof must close BINARY truth; delegated FUNCTION debt
//! remains explicitly OPEN until the independent complete-manifest receiver.
const W = @import("stwo_riscv_frontend").rv64_air.word16_cpu;
pub const Public = W.public.Public;
pub const publicDigest = W.public.digest;
pub const Materials = @import("cpu_materials.zig").Materials;
pub const Geometry = @import("cpu_materials.zig").Geometry;
pub const Mode = @import("cpu_materials.zig").Mode;
pub const schema = @import("cpu_materials.zig").schema;
pub const Stage1 = @import("cpu_stage.zig").Stage1;
pub const Encoded = @import("cpu_stage.zig").Encoded;
pub const produce = @import("cpu_stage.zig").produce;
pub const produceProfiled = @import("cpu_stage.zig").produceProfiled;
pub const produceDeduplicated = @import("cpu_stage.zig").produceDeduplicated;
pub const produceDeduplicatedProfiled = @import("cpu_stage.zig").produceDeduplicatedProfiled;
pub const verifyClosed = @import("cpu_verify.zig").verifyClosed;
pub const verifyOpen = @import("cpu_verify.zig").verifyOpen;

pub const Profile = @import("stwo_riscv_frontend").rv64_air.word16_cpu.profile.Profile;
pub const schemaForProfile = @import("cpu_materials.zig").schemaForProfile;
