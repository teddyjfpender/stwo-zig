//! Independently derived family11 six-table demand for field-safe groups.
//! This is planning metadata. Fresh same-root projection supplies the claims.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Plan = @import("block_v5_native_lookup_plan_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");

pub fn fromStatement(a: std.mem.Allocator, statement: *const Profile.admission.Statement, total_steps: u32, config: core.pcs.PcsConfig) ![Schema.KIND_COUNT]u64 {
    try Protocol.validate(statement, total_steps, config);
    try Witness.validateAdmission(a, statement);
    // SHA weights come from all five authenticated AIRs and padding patterns.
    // Keccak and signer add their shipped caller effects. No proof claims or
    // prover-produced counter contents choose the admitted closure bounds.
    return Profile.fixedBounds(statement);
}
pub fn add(a: std.mem.Allocator, demand: *[Schema.KIND_COUNT]u64, statement: *const Profile.admission.Statement, total_steps: u32, config: core.pcs.PcsConfig) !void {
    try Plan.addDemand(demand, try fromStatement(a, statement, total_steps, config));
}
