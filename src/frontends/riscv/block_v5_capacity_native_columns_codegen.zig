//! Actual CPU collection, reconstruction, original PCS transfer and teardown
//! bodies retained without invocation. No guest/commitment/proof/device runs.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Owner = @import("prover/blake3_execution_trace.zig").Owner;
const Profile = @import("isa/execution_profile.zig").ExecutionProfile;
const Public = @import("prover/block_v5_native_public_admission_v1.zig");
const Root = @import("prover/block_v5_cpu_capacity_root_proposal_v1.zig");
const Stage = @import("prover/block_v5_capacity_native_columns_stage_v1.zig");
const Api = Stage.ForBackend(Cpu);
const Native = @import("prover/block_v5_native_capacity_proof_v1.zig").ForBackend(Cpu);
const OldRoot = @import("prover/block_v5_cpu_native_root_proposal_v1.zig");
const OldStage = @import("prover/block_v5_native_columns_stage_v1.zig");
const OldApi = OldStage.ForBackend(Cpu);
fn collect(a: std.mem.Allocator, owner: *Owner, config: core.pcs.PcsConfig, profile: Profile, index: u32, first_cycle: u64, limits: Root.Limits) anyerror!Root.Proposal {
    return Root.ForBackend(Cpu).collect(a, owner, config, profile, index, first_cycle, limits);
}
fn collectFixed(a: std.mem.Allocator, owner: *Owner, config: core.pcs.PcsConfig, profile: Profile, index: u32, first_cycle: u64, limits: Root.Limits, basis: *Api.FixedBasis) anyerror!Root.Proposal {
    return Root.ForBackend(Cpu).collectWithBasis(a, owner, config, profile, index, first_cycle, limits, basis);
}
fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, owner: *const Owner, proposal: *const Root.Proposal, limits: Stage.Limits) anyerror!Stage.Pin {
    return Stage.write(a, dir, name, owner, proposal, limits);
}
fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Stage.Pin, limits: Stage.Limits, profile: Profile) anyerror!Api.Prepared {
    return Api.load(a, dir, name, proposal, pin, limits, profile);
}
fn loadFixed(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Stage.Pin, limits: Stage.Limits, profile: Profile, basis: *Api.FixedBasis) anyerror!Api.Prepared {
    return Api.loadWithBasis(a, dir, name, proposal, pin, limits, profile, basis);
}
fn take(self: *Api.Prepared, proposal: *const Root.Proposal, pin: Public.Admission) anyerror!Native.FirstRound {
    return self.takeFirstRound(proposal, pin);
}
fn oldWrite(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, owner: *const Owner, proposal: *const OldRoot.Proposal, limits: OldStage.Limits) anyerror!OldStage.Pin {
    return OldStage.write(a, dir, name, owner, proposal, limits);
}
fn oldLoad(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const OldRoot.Proposal, pin: OldStage.Pin, limits: OldStage.Limits, profile: Profile) anyerror!OldApi.Prepared {
    return OldApi.load(a, dir, name, proposal, pin, limits, profile);
}
fn oldTake(self: *OldApi.Prepared, proposal: *const OldRoot.Proposal, pin: Public.Admission) anyerror!@import("prover/block_v5_native_execution_proof_v3.zig").ForBackend(Cpu).FirstRound {
    return self.takeFirstRound(proposal, pin);
}
export fn stwo_capacity_staged_columns_body_gate() void {
    inline for (.{ &collect, &collectFixed, &write, &load, &loadFixed, &take, &Api.Prepared.deinit, &oldWrite, &oldLoad, &oldTake, &OldApi.Prepared.deinit, &Stage.rebuildOwner, &Root.Proposal.bind, &Root.Proposal.requireReplay, &Root.Proposal.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
