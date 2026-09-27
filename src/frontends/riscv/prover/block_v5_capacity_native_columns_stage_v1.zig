//! Witness-once B5CT producer. Files hold original native cells only; the real
//! capacity physical kernel regenerates proved activity/count main columns.
//! Rebuilt PCS must match retained first-pass pins and is transferred once.
const std = @import("std");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Root = @import("block_v5_cpu_capacity_root_proposal_v1.zig");
const Base = @import("blake3_execution_trace.zig");
const Rebuild = @import("block_v5_native_columns_rebuild_v1.zig");
const Store = @import("block_v5_witness_columns_store_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;
pub const Limits = Rebuild.Limits;
pub const Pin = Store.Pin;
pub fn scope(proposal: *const Root.Proposal) Store.Scope {
    return .{ .kind = .native, .execution_index = proposal.physical.index, .first_cycle = proposal.first_cycle, .cycle_count = proposal.physical.shape.total_steps, .descriptor_digest = proposal.physical.template_id, .first_roots = proposal.physical.roots };
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, owner: *const Base.Owner, proposal: *const Root.Proposal, limits: Limits) !Pin {
    try proposal.validate();
    if (!owner.native_only_v5 or !owner.tables_ready or owner.failed or owner.interaction_ready or owner.interaction.items.len != 0) return error.InvalidV5StagedNativePhase;
    try proposal.physical.template.admit(&owner.statement, owner.external_retirements, proposal.physical.template_id);
    if (owner.external_retirements != proposal.physical.external_retirements or
        !std.meta.eql(Public.publicDigest(&owner.statement.public_data), proposal.physical.public_digest)) return error.ChangedV5StagedNativePublic;
    try Rebuild.requirePublicLimits(&owner.statement, limits);
    return Store.write(a, dir, name, scope(proposal), owner.main.items, limits.columns);
}
/// Reconstructs only original base owner cells/counters. This function grants
/// no root or proof authority and performs no PCS operation.
pub fn rebuildOwner(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Pin, limits: Limits) !*Base.Owner {
    try proposal.validate();
    return Rebuild.rebuild(a, dir, name, &proposal.physical.shape, proposal.physical.external_retirements, scope(proposal), pin, limits);
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = Native.ForBackend(Backend);
        pub const FixedBasis = Api.FixedBasis;
        pub const Prepared = struct {
            owner: *Base.Owner,
            first: Api.PhysicalFirstRound,
            owns_first: bool = true,
            pub fn deinit(self: *Prepared, a: std.mem.Allocator) void {
                if (self.owns_first) self.first.deinit(a);
                self.owner.deinit();
                self.* = undefined;
            }
            /// Transfer the real already-committed PCS. Returned FirstRound
            /// must be released/proved before Prepared releases the owner.
            /// Failure before bind retains PCS; checked post-bind failure
            /// releases it and leaves Prepared owning the owner only.
            pub fn takeFirstRound(self: *Prepared, proposal: *const Root.Proposal, pin: Public.Admission) !Api.FirstRound {
                try proposal.validate();
                if (!self.owns_first or !self.first.owns_scheme or self.first.source != self.owner or self.first.index != proposal.physical.index or
                    !std.meta.eql(self.first.roots, proposal.physical.roots) or !std.meta.eql(self.first.template, proposal.physical.template) or
                    !std.meta.eql(self.first.template_id, proposal.physical.template_id) or !std.meta.eql(self.first.limits, proposal.limits.native)) return error.ChangedCapacityStagedNativeAdmission;
                try pin.validatePublic(&self.owner.statement.public_data);
                const candidate = try proposal.bind(pin.context);
                if (!std.meta.eql(pin, candidate.admission)) return error.ChangedCapacityStagedNativeAdmission;
                var first = try self.first.bind(pin);
                self.owns_first = false;
                errdefer first.deinit(self.owner.allocator);
                try proposal.requireReplay(&first);
                return first;
            }
        };
        pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Pin, limits: Limits, profile: Profile) !Prepared {
            return loadSelected(a, dir, name, proposal, pin, limits, profile, null);
        }
        pub fn loadWithBasis(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Pin, limits: Limits, profile: Profile, basis: *FixedBasis) !Prepared {
            return loadSelected(a, dir, name, proposal, pin, limits, profile, basis);
        }
        fn loadSelected(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Pin, limits: Limits, profile: Profile, basis: ?*FixedBasis) !Prepared {
            if (profile != proposal.physical.template.execution_profile) return error.ChangedCapacityStagedNativeAdmission;
            const owner = try rebuildOwner(a, dir, name, proposal, pin, limits);
            errdefer owner.deinit();
            var first = if (basis) |fixed| try Api.commitPhysicalWithBasis(a, owner, proposal.physical.template.config, profile, proposal.physical.index, proposal.limits.native, fixed) else try Api.commitPhysical(a, owner, proposal.physical.template.config, profile, proposal.physical.index, proposal.limits.native);
            errdefer first.deinit(a);
            if (!std.meta.eql(first.roots, proposal.physical.roots) or !std.meta.eql(first.template, proposal.physical.template) or
                !std.meta.eql(first.template_id, proposal.physical.template_id) or !std.meta.eql(first.public_digest, proposal.physical.public_digest)) return error.V5StagedNativeRootMismatch;
            return .{ .owner = owner, .first = first };
        }
    };
}
