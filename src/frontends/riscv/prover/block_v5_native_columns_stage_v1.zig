//! Native witness-once owner reconstruction. Proposal files never grant proof
//! authority: the existing native physical kernel recommits loaded cells and
//! must reproduce the independently retained first-pass template and roots.
const std = @import("std");
const core = @import("stwo_core");
const Store = @import("block_v5_witness_columns_store_v1.zig");
const Native = @import("blake3_execution_trace.zig");
const Root = @import("block_v5_cpu_native_root_proposal_v1.zig");
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;
const Public = @import("block_v5_native_public_admission_v1.zig");
const Rebuild = @import("block_v5_native_columns_rebuild_v1.zig");
pub const Limits = Rebuild.Limits;
pub const Pin = Store.Pin;
fn scope(proposal: *const Root.Proposal) Store.Scope {
    return .{ .kind = .native, .execution_index = proposal.index, .first_cycle = proposal.first_cycle, .cycle_count = proposal.shape.total_steps, .descriptor_digest = proposal.template_id, .first_roots = proposal.roots };
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, owner: *const Native.Owner, proposal: *const Root.Proposal, limits: Limits) !Pin {
    if (!owner.native_only_v5 or !owner.tables_ready or owner.failed or owner.interaction_ready or owner.interaction.items.len != 0)
        return error.InvalidV5StagedNativePhase;
    try proposal.template.admit(&owner.statement, proposal.template_id);
    if (owner.external_retirements != proposal.template.external_retirements or
        !std.meta.eql(Public.publicDigest(&owner.statement.public_data), proposal.public_digest))
        return error.ChangedV5StagedNativePublic;
    try Rebuild.requirePublicLimits(&owner.statement, limits);
    return Store.write(a, dir, name, scope(proposal), owner.main.items, limits.columns);
}

fn rebuild(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Pin, limits: Limits) !*Native.Owner {
    try proposal.template.admit(&proposal.shape, proposal.template_id);
    if (!std.meta.eql(Public.publicDigest(&proposal.shape.public_data), proposal.public_digest)) return error.ChangedV5StagedNativePublic;
    return Rebuild.rebuild(a, dir, name, &proposal.shape, proposal.template.external_retirements, scope(proposal), pin, limits);
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Physical = Root.ForBackend(Backend);
        pub const Prepared = struct {
            owner: *Native.Owner,
            first: Physical.PhysicalFirstRound,
            owns_first: bool = true,
            pub fn deinit(self: *Prepared, a: std.mem.Allocator) void {
                if (self.owns_first) self.first.deinit(a);
                self.owner.deinit();
                self.* = undefined;
            }
            /// Move the real recommitted PCS into the existing native-v3
            /// producer after independent late admission. The returned first
            /// round must be released BEFORE this Prepared's owner.
            pub fn takeFirstRound(self: *Prepared, proposal: *const Root.Proposal, pin: Public.Admission) !@import("block_v5_native_execution_proof_v3.zig").ForBackend(Backend).FirstRound {
                if (!self.owns_first or !std.meta.eql(self.first.roots, proposal.roots) or
                    !std.meta.eql(self.first.template, proposal.template) or
                    !std.meta.eql(self.first.template_id, proposal.template_id)) return error.ChangedV5StagedNativeAdmission;
                try pin.validatePublic(&self.owner.statement.public_data);
                const bound = try proposal.bind(pin.context);
                const Api = @import("block_v5_native_execution_proof_v3.zig").ForBackend(Backend);
                const first = Api.FirstRound{ .scheme = self.first.scheme, .roots = self.first.roots, .template = self.first.template, .template_id = self.first.template_id, .instance_id = bound.entry.instance_id, .index = proposal.index, .native = self.owner, .pin = pin };
                self.owns_first = false;
                return first;
            }
        };
        /// Returned PCS owns the one fresh recommit so a subsequent admitted
        /// producer can consume it without an additional commitment pass.
        pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proposal: *const Root.Proposal, pin: Pin, limits: Limits, profile: Profile) !Prepared {
            const owner = try rebuild(a, dir, name, proposal, pin, limits);
            errdefer owner.deinit();
            var first = try Physical.commitPhysical(a, owner, proposal.template.config, profile, proposal.index);
            errdefer first.deinit(a);
            if (!std.meta.eql(first.roots, proposal.roots) or !std.meta.eql(first.template, proposal.template) or
                !std.meta.eql(first.template_id, proposal.template_id)) return error.V5StagedNativeRootMismatch;
            return .{ .owner = owner, .first = first };
        }
    };
}
