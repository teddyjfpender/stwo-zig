//! Capacity first-pass span adapter. Owns the genuine B5CT Proposal; plain
//! metadata/root candidates are never fresh proof or receiver authority.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Owner = @import("blake3_execution_trace.zig").Owner;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;
pub const Limits = struct {
    native: Native.Limits = .{},
    max_metadata_bytes: usize,
    pub fn require(self: Limits, shape: *const Shape, external: u32) !usize {
        if (self.max_metadata_bytes < @sizeOf(Proposal)) return error.InvalidCapacityRootProposalLimits;
        const plan = try Protocol.Plan.fromShape(shape, external);
        try self.native.require(&plan, shape);
        const io = shape.public_data.io_entries;
        const bytes = try std.math.add(usize, @sizeOf(Proposal), try std.math.add(usize, try std.math.mul(usize, io.input_words.len, @sizeOf(u32)), try std.math.mul(usize, io.output_words.len, @sizeOf(@import("../air/public_data.zig").OutputWord))));
        if (bytes > self.max_metadata_bytes or bytes > self.native.max_metadata_bytes) return error.NativeCapacityResourceLimit;
        return bytes;
    }
};
pub const Candidate = struct {
    admission: Public.Admission,
    entry: Seal.Entry,
    catalog_record: Catalog.Record,
};
pub const Proposal = struct {
    physical: Native.Proposal,
    first_cycle: u64,
    last_cycle: u64,
    metadata_bytes: usize,
    candidate_catalog: Catalog.Record,
    limits: Limits,
    pub fn externalRetirements(self: *const Proposal) u32 {
        return self.physical.external_retirements;
    }
    pub fn deinit(self: *Proposal) void {
        self.physical.deinit();
        self.* = undefined;
    }
    /// Success consumes the genuine owned proposal; failure leaves it owned
    /// by the caller. Zig copies are not move-only: do not copy owned tokens.
    pub fn take(physical: *Native.Proposal, first_cycle: u64, limits: Limits) !Proposal {
        const bytes = try limits.require(&physical.shape, physical.external_retirements);
        const last = try endCycle(first_cycle, physical.shape.total_steps);
        const result = Proposal{ .physical = physical.*, .first_cycle = first_cycle, .last_cycle = last, .metadata_bytes = bytes, .candidate_catalog = try Catalog.Record.fromTemplate(physical.index, physical.template), .limits = limits };
        try result.validate();
        physical.* = undefined;
        return result;
    }
    pub fn validate(self: *const Proposal) !void {
        const native = &self.physical;
        const bytes = try self.limits.require(&native.shape, native.external_retirements);
        if (self.last_cycle != try endCycle(self.first_cycle, native.shape.total_steps) or self.metadata_bytes != bytes or
            !std.meta.eql(native.public_digest, Public.publicDigest(&native.shape.public_data)) or
            !std.meta.eql(native.roots[0], native.template.fixed_root) or
            !std.meta.eql(self.candidate_catalog, try Catalog.Record.fromTemplate(native.index, native.template))) return error.ChangedCapacityRootProposal;
        try native.template.admit(&native.shape, native.external_retirements, native.template_id);
    }
    pub fn bind(self: *const Proposal, context: Public.Context) !Candidate {
        try self.validate();
        if (context.execution_index != self.physical.index or context.first_cycle != self.first_cycle or context.last_cycle != self.last_cycle)
            return error.ChangedCapacityRootProposalSpan;
        const admission = try Public.Admission.init(context, &self.physical.shape.public_data);
        return .{ .admission = admission, .entry = try self.physical.bind(context), .catalog_record = self.candidate_catalog };
    }
    pub fn requireReplay(self: *const Proposal, first: anytype) !void {
        const candidate = try self.bind(first.pin.context);
        if (!std.meta.eql(candidate.entry, first.entry()) or !std.meta.eql(first.template, self.physical.template) or
            !std.meta.eql(first.template_id, self.physical.template_id)) return error.CapacityRootProposalReplayMismatch;
    }
};
fn endCycle(first: u64, count: u32) !u64 {
    if (first == 0 or count == 0) return error.InvalidCapacityRootProposalSpan;
    return std.math.add(u64, first, count - 1);
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = Native.ForBackend(Backend);
        pub const FixedBasis = Api.FixedBasis;
        pub fn collect(a: std.mem.Allocator, owner: *Owner, config: core.pcs.PcsConfig, profile: Profile, index: u32, first_cycle: u64, limits: Limits) !Proposal {
            return collectSelected(a, owner, config, profile, index, first_cycle, limits, null);
        }
        pub fn collectWithBasis(a: std.mem.Allocator, owner: *Owner, config: core.pcs.PcsConfig, profile: Profile, index: u32, first_cycle: u64, limits: Limits, basis: *FixedBasis) !Proposal {
            return collectSelected(a, owner, config, profile, index, first_cycle, limits, basis);
        }
        fn collectSelected(a: std.mem.Allocator, owner: *Owner, config: core.pcs.PcsConfig, profile: Profile, index: u32, first_cycle: u64, limits: Limits, basis: ?*FixedBasis) !Proposal {
            _ = try limits.require(&owner.statement, owner.external_retirements);
            _ = try endCycle(first_cycle, owner.statement.total_steps);
            var physical = if (basis) |fixed| try Api.collectWithBasis(a, owner, config, profile, index, limits.native, fixed) else try Api.collect(a, owner, config, profile, index, limits.native);
            var owns = true;
            defer if (owns) physical.deinit();
            const result = try Proposal.take(&physical, first_cycle, limits);
            owns = false;
            return result;
        }
    };
}
