//! Prechallenge physical roots, without a fabricated global admission. These
//! are producer proposals: only fresh native/global receivers grant authority.
//! No PCS tree, native owner, or runner storage survives collect().
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const native = @import("blake3_execution_trace.zig");
const shape_mod = @import("../air/statement.zig");
const public = @import("../air/public_data.zig");
const profile = @import("../isa/execution_profile.zig");
const template_mod = @import("block_v5_native_template_protocol_v3.zig");
const admission = @import("block_v5_native_public_admission_v1.zig");
const catalog = @import("block_v5_native_template_catalog_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const frame = @import("block_v5_native_frame_v1.zig");
pub const Digest = [32]u8;

pub const Limits = struct {
    max_public_words: usize,
    max_metadata_bytes: usize,
    pub fn validate(self: Limits) !void {
        if (self.max_metadata_bytes < @sizeOf(Proposal)) return error.InvalidV5RootProposalLimits;
    }
};
pub const Candidate = struct {
    admission: admission.Admission,
    entry: seal.Entry,
    catalog_record: catalog.Record,
};
pub const Proposal = struct {
    a: std.mem.Allocator,
    shape: shape_mod.Blake3ExecutionStatement,
    roots: seal.Roots,
    template: template_mod.Template,
    template_id: Digest,
    public_digest: Digest,
    index: u32,
    first_cycle: u64,
    last_cycle: u64,
    metadata_bytes: usize,

    pub fn deinit(self: *Proposal) void {
        self.a.free(self.shape.public_data.io_entries.output_words);
        self.a.free(self.shape.public_data.io_entries.input_words);
        self.* = undefined;
    }
    /// Late policy binding uses the existing native-v3 identity exactly. This
    /// returns a candidate roster entry, never a proof or accepted receipt.
    pub fn bind(self: *const Proposal, context: admission.Context) !Candidate {
        if (context.execution_index != self.index or context.first_cycle != self.first_cycle or
            context.last_cycle != self.last_cycle or !std.meta.eql(self.roots[0], self.template.fixed_root) or
            !std.meta.eql(self.public_digest, admission.publicDigest(&self.shape.public_data)))
            return error.ChangedV5RootProposal;
        try self.template.admit(&self.shape, self.template_id);
        const pin = try admission.Admission.init(context, &self.shape.public_data);
        const instance = try template_mod.instanceId(self.template_id, &self.shape, pin, self.roots, self.index);
        return .{ .admission = pin, .entry = .{ .family = .execution, .index = self.index, .instance_id = instance, .roots = self.roots }, .catalog_record = .{ .index = self.index, .template_id = self.template_id, .geometry_digest = self.template.geometry_digest, .fixed_root = self.template.fixed_root } };
    }
    /// The second replay still goes through the ordinary native-v3 producer.
    pub fn requireReplay(self: *const Proposal, first: anytype) !void {
        const candidate = try self.bind(first.pin.context);
        if (!std.meta.eql(first.entry(), candidate.entry) or !std.meta.eql(first.template, self.template) or
            !std.meta.eql(first.template_id, self.template_id)) return error.V5PhysicalRootReplayMismatch;
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        /// Shared physical kernel. NativeV3.commitFirstRound can delegate here;
        /// binding the public Admission is deliberately a separate operation.
        pub const PhysicalFirstRound = struct {
            scheme: Scheme,
            roots: seal.Roots,
            template: template_mod.Template,
            template_id: Digest,
            pub fn deinit(self: *PhysicalFirstRound, a: std.mem.Allocator) void {
                self.scheme.deinit(a);
                self.* = undefined;
            }
        };
        /// Commit and immediately discard physical PCS state. The caller owns
        /// the one live native trace; no global plan or Admission is required.
        pub fn collect(a: std.mem.Allocator, owner: *native.Owner, config: core.pcs.PcsConfig, execution_profile: profile.ExecutionProfile, index: u32, first_cycle: u64, limits: Limits) !Proposal {
            try limits.validate();
            if (!owner.native_only_v5 or !owner.tables_ready or owner.failed or owner.interaction_ready or first_cycle == 0)
                return error.InvalidV5RootProposalPhase;
            try owner.statement.validateBlake3ExecutionWithExternal(owner.external_retirements);
            try @import("blake3_execution_protocol.zig").validateConfig(config);
            const io = owner.statement.public_data.io_entries;
            const words = try std.math.add(usize, io.input_words.len, io.output_words.len);
            const bytes = try std.math.add(usize, @sizeOf(Proposal), try std.math.add(usize,
                try std.math.mul(usize, io.input_words.len, @sizeOf(u32)),
                try std.math.mul(usize, io.output_words.len, @sizeOf(public.OutputWord))));
            if (words > limits.max_public_words or bytes > limits.max_metadata_bytes) return error.V5RootProposalResourceLimit;
            if (owner.statement.total_steps == 0) return error.InvalidV5RootProposalSpan;
            const last_cycle = try std.math.add(u64, first_cycle, owner.statement.total_steps - 1);
            var physical = try commitPhysical(a, owner, config, execution_profile, index);
            defer physical.deinit(a);
            const input = try a.dupe(u32, io.input_words);
            errdefer a.free(input);
            const output = try a.dupe(public.OutputWord, io.output_words);
            errdefer a.free(output);
            var shape = owner.statement;
            shape.public_data.io_entries.input_words = input;
            shape.public_data.io_entries.output_words = output;
            return .{ .a = a, .shape = shape, .roots = physical.roots, .template = physical.template,
                .template_id = physical.template_id, .public_digest = admission.publicDigest(&shape.public_data),
                .index = index, .first_cycle = first_cycle, .last_cycle = last_cycle, .metadata_bytes = bytes };
        }
        pub fn commitPhysical(a: std.mem.Allocator, owner: *native.Owner, config: core.pcs.PcsConfig, execution_profile: profile.ExecutionProfile, index: u32) !PhysicalFirstRound {
            if (!owner.native_only_v5 or !owner.tables_ready or owner.failed or owner.interaction_ready)
                return error.InvalidNativeV5Phase;
            try owner.statement.validateBlake3ExecutionWithExternal(owner.external_retirements);
            try @import("blake3_execution_protocol.zig").validateConfig(config);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            var channel = suite.Channel{};
            channel.mixU32s(&.{ template_mod.TAG, template_mod.VERSION, 0, index });
            if (frame.required(&owner.statement)) {
                if (owner.preprocessed.items.len != 0 or owner.main.items.len != 0) return error.InvalidNativeV5FrameColumns;
                const fixed = try frame.fixedColumns(a);
                defer frame.freeColumns(a, fixed);
                const main = try frame.mainColumns(a, try frame.expected(&owner.statement, owner.external_retirements));
                defer frame.freeColumns(a, main);
                try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
                try scheme.commitBorrowedStreaming(a, main, 8, &channel);
            } else {
                try scheme.commitBorrowedStreaming(a, owner.preprocessed.items, 8, &channel);
                try scheme.commitBorrowedStreaming(a, owner.main.items, 8, &channel);
            }
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidV5RootProposalTrees;
            const pair: seal.Roots = roots.items[0..2].*;
            const template = try template_mod.Template.fromShape(&owner.statement, config, execution_profile, owner.external_retirements, pair[0]);
            return .{ .scheme = scheme, .roots = pair, .template = template, .template_id = try template.identity() };
        }
    };
}
