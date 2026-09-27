//! Bounded leaf envelopes. Keys/schedules are independent shared policy, not
//! repeated or selected by received files. Decoding never verifies a proof.
const std = @import("std");
const Parts = @import("block_v5_recursive_leaf_envelope_parts_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const MAGIC = "B5PVLF01";
pub const VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 32;
pub const Limits = struct {
    max_metadata_bytes: usize = 32 << 10,
    max_metadata_owned_bytes: usize = 2 << 20,
    max_schedule_wires: usize = 1 << 16,
    max_proof_bytes: usize = 128 << 20,
    max_file_bytes: usize = 129 << 20,
    pub fn validate(self: Limits) !void {
        if (self.max_metadata_bytes == 0 or self.max_metadata_bytes > std.math.maxInt(u32) or
            self.max_metadata_owned_bytes == 0 or self.max_schedule_wires == 0 or
            self.max_proof_bytes == 0 or self.max_file_bytes <= HEADER_BYTES)
            return error.InvalidRecursiveProviderCodecLimits;
    }
    pub fn requireBytes(self: Limits, metadata: usize, proof: usize) !usize {
        try self.validate();
        const total = try std.math.add(usize, HEADER_BYTES, try std.math.add(usize, metadata, proof));
        if (metadata == 0 or metadata > self.max_metadata_bytes or proof == 0 or
            proof > self.max_proof_bytes or total > self.max_file_bytes)
            return error.RecursiveProviderFileResourceLimit;
        return total;
    }
};
pub fn ForDefinition(comptime D: type) type {
    return struct {
        pub const TemplatePolicy = struct {
            key: D.Protocol.Key,
            key_id: [32]u8,
            schedule: []const D.Bus.Wire,
            pub fn require(self: *const TemplatePolicy, prepared: *const D.Prepared, limits: Limits) !void {
                try limits.validate();
                try prepared.validate(prepared.template_id);
                if (self.schedule.len > limits.max_schedule_wires or
                    !std.meta.eql(self.key.config, prepared.config) or
                    !std.meta.eql(self.key.profile.config(), prepared.config) or
                    !std.meta.eql(self.key.context.child_config, prepared.config) or
                    !std.meta.eql(self.key.context.child_key_id, prepared.template_id) or
                    !std.meta.eql(try self.key.identity(), self.key_id) or
                    !std.meta.eql(try D.Bus.scheduleDigest(self.schedule), self.key.public_schedule_digest))
                    return error.UntrustedRecursiveProviderTemplate;
            }
        };
        pub const Policy = struct {
            prepared: *const D.Prepared,
            /// Immutable independently pinned template; shared across leaves.
            template: *const TemplatePolicy,
            pub fn require(self: Policy, limits: Limits) !void {
                try self.template.require(self.prepared, limits);
            }
        };
        pub const Metadata = struct { key_id: [32]u8, claim: D.Claim };
        pub const Encoded = struct {
            allocator: std.mem.Allocator,
            budget: *Budget,
            header: [HEADER_BYTES]u8,
            metadata: []u8,
            /// Borrowed only until publication; no full-proof staging copy.
            proof: []const u8,
            total_bytes: usize,
            pub fn deinit(self: *Encoded) void {
                self.allocator.free(self.metadata);
                self.budget.destroy();
                self.* = undefined;
            }
            pub fn parts(self: *const Encoded) [3][]const u8 {
                return .{ &self.header, self.metadata, self.proof };
            }
        };
        pub fn encode(a: std.mem.Allocator, artifact: *const D.Stage.Artifact, policy: Policy, limits: Limits) !Encoded {
            try policy.require(limits);
            if (artifact.bytes.len == 0 or artifact.bytes.len > limits.max_proof_bytes or
                !std.meta.eql(artifact.key, policy.template.key) or
                !std.meta.eql(artifact.expected_key_id, policy.template.key_id) or
                !D.sameWires(artifact.schedule, policy.template.schedule))
                return error.UntrustedRecursiveProviderArtifact;
            const open = try D.proposal(policy.prepared, D.claim(artifact.native));
            const values = try D.values(policy.prepared, open);
            if (!std.meta.eql(open, artifact.native) or !std.meta.eql(values, artifact.public_values))
                return error.UntrustedRecursiveProviderPublicInputs;
            _ = try D.Protocol.Admission.init(policy.template.key, policy.template.key_id, policy.template.schedule, values);
            const budget = try Budget.create(a, limits.max_metadata_owned_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            const metadata = try std.json.Stringify.valueAlloc(bounded, Metadata{ .key_id = policy.template.key_id, .claim = D.claim(open) }, .{});
            errdefer bounded.free(metadata);
            const total = try limits.requireBytes(metadata.len, artifact.bytes.len);
            var header: [HEADER_BYTES]u8 = undefined;
            @memcpy(header[0..8], MAGIC);
            std.mem.writeInt(u32, header[8..12], @intFromEnum(D.FAMILY), .little);
            std.mem.writeInt(u32, header[12..16], VERSION, .little);
            std.mem.writeInt(u32, header[16..20], D.index(policy.prepared), .little);
            std.mem.writeInt(u32, header[20..24], @intCast(metadata.len), .little);
            std.mem.writeInt(u64, header[24..32], artifact.bytes.len, .little);
            return .{ .allocator = bounded, .budget = budget, .header = header, .metadata = metadata, .proof = artifact.bytes, .total_bytes = total };
        }
        pub const View = struct {
            parsed: std.json.Parsed(Metadata),
            budget: *Budget,
            /// Borrows the independently length/hash-pinned file owner.
            proof: []const u8,
            /// Still a statement proposal, not a cryptographic receipt.
            open: D.Open,
            values: D.Bus.Values,
            pub fn deinit(self: *View) void {
                self.parsed.deinit();
                self.budget.destroy();
                self.* = undefined;
            }
        };
        pub fn admitHeader(header: []const u8, policy: Policy, limits: Limits) !Parts.Extent {
            try policy.require(limits);
            return Parts.extent(header, MAGIC, @intFromEnum(D.FAMILY), VERSION, D.index(policy.prepared), limits, error.InvalidRecursiveProviderEnvelope);
        }
        pub fn maxFileBytes(limits: Limits) usize {
            return limits.max_file_bytes;
        }
        pub fn decodeMetadata(a: std.mem.Allocator, raw: []const u8, policy: Policy, limits: Limits) !View {
            if (raw.len < HEADER_BYTES) return error.InvalidRecursiveProviderEnvelope;
            const admitted = try admitHeader(raw[0..HEADER_BYTES], policy, limits);
            const slices = try Parts.parts(raw, admitted, error.InvalidRecursiveProviderEnvelope);
            return decodePayload(a, slices.metadata, slices.proof, policy, limits);
        }
        /// Separate borrowed spans share the exact original metadata decoder.
        /// A parsed statement remains a proposal; only Leaf.verify grants authority.
        pub fn decodeMetadataParts(a: std.mem.Allocator, header: []const u8, metadata: []const u8, proof: []const u8, policy: Policy, limits: Limits) !View {
            const admitted = try admitHeader(header, policy, limits);
            if (metadata.len != admitted.metadata or proof.len != admitted.proof) return error.InvalidRecursiveProviderEnvelope;
            return decodePayload(a, metadata, proof, policy, limits);
        }
        fn decodePayload(a: std.mem.Allocator, metadata: []const u8, proof: []const u8, policy: Policy, limits: Limits) !View {
            const budget = try Budget.create(a, limits.max_metadata_owned_bytes);
            errdefer budget.destroy();
            var parsed = try std.json.parseFromSlice(Metadata, budget.allocator(), metadata, .{ .allocate = .alloc_always, .ignore_unknown_fields = false, .max_value_len = limits.max_metadata_bytes });
            errdefer parsed.deinit();
            if (!std.meta.eql(parsed.value.key_id, policy.template.key_id)) return error.UntrustedRecursiveProviderTemplate;
            const open = try D.proposal(policy.prepared, parsed.value.claim);
            const values = try D.values(policy.prepared, open);
            _ = try D.Protocol.Admission.init(policy.template.key, policy.template.key_id, policy.template.schedule, values);
            return .{ .parsed = parsed, .budget = budget, .proof = proof, .open = open, .values = values };
        }
    };
}
