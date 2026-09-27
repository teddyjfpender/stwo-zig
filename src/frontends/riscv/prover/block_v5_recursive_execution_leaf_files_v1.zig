//! Typed durable transport for genuine execution/caller recursive equations.
//! Metadata/length/SHA pins remain proposals until the distinct Leaf.verify.
//! Provider transport keeps its original B5PVLF01 grammar and family domains.
const std = @import("std");
const Parts = @import("block_v5_recursive_leaf_envelope_parts_v1.zig");
const core = @import("stwo_core");
const Files = @import("block_v5_artifact_files_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Family = enum(u32) { caller_arithmetic = 1, caller_fused = 2, native_capacity_fused = 3 };
pub const MAGIC = "B5EXLF01";
pub const VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 32;
/// Execution claims include all nineteen arithmetic components or the full
/// fused slot inventory. Provider-only32KiB defaults cannot represent them.
/// Reuse the same checked extent arithmetic with explicitly bounded metadata.
pub const Limits = struct {
    codec: @import("block_v5_recursive_provider_codec_v1.zig").Limits = .{
        .max_metadata_bytes = 4 << 20,
        .max_metadata_owned_bytes = 32 << 20,
        .max_file_bytes = (132 << 20) + HEADER_BYTES,
    },
    pub fn validate(self: Limits) !void {
        try self.codec.validate();
    }
    pub fn requireBytes(self: Limits, metadata: usize, proof: usize) !usize {
        return self.codec.requireBytes(metadata, proof);
    }
};
pub const FilePin = @import("block_v5_recursive_leaf_store_core_v1.zig").FilePin;

pub fn ForFamily(comptime family: Family) type {
    return struct {
        pub const Admission = switch (family) {
            .caller_arithmetic => @import("block_v5_caller_arithmetic_recursive_admission_v1.zig"),
            .caller_fused => @import("block_v5_caller_fused_recursive_admission_v1.zig"),
            .native_capacity_fused => @import("block_v5_native_capacity_fused_recursive_admission_v1.zig"),
        };
        pub const Stage = switch (family) {
            .caller_arithmetic => @import("block_v5_caller_arithmetic_recursive_stage_v1.zig"),
            .caller_fused => @import("block_v5_caller_fused_recursive_stage_v1.zig"),
            .native_capacity_fused => @import("block_v5_native_capacity_fused_recursive_stage_v1.zig"),
        };
        pub const Bus = switch (family) {
            .caller_arithmetic => @import("../recursion/block_v5_caller_arithmetic_recursive_public_bus_v1.zig"),
            .caller_fused => @import("../recursion/block_v5_caller_fused_recursive_public_bus_v1.zig"),
            .native_capacity_fused => @import("../recursion/block_v5_native_capacity_fused_recursive_public_bus_v1.zig"),
        };
        pub const Protocol = switch (family) {
            .caller_arithmetic => @import("../recursion/block_v5_reusable_caller_arithmetic_parent_protocol_v1.zig"),
            .caller_fused => @import("../recursion/block_v5_reusable_caller_fused_parent_protocol_v1.zig"),
            .native_capacity_fused => @import("../recursion/block_v5_reusable_native_capacity_fused_parent_protocol_v1.zig"),
        };
        pub const Leaf = switch (family) {
            .caller_arithmetic => @import("../recursion/block_v5_caller_arithmetic_recursive_leaf_v1.zig"),
            .caller_fused => @import("../recursion/block_v5_caller_fused_recursive_leaf_v1.zig"),
            .native_capacity_fused => @import("../recursion/block_v5_native_capacity_fused_recursive_leaf_v1.zig"),
        };
        pub const Claims = switch (family) {
            .caller_arithmetic => Admission.Profile.ExtensionClaim,
            .caller_fused => Admission.Fused.ClaimFrames,
            .native_capacity_fused => Bus.Claims,
        };
        pub const Template = struct {
            key: Protocol.Key,
            key_id: [32]u8,
            schedule: []const Bus.Wire,
        };
        pub const Policy = struct {
            prepared: *const Admission.Prepared,
            /// Independent immutable template, never selected by the file.
            template: *const Template,
            pub fn require(self: Policy, limits: Limits) !void {
                try limits.validate();
                try self.prepared.validate(self.prepared.template_id);
                if (self.template.schedule.len > limits.codec.max_schedule_wires or
                    !std.meta.eql(self.template.key.config, self.prepared.config) or
                    !std.meta.eql(self.template.key.profile.config(), self.prepared.config) or
                    !std.meta.eql(self.template.key.context.child_config, self.prepared.config) or
                    !std.meta.eql(self.template.key.context.child_key_id, self.prepared.template_id) or
                    !std.meta.eql(try self.template.key.identity(), self.template.key_id) or
                    !std.meta.eql(try Bus.scheduleDigest(self.template.schedule), self.template.key.public_schedule_digest))
                    return error.UntrustedRecursiveExecutionTemplate;
            }
        };
        pub const Metadata = struct { key_id: [32]u8, claims: Claims };
        pub fn index(prepared: *const Admission.Prepared) u32 {
            return if (family == .native_capacity_fused) prepared.native.index else prepared.binding.execution_index;
        }
        fn claimsOf(artifact: *const Stage.Artifact) Claims {
            return switch (family) {
                .caller_arithmetic => artifact.public_values.claims,
                .caller_fused => artifact.claims,
                .native_capacity_fused => .{ .projection = artifact.projection_claims, .memory = artifact.memory_claims },
            };
        }
        fn valuesFor(a: std.mem.Allocator, prepared: *const Admission.Prepared, claims: Claims) !Bus.Values {
            return switch (family) {
                .caller_arithmetic => Bus.Values.fromCaller(prepared, .{ .binding = prepared.binding, .open_sum = claims.componentSum() }, claims),
                .caller_fused, .native_capacity_fused => Bus.Values.init(a, prepared, claims),
            };
        }
        fn releaseValues(values: *Bus.Values) void {
            if (family != .caller_arithmetic) values.deinit();
        }
        fn identity(values: Bus.Values) ![32]u8 {
            try values.validate();
            var channel = core.proof_suites.Blake3.Channel{};
            values.mix(&channel);
            return channel.digestBytes();
        }
        fn sameSchedule(left: []const Bus.Wire, right: []const Bus.Wire) bool {
            if (left.len != right.len) return false;
            for (left, right) |x, y| if (!std.meta.eql(x, y)) return false;
            return true;
        }
        pub const Encoded = struct {
            budget: *Budget,
            header: [HEADER_BYTES]u8,
            metadata: []u8,
            proof: []const u8,
            total_bytes: usize,
            pub fn deinit(self: *Encoded) void {
                self.budget.allocator().free(self.metadata);
                self.budget.destroy();
                self.* = undefined;
            }
            pub fn parts(self: *const Encoded) [3][]const u8 {
                return .{ &self.header, self.metadata, self.proof };
            }
        };
        pub fn encode(a: std.mem.Allocator, artifact: *const Stage.Artifact, policy: Policy, limits: Limits) !Encoded {
            try policy.require(limits);
            if (artifact.bytes.len == 0 or artifact.bytes.len > limits.codec.max_proof_bytes or
                !std.meta.eql(artifact.key, policy.template.key) or
                !std.meta.eql(artifact.expected_key_id, policy.template.key_id) or
                !sameSchedule(artifact.schedule, policy.template.schedule))
                return error.UntrustedRecursiveExecutionArtifact;
            const budget = try Budget.create(a, limits.codec.max_metadata_owned_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            const claims = claimsOf(artifact);
            var values = try valuesFor(bounded, policy.prepared, claims);
            defer releaseValues(&values);
            if (!std.meta.eql(try identity(values), try identity(artifact.public_values)))
                return error.UntrustedRecursiveExecutionPublicInputs;
            if (family == .caller_arithmetic) {
                if (!std.meta.eql(artifact.native.binding, values.binding) or !artifact.native.open_sum.eql(values.open_sum))
                    return error.UntrustedRecursiveExecutionPublicInputs;
            }
            _ = try Protocol.Admission.init(policy.template.key, policy.template.key_id, policy.template.schedule, values);
            const metadata = try std.json.Stringify.valueAlloc(bounded, Metadata{ .key_id = policy.template.key_id, .claims = claims }, .{});
            errdefer bounded.free(metadata);
            const total = try limits.requireBytes(metadata.len, artifact.bytes.len);
            var header: [HEADER_BYTES]u8 = undefined;
            @memcpy(header[0..8], MAGIC);
            std.mem.writeInt(u32, header[8..12], @intFromEnum(family), .little);
            std.mem.writeInt(u32, header[12..16], VERSION, .little);
            std.mem.writeInt(u32, header[16..20], index(policy.prepared), .little);
            std.mem.writeInt(u32, header[20..24], @intCast(metadata.len), .little);
            std.mem.writeInt(u64, header[24..32], artifact.bytes.len, .little);
            return .{ .budget = budget, .header = header, .metadata = metadata, .proof = artifact.bytes, .total_bytes = total };
        }
        pub const View = struct {
            budget: *Budget,
            parsed: std.json.Parsed(Metadata),
            proof: []const u8,
            values: Bus.Values,
            pub fn deinit(self: *View) void {
                releaseValues(&self.values);
                self.parsed.deinit();
                self.budget.destroy();
                self.* = undefined;
            }
            /// This is the sole authority-producing operation in the codec.
            /// The returned equation owns its original proof/public inputs.
            pub fn verify(self: *const View, a: std.mem.Allocator, policy: Policy) !Leaf.OpenEquation {
                const template = policy.template;
                var fresh = switch (family) {
                    .caller_arithmetic => try Leaf.verify(a, self.proof, template.key, template.key_id, template.schedule, policy.prepared, .{ .binding = policy.prepared.binding, .open_sum = self.parsed.value.claims.componentSum() }, self.parsed.value.claims),
                    .caller_fused => try Leaf.verify(a, self.proof, template.key, template.key_id, template.schedule, policy.prepared, self.parsed.value.claims),
                    .native_capacity_fused => try Leaf.verify(a, self.proof, template.key, template.key_id, template.schedule, policy.prepared, self.parsed.value.claims.projection, self.parsed.value.claims.memory),
                };
                errdefer fresh.deinit();
                if (!std.meta.eql(try identity(fresh.public_values), try identity(self.values))) return error.UntrustedRecursiveExecutionPublicInputs;
                return fresh;
            }
        };
        pub fn admitHeader(header: []const u8, policy: Policy, limits: Limits) !Parts.Extent {
            try policy.require(limits);
            return Parts.extent(header, MAGIC, @intFromEnum(family), VERSION, index(policy.prepared), limits, error.InvalidRecursiveExecutionEnvelope);
        }
        pub fn maxFileBytes(limits: Limits) usize {
            return limits.codec.max_file_bytes;
        }
        pub fn decodeMetadata(a: std.mem.Allocator, raw: []const u8, policy: Policy, limits: Limits) !View {
            if (raw.len < HEADER_BYTES) return error.InvalidRecursiveExecutionEnvelope;
            const admitted = try admitHeader(raw[0..HEADER_BYTES], policy, limits);
            const slices = try Parts.parts(raw, admitted, error.InvalidRecursiveExecutionEnvelope);
            return decodePayload(a, slices.metadata, slices.proof, policy, limits);
        }
        /// Separate borrowed spans share the exact original metadata decoder.
        /// A parsed statement remains a proposal; only Leaf.verify grants authority.
        pub fn decodeMetadataParts(a: std.mem.Allocator, header: []const u8, metadata: []const u8, proof: []const u8, policy: Policy, limits: Limits) !View {
            const admitted = try admitHeader(header, policy, limits);
            if (metadata.len != admitted.metadata or proof.len != admitted.proof) return error.InvalidRecursiveExecutionEnvelope;
            return decodePayload(a, metadata, proof, policy, limits);
        }
        fn decodePayload(a: std.mem.Allocator, metadata: []const u8, proof: []const u8, policy: Policy, limits: Limits) !View {
            const budget = try Budget.create(a, limits.codec.max_metadata_owned_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            var parsed = try std.json.parseFromSlice(Metadata, bounded, metadata, .{ .allocate = .alloc_always, .ignore_unknown_fields = false, .max_value_len = limits.codec.max_metadata_bytes });
            errdefer parsed.deinit();
            if (!std.meta.eql(parsed.value.key_id, policy.template.key_id)) return error.UntrustedRecursiveExecutionTemplate;
            var values = try valuesFor(bounded, policy.prepared, parsed.value.claims);
            errdefer releaseValues(&values);
            _ = try Protocol.Admission.init(policy.template.key, policy.template.key_id, policy.template.schedule, values);
            return .{ .budget = budget, .parsed = parsed, .proof = proof, .values = values };
        }
        pub fn fileName(buffer: []u8, at: u32) ![]const u8 {
            return std.fmt.bufPrint(buffer, "block-v5-recursive-{s}-{d}.leaf", .{ @tagName(family), at });
        }
        /// Exclusive synced publication; success consumes the original artifact.
        /// The enclosing exact roster/manifest must require all physical leaves.
        pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, artifact: *Stage.Artifact, policy: Policy, limits: Limits) !FilePin {
            var encoded = try encode(a, artifact, policy, limits);
            defer encoded.deinit();
            var buffer: [96]u8 = undefined;
            const parts = encoded.parts();
            const pin = FilePin{ .index = index(policy.prepared), .byte_len = encoded.total_bytes, .sha256 = Files.hashParts(&parts) };
            try Files.publishParts(dir, try fileName(&buffer, pin.index), &parts);
            artifact.deinit(a);
            return pin;
        }
        /// Independent path/index/hash/length then actual original typed leaf
        /// verification. The result never substitutes for all-family closure.
        pub fn loadFresh(a: std.mem.Allocator, dir: std.fs.Dir, pin: FilePin, policy: Policy, limits: Limits) !Leaf.OpenEquation {
            try policy.require(limits);
            if (pin.index != index(policy.prepared)) return error.InvalidRecursiveExecutionEnvelope;
            var buffer: [96]u8 = undefined;
            var raw = try Parts.readPinned(@This(), a, dir, try fileName(&buffer, pin.index), pin.byte_len, pin.sha256, policy, limits);
            defer raw.deinit();
            var view = try decodeMetadataParts(a, &raw.header, raw.metadata, raw.proof, policy, limits);
            defer view.deinit();
            return view.verify(a, policy);
        }
    };
}
