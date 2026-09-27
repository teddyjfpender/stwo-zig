//! Genuine typed PAGE recursive leaves, never scalar VerifiedPage adapters.
//! The actual original Leaf verifier runs before publishing this owned source.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Norm = @import("block_v5_memory_source_page_forest_normalizer_v1.zig");
const Algebra = @import("block_v5_memory_source_page_forest_algebra_v1.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Admit = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    const Bus = @import("block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    const Protocol = @import("block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
    const Leaf = @import("block_v5_memory_source_page_recursive_leaf_v1.zig").ForKind(kind);
    return struct {
        pub const PUBLIC_CIRCUIT: u32 = if (kind == .raw) 4_300_300 else 4_300_301;
        pub const Policy = struct {
            admitted: *const Admit.Prepared,
            claims: Bus.Claims,
            key: Protocol.Key,
            expected_id: [32]u8,
            schedule: []const Bus.Wire,
            normalization: Norm.Limits = .{},
            max_proof_bytes: usize = 512 << 20,
            pub fn validate(self: Policy) !void {
                if (self.max_proof_bytes == 0 or self.schedule.len == 0 or self.schedule.len > self.normalization.max_terms) return error.PageForestSourceLimit;
                try self.admitted.validate(self.admitted.template_id);
                try Algebra.canonical(Algebra.flatten(self.claims.semantic.claims));
                if (!std.meta.eql(self.key.config, self.admitted.config) or !std.meta.eql(self.key.context.child_config, self.admitted.config)) return error.UntrustedPageForestLeaf;
                if (!std.meta.eql(try self.key.identity(), self.expected_id) or !std.meta.eql(try Bus.scheduleDigest(self.schedule), self.key.public_schedule_digest) or !std.meta.eql(self.key.context.child_key_id, self.admitted.template_id)) return error.UntrustedPageForestLeaf;
            }
        };
        pub const Fresh = struct {
            allocator: std.mem.Allocator,
            allocation_owner: ?*Budget,
            policy: Policy,
            open: Leaf.OpenEquation,
            normalized: Norm.Normalized,
            terms: []Term,
            pub fn authority(self: *const Fresh) !Protocol.Admission {
                try self.policy.validate();
                return Protocol.Admission.init(self.policy.key, self.policy.expected_id, self.policy.schedule, self.open.public_values);
            }
            pub fn validate(self: *const Fresh) !void {
                const authority_value = try self.authority();
                try self.open.equation.validate(&authority_value, self.policy.expected_id);
                if (self.open.public_values.statement.component_claim_first < Algebra.CLAIM_COUNT or self.terms.len != self.policy.schedule.len) return error.UntrustedPageForestLeaf;
                try self.normalized.requireWithWords(self.allocator, &authority_value, self.open.public_values.statement.felts, try Algebra.semanticClaimOffset(self.open.public_values.statement.component_claim_first), self.open.public_values.statement.words, self.policy.normalization);
                for (self.terms, self.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative or !std.meta.eql(term.coordinates, try self.open.public_values.at(wire.source, wire.coordinate))) return error.UntrustedPageForestLeaf;
                const flat = Algebra.flatten(self.policy.claims.semantic.claims);
                for (flat, 0..) |claim, index| for (claim.toM31Array(), 0..) |limb, part| {
                    const cell = try self.normalized.cell(self.normalized.claim_first + @as(u32, @intCast(4 * index + part)));
                    var word: u32 = 0;
                    for (cell, 0..) |byte, b| word |= byte.v << @as(u5, @intCast(8 * b));
                    if (word != limb.v) return error.UntrustedPageForestLeaf;
                };
            }
            pub fn deinit(self: *Fresh) void {
                const a = self.allocator;
                const lease = self.allocation_owner;
                a.free(self.terms);
                self.normalized.deinit();
                self.open.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
        pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
            if (bytes.len == 0 or bytes.len > policy.max_proof_bytes) return error.PageForestSourceLimit;
            try policy.validate();
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            const fresh = try a.create(Fresh);
            errdefer a.destroy(fresh);
            fresh.allocator = a;
            fresh.allocation_owner = lease;
            fresh.policy = policy;
            fresh.open = try Leaf.verify(a, bytes, policy.key, policy.expected_id, policy.schedule, policy.admitted, policy.claims);
            errdefer fresh.open.deinit();
            const authority_value = try fresh.authority();
            const stmt = &fresh.open.public_values.statement;
            if (stmt.component_claim_first < Algebra.CLAIM_COUNT) return error.UntrustedPageForestLeaf;
            fresh.normalized = try Norm.Normalized.initWithWords(a, &authority_value, stmt.felts, try Algebra.semanticClaimOffset(stmt.component_claim_first), stmt.words, policy.normalization);
            errdefer fresh.normalized.deinit();
            fresh.terms = try a.alloc(Term, policy.schedule.len);
            errdefer a.free(fresh.terms);
            for (fresh.terms, policy.schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .coordinates = try fresh.open.public_values.at(wire.source, wire.coordinate) };
            try fresh.validate();
            return fresh;
        }
        pub const Source = struct {
            fresh: *const Fresh,
            terms: []const Term,
            pub const complete_source_authority = false;
            pub fn init(fresh: *const Fresh) !Source {
                try fresh.validate();
                return .{ .fresh = fresh, .terms = fresh.terms };
            }
            pub fn validate(self: *const Source) !void {
                if (self.terms.ptr != self.fresh.terms.ptr or self.terms.len != self.fresh.terms.len) return error.UntrustedPageForestLeaf;
                try self.fresh.validate();
            }
            pub fn cell(self: *const Source, index: u32) ![4]M {
                return self.fresh.normalized.cell(index);
            }
            pub fn pageIndex(self: *const Source) !u32 {
                return std.math.add(u32, self.fresh.normalized.word_first orelse return error.UntrustedPageForestClaimLayout, if (kind == .raw) 19 else 27);
            }
            pub fn pageRows(self: *const Source) !u32 {
                return std.math.add(u32, try self.pageIndex(), 1);
            }
            pub fn claimFirst(self: *const Source) u32 {
                return self.fresh.normalized.claim_first;
            }
            pub fn replayPublic(self: *const Source, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
                self.fresh.normalized.replay(recorder, PUBLIC_CIRCUIT);
            }
        };
        pub const Admission = struct {
            pub const open_parent_v5_v2 = true;
            source: *const Source,
            key: Base.Key,
            expected_id: [32]u8,
            pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
            pub fn init(source: *const Source) Admission {
                const k = source.fresh.policy.key;
                return .{ .source = source, .key = .{ .profile = k.profile, .config = k.config, .context = k.context, .log_sizes = k.log_sizes, .preprocessed_root = k.preprocessed_root }, .expected_id = source.fresh.policy.expected_id };
            }
            pub fn validate(self: *const Admission) !void {
                try self.source.validate();
                const expected = init(self.source);
                if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedPageForestLeaf;
            }
            pub fn config(self: *const Admission) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
            pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.admitRoot(root);
            }
            pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
                try self.validate();
                const actual = try self.source.fresh.authority();
                return actual.publicInputIdentity();
            }
            pub fn mix(self: *const Admission, channel: anytype) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.mix(channel);
            }
            pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.mixClaims(channel, claims);
            }
            pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.validateClaimsForRelations(claims, relations);
            }
        };
    };
}
