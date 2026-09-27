//! Genuine original leaf-public normalization shared by provider/range children.
//! Sources borrow actual Parent.Verified owners; proposals cannot mint Fresh.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const Compare = @import("air/block_v5_recursive_statement_compare_v1.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
const Base = @import("blake3_execution_parent_protocol.zig");
pub const Kind = enum { provider, range };
pub const Limits = struct { max_proof_bytes: usize = 512 << 20, max_words: usize = 4096, max_felts: usize = 64, max_steps: usize = 1024, max_terms: usize = 1 << 20 };
pub fn ForKind(comptime kind: Kind) type {
    const Bus = if (kind == .provider) @import("block_v5_readonly_provider_recursive_public_bus_v2.zig") else @import("block_v5_range16_recursive_public_bus_v1.zig");
    const Protocol = if (kind == .provider) @import("block_v5_reusable_readonly_provider_parent_protocol_v2.zig") else @import("block_v5_reusable_range16_parent_protocol_v1.zig");
    const Leaf = if (kind == .provider) @import("block_v5_readonly_provider_recursive_leaf_v2.zig") else @import("block_v5_range16_recursive_leaf_v1.zig");
    const PolicyAdmission = if (kind == .provider) @import("../prover/block_v5_readonly_provider_recursive_admission_v2.zig") else @import("../prover/block_v5_readonly_range_recursive_admission_v2.zig");
    const Proposal = if (kind == .provider) @import("../prover/block_v5_readonly_input_provider_component_v2.zig").Claim else @import("../prover/block_v5_range16_proof_v1.zig").OpenReceipt;
    return struct {
        const Self = @This();
        pub const PUBLIC_CIRCUIT: u32 = if (kind == .provider) 4_300_470 else 4_300_471;
        pub const Policy = struct {
            admitted: *const PolicyAdmission.Prepared,
            key: Protocol.Key,
            expected_id: [32]u8,
            schedule: []const Bus.Wire,
            proposal: Proposal,
            limits: Limits = .{},
            pub fn validate(self: @This()) !void {
                try self.admitted.validate(self.admitted.template_id);
                if (!std.meta.eql(self.key.config, self.admitted.config) or !std.meta.eql(self.key.context.child_config, self.admitted.config) or
                    !std.meta.eql(self.key.context.child_key_id, self.admitted.template_id) or !std.meta.eql(try self.key.identity(), self.expected_id) or
                    !std.meta.eql(try Bus.scheduleDigest(self.schedule), self.key.public_schedule_digest) or self.limits.max_proof_bytes == 0 or
                    self.limits.max_words == 0 or self.limits.max_felts == 0 or self.limits.max_steps == 0 or self.schedule.len > self.limits.max_terms) return error.UntrustedReadonlyPairChildPolicy;
                if (kind == .provider) try @import("../prover/block_v5_readonly_input_provider_proof_v2.zig").requireClaim(self.admitted.pin, self.proposal) else {
                    _ = try Bus.Values.fromRange(self.admitted, self.proposal);
                }
            }
        };
        fn requireProviderValues(admitted: *const PolicyAdmission.Prepared, proposed: Proposal, values: *const Bus.Values) !void {
            comptime if (kind != .provider) @compileError("provider values require provider specialization");
            const Provider = @import("../prover/block_v5_readonly_input_provider_proof_v2.zig");
            const Global = @import("../prover/block_v5_readonly_input_global_protocol_v2.zig");
            try values.validate();
            if (values.roots_count != 2 or !std.meta.eql(values.template, admitted.template_id) or values.public.len != 20 or values.statement.felts.len != 0) return error.UnpairedReadonlyPairChild;
            const frame = &values.statement;
            if (frame.sealed_offset > frame.words.len or 8 > frame.words.len - frame.sealed_offset or frame.claims.len < 8 or
                frame.claims[6] != .root or frame.claims[7] != .root or !std.meta.eql(frame.roots_offset, [3]u32{ frame.claims[6].root, frame.claims[7].root, 0 }) or
                !std.meta.eql(try frame.digest(frame.sealed_offset), admitted.sealed.digest)) return error.UnpairedReadonlyPairChild;
            var first = frame.*;
            first.words = frame.words[0..frame.sealed_offset];
            first.first = frame.first;
            first.claims = &.{};
            first.sealed_offset = 0;
            first.roots_offset = @splat(0);
            var compare = try Compare.Comparator.initFirst(&first, .{}, .{ .sealed_offset = 0, .roots_offset = @splat(0) });
            Provider.mixFirst(&compare, admitted.pin);
            try compare.finish();
            var suffix = frame.*;
            suffix.first = frame.claims;
            suffix.claims = &.{};
            suffix.sealed_offset = 0;
            suffix.roots_offset = @splat(0);
            compare = try Compare.Comparator.initFirst(&suffix, .{}, .{ .sealed_offset = 0, .roots_offset = @splat(0) });
            compare.word_position = frame.sealed_offset + 8;
            const epoch = admitted.authority.epoch();
            Global.mixSuffix(&compare, epoch.plan_digest, epoch.roster_digest);
            try Provider.mixPcsSuffix(&compare, admitted.pin, proposed);
            try compare.finish();
            const sums = [_]Q{ proposed.classification_sum, proposed.read_sum } ++ proposed.range_sums;
            for (values.public[0..11], sums) |left, right| if (!left.eql(right)) return error.UnpairedReadonlyPairChild;
            for ([_]u64{ proposed.counts.events, proposed.counts.readonly }, 0..) |count, which| for (0..4) |limb| {
                const expected = Q.fromBase(M.fromCanonical(@intCast((count >> @as(u6, @intCast(16 * limb))) & 65535)));
                if (!values.public[11 + 4 * which + limb].eql(expected)) return error.UnpairedReadonlyPairChild;
            };
            if (!values.public[19].eql(Q.fromBase(M.fromCanonical(admitted.pin.shape.group_id)))) return error.UnpairedReadonlyPairChild;
        }
        pub const Fresh = struct {
            a: std.mem.Allocator,
            parent: ?*Budget,
            policy: Policy,
            open: Leaf.OpenEquation,
            frame: Frames.Statement,
            claim_first: u32,
            count_first: u32,
            terms: []Term,
            pub fn authority(self: *const @This()) !Protocol.Admission {
                try self.policy.validate();
                if (kind == .provider) {
                    try requireProviderValues(self.policy.admitted, self.policy.proposal, &self.open.public_values);
                } else if (!std.meta.eql(try Bus.Values.fromRange(self.policy.admitted, self.policy.proposal), self.open.public_values)) return error.UnpairedReadonlyPairChild;
                return Protocol.Admission.init(self.policy.key, self.policy.expected_id, self.policy.schedule, self.open.public_values);
            }
            pub fn validate(self: *const @This()) !void {
                const admitted = try self.authority();
                try self.open.equation.validate(&admitted, self.policy.expected_id);
                try Compare.compareFirst(&self.frame, .{ .max_words = self.policy.limits.max_words, .max_felts = self.policy.limits.max_felts, .max_steps = self.policy.limits.max_steps }, .{ .sealed_offset = 0, .roots_offset = @splat(0) }, &admitted);
                if (self.frame.first.len < 2) return error.UntrustedReadonlyPairChildLayout;
                const last = self.frame.first[self.frame.first.len - 1];
                if (last != .felts or last.felts.len != (if (kind == .provider) @as(usize, 20) else 1) or
                    self.claim_first != try std.math.add(u32, @intCast(self.frame.words.len), try std.math.mul(u32, 4, last.felts.first))) return error.UntrustedReadonlyPairChildLayout;
                if (kind == .range) {
                    const before = self.frame.first[self.frame.first.len - 2];
                    if (before != .integer or self.count_first != before.integer or try std.math.add(u32, before.integer, 2) != self.frame.words.len) return error.UntrustedReadonlyPairChildLayout;
                } else if (self.count_first != 0) return error.UntrustedReadonlyPairChildLayout;
                if (self.terms.len != self.policy.schedule.len) return error.UnpairedReadonlyPairChild;
                for (self.terms, self.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative or
                    !std.meta.eql(term.coordinates, try self.open.public_values.at(wire.source, wire.coordinate))) return error.UnpairedReadonlyPairChild;
            }
            pub fn deinit(self: *@This()) void {
                const a = self.a;
                const lease = self.parent;
                a.free(self.terms);
                self.frame.deinit();
                self.open.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
        pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
            try policy.validate();
            if (bytes.len == 0 or bytes.len > policy.limits.max_proof_bytes) return error.ReadonlyPairChildResourceLimit;
            const parent = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (parent) |owner| owner.destroy();
            const fresh = try a.create(Fresh);
            errdefer a.destroy(fresh);
            fresh.a = a;
            fresh.parent = parent;
            fresh.policy = policy;
            fresh.open = try Leaf.verify(a, bytes, policy.key, policy.expected_id, policy.schedule, policy.admitted, policy.proposal);
            errdefer fresh.open.deinit();
            const authority = try fresh.authority();
            var builder = Frames.Builder{ .allocator = a, .max_words = policy.limits.max_words, .max_felts = policy.limits.max_felts };
            defer builder.deinit();
            try authority.mix(&builder);
            try builder.check();
            if (builder.steps.items.len > policy.limits.max_steps or builder.steps.items.len < 2) return error.ReadonlyPairChildResourceLimit;
            const last = builder.steps.items[builder.steps.items.len - 1];
            if (last != .felts or last.felts.len != (if (kind == .provider) @as(usize, 20) else 1)) return error.UntrustedReadonlyPairChildLayout;
            fresh.claim_first = @intCast(builder.data.items.len + 4 * @as(usize, last.felts.first));
            fresh.count_first = if (kind == .range) count: {
                const before = builder.steps.items[builder.steps.items.len - 2];
                if (before != .integer or before.integer + 2 != builder.data.items.len) return error.UntrustedReadonlyPairChildLayout;
                break :count before.integer;
            } else 0;
            var owns_parts = true;
            const words = try builder.data.toOwnedSlice(a);
            errdefer if (owns_parts) a.free(words);
            const felts = try builder.fields.toOwnedSlice(a);
            errdefer if (owns_parts) a.free(felts);
            const first = try builder.steps.toOwnedSlice(a);
            errdefer if (owns_parts) a.free(first);
            const claims = try a.alloc(Frames.Step, 0);
            fresh.frame = .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) };
            owns_parts = false;
            errdefer fresh.frame.deinit();
            fresh.terms = try a.alloc(Term, policy.schedule.len);
            errdefer a.free(fresh.terms);
            for (fresh.terms, policy.schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .coordinates = try fresh.open.public_values.at(wire.source, wire.coordinate) };
            try fresh.validate();
            return fresh;
        }
        pub const Source = struct {
            fresh: *const Fresh,
            terms: []const Term,
            pub fn init(fresh: *const Fresh) !@This() {
                try fresh.validate();
                return .{ .fresh = fresh, .terms = fresh.terms };
            }
            pub fn validate(self: *const @This()) !void {
                if (self.terms.ptr != self.fresh.terms.ptr or self.terms.len != self.fresh.terms.len) return error.UnpairedReadonlyPairChild;
                try self.fresh.validate();
            }
            pub fn cell(self: *const @This(), coordinate: u32) ![4]M {
                if (coordinate >= self.fresh.frame.words.len + 4 * self.fresh.frame.felts.len) return error.UntrustedReadonlyPairChildLayout;
                const words = self.fresh.frame.words;
                const value = if (coordinate < words.len) words[coordinate] else self.fresh.frame.felts[(coordinate - words.len) / 4].toM31Array()[(coordinate - words.len) % 4].toU32();
                var bytes: [4]M = undefined;
                for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((value >> @as(u5, @intCast(8 * part))) & 255);
                return bytes;
            }
            pub fn replayPublic(self: *const @This(), recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
                self.fresh.frame.recordAt(recorder, self.fresh.frame.first, PUBLIC_CIRCUIT) catch |err| {
                    recorder.failure = err;
                };
            }
        };
        pub const Admission = struct {
            pub const open_parent_v5_v2 = true;
            source: *const Source,
            key: Base.Key,
            expected_id: [32]u8,
            pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
            pub fn init(source: *const Source) @This() {
                const key = source.fresh.policy.key;
                return .{ .source = source, .key = .{ .profile = key.profile, .config = key.config, .context = key.context, .log_sizes = key.log_sizes, .preprocessed_root = key.preprocessed_root }, .expected_id = source.fresh.policy.expected_id };
            }
            pub fn validate(self: *const @This()) !void {
                try self.source.validate();
                const expected = init(self.source);
                if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UnpairedReadonlyPairChild;
            }
            pub fn config(self: *const @This()) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
            pub fn admitRoot(self: *const @This(), root: [32]u8) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.admitRoot(root);
            }
            pub fn publicInputIdentity(self: *const @This()) ![32]u8 {
                try self.validate();
                const actual = try self.source.fresh.authority();
                return actual.publicInputIdentity();
            }
            pub fn mix(self: *const @This(), channel: anytype) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.mix(channel);
            }
            pub fn mixClaims(self: *const @This(), channel: anytype, claims: []const Q) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.mixClaims(channel, claims);
            }
            pub fn validateClaimsForRelations(self: *const @This(), claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.validateClaimsForRelations(claims, relations);
            }
        };
    };
}
