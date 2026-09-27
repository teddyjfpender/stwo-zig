//! Actual original RAM/range leaf verifiers and exact public transcript cells.
//! Sources borrow a genuine Parent.Verified owner; metadata cannot mint one.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
pub const Kind = enum { ram, range };
pub const Limits = struct { max_proof_bytes: usize = 512 << 20, max_words: usize = 4096, max_felts: usize = 256, max_steps: usize = 2048, max_terms: usize = 1024 };
pub fn ForKind(comptime kind: Kind) type {
    const Bus = if (kind == .ram) @import("block_v5_ram_lanes_recursive_public_bus_v1.zig") else @import("block_v5_range16_recursive_public_bus_v1.zig");
    const Protocol = if (kind == .ram) @import("block_v5_reusable_ram_lanes_parent_protocol_v1.zig") else @import("block_v5_reusable_range16_parent_protocol_v1.zig");
    const Leaf = if (kind == .ram) @import("block_v5_ram_lanes_recursive_leaf_v1.zig") else @import("block_v5_range16_recursive_leaf_v1.zig");
    const OriginalAdmission = if (kind == .ram) @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig") else @import("../prover/block_v5_range16_recursive_admission_v1.zig");
    const Native = if (kind == .ram) @import("../prover/block_v5_ram_lanes_proof_v1.zig") else @import("../prover/block_v5_range16_proof_v1.zig");
    return struct {
        const Self = @This();
        pub const PUBLIC_CIRCUIT: u32 = if (kind == .ram) 4_300_410 else 4_300_411;
        pub const Policy = struct {
            admitted: *const OriginalAdmission.Prepared,
            proposal: Native.OpenReceipt,
            key: Protocol.Key,
            expected_id: [32]u8,
            schedule: []const Bus.Wire,
            limits: Limits = .{},
            pub fn authority(self: @This()) !Protocol.Admission {
                if (self.limits.max_proof_bytes == 0 or self.limits.max_words == 0 or self.limits.max_felts == 0 or self.limits.max_steps == 0 or self.schedule.len == 0 or self.schedule.len > self.limits.max_terms) return error.RecursiveMemorySourceLimit;
                return Protocol.Admission.init(self.key, self.expected_id, self.schedule, if (kind == .ram) try Bus.Values.fromLanes(self.admitted, self.proposal) else try Bus.Values.fromRange(self.admitted, self.proposal));
            }
        };
        pub const Normalized = struct {
            frame: Frames.Statement,
            /// RAM: first of original 90 claim words. RANGE: original count LE2.
            count_first: u32,
            /// RANGE: original secure sum. RAM sums are claim words, not felts.
            sum_first: u32,
            pub fn init(a: std.mem.Allocator, authority_value: *const Protocol.Admission, limits: Limits) !Normalized {
                var builder = Frames.Builder{ .allocator = a, .max_words = limits.max_words, .max_felts = limits.max_felts };
                defer builder.deinit();
                try authority_value.mix(&builder);
                try builder.check();
                if (builder.steps.items.len > limits.max_steps) return error.RecursiveMemorySourceLimit;
                const steps = builder.steps.items;
                var count_first: u32 = undefined;
                var sum_offset: u32 = undefined;
                if (kind == .ram) {
                    // Original Values.mix ends with mixClaims followed by exact
                    // equation_inputs. Locate by invocation/length/order, never
                    // equal-value matching or a transported offset.
                    const calls = 3 + 4 * (4 + @import("../prover/block_v5_ram_lanes_interaction_v1.zig").RANGE_PLANES);
                    if (steps.len < calls + 1 or builder.data.items.len < 90) return error.RecursiveMemoryClaimLayout;
                    const first_step = steps.len - calls - 1;
                    if (steps[first_step] != .integer or steps[steps.len - 3] != .integer or steps[steps.len - 2] != .integer or steps[steps.len - 1] != .felts or steps[steps.len - 1].felts.len != authority_value.values.equation_inputs.len) return error.RecursiveMemoryClaimLayout;
                    count_first = steps[first_step].integer;
                    if (count_first + 90 != builder.data.items.len or
                        steps[steps.len - 3].integer != count_first + 86 or
                        steps[steps.len - 2].integer != count_first + 88) return error.RecursiveMemoryClaimLayout;
                    for (steps[first_step + 1 .. steps.len - 3], 0..) |step, index| if (step != .words or step.words.len != 1 or step.words.first != count_first + 2 + index) return error.RecursiveMemoryClaimLayout;
                    const expected = authority_value.values.claimWords();
                    if (!std.mem.eql(u32, builder.data.items[count_first..][0..90], &expected)) return error.RecursiveMemoryClaimLayout;
                    sum_offset = 0;
                } else {
                    if (steps.len < 2 or steps[steps.len - 2] != .integer or steps[steps.len - 1] != .felts or steps[steps.len - 1].felts.len != 1) return error.RecursiveMemoryClaimLayout;
                    count_first = steps[steps.len - 2].integer;
                    if (count_first + 2 != builder.data.items.len) return error.RecursiveMemoryClaimLayout;
                    sum_offset = steps[steps.len - 1].felts.first;
                }
                const words = try builder.data.toOwnedSlice(a);
                errdefer a.free(words);
                const felts = try builder.fields.toOwnedSlice(a);
                errdefer a.free(felts);
                const first = try builder.steps.toOwnedSlice(a);
                errdefer a.free(first);
                const claims = try a.alloc(Frames.Step, 0);
                errdefer a.free(claims);
                return .{ .frame = .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) }, .count_first = count_first, .sum_first = @intCast(words.len + 4 * @as(usize, sum_offset)) };
            }
            pub fn deinit(self: *@This()) void {
                self.frame.deinit();
                self.* = undefined;
            }
            pub fn cell(self: *const @This(), coordinate: u32) ![4]M {
                if (coordinate >= self.frame.words.len + 4 * self.frame.felts.len) return error.InvalidRecursiveMemoryCell;
                const word = if (coordinate < self.frame.words.len) self.frame.words[coordinate] else self.frame.felts[(coordinate - self.frame.words.len) / 4].toM31Array()[(coordinate - self.frame.words.len) % 4].v;
                var bytes: [4]M = undefined;
                for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
                return bytes;
            }
            pub fn require(self: *const @This(), a: std.mem.Allocator, authority_value: *const Protocol.Admission, limits: Limits) !void {
                var expected = try init(a, authority_value, limits);
                defer expected.deinit();
                if (self.count_first != expected.count_first or self.sum_first != expected.sum_first or !std.mem.eql(u32, self.frame.words, expected.frame.words) or self.frame.felts.len != expected.frame.felts.len or self.frame.first.len != expected.frame.first.len or self.frame.claims.len != 0) return error.MutatedRecursiveMemorySource;
                for (self.frame.felts, expected.frame.felts) |left, right| if (!left.eql(right)) return error.MutatedRecursiveMemorySource;
                for (self.frame.first, expected.frame.first) |left, right| if (!std.meta.eql(left, right)) return error.MutatedRecursiveMemorySource;
            }
        };
        pub const Fresh = struct {
            allocator: std.mem.Allocator,
            allocation_owner: ?*Budget,
            policy: Policy,
            open: Leaf.OpenEquation,
            normalized: Self.Normalized,
            terms: []Term,
            pub fn authority(self: *const @This()) !Protocol.Admission {
                const expected = try self.policy.authority();
                if (!std.meta.eql(expected.values, self.open.public_values)) return error.UnpairedRecursiveMemorySource;
                return expected;
            }
            pub fn validate(self: *const @This()) !void {
                const original = try self.authority();
                try self.open.equation.validate(&original, self.policy.expected_id);
                try self.normalized.require(self.allocator, &original, self.policy.limits);
                if (self.terms.len != self.policy.schedule.len) return error.UnpairedRecursiveMemorySource;
                for (self.terms, self.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative or !std.meta.eql(term.coordinates, try self.open.public_values.at(wire.source, wire.coordinate))) return error.UnpairedRecursiveMemorySource;
            }
            pub fn deinit(self: *@This()) void {
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
            if (bytes.len == 0 or bytes.len > policy.limits.max_proof_bytes) return error.RecursiveMemorySourceLimit;
            _ = try policy.authority();
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            const fresh = try a.create(Fresh);
            errdefer a.destroy(fresh);
            fresh.allocator = a;
            fresh.allocation_owner = lease;
            fresh.policy = policy;
            fresh.open = try Leaf.verify(a, bytes, policy.key, policy.expected_id, policy.schedule, policy.admitted, policy.proposal);
            errdefer fresh.open.deinit();
            const original = try fresh.authority();
            fresh.normalized = try Self.Normalized.init(a, &original, policy.limits);
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
            pub fn init(fresh: *const Fresh) !@This() {
                try fresh.validate();
                return .{ .fresh = fresh, .terms = fresh.terms };
            }
            pub fn validate(self: *const @This()) !void {
                if (self.terms.ptr != self.fresh.terms.ptr or self.terms.len != self.fresh.terms.len) return error.UnpairedRecursiveMemorySource;
                try self.fresh.validate();
            }
            pub fn cell(self: *const @This(), coordinate: u32) ![4]M {
                return self.fresh.normalized.cell(coordinate);
            }
            pub fn replayPublic(self: *const @This(), recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
                self.fresh.normalized.frame.recordAt(recorder, self.fresh.normalized.frame.first, PUBLIC_CIRCUIT) catch |failure| {
                    recorder.failure = failure;
                };
            }
            pub fn sumFirst(self: *const @This(), index: u32) !u32 {
                if (kind == .range) {
                    if (index != 0) return error.InvalidRecursiveMemoryCell;
                    return self.fresh.normalized.sum_first;
                }
                if (index >= 4 + @import("../prover/block_v5_ram_lanes_interaction_v1.zig").RANGE_PLANES) return error.InvalidRecursiveMemoryCell;
                return self.fresh.normalized.count_first + 2 + 4 * index;
            }
            pub fn countFirst(self: *const @This(), index: u32) !u32 {
                if (kind == .range) {
                    if (index != 0) return error.InvalidRecursiveMemoryCell;
                    return self.fresh.normalized.count_first;
                }
                return self.fresh.normalized.count_first + switch (index) {
                    0 => @as(u32, 0),
                    1 => 86,
                    2 => 88,
                    else => return error.InvalidRecursiveMemoryCell,
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
                if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UnpairedRecursiveMemorySource;
            }
            pub fn config(self: *const @This()) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
            pub fn admitRoot(self: *const @This(), root: [32]u8) !void {
                const original = try self.source.fresh.authority();
                try self.validate();
                try original.admitRoot(root);
            }
            pub fn publicInputIdentity(self: *const @This()) ![32]u8 {
                const original = try self.source.fresh.authority();
                try self.validate();
                return original.publicInputIdentity();
            }
            pub fn mix(self: *const @This(), channel: anytype) !void {
                try self.validate();
                const original = try self.source.fresh.authority();
                try original.mix(channel);
            }
            pub fn mixClaims(self: *const @This(), channel: anytype, claims: []const Q) !void {
                try self.validate();
                const original = try self.source.fresh.authority();
                try original.mixClaims(channel, claims);
            }
            pub fn validateClaimsForRelations(self: *const @This(), claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
                try self.validate();
                const original = try self.source.fresh.authority();
                try original.validateClaimsForRelations(claims, relations);
            }
        };
    };
}
