//! Capture-free compiler views. Native expected keys are rederived from the
//! original Word factory. Compact node keys belong to the topological factory;
//! these views alone provide no independent setup or proof acceptance.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("blake3_execution_parent_protocol.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
const Span = @import("block_v5_pc_clock_span_v1.zig").Span;
const Provider = @import("block_v5_memory_recursive_provider_source_v1.zig");
const Norm = @import("block_v5_memory_source_page_forest_normalizer_v1.zig");
const Word = @import("block_v5_word_recursive_fixed_roster_v1.zig");
fn baseKey(k: anytype) Base.Key {
    return .{ .profile = k.profile, .config = k.config, .context = k.context, .log_sizes = k.log_sizes, .preprocessed_root = k.preprocessed_root };
}
pub fn ForKind(comptime kind: Provider.Kind) type {
    const Original = Provider.ForKind(kind);
    const Family = Word.ForFamily(if (kind == .ram) .ram_lanes else .range16);
    return struct {
        pub const PUBLIC_CIRCUIT = Original.PUBLIC_CIRCUIT;
        pub const Source = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            policy: Original.Policy,
            normal: Original.Normalized,
            terms: []Term,
            pub fn derive(comptime Backend: type, a: std.mem.Allocator, policy: Original.Policy, capacity: u32, profile: Base.Profile, limits: Word.Limits) !Self {
                var fixed = try Family.ForBackend(Backend).deriveKeyAndScheduleForPolicy(a, policy.admitted, policy.admitted.template_id, capacity, profile, limits);
                defer fixed.deinit();
                const key = fixed.key;
                if (!std.meta.eql(key, policy.key) or !std.meta.eql(try key.identity(), policy.expected_id) or fixed.wires.len != policy.schedule.len) return error.UntrustedRamRangeFixedLeafSetup;
                for (fixed.wires, policy.schedule) |expected, proposed| if (!std.meta.eql(expected, proposed)) return error.UntrustedRamRangeFixedLeafSetup;
                const authority = try policy.authority();
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                var normal = try Original.Normalized.init(a, &authority, policy.limits);
                errdefer normal.deinit();
                const terms = try a.alloc(Term, policy.schedule.len);
                errdefer a.free(terms);
                for (terms, policy.schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .coordinates = try authority.values.at(wire.source, wire.coordinate) };
                return .{ .allocator = a, .lease = lease, .policy = policy, .normal = normal, .terms = terms };
            }
            pub fn validate(self: *const Self) !void {
                const authority = try self.policy.authority();
                try self.normal.require(self.allocator, &authority, self.policy.limits);
                if (self.terms.len != self.policy.schedule.len) return error.UntrustedRamRangeFixedLeafSetup;
                for (self.terms, self.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative or !std.meta.eql(term.coordinates, try authority.values.at(wire.source, wire.coordinate))) return error.UntrustedRamRangeFixedLeafSetup;
            }
            pub fn replayPublic(self: *const Self, recorder: anytype) void {
                self.normal.frame.recordAt(recorder, self.normal.frame.first, PUBLIC_CIRCUIT) catch |failure| {
                    recorder.failure = failure;
                };
            }
            pub fn deinit(self: *Self) void {
                const lease = self.lease;
                self.allocator.free(self.terms);
                self.normal.deinit();
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        pub const Admission = struct {
            pub const fixed_setup_only = true;
            source: *const Source,
            key: Base.Key,
            pc_clock_children: []const Span = &.{},
            pub fn init(source: *const Source) !@This() {
                try source.validate();
                return .{ .source = source, .key = baseKey(source.policy.key) };
            }
            pub fn validate(self: *const @This()) !void {
                try self.source.validate();
                if (self.pc_clock_children.len != 0 or !std.meta.eql(self.key, baseKey(self.source.policy.key))) return error.UntrustedRamRangeFixedLeafSetup;
            }
            pub fn config(self: *const @This()) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
        };
    };
}
/// Same exact original summary Admission.mix, without any Fresh/capture.
/// Only the fixed factory independently derives the Spec; this compiler view
/// cannot certify a supplied Spec or produce a receiving authority.
pub fn ForSummary(comptime Bus: type, comptime Protocol: type, comptime public_circuit: u32, comptime page: bool) type {
    return struct {
        pub const PUBLIC_CIRCUIT = public_circuit;
        pub const Source = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            public: *const Bus.Owner,
            normal: Norm.Normalized,
            terms: []Term,
            pub fn init(a: std.mem.Allocator, public: *const Bus.Owner) !Self {
                try public.validate();
                const authority = try original(public);
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                var normal = try Norm.Normalized.initWithWords(a, &authority, if (page) &public.summary.value.claims else &public.summary.value, 0, &public.summary.header, public.limits.normalization);
                errdefer normal.deinit();
                const terms = try a.alloc(Term, 0);
                return .{ .allocator = a, .lease = lease, .public = public, .normal = normal, .terms = terms };
            }
            fn original(public: *const Bus.Owner) !Protocol.Admission {
                const spec = public.policy.specs[public.policy.index];
                return Protocol.Admission.init(try Protocol.Key.fromGeometry(spec.geometry, &.{}), spec.expected_id, &.{}, .{ .public = public });
            }
            pub fn validate(self: *const Self) !void {
                try self.public.validate();
                const authority = try original(self.public);
                try self.normal.requireWithWords(self.allocator, &authority, if (page) &self.public.summary.value.claims else &self.public.summary.value, 0, &self.public.summary.header, self.public.limits.normalization);
                if (self.terms.len != 0) return error.UntrustedCompactFixedSetup;
            }
            pub fn cell(self: *const Self, index: u32) ![4]core.fields.m31.M31 {
                return self.normal.cell(index);
            }
            pub fn claim(self: *const Self, index: u32) !struct { first_cell: u32, word_count: u32 } {
                if (index >= 22) return error.InvalidCompactFixedCell;
                return .{ .first_cell = try std.math.add(u32, self.normal.claim_first, try std.math.mul(u32, 4, index)), .word_count = 4 };
            }
            pub fn headerFirst(self: *const Self) !u32 {
                return self.normal.word_first orelse error.UntrustedCompactFixedSetup;
            }
            pub fn rangeCoordinates(self: *const Self) !struct { first: u32, count: u32, raw_pages: u32, fold_pages: u32, raw_rows: u32, fold_rows: u32 } {
                const first = try self.headerFirst();
                return .{ .first = first + 3, .count = first + 4, .raw_pages = first + 5, .fold_pages = first + 6, .raw_rows = first + 7, .fold_rows = first + 8 };
            }
            pub fn replayPublic(self: *const Self, recorder: anytype) void {
                self.normal.frame.recordAt(recorder, self.normal.frame.first, PUBLIC_CIRCUIT) catch |failure| {
                    recorder.failure = failure;
                };
            }
            pub fn deinit(self: *Self) void {
                const lease = self.lease;
                self.allocator.free(self.terms);
                self.normal.deinit();
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        pub const Admission = struct {
            pub const fixed_setup_only = true;
            source: *const Source,
            key: Base.Key,
            pc_clock_children: []const Span = &.{},
            pub fn init(source: *const Source) !@This() {
                try source.validate();
                return .{ .source = source, .key = source.public.policy.specs[source.public.policy.index].geometry };
            }
            pub fn validate(self: *const @This()) !void {
                try self.source.validate();
                if (self.pc_clock_children.len != 0 or !std.meta.eql(self.key, self.source.public.policy.specs[self.source.public.policy.index].geometry)) return error.UntrustedCompactFixedSetup;
            }
            pub fn config(self: *const @This()) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
        };
    };
}
pub const Node = ForSummary(@import("block_v5_ram_range_forest_summary_bus_v1.zig"), @import("block_v5_ram_range_forest_summary_protocol_v1.zig"), @import("block_v5_ram_range_forest_source_v1.zig").PUBLIC_CIRCUIT, false);
