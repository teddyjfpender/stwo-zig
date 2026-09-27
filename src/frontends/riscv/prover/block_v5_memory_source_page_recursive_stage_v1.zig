//! Explicit original PAGE capture -> full verifier rows -> real recursive
//! parent -> fresh recursive receiver. No canonical/default activation.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const ExpectedModule = @import("block_v5_page_recursive_expected_setup_v1.zig");
const PolicyFile = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Original = @import("block_v5_memory_source_unified_page_proof_v1.zig").ForKind(kind);
    const Admission = @import("block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    const Capture = @import("block_v5_memory_source_page_recursive_capture_v1.zig").ForKind(kind);
    const Bus = @import("../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    const Protocol = @import("../recursion/block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
    const ExpectedChecks = ExpectedModule.ForKind(kind);
    const Leaf = @import("../recursion/block_v5_memory_source_page_recursive_leaf_v1.zig").ForKind(kind);
    return struct {
        pub const TemplateCallback = @import("block_v5_recursive_template_callback_v1.zig").ForTypes(Admission.Prepared, Protocol.Key, Bus.Wire);
        pub const Artifact = struct {
            allocator: std.mem.Allocator,
            allocation_owner: ?*Budget,
            bytes: []u8,
            key: Protocol.Key,
            expected_key_id: [32]u8,
            schedule: []Bus.Wire,
            native: Original.VerifiedPage,
            claims: Bus.Claims,
            public_values: Bus.Values,
            pub fn deinit(self: *Artifact) void {
                const owner = self.allocation_owner;
                self.public_values.deinit();
                self.allocator.free(self.bytes);
                self.allocator.free(self.schedule);
                self.* = undefined;
                if (owner) |value| value.destroy();
            }
        };
        pub const Sink = struct {
            context: *anyopaque,
            /// Success consumes every artifact owner, error consumes none.
            put_page: *const fn (*anyopaque, u32, *Artifact) anyerror!void,
        };
        pub fn ForBackend(comptime Backend: type) type {
            return struct {
                const ExpectedSetup = ExpectedChecks.ForBackend(Backend);
                pub const SetupCache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForModules(Backend, Bus, Protocol);
                pub const Options = struct {
                    on_template: ?TemplateCallback = null,
                    profile: Parent.protocol.Profile,
                    transcript_capacity: u32 = 2,
                    cache: ?*SetupCache = null,
                    expected_claims: ?Semantic.Claims = null,
                    fixed_limits: ExpectedModule.Limits = .{},
                    pub fn validate(self: @This(), config: core.pcs.PcsConfig) !void {
                        _ = try PolicyFile.expectedClaims(kind, self.expected_claims);
                        if (self.transcript_capacity == 0 or self.fixed_limits.max_bytes == 0) return error.PageFixedRosterResourceLimit;
                        if (!std.meta.eql(self.profile.config(), config)) return error.SourcePageRecursiveSecurityMismatch;
                        if (self.cache) |cache| if (cache.options.profile != self.profile) return error.SourcePageRecursiveSecurityMismatch;
                    }
                };
                pub fn publish(a: std.mem.Allocator, proof: *const Original.Proof, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
                    try options.validate(admitted.config);
                    var expected = try ExpectedSetup.derive(a, admitted, try PolicyFile.expectedClaims(kind, options.expected_claims), options.transcript_capacity, options.profile, options.fixed_limits);
                    defer expected.deinit();
                    // Independent setup has released all fixed rows before
                    // the mandatory original proof capture starts.
                    var capture = try Capture.verifyBorrowed(a, proof, admitted);
                    defer capture.deinit();
                    try publishExpectedCapture(a, &capture, admitted, options, sink, &expected);
                }
                pub fn publishFromVerifiedCapture(a: std.mem.Allocator, capture: *const Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
                    try options.validate(admitted.config);
                    var expected = try ExpectedSetup.derive(a, admitted, try PolicyFile.expectedClaims(kind, options.expected_claims), options.transcript_capacity, options.profile, options.fixed_limits);
                    defer expected.deinit();
                    try publishExpectedCapture(a, capture, admitted, options, sink, &expected);
                }
                fn publishExpectedCapture(a: std.mem.Allocator, capture: *const Capture.VerifiedCapture, admitted: *const Admission.Prepared, options: Options, sink: Sink, expected: *const ExpectedSetup.Expected) !void {
                    try capture.validate(admitted, admitted.template_id);
                    try ExpectedModule.requireClaims(kind, try PolicyFile.expectedClaims(kind, options.expected_claims), capture.original.frame.semantic.claims);
                    var rows = try Bus.prepare(a, admitted, capture, options.transcript_capacity);
                    defer rows.deinit();
                    const key = expected.key;
                    const key_id = try key.identity();
                    try ExpectedChecks.requirePrepared(key, expected.wires, &rows);
                    if (options.on_template) |callback| try callback.admit(admitted, key, key_id, expected.wires);
                    var cached: ?SetupCache.Proved = null;
                    var owns_cached = false;
                    defer if (owns_cached) cached.?.proof.deinit();
                    if (options.cache) |cache| {
                        cached = try cache.provePreparedExpectedConsuming(&rows, key_id);
                        owns_cached = true;
                        if (!std.meta.eql(cached.?.key, key) or !std.meta.eql(cached.?.key_id, key_id)) return error.UntrustedSourcePageRecursiveKey;
                    }
                    const authority = try Protocol.Admission.init(key, key_id, rows.wires, rows.values);
                    const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
                    var plan: ?*Plan = null;
                    defer if (plan) |value| value.deinit();
                    if (cached == null) plan = try Plan.init(a, &rows.recursive.rows, authority);
                    var workspace = @import("../recursion/blake3_native_parent_producer.zig").Workspace.init(a, 0);
                    defer workspace.deinit();
                    var proved = if (cached) |value| value.proof else try plan.?.proveConsumingWithWorkspace(a, &rows.recursive.rows, &workspace);
                    owns_cached = false;
                    defer proved.deinit();
                    const owner = Budget.fromAllocator(a);
                    if (owner) |value| _ = value.retain();
                    var owns_owner = true;
                    defer if (owns_owner) if (owner) |value| value.destroy();
                    const bytes = try Parent.codec.encode(a, &proved, &authority);
                    var owns_bytes = true;
                    defer if (owns_bytes) a.free(bytes);
                    const claims = Bus.Claims{ .semantic = capture.original.frame.semantic, .components = capture.original.frame.claims };
                    var fresh = try Leaf.verify(a, bytes, key, key_id, rows.wires, admitted, claims);
                    defer fresh.deinit();
                    const schedule = try a.dupe(Bus.Wire, rows.wires);
                    var owns_schedule = true;
                    defer if (owns_schedule) a.free(schedule);
                    var values = try fresh.public_values.clone(a);
                    var owns_values = true;
                    defer if (owns_values) values.deinit();
                    var artifact = Artifact{ .allocator = a, .allocation_owner = owner, .bytes = bytes, .key = key, .expected_key_id = key_id, .schedule = schedule, .native = capture.receipt, .claims = claims, .public_values = values };
                    try sink.put_page(sink.context, capture.receipt.page_index, &artifact);
                    owns_values = false;
                    owns_schedule = false;
                    owns_bytes = false;
                    owns_owner = false;
                }
            };
        }
    };
}
