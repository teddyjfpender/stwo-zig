//! Explicit genuine range16 recursive publication. No canonical receiver or
//! driver/default is switched; parent rows include every actual verifier stage.
const std = @import("std");
const Native = @import("block_v5_range16_proof_v1.zig");
const Admission = @import("block_v5_range16_recursive_admission_v1.zig");
const Capture = @import("block_v5_range16_recursive_capture_v1.zig");
const Bus = @import("../recursion/block_v5_range16_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_range16_parent_protocol_v1.zig");
const Receiver = @import("../recursion/block_v5_range16_recursive_leaf_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Templates = @import("block_v5_cpu_recursive_template_derivation_v1.zig");
const Template = @import("block_v5_recursive_provider_store_v1.zig").ForFamily(.range16).TemplatePolicy;
pub const TemplateCallback = @import("block_v5_recursive_template_callback_v1.zig").ForTypes(Admission.Prepared, Protocol.Key, Bus.Wire);
pub const Artifact = struct {
    bytes: []u8,
    key: Protocol.Key,
    expected_key_id: [32]u8,
    schedule: []Bus.Wire,
    native: Native.OpenReceipt,
    public_values: Bus.Values,
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.schedule);
        self.* = undefined;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success consumes the owned artifact; error leaves it with this stage.
    put_range: *const fn (*anyopaque, u32, *Artifact) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const SetupCache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForRangeBackend(Backend);
        pub const ExpectedCache = @import("block_v5_word_expected_setup_cache_v1.zig").ForFamily(.range16, Backend);
        pub const Options = struct {
            /// Independently derived native fixed policy is checked against
            /// genuine original verifier rows before this callback/proving.
            on_template: ?TemplateCallback = null,
            profile: Parent.protocol.Profile,
            transcript_capacity: u32 = 2,
            /// Borrowed cache and pool remain alive throughout this synchronous
            /// call. All publication data is independently owned on success.
            cache: ?*SetupCache = null,
            /// Synchronous borrow. No get/deinit may overlap this publication.
            /// Only independent admitted fixed policy can fill this cache.
            expected_cache: ?*ExpectedCache = null,
            pub fn validate(self: @This(), config: @import("stwo_core").pcs.PcsConfig) !void {
                if (!std.meta.eql(self.profile.config(), config)) return error.RangeRecursiveSecurityMismatch;
                if (self.cache) |cache| if (cache.options.profile != self.profile) return error.RangeRecursiveSecurityMismatch;
            }
        };
        pub fn publish(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Admission.Prepared, options: Options, sink: Sink) !void {
            try options.validate(admitted.config);
            var owned_expected: ?Templates.OwnedFor(Template) = null;
            defer if (owned_expected) |*value| value.deinit();
            const expected = if (options.expected_cache) |cache|
                (try cache.get(a, admitted, options.profile, options.transcript_capacity)).*
            else independent: {
                // Fixed scratch dies inside this independent factory before
                // the original proof capture or its live rows are created.
                owned_expected = try Templates.providerPolicyForBackend(.range16, Backend, a, admitted, options.profile, options.transcript_capacity);
                break :independent owned_expected.?.template;
            };
            var capture = try Capture.ForBackend(Backend).verifyBorrowed(a, proof, admitted);
            defer capture.deinit();
            var rows = try Bus.prepare(a, admitted, &capture, options.transcript_capacity);
            defer rows.deinit();
            try Templates.requirePolicyRows(.range16, expected, &rows, options.profile);
            const key = expected.key;
            const key_id = expected.key_id;
            if (options.on_template) |callback| try callback.admit(admitted, key, key_id, rows.wires);
            const authority = try Protocol.Admission.init(key, key_id, rows.wires, rows.values);
            const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            var proved = if (options.cache) |cache| reused: {
                var value = try cache.provePreparedExpectedConsuming(&rows, key_id);
                errdefer value.proof.deinit();
                if (!std.meta.eql(value.key, key) or !std.meta.eql(value.key_id, key_id)) return error.UntrustedReusableRangeParentKey;
                break :reused value.proof;
            } else cold: {
                const plan = try Plan.init(a, &rows.recursive.rows, authority);
                defer plan.deinit();
                var workspace = @import("../recursion/blake3_native_parent_producer.zig").Workspace.init(a, 0);
                defer workspace.deinit();
                break :cold try plan.proveConsumingWithWorkspace(a, &rows.recursive.rows, &workspace);
            };
            defer proved.deinit();
            const bytes = try Parent.codec.encode(a, &proved, &authority);
            var owns_bytes = true;
            defer if (owns_bytes) a.free(bytes);
            var fresh = try Receiver.verify(a, bytes, key, key_id, rows.wires, admitted, capture.receipt);
            defer fresh.deinit();
            const schedule = try a.dupe(Bus.Wire, rows.wires);
            var owns_schedule = true;
            defer if (owns_schedule) a.free(schedule);
            var artifact = Artifact{ .bytes = bytes, .key = key, .expected_key_id = key_id, .schedule = schedule, .native = capture.receipt, .public_values = fresh.public_values };
            try sink.put_range(sink.context, admitted.shard.index, &artifact);
            owns_bytes = false;
            owns_schedule = false;
        }
    };
}

test "word expected setup: range publication rejects invalid independent capacity before proof capture or allocation" {
    const Stage = ForBackend(@import("stwo_cpu_backend").CpuBackend);
    comptime if (Stage.ExpectedCache != @import("block_v5_word_expected_setup_cache_v1.zig").ForFamily(.range16, @import("stwo_cpu_backend").CpuBackend)) @compileError("range publication uses a different independent setup cache");
    var admitted: Admission.Prepared = undefined;
    admitted.config = Parent.protocol.Profile.csp_q70_pow26.config();
    var denied = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const options = Stage.Options{ .profile = .csp_q70_pow26, .transcript_capacity = 0 };
    try std.testing.expect(options.expected_cache == null);
    try std.testing.expectError(error.RecursiveTemplateDerivationSecurityMismatch, Stage.publish(denied.allocator(), undefined, &admitted, options, undefined));
    try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
}
