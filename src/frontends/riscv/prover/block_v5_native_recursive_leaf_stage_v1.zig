//! Genuine native-v3 recursive leaf publication inside the bounded producer's
//! on_proof callback. Only owned wire/policy values leave the callback; native
//! capture, prepared verifier, rows and setup never outlive one execution.
const std = @import("std");
const ProducerModule = @import("block_v5_block_producer_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Prepared = @import("block_v5_native_recursive_admission_v3.zig").Prepared;
const Bus = @import("../recursion/block_v5_recursive_public_bus_v1.zig");
const Protocol = @import("../recursion/block_v5_reusable_native_parent_protocol_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Receiver = @import("../recursion/block_v5_reusable_native_leaf_v1.zig");
const Span = @import("../recursion/block_v5_pc_clock_span_v1.zig");

pub const Options = struct {
    profile: Parent.protocol.Profile,
};
pub const Artifact = struct {
    bytes: []u8,
    key: Protocol.Key,
    expected_key_id: [32]u8,
    schedule: []Bus.Wire,
    native: Native.OpenReceipt,
    public_values: Bus.Values,
    span: Span.Span,
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.schedule);
        self.* = undefined;
    }
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers the complete owned artifact; error leaves it here.
    /// A file sink can persist bytes and pins, then release this allocation.
    put_leaf: *const fn (*anyopaque, u32, *Artifact) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Producer = ProducerModule.ForLightweightBackend(Backend);
        pub const SetupCache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForBackend(Backend);
        pub const TypedOptions = struct {
            profile: Parent.protocol.Profile,
            cache: ?*SetupCache = null,
        };
        options: TypedOptions,
        sink: Sink,
        pub fn hooks(self: *Self) Producer.Hooks {
            return .{ .context = self, .on_proof = onProof };
        }
        fn onProof(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmExecution, proof: *const Native.Proof) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            // Canonical native security cannot be compressed by a diagnostic
            // recursive verifier, nor vice versa. Both setup layers match B5SS.
            if (!std.meta.eql(self.options.profile.config(), warm.pins.config) or
                !std.meta.eql(warm.first.template.config, warm.pins.config)) return error.V5NativeLeafStageSecurityMismatch;
            if (warm.first.index != warm.index or warm.first.native != warm.replay.owner or
                !warm.replay.owner.native_only_v5 or warm.first.owns_scheme or
                warm.replay.admission.context.execution_index != warm.index or
                !std.meta.eql(warm.first.pin, warm.replay.admission) or
                warm.first.template.execution_profile != warm.replay.profile or
                warm.first.template.external_retirements != warm.replay.owner.external_retirements or
                !std.meta.eql(proof.template_id, warm.first.template_id) or
                !std.meta.eql(proof.instance_id, warm.first.instance_id)) return error.UntrustedV5WarmNativeLeaf;
            try warm.sealed.require(warm.pins, warm.entries);
            try warm.replay.admission.require(warm.pins, &warm.replay.owner.statement.public_data);
            try warm.first.template.admit(&warm.replay.owner.statement, warm.first.template_id);
            try warm.catalog.admit(warm.pins, warm.sealed, warm.index, warm.first.template, warm.first.template_id);
            // Fresh verification borrows the bounded producer artifact. All
            // returned capture material is owned, without encoding/decoding
            // a second native proof. Independent file admission is unchanged.
            var capture = try Native.ForBackend(Backend).verifyCaptureBorrowedWithCatalog(a, proof, &warm.replay.owner.statement, warm.replay.admission, warm.first.template, warm.first.template_id, warm.replay.profile, warm.index, warm.sealed, warm.pins, warm.entries, warm.catalog);
            defer capture.deinit();
            var admitted = try Prepared.init(a, &warm.replay.owner.statement, warm.replay.admission, warm.first.template, warm.first.template_id, warm.index, warm.sealed, warm.pins, warm.entries, warm.catalog);
            defer admitted.deinit();
            var rows = try Bus.prepare(a, &admitted, &capture, 2);
            defer rows.deinit();
            var cached: ?SetupCache.Proved = null;
            var owns_cached = false;
            defer if (owns_cached) cached.?.proof.deinit();
            const key = if (self.options.cache) |cache| from_cache: {
                if (cache.options.profile != self.options.profile) return error.V5NativeLeafStageSecurityMismatch;
                cached = try cache.provePreparedConsuming(&rows);
                owns_cached = true;
                break :from_cache cached.?.key;
            } else uncached: {
                const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(a, &rows.recursive, self.options.profile);
                break :uncached try Protocol.Key.fromGeometry(geometry, rows.wires);
            };
            if (!std.meta.eql(key.config, warm.pins.config) or !std.meta.eql(key.context.child_config, warm.pins.config)) return error.V5NativeLeafStageSecurityMismatch;
            const key_id = try key.identity();
            const authority = try Protocol.Admission.init(key, key_id, rows.wires, rows.values);
            const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
            var plan: ?*Plan = null;
            defer if (plan) |owned| owned.deinit();
            if (cached == null) plan = try Plan.init(a, &rows.recursive.rows, authority);
            var proved = if (cached) |value| value.proof else try plan.?.prove(a, &rows.recursive.rows);
            owns_cached = false;
            defer proved.deinit();
            const bytes = try Parent.codec.encode(a, &proved, &authority);
            var owns_bytes = true;
            defer if (owns_bytes) a.free(bytes);
            var fresh = try Receiver.verify(a, bytes, key, key_id, rows.wires, &admitted, capture.receipt);
            defer fresh.deinit();
            const schedule = try a.dupe(Bus.Wire, rows.wires);
            var owns_schedule = true;
            defer if (owns_schedule) a.free(schedule);
            var output = Artifact{ .bytes = bytes, .key = key, .expected_key_id = key_id, .schedule = schedule, .native = capture.receipt, .public_values = fresh.public_values, .span = fresh.pc_clock_span orelse return error.MissingV5NativeLeafPcSpan };
            try self.sink.put_leaf(self.sink.context, warm.index, &output);
            owns_bytes = false;
            owns_schedule = false;
        }
    };
}
