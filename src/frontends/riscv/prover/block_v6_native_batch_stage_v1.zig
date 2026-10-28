//! Bounded NativeV3 captures -> one direct recursive proof, no leaf wrappers.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Prep = @import("../recursion/block_v6_native_batch_prepare_v1.zig");
const Bus = @import("../recursion/block_v6_native_batch_public_v1.zig");
const Protocol = @import("../recursion/block_v6_native_batch_protocol_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Producer = @import("block_v5_block_producer_v1.zig").ForLightweightBackend(Cpu);
const Global = @import("block_v5_global_receiver_v1.zig");

pub const Artifact = struct {
    bytes: []u8,
    pins: Global.NativeBatchPins,
    prepare_ns: u64,
    setup_ns: u64,
    prove_ns: u64,
    encode_ns: u64,
    pub fn deinit(self: *Artifact, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.pins.schedule);
        self.* = undefined;
    }
};
pub const Stage = struct {
    a: std.mem.Allocator,
    profile: Parent.protocol.Profile,
    prepared: []Prep.NativeAdmission,
    captures: []Prep.Capture,
    next: usize = 0,
    /// Borrow only assembly-owned statements/roster, never live replay owners.
    /// The assembly must outlive this stage and every captured proof.
    pub fn init(a: std.mem.Allocator, globals: Global.Pins, profile: Parent.protocol.Profile) !Stage {
        const count = globals.tables.executions.len;
        if (count == 0 or count > Bus.MAX_CHILDREN) return error.InvalidNativeBatchCount;
        if (!std.meta.eql(profile.config(), globals.tables.seal.config)) return error.NativeBatchSecurityMismatch;
        const sealed = try globals.validate();
        const prepared = try a.alloc(Prep.NativeAdmission, count);
        errdefer a.free(prepared);
        var initialized: usize = 0;
        errdefer for (prepared[0..initialized]) |*p| p.deinit();
        for (globals.tables.executions, 0..) |pin, i| {
            prepared[i] = try Prep.NativeAdmission.init(a, pin.shape, pin.admission, pin.template, pin.template_id, @intCast(i), sealed, globals.tables.seal, globals.tables.roster, globals.tables.catalog);
            initialized += 1;
            prepared[i].reusable_public_inputs = true;
        }
        return .{ .a = a, .profile = profile, .prepared = prepared, .captures = try a.alloc(Prep.Capture, count) };
    }
    pub fn deinit(self: *Stage) void {
        for (self.captures[0..self.next]) |*c| c.deinit();
        for (self.prepared) |*p| p.deinit();
        self.a.free(self.prepared);
        self.a.free(self.captures);
        self.* = undefined;
    }
    pub fn capture(raw: *anyopaque, a: std.mem.Allocator, warm: Producer.WarmExecution, proof: *const Native.Proof) !void {
        const self: *Stage = @ptrCast(@alignCast(raw));
        if (warm.index != self.next or self.next >= self.captures.len) return error.InvalidNativeBatchPublicationOrder;
        try @import("block_v5_native_recursive_leaf_stage_v1.zig").ForBackend(Cpu).validateWarm(self.profile, warm, proof);
        var captured = try Native.ForBackend(Cpu).verifyCaptureBorrowedWithCatalog(a, proof, &warm.replay.owner.statement, warm.replay.admission, warm.first.template, warm.first.template_id, warm.replay.profile, warm.index, warm.sealed, warm.pins, warm.entries, warm.catalog);
        errdefer captured.deinit();
        try captured.validate(&self.prepared[self.next], self.prepared[self.next].expected_id);
        self.captures[self.next] = captured;
        self.next += 1;
    }
    pub fn prove(self: *Stage) !Artifact {
        if (self.next != self.captures.len) return error.IncompleteNativeBatchPublication;
        const a = self.a;
        var timer = try std.time.Timer.start();
        var admissions: [Bus.MAX_CHILDREN]*const Prep.NativeAdmission = undefined;
        var captures: [Bus.MAX_CHILDREN]*const Prep.Capture = undefined;
        for (0..self.next) |i| {
            admissions[i] = &self.prepared[i];
            captures[i] = &self.captures[i];
        }
        var prepared = try Prep.prepare(a, admissions[0..self.next], captures[0..self.next], 2);
        defer prepared.deinit();
        const prepare_ns = timer.lap();
        const geometry = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &prepared.recursive, self.profile);
        const key = try Protocol.Key.fromGeometry(geometry, prepared.wires, self.next);
        const id = try key.identity();
        const authority = try Protocol.Admission.init(key, id, prepared.wires, prepared.values());
        const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
        const plan = try Plan.init(a, &prepared.recursive.rows, authority);
        defer plan.deinit();
        const setup_ns = timer.lap();
        var proof = try plan.prove(a, &prepared.recursive.rows);
        defer proof.deinit();
        const prove_ns = timer.lap();
        const bytes = try Parent.codec.encode(a, &proof, &authority);
        errdefer a.free(bytes);
        const wires = try a.dupe(Bus.Wire, prepared.wires);
        return .{ .bytes = bytes, .pins = .{ .key = key, .expected_id = id, .schedule = wires }, .prepare_ns = prepare_ns, .setup_ns = setup_ns, .prove_ns = prove_ns, .encode_ns = timer.lap() };
    }
};
