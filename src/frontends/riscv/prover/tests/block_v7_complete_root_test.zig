//! Six genuine original proofs -> one mixed verifier proof. Independently
//! reconstruct metadata/key, then verify only after the fixture releases all
//! original producers and proof owners. Diagnostic security, not Ethereum.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixture = @import("../block_v7_execution_caller_test_v1.zig");
const Inputs = @import("../../recursion/block_v7_mixed_inputs_v1.zig");
const Bus = @import("../../recursion/block_v7_mixed_public_v1.zig");
const Mixed = @import("../../recursion/block_v7_mixed_preparation_v1.zig");
const Cold = @import("../../recursion/block_v7_mixed_fixed_v1.zig");
const Protocol = @import("../../recursion/block_v7_mixed_protocol_v1.zig");
const Parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const Receive = @import("../../recursion/block_v7_mixed_receiver_v1.zig");
const Native = @import("../block_v7_native_proof_v1.zig");
const NativeProfile = @import("../../recursion/block_v7_native_fixed_profile_v1.zig");
const CallerProfile = @import("../../recursion/block_v7_caller_joint_fixed_profile_v1.zig");
const Program = @import("../block_v7_program_provider_v1.zig");
const ProgramProfile = @import("../../recursion/block_v7_program_fixed_profile_v1.zig");
const Lookup = @import("../block_v7_lookup_compact_proof_v1.zig");
const LookupProfile = @import("../../recursion/block_v7_lookup_compact_fixed_profile_v1.zig");
const Memory = @import("../block_v7_memory_joint_proof_v1.zig");
const MemoryProfile = @import("../../recursion/block_v7_memory_joint_fixed_profile_v1.zig");
const Initial = @import("../block_v7_initial_intervals_v1.zig");
const Original = @import("../block_v7_execution_receiver_v1.zig");
fn ProtocolFor(comptime shared: bool) type {
    return if (shared) @import("../../recursion/block_v7_shared_epoch_mixed_protocol_v1.zig") else Protocol;
}
fn MixedFor(comptime shared: bool) type {
    return if (shared) @import("../../recursion/block_v7_shared_epoch_mixed_preparation_v1.zig") else Mixed;
}
fn ColdFor(comptime shared: bool) type {
    return if (shared) @import("../../recursion/block_v7_shared_epoch_mixed_fixed_v1.zig") else Cold;
}
fn ReceiverFor(comptime shared: bool) type {
    return if (shared) @import("../../recursion/block_v7_shared_epoch_mixed_receiver_v1.zig") else Receive;
}
pub const Output = OutputFor(false);
pub fn OutputFor(comptime shared: bool) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        trusted: Original.Trusted,
        original: Original.Verified,
        initialized: *Initial.Owned,
        natives: [2]Inputs.Native,
        callers: [1]*const CallerProfile.Owned,
        program: *ProgramProfile.Owned,
        lookup: *LookupProfile.Owned,
        memory: *MemoryProfile.Owned,
        bytes: []u8,
        key: ProtocolFor(shared).Key,
        wires: []Bus.Wire,
        pub fn input(self: *const Self) Inputs.Input {
            return .{ .epoch = self.memory.input.epoch, .entries = self.memory.input.roster, .natives = &self.natives, .callers = &self.callers, .program = self.program, .lookup = self.lookup, .memory = self.memory };
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            a.free(self.bytes);
            a.free(self.wires);
            self.memory.deinit();
            self.lookup.deinit();
            self.program.deinit();
            @constCast(self.callers[0]).deinit();
            for (self.natives) |native| {
                @constCast(native.profile).deinit();
                a.free(native.claims.projection);
                a.free(native.claims.access);
            }
            self.initialized.deinit();
            a.destroy(self.initialized);
            a.free(self.trusted.elf);
            a.destroy(self);
        }
    };
}
const Consumer = ConsumerFor(false);
fn ConsumerFor(comptime shared: bool) type {
    return struct {
        pub const Result = *OutputFor(shared);
        pub fn consume(f: Fixture.Fixture) !Result {
            const SelectedMixed = MixedFor(shared);
            const SelectedProtocol = ProtocolFor(shared);
            const a = f.allocator;
            var phase_clock = try std.time.Timer.start();
            if (f.input.natives.len != 2 or f.input.callers.len != 1 or f.input.memory != .joint or f.input.lookup != .compact) return error.InvalidCompleteFixture;
            const elf = try a.dupe(u8, f.trusted.elf);
            errdefer a.free(elf);
            var trusted = f.trusted;
            trusted.elf = elf;
            const initialized = try a.create(Initial.Owned);
            errdefer a.destroy(initialized);
            initialized.* = try Initial.Owned.derive(a, elf, trusted.elf_sha256, trusted.profile, .{});
            errdefer initialized.deinit();
            var natives: [2]Inputs.Native = undefined;
            var native_count: usize = 0;
            errdefer for (natives[0..native_count]) |native| {
                @constCast(native.profile).deinit();
                a.free(native.claims.projection);
                a.free(native.claims.access);
            };
            for (f.input.natives, &natives) |native, *out| {
                const profile = try NativeProfile.Owned.derive(a, native.pin, f.input.epoch, f.input.entries, .{});
                errdefer profile.deinit();
                const claims = try a.dupe(@TypeOf(native.proof.claims[0]), native.proof.claims);
                errdefer a.free(claims);
                const access = try a.dupe(@TypeOf(native.proof.memory_claims[0]), native.proof.memory_claims);
                out.* = .{ .profile = profile, .claims = .{ .projection = claims, .access = access } };
                native_count += 1;
            }
            const c = f.input.callers[0];
            const caller = try CallerProfile.Owned.derive(a, .{ .pin = c.pin, .epoch = f.input.epoch, .entries = f.input.entries, .arithmetic = c.proof.arithmetic, .claims = c.proof.relations }, .{});
            errdefer caller.deinit();
            const program = try ProgramProfile.Owned.derive(a, .{ .policy = .{ .plan = f.input.program_plan, .expected_program_root = f.input.program_plan.program_root, .roots = f.input.program_roots, .epoch = f.input.epoch, .entries = f.input.entries }, .claim = f.input.program.claim }, .{});
            errdefer program.deinit();
            const l = f.input.lookup.compact;
            const lookup = try LookupProfile.Owned.derive(a, .{ .policy = .{ .plan = f.input.lookup_plan, .layout = l.layout, .roots = f.input.lookup_roots, .epoch = f.input.epoch, .entries = f.input.entries }, .claims = l.proof.claims }, .{});
            errdefer lookup.deinit();
            var policy = f.policy;
            policy.initialized = initialized;
            const m = f.input.memory.joint;
            const memory = try MemoryProfile.Owned.derive(a, .{ .policy = policy, .epoch = f.input.epoch, .roster = f.input.entries, .roots = m.roots, .interval_log = m.interval_log, .claims = m.claims() }, .{});
            errdefer memory.deinit();
            const caller_profiles = [_]*const CallerProfile.Owned{caller};
            const input = Inputs.Input{ .epoch = memory.input.epoch, .entries = memory.input.roster, .natives = &natives, .callers = &caller_profiles, .program = program, .lookup = lookup, .memory = memory };
            var canonical = try Inputs.Owned.init(a, input);
            defer canonical.deinit();
            std.debug.print("V7_COMPLETE phase=metadata elapsed_ns={d}\n", .{phase_clock.lap()});
            std.debug.print("V7_COMPLETE phase=cold_fixed begin=true\n", .{});
            var cold = try ColdFor(shared).Owned.derive(a, input, 2, .{});
            defer cold.deinit();
            const selected = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0;
            const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, selected);
            const key = try SelectedProtocol.Key.fromGeometry(base, cold.wires, canonical.expected);
            std.debug.print("V7_COMPLETE phase=cold_fixed done=true elapsed_ns={d}\n", .{phase_clock.lap()});
            var native_ready: [2]SelectedMixed.PreparedFor(.native) = undefined;
            var ready_count: usize = 0;
            defer for (native_ready[0..ready_count]) |*ready| ready.deinit();
            for (natives, f.input.natives, &native_ready) |metadata, original, *ready| {
                var captured = try Native.For(Cpu).verifyAndCapture(a, original.proof, metadata.profile.pin, f.input.epoch, f.input.entries);
                defer captured.deinit();
                ready.* = try @import("../../recursion/block_v7_native_preparation_v1.zig").prepare(a, metadata.profile, &captured, 2, .{ .shared_epoch = shared });
                ready_count += 1;
            }
            var caller_capture = try @import("../block_v7_caller_joint_capture_v1.zig").ForBackend(Cpu).verify(a, c.proof, &caller.admitted);
            defer caller_capture.deinit();
            var caller_ready = try @import("../../recursion/block_v7_caller_joint_preparation_v1.zig").prepare(a, &caller.admitted, &caller_capture, 2, .{ .shared_epoch = shared });
            defer caller_ready.deinit();
            var program_capture = try Program.ForBackend(Cpu).verifyAndCapture(a, f.input.program, program.input.policy);
            defer program_capture.deinit();
            var program_ready = try @import("../../recursion/block_v7_program_preparation_v1.zig").prepare(a, program, &program_capture, 2, .{ .shared_epoch = shared });
            defer program_ready.deinit();
            var lookup_capture = try Lookup.For(Cpu).verifyAndCapture(a, l.proof, lookup.input.policy, .{});
            defer lookup_capture.deinit();
            var lookup_ready = try @import("../../recursion/block_v7_lookup_compact_preparation_v1.zig").prepare(a, lookup, &lookup_capture, 2, .{ .shared_epoch = shared });
            defer lookup_ready.deinit();
            var memory_capture = try Memory.For(Cpu).verifyAndCapture(a, policy, f.input.epoch, f.input.entries, m, .{});
            defer memory_capture.deinit();
            var memory_ready = try @import("../../recursion/block_v7_memory_joint_preparation_v1.zig").prepare(a, memory, &memory_capture, 2, .{ .shared_epoch = shared });
            defer memory_ready.deinit();
            const pieces = [_]SelectedMixed.Input{
                .{ .native = .{ .index = 0, .prepared = &native_ready[0] } },
                .{ .native = .{ .index = 1, .prepared = &native_ready[1] } },
                .{ .caller = .{ .index = 0, .prepared = &caller_ready } },
                .{ .program = .{ .index = 0, .prepared = &program_ready } },
                .{ .lookup = .{ .index = 0, .prepared = &lookup_ready } },
                .{ .memory = .{ .index = 0, .prepared = &memory_ready } },
            };
            std.debug.print("V7_COMPLETE phase=verifier_witness done=true elapsed_ns={d}\n", .{phase_clock.lap()});
            std.debug.print("V7_COMPLETE phase=join begin=true\n", .{});
            var joined = if (shared) try SelectedMixed.prepareDraining(a, &pieces, canonical.expected, input.epoch, 2) else try SelectedMixed.prepareDraining(a, &pieces, canonical.expected);
            defer joined.deinit();
            try cold.validateLive(&joined);
            try canonical.requireSame(joined.values());
            std.debug.print("V7_COMPLETE phase=join_parity done=true elapsed_ns={d} retained_bytes={d}\n", .{ phase_clock.lap(), try joined.recursive.rows.retainedBytes() });
            const live_key = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &joined.recursive, selected);
            try std.testing.expectEqualDeep(base, live_key);
            const admission = try SelectedProtocol.Admission.init(key, try key.identity(), joined.wires, joined.values(), canonical.expected);
            const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, SelectedProtocol);
            const plan = try Plan.init(a, &joined.recursive.rows, admission);
            defer plan.deinit();
            std.debug.print("V7_COMPLETE phase=live_key_and_plan done=true elapsed_ns={d}\n", .{phase_clock.lap()});
            std.debug.print("V7_COMPLETE phase=proof begin=true\n", .{});
            var proof = try plan.prove(a, &joined.recursive.rows);
            defer proof.deinit();
            std.debug.print("V7_COMPLETE phase=proof done=true elapsed_ns={d}\n", .{phase_clock.lap()});
            const bytes = try Parent.codec.encode(a, &proof, &admission);
            errdefer a.free(bytes);
            const wires = try a.dupe(Bus.Wire, cold.wires);
            errdefer a.free(wires);
            const result = try a.create(OutputFor(shared));
            result.* = .{ .allocator = a, .trusted = trusted, .original = f.original, .initialized = initialized, .natives = natives, .callers = caller_profiles, .program = program, .lookup = lookup, .memory = memory, .bytes = bytes, .key = key, .wires = wires };
            return result;
        }
    };
}
/// Genuine test fixture shared by nested-root qualification; the returned
/// object owns only detached metadata/key/root, never original proof owners.
pub fn produceComplete() !*Output {
    return Fixture.runFixture(true, true, Consumer);
}
test "v7 complete actual SHA Keccak execution closes one detached recursive root" {
    try qualify(false);
}
pub fn qualify(comptime shared: bool) !void {
    const SelectedReceiver = ReceiverFor(shared);
    const a = std.testing.allocator;
    const output = try Fixture.runFixture(true, true, ConsumerFor(shared));
    defer output.deinit();
    // The whole fixture, including original proof/capture/wide row owners, has
    // returned. Only the independently reconstructed metadata and root remain.
    var verify_clock = try std.time.Timer.start();
    var verified = try SelectedReceiver.verify(a, output.bytes, output.trusted, output.input(), output.key, output.wires, .{});
    defer verified.deinit();
    std.debug.print("V7_COMPLETE phase=fresh_verify done=true elapsed_ns={d}\n", .{verify_clock.read()});
    try std.testing.expectEqualDeep(output.original.output, verified.summary.output);
    try std.testing.expectEqual(output.original.ram_events, verified.summary.ram_events);
    try std.testing.expectEqual(output.original.program_fetches, verified.summary.program_fetches);
    try std.testing.expectEqual(output.original.cycles, verified.summary.cycles);
    var wrong = output.trusted;
    wrong.terminal.output[0] ^= 1;
    try std.testing.expectError(error.UntrustedV7Epoch, SelectedReceiver.verify(a, output.bytes, wrong, output.input(), output.key, output.wires, .{}));
    var missing = output.input();
    missing.callers = &.{};
    try std.testing.expectError(error.InvalidV7CompleteMixedRoster, SelectedReceiver.verify(a, output.bytes, output.trusted, missing, output.key, output.wires, .{}));
    const old = output.lookup.input.claims[0];
    output.lookup.input.claims[0] = old.add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.InvalidProviderBatchPublicClosure, SelectedReceiver.verify(a, output.bytes, output.trusted, output.input(), output.key, output.wires, .{}));
    output.lookup.input.claims[0] = old;
    var bad_key = output.key;
    bad_key.preprocessed_root[0] ^= 1;
    if (SelectedReceiver.verify(a, output.bytes, output.trusted, output.input(), bad_key, output.wires, .{})) |got| {
        var bad = got;
        bad.deinit();
        return error.AcceptedWrongV7CompleteKey;
    } else |_| {}
    std.debug.print("V7_COMPLETE_ROOT verified=true originals=6 segments=2 cycles={d} ram_events={d} fetches={d} proof_bytes={d} shared_epoch={} originals_destroyed=true independent_key=true canonical_security=false ethereum_block=false\n", .{ verified.summary.cycles, verified.summary.ram_events, verified.summary.program_fetches, output.bytes.len, shared });
}
