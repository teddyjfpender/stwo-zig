//! Fresh original-proof admission for the new RAM protocol. No producer receipt,
//! old machine-memory root, or public transition list is trusted. Caller sources
//! use their explicit versioned v7 joint adapters with exact native coupling.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const E = @import("block_v7_execution_epoch_v1.zig");
const I = @import("block_v7_initial_intervals_v1.zig");
const P = @import("block_v7_execution_policy_v1.zig");
const N = @import("block_v7_native_proof_v1.zig");
const R = @import("block_v7_program_provider_v1.zig");
const L = @import("block_v7_lookup_provider_v1.zig");
const Compact = @import("block_v7_lookup_compact_proof_v1.zig");
const M = @import("block_v7_memory_source_v1.zig");
const JointMemory = @import("block_v7_memory_joint_proof_v1.zig");
const WindowMemory = @import("block_v7_window_memory_joint_v1.zig");
const ActiveCallerProof = @import("block_v7_caller_active_proof_v1.zig");
const CallerProof = @import("block_v7_caller_joint_proof_v1.zig");
const CallerSource = @import("block_v7_caller_joint_source_v1.zig");
const CallerProfile = @import("blake3_ethereum_sha_profile.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
pub const Trusted = struct {
    elf: []const u8,
    elf_sha256: [32]u8,
    profile: @import("../air/program/decode.zig").ExecutionProfile,
    terminal: @import("block_v7_terminal_protocol_v1.zig").Policy,
    config: core.pcs.PcsConfig,
    window: ?*const @import("block_v7_real_window_policy_v2.zig").Owned = null,
};
pub const Native = struct { pin: N.Pin, proof: *const N.Proof };
pub const Caller = struct { pin: CallerSource.Pin, proof: *const CallerProof.Proof };
pub const ActiveCaller = struct { pin: @import("block_v7_caller_active_source_v1.zig").Pin, proof: *const @import("block_v7_caller_active_proof_v1.zig").Proof };
pub const MemoryProof = union(enum) { separate: *const M.Bundle, joint: *const JointMemory.Proof, window_joint: *const WindowMemory.Proof };
/// The selected verifier must authenticate the exact layout-specific epoch
/// entry. A compact proof is never relabelled as a legacy dense provider.
pub const LookupProof = union(enum) {
    dense: *const L.Proof,
    compact: struct { layout: @import("block_v7_lookup_compact_layout_v1.zig").Layout, proof: *const Compact.Proof },
};
pub const Input = struct {
    epoch: E.Epoch,
    entries: []const E.Entry,
    natives: []const Native,
    callers: []const Caller = &.{},
    active_callers: []const ActiveCaller = &.{},
    program_plan: @import("block_v5_program_table_v1.zig").Plan,
    program_roots: [2][32]u8,
    program: *const R.Proof,
    lookup_plan: LP.Plan,
    lookup_roots: [2][32]u8,
    lookup: LookupProof,
    memory: MemoryProof,
};
pub const Limits = struct { initial: I.Limits = .{}, memory: M.Limits = .{}, joint_memory: JointMemory.Limits = .{}, window_memory: WindowMemory.Limits = .{}, compact_lookup: Compact.Limits = .{}, max_segments: usize = 4096, max_entries: usize = 1 << 16 };
pub const Scope = enum { complete_execution, declared_window };
pub const Verified = struct { statement: [32]u8, epoch: [32]u8, cycles: u64, segments: u32, ram_events: u64, program_fetches: u64, output: [43]u8, scope: Scope = .complete_execution };
const CaptureBudget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Fingerprint = @import("block_v7_original_capture_fingerprint_v1.zig");
pub const CaptureKind = Fingerprint.Kind;
pub const CaptureLimits = struct { max_bytes: usize = 4 << 30, fingerprint: Fingerprint.Limits = .{} };
pub fn CaptureType(comptime kind: CaptureKind) type {
    return switch (kind) {
        .native => N.VerifiedCapture,
        .caller => CallerProof.VerifiedCapture,
        .caller_active => ActiveCallerProof.VerifiedCapture,
        .program => R.VerifiedCapture,
        .lookup => Compact.VerifiedCapture,
        .memory => JointMemory.VerifiedCapture,
        .window_memory => WindowMemory.VerifiedCapture,
    };
}
pub fn RetainedCapture(comptime kind: CaptureKind) type {
    return struct {
        capture: CaptureType(kind),
        budget: ?*CaptureBudget = null,
        pub fn deinit(self: *@This()) void {
            self.capture.deinit();
            if (self.budget) |owner| owner.destroy();
            self.* = undefined;
        }
    };
}
const CaptureValue = union(CaptureKind) {
    native: N.VerifiedCapture,
    caller: CallerProof.VerifiedCapture,
    caller_active: ActiveCallerProof.VerifiedCapture,
    program: R.VerifiedCapture,
    lookup: Compact.VerifiedCapture,
    memory: JointMemory.VerifiedCapture,
    window_memory: WindowMemory.VerifiedCapture,
    fn deinit(self: *@This()) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
    }
};
const CaptureSlot = struct { entry: E.Entry, fingerprint: [32]u8, value: CaptureValue };
const CaptureOwner = struct {
    a: std.mem.Allocator,
    budget: *CaptureBudget,
    epoch: E.Epoch,
    entries: []E.Entry,
    natives: usize,
    callers: usize,
    active: bool,
    window: bool,
    limits: CaptureLimits,
    verified: ?Verified = null,
    slots: []?CaptureSlot,
    fn create(backing: std.mem.Allocator, input: Input, limits: Limits, capture_limits: CaptureLimits) !*CaptureOwner {
        if (input.lookup != .compact or input.memory == .separate) return error.UnsupportedOriginalCaptureMode;
        if (input.natives.len == 0 or input.natives.len > limits.max_segments or input.entries.len > limits.max_entries or capture_limits.max_bytes == 0) return error.OriginalCaptureResourceLimit;
        const callers = try std.math.add(usize, input.callers.len, input.active_callers.len);
        const count = try std.math.add(usize, try std.math.add(usize, input.natives.len, callers), 3);
        if (count > limits.max_entries) return error.OriginalCaptureResourceLimit;
        const budget = try CaptureBudget.createRetainingParent(backing, capture_limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(CaptureOwner);
        errdefer a.destroy(self);
        const entries = try a.dupe(E.Entry, input.entries);
        errdefer a.free(entries);
        const slots = try a.alloc(?CaptureSlot, count);
        @memset(slots, null);
        self.* = .{ .a = a, .budget = budget, .epoch = input.epoch, .entries = entries, .natives = input.natives.len, .callers = callers, .active = input.active_callers.len != 0, .window = input.memory == .window_joint, .limits = capture_limits, .slots = slots };
        return self;
    }
    fn ordinal(self: *const CaptureOwner, kind: CaptureKind, index: usize) !usize {
        return switch (kind) {
            .native => if (index < self.natives) index else error.OriginalCaptureIndex,
            .caller, .caller_active => if (index < self.callers and (kind == .caller_active) == self.active) self.natives + index else error.OriginalCaptureIndex,
            .program => if (index == 0) self.natives + self.callers else error.OriginalCaptureIndex,
            .lookup => if (index == 0) self.natives + self.callers + 1 else error.OriginalCaptureIndex,
            .memory, .window_memory => if (index == 0 and (kind == .window_memory) == self.window) self.natives + self.callers + 2 else error.OriginalCaptureIndex,
        };
    }
    fn store(self: *CaptureOwner, comptime kind: CaptureKind, index: usize, entry: E.Entry, proof: anytype, capture: CaptureType(kind)) !void {
        const ordinal_ = try self.ordinal(kind, index);
        if (self.slots[ordinal_] != null) return error.DuplicateOriginalCapture;
        self.slots[ordinal_] = .{ .entry = entry, .fingerprint = try Fingerprint.compute(kind, proof, self.limits.fingerprint), .value = @unionInit(CaptureValue, @tagName(kind), capture) };
    }
    fn deinit(self: *CaptureOwner) void {
        for (self.slots) |*slot| if (slot.*) |*present| present.value.deinit();
        const budget = self.budget;
        const a = self.a;
        a.free(self.slots);
        a.free(self.entries);
        a.destroy(self);
        budget.destroy();
    }
};
/// No public constructor or decoder: only verifyWithCaptures can produce a
/// sealed set. Each slot is consumed once and retains its allocation owner.
pub const Captures = opaque {
    fn owner(self: *Captures) *CaptureOwner {
        return @ptrCast(@alignCast(self));
    }
    pub fn deinit(self: *Captures) void {
        self.owner().deinit();
    }
    pub fn requireRequest(self: *Captures, input: Input) !void {
        const owned = self.owner();
        if (owned.verified == null or !std.meta.eql(owned.epoch, input.epoch) or input.entries.len != owned.entries.len or input.natives.len != owned.natives or (try std.math.add(usize, input.callers.len, input.active_callers.len)) != owned.callers or (input.active_callers.len != 0) != owned.active or input.lookup != .compact or (input.memory == .window_joint) != owned.window or input.memory == .separate) return error.OriginalCaptureRequestMismatch;
        for (input.entries, owned.entries) |got, want| if (!std.meta.eql(got, want)) return error.OriginalCaptureRequestMismatch;
    }
    /// Distinct canonical slots may drain concurrently. Callers must not
    /// consume the same slot twice concurrently or mutate proof storage while
    /// it is being fingerprinted. The set itself is request-local, never wire data.
    pub fn take(self: *Captures, comptime kind: CaptureKind, index: usize, entry: E.Entry, proof: anytype) !RetainedCapture(kind) {
        const owned = self.owner();
        if (owned.verified == null) return error.UnsealedOriginalCaptures;
        const slot = &owned.slots[try owned.ordinal(kind, index)];
        const present = slot.* orelse return error.OriginalCaptureAlreadyDrained;
        if (std.meta.activeTag(present.value) != kind or !std.meta.eql(present.entry, entry)) return error.OriginalCaptureProfileMismatch;
        if (!std.meta.eql(present.fingerprint, try Fingerprint.compute(kind, proof, owned.limits.fingerprint))) return error.OriginalCaptureProofMismatch;
        slot.* = null;
        return .{ .capture = @field(present.value, @tagName(kind)), .budget = owned.budget.retain() };
    }
    /// Charged retained verification heap; excludes caller-owned proofs and
    /// process overhead. Peak includes the original verification scratch.
    pub fn memory(self: *Captures) CaptureBudget.Snapshot {
        return self.owner().budget.snapshot();
    }
    pub fn requireDrained(self: *Captures) !void {
        for (self.owner().slots) |slot| if (slot != null) return error.UndrainedOriginalCaptures;
    }
};
pub const Captured = struct { verified: Verified, captures: *Captures };
fn memoryEntry(input: Input, window: bool) !E.Entry {
    const family: E.Family = if (window) .window_memory_joint else .memory_joint;
    for (input.entries) |entry| if (entry.family == family and entry.index == 0) return entry;
    return error.MissingOriginalCaptureEntry;
}
/// Window policy is receiver-selected, never decoded from a candidate proof.
/// ProgramImage.init subsequently checks its ELF and loader metadata afresh.
pub fn deriveInitialization(a: std.mem.Allocator, trusted: Trusted, limits: I.Limits) !I.Owned {
    if (trusted.window) |window| {
        try window.validate();
        if (trusted.elf.len > limits.max_elf_bytes or window.initial.intervals.len > limits.max_intervals or
            !std.meta.eql(window.initial.elf_sha256, trusted.elf_sha256) or window.initial.info.execution_profile != trusted.profile)
            return error.UntrustedV7WindowInitialization;
        return window.cloneInitial(a);
    }
    return I.Owned.derive(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits);
}
pub fn For(comptime Backend: type) type {
    return struct {
        pub fn verify(a: std.mem.Allocator, trusted: Trusted, input: Input, limits: Limits) !Verified {
            return verifyMode(a, trusted, input, limits, null);
        }
        pub fn verifyWithCaptures(a: std.mem.Allocator, trusted: Trusted, input: Input, limits: Limits, capture_limits: CaptureLimits) !Captured {
            const owner = try CaptureOwner.create(a, input, limits, capture_limits);
            errdefer owner.deinit();
            const verified = try verifyMode(owner.a, trusted, input, limits, owner);
            for (owner.slots) |slot| if (slot == null) return error.IncompleteOriginalCaptures;
            owner.verified = verified;
            return .{ .verified = verified, .captures = @ptrCast(owner) };
        }
        fn verifyMode(a: std.mem.Allocator, trusted: Trusted, input: Input, limits: Limits, captures: ?*CaptureOwner) !Verified {
            if (input.natives.len == 0 or input.natives.len > limits.max_segments or input.entries.len > limits.max_entries or input.natives.len != input.epoch.counts[@intFromEnum(E.Family.native)]) return error.InvalidV7ExecutionRoster;
            if (input.callers.len != 0 and input.active_callers.len != 0) return error.InvalidV7MixedCallerMode;
            const caller_count = try std.math.add(usize, input.callers.len, input.active_callers.len);
            if (input.epoch.counts[@intFromEnum(E.Family.caller_arithmetic)] != 0 or input.epoch.counts[@intFromEnum(E.Family.caller_fused)] != caller_count or caller_count > input.natives.len) return error.InvalidV7CallerRoster;
            try input.epoch.requireCompleteFamilies();
            const joint = input.epoch.counts[@intFromEnum(E.Family.memory_joint)] == 1;
            if (joint != (input.memory == .joint)) return error.MismatchedV7MemoryMode;
            const window_mode = input.epoch.counts[@intFromEnum(E.Family.window_memory_joint)] == 1;
            if (window_mode != (input.memory == .window_joint) or window_mode != (trusted.window != null)) return error.MismatchedV7MemoryMode;
            var initialized = try deriveInitialization(a, trusted, limits.initial);
            defer initialized.deinit();
            var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, trusted.elf, &initialized, limits.initial);
            defer image.deinit();
            const policy = P.Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = trusted.terminal, .config = trusted.config, .window = trusted.window };
            try input.epoch.require(try policy.digest(), trusted.config, input.epoch.counts, input.entries, limits.max_entries);
            const windows = try a.alloc(P.Native, input.natives.len);
            defer a.free(windows);
            const external = try a.alloc(u32, input.natives.len);
            defer a.free(external);
            @memset(external, 0);
            var demands: [6]u64 = @splat(0);
            inline for (.{ false, true }) |active| {
                const callers = if (active) input.active_callers else input.callers;
                for (callers, 0..) |caller, index| {
                    const pin = caller.pin;
                    if (trusted.profile != CallerProfile.execution_profile or pin.index != index or pin.execution_index >= input.natives.len or (index != 0 and pin.execution_index <= callers[index - 1].pin.execution_index)) return error.UntrustedV7CallerRoster;
                    const native = input.natives[pin.execution_index].pin;
                    if (!std.meta.eql(pin.frame, native.frame) or pin.total_steps != native.frame.cycle_count or !std.meta.eql(pin.execution_identity, (try native.entry(a)).identity)) return error.UntrustedV7CallerExecution;
                    _ = try pin.require(a, input.epoch, input.entries);
                    external[pin.execution_index] = CallerProfile.externalCount(pin.statement);
                    var schedule = try @import("block_v5_caller_fused_schedule_v1.zig").Schedule.init(a, pin.statement, pin.total_steps, pin.frame, 1);
                    defer schedule.deinit();
                    const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(pin.statement, schedule.memory, 1);
                    try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demands, pin.statement, pin.total_steps, trusted.config);
                    try LP.addDemand(&demands, try LP.sidecarMemoryDemand(demand.event_count));
                }
            }
            for (input.natives, windows, 0..) |native, *window, index| {
                if (native.pin.index != index or native.pin.template.execution_profile != trusted.profile or native.pin.template.external_retirements != external[index]) return error.UntrustedV7NativeRoster;
                window.* = .{ .shape = native.pin.shape, .frame = native.pin.frame, .external_retirements = external[index] };
                try LP.addDemand(&demands, try LP.nativeDemand(native.pin.shape, external[index]));
                try LP.addDemand(&demands, try LP.sidecarMemoryDemand(native.pin.expected_events));
            }
            try policy.validateWindows(windows);
            const expected_plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = @intCast(input.natives.len), .max_requests = demands };
            if (!std.meta.eql(expected_plan, input.lookup_plan)) return error.UntrustedV7LookupDemand;
            if (!std.meta.eql(input.program_plan.program_root, image.root) or input.program_plan.leaves.len != image.leaves.len) return error.UntrustedV7ProgramImage;
            for (input.program_plan.leaves, image.leaves) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedV7ProgramImage;
            const rom_policy = R.Policy{ .plan = input.program_plan, .expected_program_root = image.root, .roots = input.program_roots, .epoch = input.epoch, .entries = input.entries };
            const rom = if (captures) |sink| blk: {
                var captured = try R.ForBackend(Backend).verifyAndCapture(a, input.program, rom_policy);
                errdefer captured.deinit();
                const receipt = captured.receipt;
                try sink.store(.program, 0, try rom_policy.entry(), input.program, captured);
                break :blk receipt;
            } else try R.ForBackend(Backend).verifyBorrowed(a, input.program, rom_policy);
            const lookup_claims = switch (input.lookup) {
                .dense => |proof| (try L.ForBackend(Backend).verifyBorrowed(a, proof, .{ .plan = input.lookup_plan, .roots = input.lookup_roots, .epoch = input.epoch, .entries = input.entries })).claims,
                .compact => |value| blk: {
                    const lookup_policy = Compact.Policy{ .plan = input.lookup_plan, .layout = value.layout, .roots = input.lookup_roots, .epoch = input.epoch, .entries = input.entries };
                    if (captures) |sink| {
                        var captured = try Compact.For(Backend).verifyAndCapture(a, value.proof, lookup_policy, limits.compact_lookup);
                        errdefer captured.deinit();
                        const claims = captured.receipt.claims;
                        try sink.store(.lookup, 0, try lookup_policy.entry(), value.proof, captured);
                        break :blk claims;
                    }
                    break :blk try Compact.For(Backend).verify(a, value.proof, lookup_policy, limits.compact_lookup);
                },
            };
            const memory = switch (input.memory) {
                .separate => |proof| try M.For(Backend).verify(a, policy, input.epoch, input.entries, proof, limits.memory),
                .joint => |proof| blk: {
                    if (captures) |sink| {
                        var captured = try JointMemory.For(Backend).verifyAndCapture(a, policy, input.epoch, input.entries, proof, limits.joint_memory);
                        errdefer captured.deinit();
                        const open = captured.open;
                        try sink.store(.memory, 0, try memoryEntry(input, false), proof, captured);
                        break :blk open;
                    }
                    break :blk try JointMemory.For(Backend).verify(a, policy, input.epoch, input.entries, proof, limits.joint_memory);
                },
                .window_joint => |proof| blk: {
                    if (captures) |sink| {
                        var captured = try WindowMemory.For(Backend).verifyAndCapture(a, policy, input.epoch, input.entries, proof, limits.window_memory);
                        errdefer captured.deinit();
                        const open = captured.open;
                        try sink.store(.window_memory, 0, try memoryEntry(input, true), proof, captured);
                        break :blk open;
                    }
                    break :blk try WindowMemory.For(Backend).verify(a, policy, input.epoch, input.entries, proof, limits.window_memory);
                },
            };
            var closure = try @import("block_v7_execution_claim_closure_v1.zig").Accumulator.init(a, input.natives.len, caller_count, rom.claim, rom.fetch_count, lookup_claims, memory);
            defer closure.deinit();
            for (input.natives, 0..) |native, index| {
                const n = if (captures) |sink| blk: {
                    var captured = try N.For(Backend).verifyAndCapture(a, native.proof, native.pin, input.epoch, input.entries);
                    errdefer captured.deinit();
                    const open = captured.open;
                    try sink.store(.native, index, try native.pin.entry(a), native.proof, captured);
                    break :blk open;
                } else try N.For(Backend).verify(a, native.proof, native.pin, input.epoch, input.entries);
                try closure.addNative(index, n);
            }
            inline for (.{ false, true }) |active| {
                const callers = if (active) input.active_callers else input.callers;
                const CallerVerifier = if (comptime active) @import("block_v7_caller_active_proof_v1.zig") else CallerProof;
                for (callers) |caller| {
                    const n = if (captures) |sink| blk: {
                        var captured = try CallerVerifier.ForBackend(Backend).verifyCapture(a, caller.proof, caller.pin, input.epoch, input.entries);
                        errdefer captured.deinit();
                        const open = captured.receipt;
                        try sink.store(comptime if (active) .caller_active else .caller, caller.pin.index, try caller.pin.entry(a), caller.proof, captured);
                        break :blk open;
                    } else try CallerVerifier.ForBackend(Backend).verify(a, caller.proof, caller.pin, input.epoch, input.entries);
                    try closure.addCaller(caller.pin.execution_index, n);
                }
            }
            const closed = try closure.finish();
            return .{ .statement = try policy.digest(), .epoch = input.epoch.digest, .cycles = policy.finalCycle(), .segments = @intCast(input.natives.len), .ram_events = closed.events, .program_fetches = closed.fetches, .output = if (trusted.window == null) trusted.terminal.output else @splat(0), .scope = if (trusted.window == null) .complete_execution else .declared_window };
        }
    };
}
