//! Bounded execution advice, captured once before choosing component domains.
//! Restoration projects advice through immutable decoded ROM; it never executes
//! an instruction or reads mutable guest RAM. This is not a proof authority.
const std = @import("std");
const isa = @import("decode.zig");
const profile = @import("execution_profile.zig");
const machine = @import("machine.zig");
const Word = @import("word.zig").Word;
const memory = @import("memory_types.zig");
const services = @import("service_session.zig");
const ethereum = @import("ethereum_services/session.zig");
pub const NO_MEMORY = std.math.maxInt(u32);
// The last ordinary RAM timestamp is 4*steps, strictly below 2^24.
pub const MAX_STEPS = (1 << 22) - 1;
pub const Clock = enum { local, global };
pub const Step = extern struct {
    next_pc: u64,
    lhs: u64,
    rhs: u64,
    previous_rd: u64,
    result: u64,
    memory_index: u32,
    flags: u32,
};
comptime {
    if (@sizeOf(Step) != 48) @compileError("RV64 compact advice must remain 48 bytes per instruction");
}
pub const Entry = struct {
    raw: u32,
    instruction: isa.Instruction,
    /// Derive once when constructing immutable ROM, not once per retirement.
    pub fn decode(execution_profile: profile.Profile, raw: u32) !Entry {
        const instruction = try profile.decode(execution_profile, raw);
        if (!profile.admitted(execution_profile, instruction.opcode)) return error.UnadmittedTapeInstruction;
        return .{ .raw = raw, .instruction = instruction };
    }
};
/// Admitted v3 bulk-memory ECALL (no payload; the step record is the call).
pub const BulkCall = ethereum.bulk_memory.BulkCall;
pub const Tape = struct {
    allocator: std.mem.Allocator,
    storage: []Step,
    len: usize = 0,
    memory_before: std.ArrayList(u64) = .empty,
    service_calls: std.ArrayList(services.Call) = .empty,
    secp_calls: std.ArrayList(ethereum.SecpCall) = .empty,
    last_secp_ids: [2]?u64 = @splat(null),
    /// Admitted v3 SHA-256 compressions; always empty below v3.
    sha256_calls: std.ArrayList(ethereum.Sha256Call) = .empty,
    /// Admitted v3 arith256_mod calls; always empty below v3.
    arith256_mod_calls: std.ArrayList(ethereum.Arith256ModCall) = .empty,
    /// Admitted v3 curve/field calls (all ops, chronological); empty below v3.
    curve_calls: std.ArrayList(ethereum.CurveCall) = .empty,
    last_curve_ids: [ethereum.curves.COUNT]?u64 = @splat(null),
    initial_pc: u64,
    initial_clock: u64,
    execution_profile: profile.Profile,

    pub fn init(a: std.mem.Allocator, capacity: u32, initial_pc: u64, initial_clock: u64, execution_profile: profile.Profile) !Tape {
        if (capacity == 0 or capacity > MAX_STEPS or initial_pc & 3 != 0 or initial_clock > std.math.maxInt(u64) - @as(u64, capacity)) return error.InvalidTapeGeometry;
        return .{ .allocator = a, .storage = try a.alloc(Step, capacity), .initial_pc = initial_pc, .initial_clock = initial_clock, .execution_profile = execution_profile };
    }
    pub fn deinit(self: *Tape) void {
        self.allocator.free(self.storage);
        self.memory_before.deinit(self.allocator);
        self.service_calls.deinit(self.allocator);
        self.secp_calls.deinit(self.allocator);
        self.sha256_calls.deinit(self.allocator);
        self.arith256_mod_calls.deinit(self.allocator);
        self.curve_calls.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn steps(self: *const Tape) []const Step {
        return self.storage[0..self.len];
    }
    pub fn retainedBytes(self: *const Tape) usize {
        return self.storage.len * @sizeOf(Step) + self.memory_before.capacity * @sizeOf(u64) + self.service_calls.capacity * @sizeOf(services.Call) + self.secp_calls.capacity * @sizeOf(ethereum.SecpCall) + self.sha256_calls.capacity * @sizeOf(ethereum.Sha256Call) + self.arith256_mod_calls.capacity * @sizeOf(ethereum.Arith256ModCall) + self.curve_calls.capacity * @sizeOf(ethereum.CurveCall);
    }
    /// Start the adjacent batch with already allocated buffers. This does not
    /// establish a public continuation relation; the proof coordinator must bind
    /// both CPU boundaries and authenticated RAM roots before releasing advice.
    pub fn clearRetainingCapacity(self: *Tape) void {
        if (self.len != 0) self.initial_pc = self.storage[self.len - 1].next_pc;
        self.initial_clock += self.len;
        self.len = 0;
        self.memory_before.clearRetainingCapacity();
        self.service_calls.clearRetainingCapacity();
        self.secp_calls.clearRetainingCapacity();
        self.last_secp_ids = @splat(null);
        self.sha256_calls.clearRetainingCapacity();
        self.arith256_mod_calls.clearRetainingCapacity();
        self.curve_calls.clearRetainingCapacity();
        self.last_curve_ids = @splat(null);
    }
    /// Allocation and validation precede tape publication. The caller retains
    /// ownership of `record` on failure and may retry without executing again.
    pub fn append(self: *Tape, record: machine.Retirement) !void {
        if (record.opcode == .ECALL) return error.MissingTapeService;
        try self.appendRecord(record);
    }
    pub fn appendService(self: *Tape, call: services.Call) !void {
        if (self.execution_profile == .rv64im or call.call_id == 0) return error.InvalidTapeService;
        if (self.len == self.storage.len) return error.TapeFull;
        if (self.service_calls.getLastOrNull()) |previous| {
            if (previous.call_id == std.math.maxInt(u64) or call.call_id != previous.call_id + 1) return error.InvalidTapeService;
        }
        try self.service_calls.ensureUnusedCapacity(self.allocator, 1);
        try self.appendRecord(call.retirement());
        self.service_calls.appendAssumeCapacity(call);
    }
    pub fn appendSecp(self: *Tape, call: ethereum.SecpCall) !void {
        const expected_format: profile.SecpPacketFormat = switch (self.execution_profile) {
            .ethereum_services_v1 => .big_endian_bytes_v1,
            .ethereum_services_v2, .ethereum_services_v3 => .little_endian_words_v2,
            else => return error.InvalidTapeService,
        };
        if (call.packet_format != expected_format or call.call_id == 0) return error.InvalidTapeService;
        if (self.len == self.storage.len) return error.TapeFull;
        const family = @intFromEnum(call.kind) - 1;
        if (self.last_secp_ids[family]) |previous| {
            if (previous == std.math.maxInt(u64) or call.call_id != previous + 1) return error.InvalidTapeService;
        }
        try self.secp_calls.ensureUnusedCapacity(self.allocator, 1);
        try self.appendRecord(call.retirement());
        self.secp_calls.appendAssumeCapacity(call);
        self.last_secp_ids[family] = call.call_id;
    }
    /// Bulk memory carries no tape payload: the ECALL step (pointer, tag,
    /// clock) is the whole call; the prover replays it on its RAM ledger.
    /// Not counted by serviceCount; the tape wire needs no new section.
    pub fn appendBulk(self: *Tape, call: BulkCall) !void {
        if (self.execution_profile != .ethereum_services_v3 or (call.tag != profile.MEMCPY_TAG and call.tag != profile.MEMSET_TAG and call.tag != profile.MEMCMP_TAG)) return error.InvalidTapeService;
        try self.appendRecord(call.retirement());
    }
    pub fn appendSha256(self: *Tape, call: ethereum.Sha256Call) !void {
        if (self.execution_profile != .ethereum_services_v3 or call.call_id == 0) return error.InvalidTapeService;
        if (self.len == self.storage.len) return error.TapeFull;
        if (self.sha256_calls.getLastOrNull()) |previous| {
            if (previous.call_id == std.math.maxInt(u64) or call.call_id != previous.call_id + 1) return error.InvalidTapeService;
        }
        try self.sha256_calls.ensureUnusedCapacity(self.allocator, 1);
        try self.appendRecord(call.retirement());
        self.sha256_calls.appendAssumeCapacity(call);
    }
    pub fn appendArith256Mod(self: *Tape, call: ethereum.Arith256ModCall) !void {
        if (self.execution_profile != .ethereum_services_v3 or call.call_id == 0) return error.InvalidTapeService;
        if (self.len == self.storage.len) return error.TapeFull;
        if (self.arith256_mod_calls.getLastOrNull()) |previous| {
            if (previous.call_id == std.math.maxInt(u64) or call.call_id != previous.call_id + 1) return error.InvalidTapeService;
        }
        try self.arith256_mod_calls.ensureUnusedCapacity(self.allocator, 1);
        try self.appendRecord(call.retirement());
        self.arith256_mod_calls.appendAssumeCapacity(call);
    }
    /// The admitted Keccak sponge carries no tape payload: the ECALL step
    /// (pointer, tag, clock) is the whole call and provers replay it on their
    /// RAM ledger. Not counted by serviceCount; the tape wire is unchanged.
    pub fn appendSponge(self: *Tape, call: ethereum.keccak_sponge.Call) !void {
        if (self.execution_profile != .ethereum_services_v3) return error.InvalidTapeService;
        try self.appendRecord(call.retirement());
    }
    pub fn appendCurve(self: *Tape, call: ethereum.CurveCall) !void {
        if (self.execution_profile != .ethereum_services_v3 or call.call_id == 0) return error.InvalidTapeService;
        if (self.len == self.storage.len) return error.TapeFull;
        const k = ethereum.curves.index(call.op);
        if (self.last_curve_ids[k]) |previous| {
            if (previous == std.math.maxInt(u64) or call.call_id != previous + 1) return error.InvalidTapeService;
        }
        try self.curve_calls.ensureUnusedCapacity(self.allocator, 1);
        try self.appendRecord(call.retirement());
        self.curve_calls.appendAssumeCapacity(call);
        self.last_curve_ids[k] = call.call_id;
    }
    pub fn appendEvent(self: *Tape, event: ethereum.Event) !void {
        switch (event) {
            .sponge => |e| try self.appendSponge(e.call),
            .keccak => |call| try self.appendService(call),
            .secp => |call| try self.appendSecp(call),
            .sha256 => |call| try self.appendSha256(call),
            .arith256_mod => |call| try self.appendArith256Mod(call),
            .bulk => |e| try self.appendBulk(e.call),
            .curve => |call| try self.appendCurve(call),
        }
    }
    /// Every service retirement recorded in this tape (all families).
    pub fn serviceCount(self: *const Tape) usize {
        return self.service_calls.items.len + self.secp_calls.items.len + self.sha256_calls.items.len + self.arith256_mod_calls.items.len + self.curve_calls.items.len;
    }
    fn appendRecord(self: *Tape, record: machine.Retirement) !void {
        if (self.len == self.storage.len) return error.TapeFull;
        const pc = if (self.len == 0) self.initial_pc else self.storage[self.len - 1].next_pc;
        const clock = std.math.add(u64, self.initial_clock, self.len + 1) catch return error.InvalidTapeRetirement;
        if (record.clock != clock or record.pc.toInt() != pc or record.next_pc.toInt() & 3 != 0) return error.InvalidTapeRetirement;
        var memory_index: u32 = NO_MEMORY;
        if (record.memory != null) {
            if (self.memory_before.items.len >= NO_MEMORY) return error.InvalidTapeGeometry;
            try self.memory_before.ensureUnusedCapacity(self.allocator, 1);
            memory_index = @intCast(self.memory_before.items.len);
        }
        self.storage[self.len] = .{ .next_pc = record.next_pc.toInt(), .lhs = record.lhs.toInt(), .rhs = record.rhs.toInt(), .previous_rd = record.previous_rd.toInt(), .result = record.result.toInt(), .memory_index = memory_index, .flags = @intFromBool(record.branch_taken) };
        if (record.memory) |event| self.memory_before.appendAssumeCapacity(event.before_word.toInt());
        self.len += 1;
    }
    /// `entry` must come from the independently admitted immutable program at
    /// this PC. The CPU's ROM relation still authenticates every projected row.
    /// Narrow advice, including results and branch decisions, remains untrusted.
    pub fn restore(self: *const Tape, index: usize, entry: Entry, clocks: Clock) !machine.Retirement {
        if (index >= self.len) return error.InvalidTapeIndex;
        const step = self.storage[index];
        const inst = entry.instruction;
        if (!profile.admitted(self.execution_profile, inst.opcode) or step.flags > 1) return error.InvalidTapeRetirement;
        const effects = profile.effects(self.execution_profile, inst.opcode);
        if ((!effects.reads_rs1 and step.lhs != 0) or (!effects.reads_rs2 and step.rhs != 0) or (!effects.writes_rd and (step.previous_rd != 0 or step.result != 0))) return error.InvalidTapeRetirement;
        var event: ?machine.MemoryEffect = null;
        if (effects.memory_width != 0) {
            if (step.memory_index >= self.memory_before.items.len) return error.InvalidTapeMemoryIndex;
            const before = self.memory_before.items[step.memory_index];
            const address = step.lhs +% @as(u64, @bitCast(inst.imm));
            const width = effects.memory_width;
            try memory.aligned(address, width);
            _ = try memory.endAddress(address, width);
            const shift: u6 = @intCast((address & 7) * 8);
            const mask = memory.widthMask(width);
            const write = !effects.writes_rd;
            const value = if (write) step.rhs & mask else (before >> shift) & mask;
            const after = if (write) (before & ~(mask << shift)) | (value << shift) else before;
            event = .{ .address = Word.fromInt(address), .width = width, .value = Word.fromInt(value), .before_word = Word.fromInt(before), .after_word = Word.fromInt(after), .write = write };
        } else if (step.memory_index != NO_MEMORY) return error.InvalidTapeMemoryIndex;
        const pc = if (index == 0) self.initial_pc else self.storage[index - 1].next_pc;
        return .{ .clock = (if (clocks == .global) self.initial_clock else 0) + index + 1, .pc = Word.fromInt(pc), .next_pc = Word.fromInt(step.next_pc), .immediate = Word.fromInt(@bitCast(inst.imm)), .instruction = entry.raw, .opcode = inst.opcode, .rs1 = if (effects.reads_rs1) inst.rs1 else 0, .rs2 = if (effects.reads_rs2) inst.rs2 else 0, .lhs = Word.fromInt(step.lhs), .rhs = Word.fromInt(step.rhs), .rd = if (effects.writes_rd) inst.rd else 0, .previous_rd = Word.fromInt(step.previous_rd), .result = Word.fromInt(step.result), .writes_rd = effects.writes_rd and inst.rd != 0, .branch_taken = step.flags == 1, .memory = event };
    }
};
