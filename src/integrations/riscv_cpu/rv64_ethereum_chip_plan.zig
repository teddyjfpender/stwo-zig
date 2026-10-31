//! Diagnostic fixed-capacity chip packing. NOT a proving coordinator: current
//! proofs/transcripts remain unchanged. A future receiver must authenticate CPU
//! counters, namespace cross-instance buses and seal every participant's main
//! commitment before shared challenges. This owner validates coverage/geometry
//! and characteristic bounds only; it never treats counts as setup authority.
const std = @import("std");
const air = @import("stwo_riscv_frontend").rv64_air;
const K = air.crypto.keccak.layout;
const P = air.crypto.secp256k1.program;
const Modulus = @import("stwo_core").fields.m31.Modulus;
pub const Chip = enum(u8) { division, multiplication, load_store, keccak, keccak_bridge, add_product, add_linear, add_bridge, double_product, double_linear, double_bridge, alu, binary, shift };
pub const CHIP_COUNT = @typeInfo(Chip).@"enum".fields.len;
pub const MAX_INSTANCES = 4096;
pub const Counts = struct { division: u32 = 0, multiplication: u32 = 0, load_store: u32 = 0, keccak: u32 = 0, add: u32 = 0, double: u32 = 0, alu: u32 = 0, binary: u32 = 0, shift: u32 = 0 };
pub const FirstIds = struct { division: u32 = 1, multiplication: u32 = 1, load_store: u32 = 1, keccak: u32 = 1, add: u32 = 1, double: u32 = 1, alu: u32 = 1, binary: u32 = 1, shift: u32 = 1 };
pub const Group = struct { rows: usize, requests: usize = 1 };
pub fn group(chip: Chip) Group {
    return switch (chip) {
        .division, .multiplication, .load_store, .alu, .binary, .shift => .{ .rows = 1 },
        .keccak => .{ .rows = K.ROWS_PER_PAIR, .requests = 2 },
        .keccak_bridge => .{ .rows = K.IO_LANES },
        .add_product => .{ .rows = P.add.rows(true) },
        .add_linear => .{ .rows = P.add.rows(false) },
        .add_bridge => .{ .rows = P.add.inputs },
        .double_product => .{ .rows = P.double.rows(true) },
        .double_linear => .{ .rows = P.double.rows(false) },
        .double_bridge => .{ .rows = P.double.inputs },
    };
}
pub const Profile = struct {
    cpu_log: u5 = 22,
    // Explicit model choice, not a measured optimal prover configuration.
    logs: [CHIP_COUNT]u5 = .{ 10, 18, 20, 18, 16, 15, 15, 13, 14, 13, 12, 20, 18, 18 },
    pub fn validate(self: Profile) !void {
        if (self.cpu_log < 5 or self.cpu_log > 22) return error.InvalidChipProfile;
        for (self.logs, 0..) |log, i| {
            if (log < 5 or log > 22 or (@as(usize, 1) << log) < group(@enumFromInt(i)).rows) return error.InvalidChipProfile;
        }
    }
    pub fn capacity(self: Profile, chip: Chip) !u32 {
        try self.validate();
        const g = group(chip);
        return @intCast((@as(usize, 1) << self.logs[@intFromEnum(chip)]) / g.rows * g.requests);
    }
    pub fn cpuCapacity(self: Profile) !u32 {
        try self.validate();
        // Existing local clocks are24bits, so a full2^22 active CPU domain is
        // forbidden: at least its terminal padding row remains inactive.
        return (@as(u32, 1) << self.cpu_log) - 1;
    }
    /// The caller binds program/ISA/opcode union/math/state/control semantics.
    /// Exact request counts and execution paths are deliberately excluded.
    pub fn identity(self: Profile, semantic_identity: [32]u8) ![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("rv64-fixed-chip-caps-word16-diagnostic-v2");
        hash.update(&semantic_identity);
        hash.update(&.{self.cpu_log});
        for (self.logs) |log| hash.update(&.{log});
        return hash.finalResult();
    }
};
pub const Instance = struct { chip: Chip, index: u32, first_id: u32, requests: u32, log: u5 };
pub const CpuSpan = struct { index: u32, first_step: u64, steps: u32, log: u5 };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    profile: Profile,
    semantic_identity: [32]u8,
    profile_identity: [32]u8,
    first_step: u64,
    instructions: u64,
    cpu_instances: u32,
    counts: Counts,
    first_ids: FirstIds,
    instances: []Instance,
    pub fn init(a: std.mem.Allocator, profile: Profile, semantic_identity: [32]u8, first_step: u64, instructions: u64, counts: Counts, first_ids: FirstIds) !Plan {
        const identity = try profile.identity(semantic_identity);
        const cpu_capacity = try profile.cpuCapacity();
        if (requestCount(counts) > instructions) return error.InvalidChipCoverage;
        if (instructions == 0 or first_step > std.math.maxInt(u64) - instructions) return error.InvalidChipCoverage;
        const cpus = try std.math.divCeil(u64, instructions, cpu_capacity);
        if (cpus > MAX_INSTANCES) return error.ChipInstanceLimit;
        var n: usize = 0;
        for (0..CHIP_COUNT) |i| {
            const chip: Chip = @enumFromInt(i);
            const count = countFor(counts, chip);
            try validateSpan(firstFor(first_ids, chip), count);
            n += try std.math.divCeil(usize, count, try profile.capacity(chip));
            if (@as(u64, n) + cpus > MAX_INSTANCES) return error.ChipInstanceLimit;
        }
        const instances = try a.alloc(Instance, n);
        errdefer a.free(instances);
        var at: usize = 0;
        for (0..CHIP_COUNT) |i| {
            const chip: Chip = @enumFromInt(i);
            var remaining = countFor(counts, chip);
            var next = firstFor(first_ids, chip);
            var index: u32 = 0;
            const capacity = try profile.capacity(chip);
            while (remaining != 0) : (index += 1) {
                const take = @min(remaining, capacity);
                instances[at] = .{ .chip = chip, .index = index, .first_id = next, .requests = take, .log = profile.logs[i] };
                at += 1;
                remaining -= take;
                next += take;
            }
        }
        return .{ .allocator = a, .profile = profile, .semantic_identity = semantic_identity, .profile_identity = identity, .first_step = first_step, .instructions = instructions, .cpu_instances = @intCast(cpus), .counts = counts, .first_ids = first_ids, .instances = instances };
    }
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.instances);
        self.* = undefined;
    }
    pub fn cpu(self: *const Plan, index: u32) !CpuSpan {
        if (index >= self.cpu_instances) return error.InvalidChipCoverage;
        const capacity = try self.profile.cpuCapacity();
        const offset = @as(u64, index) * capacity;
        if (offset >= self.instructions or self.first_step > std.math.maxInt(u64) - self.instructions) return error.InvalidChipCoverage;
        return .{ .index = index, .first_step = self.first_step + offset, .steps = @intCast(@min(capacity, self.instructions - offset)), .log = self.profile.cpu_log };
    }
    /// Independent framing validation. It does not prove that CPU actually
    /// emitted these requests; typed consumer counters must establish that.
    pub fn validate(self: *const Plan) !void {
        if (!std.mem.eql(u8, &(try self.profile.identity(self.semantic_identity)), &self.profile_identity)) return error.InvalidChipProfile;
        if (self.instructions == 0 or self.first_step > std.math.maxInt(u64) - self.instructions or self.cpu_instances != try std.math.divCeil(u64, self.instructions, try self.profile.cpuCapacity()) or self.cpu_instances > MAX_INSTANCES or self.instances.len > MAX_INSTANCES or self.instances.len + self.cpu_instances > MAX_INSTANCES or requestCount(self.counts) > self.instructions) return error.InvalidChipCoverage;
        var at: usize = 0;
        for (0..CHIP_COUNT) |i| {
            const chip: Chip = @enumFromInt(i);
            var remaining = countFor(self.counts, chip);
            var next = firstFor(self.first_ids, chip);
            try validateSpan(next, remaining);
            const capacity = try self.profile.capacity(chip);
            var index: u32 = 0;
            while (remaining != 0) : (index += 1) {
                if (at >= self.instances.len) return error.InvalidChipCoverage;
                const instance = self.instances[at];
                const expected = @min(remaining, capacity);
                if (instance.chip != chip or instance.index != index or instance.first_id != next or instance.requests != expected or instance.log != self.profile.logs[i]) return error.InvalidChipCoverage;
                remaining -= expected;
                next += expected;
                at += 1;
            }
        }
        if (at != self.instances.len) return error.InvalidChipCoverage;
    }
    /// Include CPU/RAM/other provider padding mass independently derived from
    /// their admitted geometries. Whole-block CPU BYTE mass exceeds M31 here;
    /// an actual protocol must partition challenged epochs, never skip this.
    pub fn admitMass(self: *const Plan, other_byte_queries: u64) !u64 {
        try self.validate();
        if (self.counts.load_store != 0) return error.UnqualifiedLoadStoreMass;
        if (self.counts.alu != 0 or self.counts.binary != 0 or self.counts.shift != 0) return error.UnqualifiedWord16Mass;
        var bytes = other_byte_queries;
        for (self.instances) |instance| {
            const per_row: u64 = switch (instance.chip) {
                .division, .keccak => 0,
                .load_store, .alu, .binary, .shift => unreachable,
                .multiplication => 96,
                .keccak_bridge => 40,
                .add_product, .double_product => air.crypto.secp256k1.layout.byteCount(.product),
                .add_linear, .double_linear => air.crypto.secp256k1.layout.byteCount(.linear),
                .add_bridge, .double_bridge => air.crypto.secp256k1.bridge.layout.RANGE_COUNT,
            };
            bytes = try std.math.add(u64, bytes, per_row * (@as(u64, 1) << instance.log));
        }
        _ = try K.admitRoster(&.{self.counts.keccak}, &.{bytes});
        return bytes;
    }
};
pub fn countFor(counts: Counts, chip: Chip) u32 {
    return switch (chip) {
        .alu => counts.alu,
        .binary => counts.binary,
        .shift => counts.shift,
        .division => counts.division,
        .multiplication => counts.multiplication,
        .load_store => counts.load_store,
        .keccak, .keccak_bridge => counts.keccak,
        .add_product, .add_linear, .add_bridge => counts.add,
        .double_product, .double_linear, .double_bridge => counts.double,
    };
}
pub fn firstFor(ids: FirstIds, chip: Chip) u32 {
    return switch (chip) {
        .alu => ids.alu,
        .binary => ids.binary,
        .shift => ids.shift,
        .division => ids.division,
        .multiplication => ids.multiplication,
        .load_store => ids.load_store,
        .keccak, .keccak_bridge => ids.keccak,
        .add_product, .add_linear, .add_bridge => ids.add,
        .double_product, .double_linear, .double_bridge => ids.double,
    };
}
pub fn validateSpan(first: u32, count: u32) !void {
    if (first == 0 or first >= Modulus or @as(u64, first) + count > Modulus) return error.InvalidChipCoverage;
}

/// Disjoint dispatched instruction families; companion subchips are not counted twice.
pub fn requestCount(counts: Counts) u64 {
    return @as(u64, counts.division) + counts.multiplication + counts.load_store + counts.keccak + counts.add + counts.double + counts.alu + counts.binary + counts.shift;
}
