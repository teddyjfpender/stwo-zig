//! Pinned-SameBoy interrupt-dispatch cycles and logical side effects.
//!
//! Oracle: SameBoy commit `213a12ce93d66b105a113debd9396306066a7cfc`,
//! `Core/sm83_cpu.c:1629-1699`. The five dispatch M-cycles are a dummy PC
//! read, OAM-bug cycle, no-access cycle, high stack write, and low stack
//! write. HALT contributes one leading no-access M-cycle. IE/IF resampling and
//! the IF acknowledgement inside the low-write cycle are logical operations,
//! not additional bus accesses.

const std = @import("std");
const runner = @import("mod.zig");
const mbc3 = @import("../cartridge/mbc3.zig");

pub const SAMEBOY_COMMIT = "213a12ce93d66b105a113debd9396306066a7cfc";
pub const MAX_CYCLES: usize = 6;
pub const IF: u16 = 0xff0f;
pub const IE: u16 = 0xffff;

pub const CycleKind = enum {
    unused,
    halt_idle,
    dummy_read,
    oam_bug,
    no_access,
    stack_high,
    stack_low,
};

pub const ServiceCycle = struct {
    kind: CycleKind = .unused,
    /// `null` is a real elapsed M-cycle with no CPU bus access.
    access: ?runner.cartridge_memory.Access = null,
};

pub const LogicalSample = struct {
    after_cycle: u3,
    value: u8,
};

pub const Acknowledgement = struct {
    during_cycle: u3,
    index: u3,
    before: u8,
    after: u8,
};

pub const Expected = struct {
    halted: bool,
    return_pc: u16,
    stack_pointer: u16,
    interrupt_enable_before: u8,
    interrupt_enable_after: u8,
    interrupt_flags_after: u8,
    interrupt_index: ?u3,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
};

pub const Trace = struct {
    cycles: [MAX_CYCLES]ServiceCycle =
        [_]ServiceCycle{.{}} ** MAX_CYCLES,
    count: u3 = 0,
    ie_resample: ?LogicalSample = null,
    if_resample: ?LogicalSample = null,
    acknowledgement: ?Acknowledgement = null,

    pub fn activeCycles(self: *const Trace) []const ServiceCycle {
        return self.cycles[0..self.count];
    }

    pub fn append(
        self: *Trace,
        kind: CycleKind,
        access: ?runner.cartridge_memory.Access,
    ) void {
        std.debug.assert(self.count < self.cycles.len);
        self.cycles[self.count] = .{ .kind = kind, .access = access };
        self.count += 1;
    }

    pub fn isEmpty(self: Trace) bool {
        if (self.count != 0 or self.ie_resample != null or
            self.if_resample != null or self.acknowledgement != null)
            return false;
        for (self.cycles) |cycle|
            if (cycle.kind != .unused or cycle.access != null) return false;
        return true;
    }

    pub fn hasCanonicalShape(self: Trace, expected: Expected) bool {
        const offset: u3 = if (expected.halted) 1 else 0;
        const expected_count: u3 = 5 + offset;
        if (self.count != expected_count) return false;
        for (self.cycles[self.count..]) |cycle| if (cycle.kind != .unused or cycle.access != null) return false;

        if (expected.halted and
            !matchesNoAccess(self.cycles[0], .halt_idle))
            return false;
        const dummy = self.cycles[offset].access orelse return false;
        if (self.cycles[offset].kind != .dummy_read or
            !matchesAccess(dummy, expected.return_pc, .read, dummy.value))
            return false;
        if (!matchesNoAccess(self.cycles[offset + 1], .oam_bug) or
            !matchesNoAccess(self.cycles[offset + 2], .no_access))
            return false;
        const high = self.cycles[offset + 3].access orelse return false;
        const low = self.cycles[offset + 4].access orelse return false;
        if (self.cycles[offset + 3].kind != .stack_high or
            self.cycles[offset + 4].kind != .stack_low or !matchesAccess(
            high,
            expected.stack_pointer -% 1,
            .write,
            @truncate(expected.return_pc >> 8),
        ) or !matchesAccess(
            low,
            expected.stack_pointer -% 2,
            .write,
            @truncate(expected.return_pc),
        ))
            return false;

        const ie = self.ie_resample orelse return false;
        const interrupt_flags = self.if_resample orelse return false;
        if (ie.after_cycle != offset + 3 or
            interrupt_flags.after_cycle != offset + 4 or
            interrupt_flags.value & 0xe0 != 0)
            return false;
        const expected_ie = if (high.logical_address == IE)
            high.value
        else
            expected.interrupt_enable_before;
        if (ie.value != expected_ie) return false;
        const expected_final_ie = if (low.logical_address == IE)
            low.value
        else
            expected_ie;
        if (expected.interrupt_enable_after != expected_final_ie) return false;

        if (!mapperChainIsCanonical(
            self.activeCycles(),
            expected.mapper_before,
            expected.mapper_after,
        )) return false;

        const queue = ie.value & interrupt_flags.value & 0x1f;
        const selected: ?u3 =
            if (queue == 0) null else @intCast(@ctz(queue));
        if (selected != expected.interrupt_index) return false;
        const if_after_low = if (low.logical_address == IF)
            low.value
        else
            interrupt_flags.value;
        if (selected) |index| {
            const ack = self.acknowledgement orelse return false;
            if (ack.during_cycle != offset + 4 or ack.index != index or
                ack.after != ack.before & ~(@as(u8, 1) << index) or
                ack.before | if_after_low != ack.before or
                expected.interrupt_flags_after | ack.after !=
                    expected.interrupt_flags_after)
                return false;
        } else {
            if (self.acknowledgement != null or
                expected.interrupt_flags_after | if_after_low !=
                    expected.interrupt_flags_after)
                return false;
        }
        return true;
    }
};

fn mapperChainIsCanonical(
    cycles: []const ServiceCycle,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
) bool {
    var previous = mapper_before;
    var count: u3 = 0;
    for (cycles) |cycle| if (cycle.access) |access| {
        if (!std.meta.eql(previous, access.mapper_before) or
            !canonicalMapperTransition(access))
            return false;
        previous = access.mapper_after;
        count += 1;
    };
    return count == 3 and std.meta.eql(previous, mapper_after);
}

fn matchesAccess(
    access: runner.cartridge_memory.Access,
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
) bool {
    return access.logical_address == address and
        access.action == action and access.value == value;
}

fn matchesNoAccess(cycle: ServiceCycle, kind: CycleKind) bool {
    return cycle.kind == kind and cycle.access == null;
}

fn canonicalMapperTransition(access: runner.cartridge_memory.Access) bool {
    if (access.action == .write and access.logical_address <= 0x7fff) {
        const expected = mbc3.transition(
            access.mapper_before,
            access.logical_address,
            access.value,
        ) catch return false;
        return access.region == .mapper_control and
            access.physical_offset == null and
            std.meta.eql(access.mapper_after, expected);
    }
    return std.meta.eql(access.mapper_before, access.mapper_after);
}

test "service trace pins SameBoy bus order and rejects vacuous mutations" {
    const expected = Expected{
        .halted = false,
        .return_pc = 0x2345,
        .stack_pointer = 0xc102,
        .interrupt_enable_before = 1,
        .interrupt_enable_after = 1,
        .interrupt_flags_after = 0,
        .interrupt_index = 0,
        .mapper_before = .{},
        .mapper_after = .{},
    };
    const honest = honestTrace(expected);
    try std.testing.expect(honest.hasCanonicalShape(expected));

    var forged = honest;
    forged.count = 0;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.cycles[0].access = null;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.cycles[1].access = forged.cycles[0].access;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.cycles[1].kind = .no_access;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.cycles[0].access.?.logical_address +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.cycles[3].access.?.value +%= 1;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.cycles[3].access.?.action = .read;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.cycles[4].access.?.mapper_before.rom_bank_register = 7;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.cycles[5].access = forged.cycles[0].access;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.ie_resample = null;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.if_resample.?.after_cycle -%= 1;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.if_resample.?.value = 0;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.acknowledgement = null;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.acknowledgement.?.after = 1;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
}

test "HALT service trace retains its leading no-access M-cycle" {
    const expected = Expected{
        .halted = true,
        .return_pc = 0x2345,
        .stack_pointer = 0xc102,
        .interrupt_enable_before = 1,
        .interrupt_enable_after = 1,
        .interrupt_flags_after = 0,
        .interrupt_index = 0,
        .mapper_before = .{},
        .mapper_after = .{},
    };
    const honest = honestTrace(expected);
    try std.testing.expectEqual(@as(u3, 6), honest.count);
    try std.testing.expect(honest.cycles[0].access == null);
    try std.testing.expect(honest.hasCanonicalShape(expected));

    var forged = honest;
    forged.cycles[0].access = forged.cycles[1].access;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
    forged = honest;
    forged.ie_resample.?.after_cycle = 2;
    try std.testing.expect(!forged.hasCanonicalShape(expected));
}

test "logical resampling preserves cancellation reprioritization and IF alias" {
    const cancelled = Expected{
        .halted = false,
        .return_pc = 0,
        .stack_pointer = 0,
        .interrupt_enable_before = 1,
        .interrupt_enable_after = 0,
        .interrupt_flags_after = 1,
        .interrupt_index = null,
        .mapper_before = .{},
        .mapper_after = .{},
    };
    const cancelled_trace = honestTrace(cancelled);
    try std.testing.expect(cancelled_trace.acknowledgement == null);
    try std.testing.expect(cancelled_trace.hasCanonicalShape(cancelled));

    const reprioritized = Expected{
        .halted = false,
        .return_pc = 0x0200,
        .stack_pointer = 0,
        .interrupt_enable_before = 1,
        .interrupt_enable_after = 2,
        .interrupt_flags_after = 1,
        .interrupt_index = 1,
        .mapper_before = .{},
        .mapper_after = .{},
    };
    const reprioritized_trace = honestTrace(reprioritized);
    try std.testing.expect(
        reprioritized_trace.hasCanonicalShape(reprioritized),
    );

    const if_alias = Expected{
        .halted = false,
        .return_pc = 2,
        .stack_pointer = IF + 2,
        .interrupt_enable_before = 1,
        .interrupt_enable_after = 1,
        .interrupt_flags_after = 2,
        .interrupt_index = 0,
        .mapper_before = .{},
        .mapper_after = .{},
    };
    var alias_trace = honestTrace(if_alias);
    alias_trace.if_resample.?.value = 1;
    alias_trace.acknowledgement.?.before = 2;
    alias_trace.acknowledgement.?.after = 2;
    try std.testing.expect(alias_trace.hasCanonicalShape(if_alias));
    try std.testing.expectEqual(
        @as(u8, 1),
        alias_trace.if_resample.?.value,
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        alias_trace.acknowledgement.?.before,
    );
}

fn honestTrace(expected: Expected) Trace {
    var trace = Trace{};
    if (expected.halted) trace.append(.halt_idle, null);
    trace.append(
        .dummy_read,
        testAccess(expected.return_pc, .read, 0x5a, .{}, .{}),
    );
    trace.append(.oam_bug, null);
    trace.append(.no_access, null);
    const high = expected.stack_pointer -% 1;
    trace.append(
        .stack_high,
        testAccess(
            high,
            .write,
            @truncate(expected.return_pc >> 8),
            .{},
            .{},
        ),
    );
    const ie = if (high == IE)
        @as(u8, @truncate(expected.return_pc >> 8))
    else
        expected.interrupt_enable_before;
    trace.ie_resample = .{
        .after_cycle = trace.count - 1,
        .value = ie,
    };
    const low = expected.stack_pointer -% 2;
    trace.append(
        .stack_low,
        testAccess(
            low,
            .write,
            @truncate(expected.return_pc),
            .{},
            .{},
        ),
    );
    const if_value: u8 = if (expected.interrupt_index == null)
        expected.interrupt_flags_after & 0x1f
    else if (low == IF)
        0
    else
        expected.interrupt_flags_after |
            (@as(u8, 1) << expected.interrupt_index.?);
    trace.if_resample = .{
        .after_cycle = trace.count - 1,
        .value = if_value,
    };
    if (expected.interrupt_index) |index| {
        const before = if (low == IF)
            @as(u8, @truncate(expected.return_pc))
        else
            if_value;
        trace.acknowledgement = .{
            .during_cycle = trace.count - 1,
            .index = index,
            .before = before,
            .after = before & ~(@as(u8, 1) << index),
        };
    }
    return trace;
}

fn testAccess(
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
) runner.cartridge_memory.Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = if (action == .read and address <= 0x7fff)
            .cartridge_rom
        else if (action == .write and address <= 0x7fff)
            .mapper_control
        else
            .system,
        .physical_offset = if (action == .read and address <= 0x7fff)
            address
        else
            null,
        .mapper_before = mapper_before,
        .mapper_after = mapper_after,
        .value = value,
    };
}
