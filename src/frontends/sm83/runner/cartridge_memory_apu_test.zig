//! Fail-closed CPU-visible APU attachment tests.

const std = @import("std");
const cartridge_mod = @import("../cartridge/mod.zig");
const header = cartridge_mod.header;
const memory_mod = @import("cartridge_memory.zig");
const apu_mmio = @import("apu_mmio.zig");
const Fixture = @import("cartridge_memory_test_support.zig").Fixture(
    cartridge_mod,
    header,
    memory_mod.Memory,
    memory_mod.SYSTEM_SIZE,
);

test "attached APU owns FF10 through FF3F and preserves raw latches" {
    var fixture = try Fixture.init(std.testing.allocator, 0x5a);
    defer fixture.deinit(std.testing.allocator);
    var io = [_]u8{0} ** 0x80;
    io[0x25] = 0x12;
    io[0x30] = 0x34;
    var apu = try apu_mmio.State.fromIo(
        &io,
        true,
        0x5,
        .inactive,
    );
    try fixture.memory.attachApu(&apu);

    const nr51 = try fixture.memory.read(0xff25);
    try std.testing.expectEqual(@as(u8, 0x12), nr51.value);
    try std.testing.expectEqual(memory_mod.Region.apu_mmio, nr51.access.region);
    try std.testing.expectEqual(@as(u8, 0xf5), (try fixture.memory.read(apu_mmio.NR52)).value);

    const write = try fixture.memory.write(0xff25, 0x67);
    try std.testing.expectEqual(memory_mod.Region.apu_mmio, write.region);
    try std.testing.expectEqual(@as(u8, 0x67), fixture.system[0xff25]);
    try std.testing.expectEqual(@as(u8, 0x67), apu.read(0xff25));
    try std.testing.expectEqualDeep(write.mapper_before, write.mapper_after);

    fixture.memory.detachApu();
    const detached = try fixture.memory.read(0xff25);
    try std.testing.expectEqual(memory_mod.Region.system, detached.access.region);
    try std.testing.expectEqual(@as(u8, 0x67), detached.value);
}

test "unknown APU status and wave phase propagate instead of falling back" {
    var fixture = try Fixture.init(std.testing.allocator, 0xa5);
    defer fixture.deinit(std.testing.allocator);
    var io = [_]u8{0} ** 0x80;
    var apu = try apu_mmio.State.fromIo(&io, true, 0, .inactive);
    try fixture.memory.attachApu(&apu);

    _ = try fixture.memory.write(0xff14, 0x80);
    try std.testing.expectError(
        error.UnknownChannelStatus,
        fixture.memory.read(apu_mmio.NR52),
    );
    try std.testing.expectEqual(@as(u8, 0x80), fixture.system[0xff14]);

    _ = try fixture.memory.write(apu_mmio.NR34, 0x80);
    try std.testing.expectError(
        error.UnknownWavePhase,
        fixture.memory.read(apu_mmio.WAVE_START),
    );
    try std.testing.expectError(
        error.UnsupportedWrite,
        fixture.memory.write(0xff27, 0x11),
    );
    try std.testing.expectEqual(@as(u8, 0x80), fixture.memory.data_bus);
}
