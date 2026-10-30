const std = @import("std");
const core = @import("stwo_core");
const B = @import("block_v7_memory_bundle_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
const Sources = @import("block_v5_initial_sources_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Fixture = @import("../runner/guest_precompile/test_elf.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
const raw = Fixture.buildReleaseProgram(1, &.{0x0000006f}, 64, .rv32im_zkvm_v1);
const base = makeElf();
fn makeElf() [raw.len]u8 {
    var elf = raw;
    const table = std.mem.readInt(u32, elf[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 64, 0x100180, 0x100190 }) |index, value|
        std.mem.writeInt(u32, elf[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    std.mem.writeInt(u32, elf[644..648], 0x44332211, .little);
    return elf;
}
const Proof = B.For(Cpu);
fn setup(a: std.mem.Allocator) !struct { trusted: B.Trusted, guest: [16]Event } {
    var policy = try Initial.Owned.derive(a, &base, Sources.sha256(&base), .rv32im_zkvm_v1, .{});
    defer policy.deinit();
    // Use the independently selected fixture ABI, not another machine's paths.
    var out: [43]u8 = undefined;
    for (&out, 0..) |*v, i| v.* = @intCast(i + 1);
    out[32] = 1;
    const terminal = Terminal.Policy{ .final_cycle = 100, .halt_address = policy.info.halt_flag, .length_address = policy.info.output_len, .data_address = policy.info.output_data, .output_end = policy.info.output_end, .output = out };
    const plan = try Terminal.Plan.init(terminal);
    var guest: [16]Event = undefined;
    for (guest[0..13], 0..) |*v, i| {
        const read = try plan.transition(i, 0xa5);
        v.* = .{ .space = 1, .address = read.address, .clock = if (i == 0) 4 * terminal.final_cycle - 1 else 4 * (i / 3) + i % 3 + 1, .before = (try policy.find(read.address)).value, .after = read.before };
    }
    guest[13] = .{ .space = 1, .address = 0x100100, .clock = 21, .before = (try policy.find(0x100100)).value, .after = 19 };
    guest[14] = .{ .space = 1, .address = 0x100100, .clock = 22, .before = 19, .after = 23 };
    guest[15] = .{ .space = 1, .address = policy.info.input_start, .clock = 23, .before = 0xdeadbeef, .after = 7 };
    return .{ .trusted = .{ .elf = &base, .elf_sha256 = Sources.sha256(&base), .profile = .rv32im_zkvm_v1, .terminal = terminal, .guest = &.{}, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null } }, .guest = guest };
}
test "v7 memory original STARK closes multi-shard initialization and terminal13 freshly" {
    const a = std.testing.allocator;
    var fixture = try setup(a);
    fixture.trusted.guest = &fixture.guest;
    var bundle = try Proof.prove(a, fixture.trusted, 0xa5, 7, .{});
    defer bundle.deinit(a);
    try std.testing.expectEqual(@as(usize, 5), bundle.ram.len);
    var split_same_address = false;
    for (bundle.ram[1..]) |item| if (item.geometry.preceding.?.address == item.geometry.first.address) {
        split_same_address = true;
    };
    try std.testing.expect(split_same_address);
    for (bundle.ram) |*item| try roundTrip(a, &item.proof.stark);
    try roundTrip(a, &bundle.interval.stark);
    try roundTrip(a, &bundle.range16.stark);
    try roundTrip(a, &bundle.terminal.stark);
    try Proof.verify(a, fixture.trusted, &bundle, .{});
    // Every per-plane sum is authoritative and bound to its original transcript.
    const old = bundle.ram[0].proof.sums[3];
    bundle.ram[0].proof.sums[3] = old.add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.OodsNotMatching, Proof.verify(a, fixture.trusted, &bundle, .{}));
    bundle.ram[0].proof.sums[3] = old;
    var wrong = fixture.trusted;
    wrong.terminal.halt_address += 4;
    try std.testing.expectError(error.InvalidTerminalAddresses, Proof.verify(a, wrong, &bundle, .{}));
    wrong = fixture.trusted;
    wrong.terminal.output[1] ^= 1;
    try std.testing.expectError(error.OodsNotMatching, Proof.verify(a, wrong, &bundle, .{}));
    std.mem.swap(B.RamItem, &bundle.ram[0], &bundle.ram[1]);
    try std.testing.expectError(error.InvalidV5RamLanesCensus, Proof.verify(a, fixture.trusted, &bundle, .{}));
    std.mem.swap(B.RamItem, &bundle.ram[0], &bundle.ram[1]);
    try std.testing.expectError(error.InvalidV7Roster, Proof.verify(a, fixture.trusted, &bundle, .{ .max_shards = 1 }));
}

fn roundTrip(a: std.mem.Allocator, proof: *core.proof_suites.Blake3.Proof) !void {
    const wire = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.*);
    var reader = std.io.fixedBufferStream(writer.written());
    const rebuilt = try wire.deserializeProof(core.proof_suites.Blake3.Hasher, a, reader.reader());
    proof.deinit(a);
    proof.* = rebuilt;
    try std.testing.expectEqual(writer.written().len, reader.pos);
}
test "v7 memory original prover rejects false ELF initialization rather than trusting source summary" {
    const a = std.testing.allocator;
    var fixture = try setup(a);
    fixture.trusted.guest = &fixture.guest;
    fixture.guest[13].before = 0;
    if (Proof.prove(a, fixture.trusted, 0xa5, 7, .{})) |value| {
        var unexpected = value;
        unexpected.deinit(a);
        return error.ExpectedInitializationRejection;
    } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
}

test "v7 memory original source clock slots and terminal bounds reject before proving" {
    var fixture = try setup(std.testing.allocator);
    fixture.trusted.guest = &fixture.guest;
    const original = fixture.guest[0].clock;
    for ([4]u64{ 0, 4, 4 * fixture.trusted.terminal.final_cycle, 4 * fixture.trusted.terminal.final_cycle + 1 }) |clock| {
        fixture.guest[0].clock = clock;
        try std.testing.expectError(error.InvalidV7GuestTransition, fixture.trusted.validate(.{}));
    }
    fixture.guest[0].clock = original;
    try fixture.trusted.validate(.{});
}

test "v7 original RAM proof rejects early halt even when terminal state is correct" {
    const a = std.testing.allocator;
    var fixture = try setup(a);
    fixture.guest[0].clock = 1;
    fixture.trusted.guest = &fixture.guest;
    try fixture.trusted.validate(.{}); // Not rejected by a host-only filter.
    if (Proof.prove(a, fixture.trusted, 0xa5, 7, .{})) |value| {
        var unexpected = value;
        unexpected.deinit(a);
        return error.ExpectedFirstHaltRejection;
    } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
}
