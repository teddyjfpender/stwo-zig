const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const R = @import("../../roster.zig");
const P = @import("../../protocol.zig");
const Collector = @import("../../collector.zig");
const Program = @import("../../../../word16_execution/program.zig").Program;
const Native = @import("../../../../word16_execution/prepared.zig").Prepared;
const Control = @import("control.zig");
const a = std.testing.allocator;
const WORDS = [_]u32{ 0x00700093, 0x00153023, 0x00053103, 0x0020c1b3 };
const ADDRESS: u64 = 8192;
const marker: u8 = 0;
fn word(_: *const anyopaque, address: u64) !u64 {
    if (address != ADDRESS) return error.UntrustedControlTestAddress;
    return 0;
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    return if (address >= ADDRESS and address < ADDRESS + 8) 3 else 0;
}
fn image() @import("../../../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = word, .rights_at = rights };
}
const Fixture = struct {
    program: *Program,
    tape: front.rv64.compact_tape.Tape,
    native: Native,
    advice: Collector.Advice,
    boundary: A.word16_execution.types.Boundary,
    fn init() !@This() {
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.init(a, .{ .base = 4096, .words = &WORDS });
        errdefer program.deinit();
        var tape = try front.rv64.compact_tape.Tape.init(a, 4, 4096, 0, .ethereum_services_v2);
        errdefer tape.deinit();
        tape.len = 4;
        tape.storage[0] = .{ .next_pc = 4100, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 7, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        tape.storage[1] = .{ .next_pc = 4104, .lhs = ADDRESS, .rhs = 7, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        tape.storage[2] = .{ .next_pc = 4108, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = 7, .memory_index = 1, .flags = 0 };
        tape.storage[3] = .{ .next_pc = 4112, .lhs = 7, .rhs = 7, .previous_rd = 0, .result = 0, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        try tape.memory_before.append(a, 0);
        try tape.memory_before.append(a, 7);
        var b: A.word16_execution.types.Boundary = .{ .steps = 4, .initial_pc = 4096, .final_pc = 4112, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
        b.initial_registers[10] = ADDRESS;
        b.final_registers[10] = ADDRESS;
        b.final_registers[1] = 7;
        b.final_registers[2] = 7;
        b.register_clocks[1] = 13;
        b.register_clocks[2] = 14;
        b.register_clocks[3] = 15;
        b.register_clocks[10] = 9;
        var n = try Native.init(a, program, b, 1, 5, &tape, .{ .deduplicate_shift = true });
        errdefer n.deinit();
        var advice = try Collector.collect(a, &.{&n}, &.{&tape}, image());
        errdefer advice.deinit();
        return .{ .program = program, .tape = tape, .native = n, .advice = advice, .boundary = b };
    }
    fn deinit(f: *@This()) void {
        f.advice.deinit();
        f.native.deinit();
        f.tape.deinit();
        f.program.deinit();
        a.destroy(f.program);
    }
    fn request(f: *const @This()) P.Request {
        return .{ .calls = @splat(0), .base = .{ .cpu = f.boundary, .epoch = 1, .division_requests = f.native.raw_counts.division, .multiplication_requests = f.native.raw_counts.multiplication, .memory = .{ .epoch = 1, .ls_count = @intCast(f.native.raw_counts.memory), .initial = f.advice.initial, .terminal = f.advice.terminal } } };
    }
    fn expected(f: *const @This()) P.Expected {
        return .{ .admission = .{ .image = image(), .image_identity = @splat(7), .initial_pc = 4096, .initial_registers = f.boundary.initial_registers, .max_prefix_steps = 4 }, .program_identity = f.program.identity, .total_steps = 4, .max_total_steps = 4, .final_pc = 4112, .final_registers = f.boundary.final_registers };
    }
};
test "benchmark wide classic full CPU RAM proof fresh-verifies and binds balanced claims and endpoints" {
    var f = try Fixture.init();
    defer f.deinit();
    const request = f.request();
    var geometry = try f.native.geometry();
    geometry.omit_empty_division = true;
    var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, geometry, .{});
    defer setup.deinit();
    const source = try @import("../../pipeline.zig").buildCpuSource(a, &setup, request, &f.native, &f.advice, 0, .{ 1, 1, 1 }, false, null);
    const config = @import("../../gkr_local/worker_protocol.zig").PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(core.fields.om31.OM31).FriConfig.init(0, 1, 12) };
    var encoded = try Control.prove(a, &setup, request, f.expected(), config, source, 2 << 30, null, null);
    defer encoded.deinit(a);
    var fresh = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, geometry, .{});
    defer fresh.deinit();
    try Control.verify(a, &fresh, request, f.expected(), config, &encoded);
    const O = core.fields.om31.OM31;
    encoded.local_claims[0] = encoded.local_claims[0].add(O.one());
    encoded.local_claims[1] = encoded.local_claims[1].sub(O.one());
    if (Control.verify(a, &fresh, request, f.expected(), config, &encoded)) return error.AcceptedBalancedAlteredClassicClaims else |_| {}
    encoded.local_claims[0] = encoded.local_claims[0].sub(O.one());
    encoded.local_claims[1] = encoded.local_claims[1].add(O.one());
    var changed = request;
    changed.base.cpu.final_registers[3] ^= 1;
    var want = f.expected();
    want.final_registers = changed.base.cpu.final_registers;
    if (Control.verify(a, &fresh, changed, want, config, &encoded)) return error.AcceptedChangedClassicEndpoint else |_| {}
    encoded.bytes[encoded.bytes.len / 2] ^= 1;
    if (Control.verify(a, &fresh, request, f.expected(), config, &encoded)) return error.AcceptedCorruptClassicProof else |_| {}
}

test "benchmark budget refusal consumes native source without leaking partial MAIN" {
    var f = try Fixture.init();
    defer f.deinit();
    var geometry = try f.native.geometry();
    geometry.omit_empty_division = true;
    var setup = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, geometry, .{});
    defer setup.deinit();
    const request = f.request();
    const source = try @import("../../pipeline.zig").buildCpuSource(a, &setup, request, &f.native, &f.advice, 0, .{ 1, 1, 1 }, false, null);
    const config = @import("../../gkr_local/worker_protocol.zig").PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.ForField(core.fields.om31.OM31).FriConfig.init(0, 1, 12) };
    try std.testing.expectError(error.ClassicWitnessBudgetExceeded, Control.prove(a, &setup, request, f.expected(), config, source, 1, null, null));
}
