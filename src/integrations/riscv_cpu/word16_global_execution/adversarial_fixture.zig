//! A store followed by a load-to-x0: a false read cannot be caught by endpoint
//! register values. Only the physical global RAM argument links the two shards.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const X = A.word16_execution;
const R = A.memory.closed_ram;
const Native = @import("../word16_execution/prepared.zig").Prepared;
const Program = @import("../word16_execution/program.zig").Program;
const Setup = @import("../word16_execution/setup.zig").Setup;
const E = @import("execution.zig");
const P = @import("protocol.zig");
const ADDRESS: u64 = 0x8000000000000080;
const VALUE: u64 = 7;
const words = [_]u32{ 0x00113023, 0x00013003 }; // SD x1,0(x2); LD x0,0(x2).
const marker: u8 = 0;
fn initialWord(_: *const anyopaque, address: u64) !u64 {
    if (address != ADDRESS) return error.UntrustedFixtureAddress;
    return 0;
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address > ADDRESS + 7) return error.UntrustedFixtureAddress;
    return 3;
}
fn registers() [32]u64 {
    var out: [32]u64 = @splat(0);
    out[1] = VALUE;
    out[2] = ADDRESS;
    return out;
}
pub const Case = struct {
    allocator: std.mem.Allocator,
    setup: *Setup,
    bundle: E.Bundle,
    pub fn expected(self: *const Case) P.Expected {
        return .{
            .admission = .{ .image = .{ .context = &marker, .initial_word = initialWord, .rights_at = rights }, .image_identity = @splat(0x37), .initial_pc = 4096, .initial_registers = registers(), .max_prefix_steps = 31 },
            .program_identity = self.setup.materials.program.identity,
            .total_steps = 2,
            .max_total_steps = 2,
            .final_pc = 4104,
            .final_registers = registers(),
        };
    }
    pub fn keys(self: *const Case) [2]*const Setup {
        return .{ self.setup, self.setup };
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        self.setup.deinit();
        self.allocator.destroy(self.setup);
    }
    pub fn init(a: std.mem.Allocator, false_read: bool) !Case {
        var program = try Program.init(a, .{ .base = 4096, .words = &words });
        defer program.deinit();
        var tape0 = try front.rv64.compact_tape.Tape.init(a, 1, 4096, 0, .ethereum_services_v2);
        defer tape0.deinit();
        var tape1 = try front.rv64.compact_tape.Tape.init(a, 1, 4100, 1, .ethereum_services_v2);
        defer tape1.deinit();
        const read_value: u64 = if (false_read) 0 else VALUE;
        tape0.len = 1;
        tape0.storage[0] = .{ .next_pc = 4100, .lhs = ADDRESS, .rhs = VALUE, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try tape0.memory_before.append(a, 0);
        tape1.len = 1;
        tape1.storage[0] = .{ .next_pc = 4104, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = read_value, .memory_index = 0, .flags = 0 };
        try tape1.memory_before.append(a, read_value);
        var public0: X.types.Boundary = .{ .steps = 1, .initial_pc = 4096, .final_pc = 4100, .initial_registers = registers(), .final_registers = registers(), .register_clocks = @splat(0) };
        public0.register_clocks[2] = 1;
        public0.register_clocks[1] = 2;
        var public1 = public0;
        public1.initial_pc = 4100;
        public1.final_pc = 4104;
        public1.register_clocks[1] = 0;
        var native0 = try Native.init(a, &program, public0, 1, 5, &tape0, .{});
        defer native0.deinit();
        var native1 = try Native.init(a, &program, public1, 2, 5, &tape1, .{});
        defer native1.deinit();
        const setup = try a.create(Setup);
        errdefer a.destroy(setup);
        setup.* = try Setup.init(a, .{ .base = 4096, .words = &words }, try native0.geometry());
        errdefer setup.deinit();
        const zero = R.types.State{ .value = 0, .rights = 3 };
        const stored = R.types.State{ .value = VALUE, .rights = 3, .epoch = 1, .tick = 4 };
        const loaded = R.types.State{ .value = read_value, .rights = 3, .epoch = 2, .tick = 4 };
        var first = [_]A.memory.load_store_v2.native.Event{.{ .opcode = .SD, .immediate = 0, .a = ADDRESS, .b = VALUE, .c = 0, .epoch = 1, .tick = 4, .before = zero, .after = stored }};
        var second = [_]A.memory.load_store_v2.native.Event{.{ .opcode = .LD, .immediate = 0, .a = ADDRESS, .b = 0, .c = read_value, .epoch = 2, .tick = 4, .before = if (false_read) zero else stored, .after = loaded }};
        var events = [_][]A.memory.load_store_v2.native.Event{ &first, &second };
        var initial = [_]R.types.Cell{.{ .address = ADDRESS, .state = zero }};
        var terminal = [_]R.types.Cell{.{ .address = ADDRESS, .state = loaded }};
        // Deliberate adversarial advice bypasses the native collector. Arrays
        // are borrowed for this call only; no Advice.deinit on stack storage.
        const advice = E.Advice{ .allocator = a, .events = &events, .initial = &initial, .terminal = &terminal };
        var out = Case{ .allocator = a, .setup = setup, .bundle = undefined };
        const handles = out.keys();
        out.bundle = try E.produceWithAdvice(a, &handles, &.{ &native0, &native1 }, &advice, out.expected());
        return out;
    }
};
