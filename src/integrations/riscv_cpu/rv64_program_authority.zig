//! Receiver-derived immutable ROM and fixed providers, shared by independently
//! sized execution batches. No request, endpoint, count, transcript or proof
//! enters this owner. Every borrowing materials object must die before it.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64_air;
const Profile = frontend.rv64.execution_profile.Profile;
const M = @import("stwo_core").fields.m31.M31;
pub const Authority = struct {
    allocator: std.mem.Allocator,
    profile: Profile,
    control_policy: @import("stwo_riscv_frontend").rv64_air.control_policy.Policy = .bytes_v1,
    words: []u32,
    program: rv.program.setup.Setup,
    opcodes: [65]bool,
    rom_fixed: []M,
    byte_table: rv.range.provider.Trace,
    and_table: ?rv.providers.tables.Setup,
    shift_table: ?rv.providers.tables.Setup,
    pub fn init(a: std.mem.Allocator, expected: rv.program.setup.Program, profile: Profile) !Authority {
        return initWithControl(a, expected, profile, .bytes_v1);
    }
    pub fn initWithControl(a: std.mem.Allocator, expected: rv.program.setup.Program, profile: Profile, control: rv.control_policy.Policy) !Authority {
        var program = try rv.program.setup.Setup.initWithProfile(a, expected, profile);
        errdefer program.deinit();
        const words = try a.dupe(u32, expected.words);
        errdefer a.free(words);
        var opcodes: [65]bool = @splat(false);
        for (program.rows, program.decoded) |row, decoded| if (row[rv.program.setup.field.valid].v == 1) {
            opcodes[@intFromEnum(decoded.instruction.opcode)] = true;
        };
        var operations: [65]rv.evaluation.O = undefined;
        var count: usize = 0;
        for (opcodes, 0..) |yes, opcode| if (yes) {
            operations[count] = @enumFromInt(opcode);
            count += 1;
        };
        const plan = try rv.encoding.Plan.fromOpcodesWithProfiles(operations[0..count], .division_service_v2, profile);
        const rom_fixed = try program.fixedColumnsWithControl(a, control);
        errdefer a.free(rom_fixed);
        var byte_table = try rv.range.provider.Trace.init(a, &@as([256]u64, @splat(0)));
        errdefer byte_table.deinit();
        var and_table: ?rv.providers.tables.Setup = if (rv.range.table_cpu.requests(&plan, .byte_and) != 0) try rv.providers.tables.Setup.init(a, .byte_and) else null;
        errdefer if (and_table) |*value| value.deinit();
        var shift_table: ?rv.providers.tables.Setup = if (rv.range.table_cpu.requests(&plan, .byte_shift) != 0) try rv.providers.tables.Setup.init(a, .byte_shift) else null;
        errdefer if (shift_table) |*value| value.deinit();
        return .{ .allocator = a, .profile = profile, .control_policy = control, .words = words, .program = program, .opcodes = opcodes, .rom_fixed = rom_fixed, .byte_table = byte_table, .and_table = and_table, .shift_table = shift_table };
    }
    pub fn expectedProgram(self: *const Authority) rv.program.setup.Program {
        return .{ .base = self.program.addresses[0], .words = self.words, .addresses = if (self.program.contiguous) &.{} else self.program.addresses };
    }
    pub fn deinit(self: *Authority) void {
        if (self.shift_table) |*value| value.deinit();
        if (self.and_table) |*value| value.deinit();
        self.byte_table.deinit();
        self.allocator.free(self.rom_fixed);
        self.allocator.free(self.words);
        self.program.deinit();
        self.* = undefined;
    }
};
