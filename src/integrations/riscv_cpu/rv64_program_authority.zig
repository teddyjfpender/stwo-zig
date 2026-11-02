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
    /// Legacy byte-ROM / native statement profile (v1 or v2 for the Ethereum
    /// routes; v3 and v3_zbb tapes run under the v2-decoded statement).
    profile: Profile,
    /// Execution ROM profile of the Word16 route. Equal to `profile` except on
    /// the Zbb route (profile v2, rom_profile ethereum_services_v3_zbb), where
    /// the Word16 ROM decodes the Zbb BINARY rows the legacy byte ROM keeps
    /// invalid; `instructionAt` exposes exactly those rows to native batch and
    /// packet bookkeeping. The legacy byte AIR never proves a Zbb row.
    rom_profile: Profile,
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
        return initWithRom(a, expected, profile, profile, control);
    }
    /// `rom_profile` may differ from `profile` only for the Zbb route
    /// (v2 legacy statement, ethereum_services_v3_zbb execution ROM).
    pub fn initWithRom(a: std.mem.Allocator, expected: rv.program.setup.Program, profile: Profile, rom_profile: Profile, control: rv.control_policy.Policy) !Authority {
        if (rom_profile != profile and (profile != .ethereum_services_v2 or rom_profile != .ethereum_services_v3_zbb)) return error.UnsupportedRv64RomProfile;
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
        return .{ .allocator = a, .profile = profile, .rom_profile = rom_profile, .control_policy = control, .words = words, .program = program, .opcodes = opcodes, .rom_fixed = rom_fixed, .byte_table = byte_table, .and_table = and_table, .shift_table = shift_table };
    }
    /// Native bookkeeping decode of the instruction at `pc`: the legacy
    /// byte-ROM row when it is valid; otherwise, only under a Zbb execution
    /// ROM, the Zbb BINARY decode of that row's raw word. Anything else
    /// (unmapped PC, invalid word, base opcode on an invalid row) fails closed.
    pub fn instructionAt(self: *const Authority, pc: u64) !struct { raw: u32, instruction: frontend.rv64.decode.Instruction } {
        const E = frontend.rv64.execution_profile;
        const index = try self.program.indexOf(pc);
        const decoded = self.program.decoded[index];
        if (!self.program.rows[index][rv.program.setup.field.valid].isZero()) return .{ .raw = decoded.raw, .instruction = decoded.instruction };
        if (self.rom_profile == self.profile or E.isaOf(self.rom_profile) != .rv64im_zbb_binary) return error.InvalidRv64RomExecution;
        const instruction = E.decode(self.rom_profile, decoded.raw) catch return error.InvalidRv64RomExecution;
        if (frontend.rv64.decode.isBase(instruction.opcode) or !E.admitted(self.rom_profile, instruction.opcode)) return error.InvalidRv64RomExecution;
        return .{ .raw = decoded.raw, .instruction = instruction };
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
