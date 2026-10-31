//! Separate accepting prefix protocol. Legacy closed/genesis and diagnostic
//! scopes remain unchanged. Only RAM14 is shared; all other debts close locally.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
pub const Old = @import("../word16_execution/protocol.zig");
pub const Setup = @import("../word16_execution/setup.zig").Setup;
pub const Admission = @import("../word16_execution/execution.zig").Admission;
pub const Q = core.fields.qm31.QM31;
pub const T = Old.T;
pub const Root = struct { bytes: [32]u8 };
pub const Receipt = struct { fixed: Root, main: Root };
pub const Expected = struct { admission: Admission, program_identity: [32]u8, total_steps: u64, max_total_steps: u64, final_pc: u64, final_registers: [32]u64 };
pub const Manifest = struct {
    allocator: std.mem.Allocator,
    specs: [][32]u8,
    roots: []Receipt,
    digest: [32]u8,
    pub fn deinit(self: *Manifest) void {
        self.allocator.free(self.specs);
        self.allocator.free(self.roots);
    }
    pub fn init(a: std.mem.Allocator, specs: []const [32]u8, roots: []const Receipt) !Manifest {
        if (specs.len == 0 or specs.len > 65535 or specs.len != roots.len) return error.IncompleteGlobalExecutionManifest;
        const ss = try a.dupe([32]u8, specs);
        errdefer a.free(ss);
        const rs = try a.dupe(Receipt, roots);
        return .{ .allocator = a, .specs = ss, .roots = rs, .digest = seal(ss, rs) };
    }
    pub fn check(self: *const Manifest, specs: []const [32]u8) !void {
        if (specs.len != self.specs.len or self.roots.len != specs.len) return error.IncompleteGlobalExecutionManifest;
        for (specs, self.specs) |x, y| if (!std.mem.eql(u8, &x, &y)) return error.GlobalExecutionInventoryMismatch;
        if (!std.mem.eql(u8, &self.digest, &seal(self.specs, self.roots))) return error.GlobalExecutionManifestChanged;
    }
    pub fn ram(self: *const Manifest) !A.memory.closed_ram.types.RamChallenges {
        try self.check(self.specs);
        var ch = T.P.Channel{};
        ch.mixU32s(&.{ 0x57474d52, 1, 14 });
        Old.digest(&ch, self.digest);
        var out: A.memory.closed_ram.types.RamChallenges = undefined;
        out.offset = ch.drawSecureFelt();
        for (&out.coefficients) |*c| c.* = ch.drawSecureFelt();
        return out;
    }
};
fn seal(specs: []const [32]u8, roots: []const Receipt) [32]u8 {
    var ch = T.P.Channel{};
    ch.mixU32s(&.{ 0x57474d46, 1 });
    ch.mixU64(specs.len);
    for (specs, roots) |s, r| {
        Old.digest(&ch, s);
        Old.digest(&ch, r.fixed.bytes);
        Old.digest(&ch, r.main.bytes);
    }
    return ch.digestBytes();
}
pub fn begin(ch: *T.P.Channel, setup: *const Setup, request: Old.Request, expected: Expected, ordinal: usize, first_step: u64) !void {
    return beginMaterials(ch, &setup.materials, request, expected, ordinal, first_step);
}
pub fn beginMaterials(ch: *T.P.Channel, materials: *const Materials, request: Old.Request, expected: Expected, ordinal: usize, first_step: u64) !void {
    ch.mixU32s(&.{ 0x52563634, 0x57474558, 1, 14, 33 });
    Old.digest(ch, expected.program_identity);
    ch.mixU64(expected.total_steps);
    ch.mixU64(expected.max_total_steps);
    ch.mixU64(expected.final_pc);
    for (expected.final_registers) |v| ch.mixU64(v);
    ch.mixU64(ordinal);
    ch.mixU64(first_step);
    try Old.mixMaterials(ch, materials, request, expected.admission.image_identity);
}

pub fn draw(ch: *T.P.Channel, manifest: *const Manifest, ordinal: usize) !Old.Draw {
    ch.mixU32s(&.{ 0x57475332, 1, @intCast(ordinal) });
    Old.digest(ch, manifest.digest);
    var out = Old.draw(ch);
    out.memory.ram = try manifest.ram();
    return out;
}
const Materials = @FieldType(Setup, "materials");
const Inventory = union(enum) {
    setups: []const *const Setup,
    materials: []const *const Materials,
    fn len(self: Inventory) usize {
        return switch (self) {
            .setups => |x| x.len,
            .materials => |x| x.len,
        };
    }
    fn at(self: Inventory, index: usize) *const Materials {
        return switch (self) {
            .setups => |x| &x[index].materials,
            .materials => |x| x[index],
        };
    }
};
/// Existing setup-based admission retains its exact checks, with no allocation.
pub fn validateRequests(setups: []const *const Setup, requests: []const Old.Request, expected: Expected) !void {
    return validateInventory(.{ .setups = setups }, requests, expected);
}
/// Concrete rootless caller supplies independently expected immutable owners.
pub fn validateMaterials(materials: []const *const Materials, requests: []const Old.Request, expected: Expected) !void {
    return validateInventory(.{ .materials = materials }, requests, expected);
}
fn validateInventory(inventory: Inventory, requests: []const Old.Request, expected: Expected) !void {
    if (inventory.len() == 0 or inventory.len() > 65535 or inventory.len() != requests.len or expected.total_steps == 0) return error.InvalidGlobalExecutionRoster;
    if (expected.max_total_steps == 0 or expected.total_steps > expected.max_total_steps) return error.GlobalExecutionBudgetExceeded;
    if (expected.admission.max_prefix_steps == 0 or expected.admission.max_prefix_steps >= 1 << 22) return error.InvalidExecutionBudget;
    var first: u64 = 0;
    var mass: u64 = 0;
    for (requests, 0..) |r, index| {
        const materials = inventory.at(index);
        try materials.geometry.validate();
        try r.cpu.validate(materials.geometry.cpu_log);
        if (r.cpu.steps > expected.admission.max_prefix_steps) return error.ExecutionPrefixBudgetExceeded;
        if (r.memory.ls_count > r.cpu.steps) return error.InvalidExecutionMemoryCount;
        if (r.epoch != index + 1 or r.memory.epoch != r.epoch) return error.InvalidGlobalExecutionEpoch;
        if (!std.mem.eql(u8, &materials.program.identity, &expected.program_identity)) return error.GlobalExecutionProgramMismatch;
        if (r.memory.ls_count >= @as(u32, 1) << @intCast(materials.geometry.ls_log) or r.memory.initial.len >= @as(usize, 1) << @intCast(materials.geometry.initialLog()) or r.memory.terminal.len >= @as(usize, 1) << @intCast(materials.geometry.terminalLog())) return error.GlobalMemoryCapacity;
        if (r.division_requests > @as(u32, 1) << @intCast(materials.geometry.division_log) or r.multiplication_requests > @as(u32, 1) << @intCast(materials.geometry.multiplication_log)) return error.GlobalArithmeticCapacity;
        if (index == 0) {
            if (r.cpu.initial_pc != expected.admission.initial_pc or !std.mem.eql(u64, &r.cpu.initial_registers, &expected.admission.initial_registers)) return error.UntrustedGlobalGenesis;
        } else {
            const p = requests[index - 1];
            if (r.cpu.initial_pc != p.cpu.final_pc or !std.mem.eql(u64, &r.cpu.initial_registers, &p.cpu.final_registers)) return error.GlobalCpuBoundaryMismatch;
            if (r.memory.initial.len != 0) return error.RepeatedGlobalInitialization;
        }
        if (index + 1 != requests.len and r.memory.terminal.len != 0) return error.PrematureGlobalTeardown;
        first = try std.math.add(u64, first, r.cpu.steps);
        mass = try std.math.add(u64, mass, 2 * @as(u64, r.memory.ls_count));
    }
    if (first != expected.total_steps or requests[requests.len - 1].cpu.final_pc != expected.final_pc or !std.mem.eql(u64, &requests[requests.len - 1].cpu.final_registers, &expected.final_registers)) return error.GlobalExecutionCoverageMismatch;
    const initial = requests[0].memory.initial;
    const terminal = requests[requests.len - 1].memory.terminal;
    if (initial.len != terminal.len) return error.GlobalTouchedSetMismatch;
    mass = try std.math.add(u64, mass, try std.math.add(u64, initial.len, terminal.len));
    if (mass >= core.fields.m31.Modulus) return error.GlobalRamCharacteristicBound;
    for (initial, terminal, 0..) |b, e, i| {
        if (b.address & 7 != 0 or (i != 0 and initial[i - 1].address >= b.address) or e.address != b.address) return error.GlobalTouchedSetMismatch;
        if (b.state.epoch != 0 or b.state.tick != 0 or b.state.value != try expected.admission.image.initialWord(b.address) or b.state.rights != try expected.admission.image.wordRights(b.address)) return error.UntrustedGlobalMemoryInitialization;
        if (e.state.rights != b.state.rights or e.state.epoch > requests.len) return error.InvalidGlobalMemoryTerminal;
    }
}
