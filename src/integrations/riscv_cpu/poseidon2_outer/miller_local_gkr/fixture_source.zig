//! Test-only fresh source authority for the fully pinned one-ECALL toy image.
//! No proof bytes, captured verifier object or proposed verifying key is read.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Runtime = @import("../pure_p2_op_runtime.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Prepared = @import("../../word16_execution/prepared.zig").Prepared;
const Driver = @import("../../word16_execution/driver.zig");
const Cell = @import("../../word16_execution/memory/statement.zig").Cell;
const Collector = @import("../../word16_global_execution/services/collector.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Wire = @import("../../word16_global_execution/services/wire.zig");
const Bounds = @import("../../word16_global_execution/services/gkr_local/source_bounds.zig");
const Plan = @import("../../word16_global_execution/ethereum/plan.zig");
const Receiver = @import("../../word16_global_execution/ethereum/receiver.zig");
const Terminal = @import("../../word16_global_execution/ethereum/terminal.zig");
const Inventory = @import("../pure_p2_op_inventory.zig");
const Key = @import("../pure_p2_fixed_key.zig").Key;
const ML = @import("worker.zig");
const Toy = @import("fixture_image.zig");
const Suite = @import("../pure_p2_source_suite.zig").Suite;
const PROFILE = @import("../pure_p2_worker_protocol.zig").Profile.op_target_b4_q72_p0_fold4_v1;
pub const SUITE = Suite{ .truth = .classic, .miller = .local_gkr };
const SPAN = T.OpTowerSpan{ .calls = 1, .first_id = 1 };
const MILLER = Bounds.OpTowerTruthDeclaration{ .calls = 1, .first_id = 1, .frontier_log = 8, .arithmetic_log = 15 };

const Canonical = struct {
    program: Program,
    native: Prepared,
    tape: front.rv64.compact_tape.Tape,
    advice: Collector.Advice,
    declaration: Wire.CpuDeclaration,
    request: Wire.CompactRequest,
    fn init(a: std.mem.Allocator, image: *const Image.Owner) !Canonical {
        var program = try Program.initWithAuthority(a, &image.authority);
        errdefer program.deinit();
        try program.makeCompact();
        var tape = try front.rv64.compact_tape.Tape.init(a, 1, Toy.PC, 0, .ethereum_services_op_v1);
        errdefer tape.deinit();
        const before = Toy.beforeWords();
        const after = try A.crypto.bn254_tower.execution.execute(&before);
        try tape.appendTower(&.{ .call_id = 1, .clock = 1, .pc = Toy.PC, .pointer = Toy.ADDRESS, .before = before, .output = after[0..A.crypto.bn254_tower.execution.WRITTEN_WORDS].* });
        var boundary = A.word16_execution.types.Boundary{ .steps = 1, .initial_pc = Toy.PC, .final_pc = Toy.TERMINAL_PC, .initial_registers = Toy.registers(), .final_registers = Toy.registers(), .register_clocks = @splat(0) };
        boundary.register_clocks[10] = 1;
        boundary.register_clocks[17] = 2;
        var native = try Prepared.captureForOpServices(a, &program, boundary, 1, 5, &tape, .{});
        errdefer native.deinit();
        var advice = try Collector.collect(a, &.{&native}, &.{&tape}, Driver.admission(image).image);
        errdefer advice.deinit();
        var declaration = try Plan.cpuForSegment(&native, &advice, 0, 1, advice.initial.len, Plan.CpuLayout.forOpGkr());
        declaration.bridges.tower = 5;
        const request = Wire.CompactRequest.from(try Coordinator.requestView(&.{&native}, &advice, 0));
        return .{ .program = program, .native = native, .tape = tape, .advice = advice, .declaration = declaration, .request = request };
    }
    fn deinit(self: *Canonical) void {
        self.advice.deinit();
        self.native.deinit();
        self.tape.deinit();
        self.program.deinit();
    }
};

pub const Owner = struct {
    allocator: std.mem.Allocator,
    image: *Image.Owner,
    setup: *R.CpuSetup,
    key: *Key,
    miller_key: *ML.Key,
    inventory: Inventory.Inventory,
    initial: []Cell,
    terminal: []Cell,
    requests: [1]P.Request,
    cpu_declarations: [1]Wire.CpuDeclaration,
    compact_requests: [1]Wire.CompactRequest,
    spans: [1]T.OpTowerSpan = .{SPAN},
    miller_declarations: [1]Bounds.OpTowerTruthDeclaration = .{MILLER},
    setups: [1]*const R.CpuSetup,
    keys: [1]*const Key,
    miller: [1]Inventory.MillerDeclaration,
    expected: P.Expected,
    output: [43]u8,

    pub fn init(a: std.mem.Allocator, metadata: Runtime.Metadata, initial: []const Cell, terminal: []const Cell) !Owner {
        if (!@import("builtin").is_test) return error.OpMillerSourceFixtureOnly;
        // The supported source shape is derived below, never selected by the
        // incoming geometry. Reject broad requests before keys or captures.
        if (metadata.schema != 3 or metadata.profile != PROFILE or metadata.cpus.len != 1 or metadata.requests.len != 1 or metadata.spans.len != 1 or metadata.truths.len != 0 or metadata.miller.len != 1 or metadata.memory_words != 80 or initial.len != 80 or terminal.len != 80 or !std.meta.eql(metadata.spans[0], SPAN) or !std.meta.eql(metadata.miller[0], MILLER)) return error.OpMillerFixtureSourcePolicy;
        const image = try a.create(Image.Owner);
        errdefer a.destroy(image);
        image.* = try Toy.init(a);
        errdefer image.deinit();
        var canonical = try Canonical.init(a, image);
        defer canonical.deinit();
        if (!std.meta.eql(metadata.cpus[0], canonical.declaration) or !std.meta.eql(metadata.requests[0], canonical.request)) return error.OpMillerFixtureSourcePolicy;
        for (initial, canonical.advice.initial, terminal, canonical.advice.terminal) |got_i, expected_i, got_t, expected_t| {
            if (!std.meta.eql(got_i, expected_i) or !std.meta.eql(got_t, expected_t)) return error.OpMillerFixtureCellPolicy;
        }
        const initial_copy = try a.dupe(Cell, initial);
        errdefer a.free(initial_copy);
        const terminal_copy = try a.dupe(Cell, terminal);
        errdefer a.free(terminal_copy);
        const requests = [1]P.Request{canonical.request.expand(initial_copy, terminal_copy)};
        const setup = try a.create(R.CpuSetup);
        errdefer a.destroy(setup);
        setup.* = try R.CpuSetup.initForOpProgram(a, .{ .base = Toy.PC, .words = &Toy.WORDS }, canonical.declaration.geometry, canonical.declaration.bridges);
        errdefer setup.deinit();
        const key = try a.create(Key);
        errdefer a.destroy(key);
        key.* = try Key.initForOp(a, setup, PROFILE);
        errdefer key.deinit();
        const miller_key = try a.create(ML.Key);
        errdefer a.destroy(miller_key);
        miller_key.* = try ML.Key.init(a, PROFILE, MILLER.frontier_log, MILLER.arithmetic_log);
        errdefer miller_key.deinit();
        const expected = try Receiver.expectedFromRequests(image, canonical.program.identity, &requests, 1, 1, true);
        const declarations = [1]Inventory.MillerDeclaration{.{ .key = &miller_key.base, .local_key = miller_key, .span = .{ .calls = SPAN.calls, .first_id = SPAN.first_id } }};
        var inventory = try Inventory.Inventory.initForSourceSuite(a, PROFILE, &.{setup}, &requests, &.{SPAN}, &.{key}, &.{}, &.{}, &declarations, expected, &.{}, SUITE);
        errdefer inventory.deinit();
        const output = try Terminal.require(image, requests[0].base.cpu, terminal_copy);
        if (!std.mem.eql(u8, &output, &image.expected_output)) return error.OpMillerFixtureOutputPolicy;
        return .{ .allocator = a, .image = image, .setup = setup, .key = key, .miller_key = miller_key, .inventory = inventory, .initial = initial_copy, .terminal = terminal_copy, .requests = requests, .cpu_declarations = .{canonical.declaration}, .compact_requests = .{canonical.request}, .setups = .{setup}, .keys = .{key}, .miller = declarations, .expected = expected, .output = output };
    }
    /// All slices remain borrowed until this owner is destroyed. Arrays are
    /// rebound here after moves, and source image/key objects have stable homes.
    pub fn view(self: *const Owner) Runtime.SourceDirectory {
        return .{ .source_suite = SUITE, .source_security = self.inventory.source_security, .image = self.image, .metadata = .{ .schema = 3, .profile = PROFILE, .cpus = &self.cpu_declarations, .requests = &self.compact_requests, .spans = &self.spans, .truths = &.{}, .miller = &self.miller_declarations, .memory_words = 80 }, .requests = &self.requests, .setups = &self.setups, .cpu_keys = &self.keys, .truths = &.{}, .truth_keys = &.{}, .miller = &self.miller, .inventory = &self.inventory, .expected = self.expected, .output = self.output, .output_address = self.image.symbols.output_data, .initial = self.initial, .terminal = self.terminal, .image_ns = 0, .program_ns = 0 };
    }
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        self.inventory.deinit();
        self.miller_key.deinit();
        a.destroy(self.miller_key);
        self.key.deinit();
        a.destroy(self.key);
        self.setup.deinit();
        a.destroy(self.setup);
        self.image.deinit();
        a.destroy(self.image);
        a.free(self.initial);
        a.free(self.terminal);
        self.* = undefined;
    }
};

test "Miller fixture fresh source rejects self-authorized geometry and owns request cells" {
    const a = std.testing.allocator;
    var image = try Toy.init(a);
    defer image.deinit();
    var canonical = try Canonical.init(a, &image);
    defer canonical.deinit();
    const cpus = [_]Wire.CpuDeclaration{canonical.declaration};
    const requests = [_]Wire.CompactRequest{canonical.request};
    var metadata = Runtime.Metadata{ .schema = 3, .profile = PROFILE, .cpus = &cpus, .requests = &requests, .spans = &.{SPAN}, .truths = &.{}, .miller = &.{MILLER}, .memory_words = 80 };
    var owner = try Owner.init(a, metadata, canonical.advice.initial, canonical.advice.terminal);
    defer owner.deinit();
    const view = owner.view();
    try std.testing.expect(view.source_security != null and !view.source_security.?.security_qualified);
    try std.testing.expect(view.initial.ptr != canonical.advice.initial.ptr);
    try std.testing.expectEqualSlices(u8, &view.output, &image.expected_output);
    var wrong_cpus = cpus;
    wrong_cpus[0].geometry.cpu_log += 1;
    metadata.cpus = &wrong_cpus;
    try std.testing.expectError(error.OpMillerFixtureSourcePolicy, Owner.init(a, metadata, canonical.advice.initial, canonical.advice.terminal));
    metadata.cpus = &cpus;
    const old = canonical.advice.terminal[0].state.value;
    canonical.advice.terminal[0].state.value ^= 1;
    try std.testing.expectError(error.OpMillerFixtureCellPolicy, Owner.init(a, metadata, canonical.advice.initial, canonical.advice.terminal));
    canonical.advice.terminal[0].state.value = old;
    try std.testing.expectEqual(old, view.terminal[0].state.value);
    metadata.schema = 2;
    try std.testing.expectError(error.OpMillerFixtureSourcePolicy, Owner.init(std.testing.failing_allocator, metadata, &.{}, &.{}));
}
