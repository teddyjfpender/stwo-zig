const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const rv = A.frontend.rv64;
const R = A.R;
const a = std.testing.allocator;
test "authenticated execution joins CPU private RAM with exact compact storage proof parity" {
    const reference = try run(false);
    defer a.free(reference);
    const compact = try run(true);
    defer a.free(compact);
    try std.testing.expectEqualSlices(u8, reference, compact);
}
fn run(compact: bool) ![]u8 {
    const pc: u64 = 4096;
    const ptr: u64 = 8192;
    const program = [_]u32{ 0x0020b023, 0x0000b183 };
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = 8, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = ptr, .size = 512, .permissions = .{ .read = true, .write = true } });
    for (program, 0..) |raw, index| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try memory.initialize(pc + 4 * index, &bytes);
    }
    var cpu = rv.machine.Cpu.init(pc, 0);
    cpu.regs[1] = ptr;
    cpu.regs[2] = 17;
    const initial = cpu.regs;
    var records: [2]rv.machine.Retirement = undefined;
    var capture = try rv.boundary_capture.Capture.init(a, 0, 2, 100);
    defer capture.deinit();
    for (&records) |*record| {
        record.* = try cpu.step(&memory);
        try capture.append(record.*, &memory);
    }
    const captured = try capture.sorted(a);
    defer a.free(captured);
    var mappings = try R.policy.Policy.init(a, &.{ .{ .first = pc, .last = pc + 7, .flags = 5 }, .{ .first = ptr, .last = ptr + 511, .flags = 3 } });
    defer mappings.deinit();
    var openings = try R.openings.Owned.init(a, .chunk512, &mappings, &memory, captured);
    defer openings.deinit();
    var cache = try R.values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    var ram_trace = try R.private_trace.Trace.initOwned(a, &cache, &mappings, &openings);
    defer ram_trace.deinit();
    var clocks: [32]u32 = @splat(0);
    clocks[1] = 5;
    clocks[2] = 2;
    clocks[3] = 7;
    const cpu_public = A.CPU.Public{ .roster = .none, .state_policy = .cyclic_v2, .division_requests = 0, .keccak_calls = 0, .statement = .{ .program = .{ .base = pc, .words = &program }, .steps = 2, .initial_pc = pc, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .cells = &.{}, .register_clocks = clocks, .memory_clocks = &.{}, .opcodes = try A.rv.program.opcode_policy.derive(.{ .base = pc, .words = &program }, .keccak_service_v1) } };
    const public = A.Public{ .cpu = cpu_public, .geometry = .chunk512, .before = ram_trace.witness.before, .after = ram_trace.witness.after, .policy_identity = mappings.identity, .ram = A.RAM.Counts.fromTrace(&ram_trace) };
    var setup = try A.Prepared.init(a, public, &mappings);
    defer setup.deinit();
    const private_cells = [_]@import("../rv64_full_statement.zig").Cell{.{ .address = ptr, .initial = 0, .final = 17, .readable = true, .writable = true }};
    if (compact) {
        var key_public = public;
        key_public.ram = .{ .hashes = 5, .common_chunks = 3, .edge_chunks = 0, .nodes = 55, .sides = 0, .edge_permits = 0 };
        var key = try A.Prepared.init(a, key_public, &mappings);
        defer key.deinit();
        key_public.ram.?.hashes = 6;
        try key.validate(key_public);
        var other = try A.Prepared.init(a, key_public, &mappings);
        defer other.deinit();
        try std.testing.expectEqualSlices(u8, &key.root, &other.root);
    }
    var full = try A.Full.Trace.initWithPrivateBoundary(a, &records, .{}, public.cpu.statement, .{ .cells = &private_cells, .memory_clocks = &.{8} }, &setup.cpu.base.program, &setup.cpu.base.plan);
    var full_owned = true;
    defer if (full_owned) full.deinit();
    var trace = try A.CPU.Trace.fromCpu(a, full, public.cpu, &setup.cpu);
    full_owned = false;
    defer trace.deinit();
    var bundle = if (compact) try A.proveTrace(a, &setup, public, &trace, A.RAM.Source.fromTrace(&ram_trace)) else try @import("../rv64_authenticated_prover.zig").proveReference(a, &setup, public, &trace, A.RAM.Source.fromTrace(&ram_trace));
    defer bundle.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), ram_trace.main_backing.len);
    try std.testing.expectEqual(R.private_trace.Phase.retired, ram_trace.phase);
    // Receiver reconstruction starts from expected program/policy and domains.
    var receiver = try A.Prepared.init(a, public, &mappings);
    defer receiver.deinit();
    const wire = @import("stwo_proof_wire");
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    errdefer a.free(encoded);
    try receiver.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var false_public = public;
    false_public.after[0] ^= 1;
    try std.testing.expectError(error.UnbalancedPrivateRamGraph, receiver.verifyOwned(a, false_public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
    if (compact) {
        var bad = bundle.claims;
        bad.ram.?.bytes = A.Q.one();
        try std.testing.expectError(error.InvalidAuthenticatedRamClaims, receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded)));
        bad = bundle.claims;
        // These forged state claims still balance the host global sum. Their
        // physical CPU/CellTable prefixes must nevertheless authenticate them.
        bad.cpu.cpu.state = bad.cpu.cpu.state.add(A.Q.one());
        bad.ram.?.callers.tables[@intFromEnum(R.private_trace.Table.common_cells)][R.cell_air.STATE_SUM] = bad.ram.?.callers.tables[@intFromEnum(R.private_trace.Table.common_cells)][R.cell_air.STATE_SUM].sub(A.Q.one());
        if (receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.AcceptedBalancedFalseStateClaims else |_| {}
        bad = bundle.claims;
        bad.ram.?.provider[1] = bad.ram.?.provider[1].add(A.Q.one());
        bad.ram.?.callers.tables[@intFromEnum(R.private_trace.Table.chunk)][0] = bad.ram.?.callers.tables[@intFromEnum(R.private_trace.Table.chunk)][0].sub(A.Q.one());
        if (receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.AcceptedBalancedFalseHashClaims else |_| {}
        var downgrade = try wire.decodeProofBytesBinary(a, encoded);
        downgrade.commitment_scheme_proof.config.pow_bits = 25;
        try std.testing.expectError(error.InvalidAuthenticatedExecutionConfig, receiver.verifyOwned(a, public, bundle.claims, downgrade));
        var wrong_policy = public;
        wrong_policy.policy_identity[0] ^= 1;
        try std.testing.expectError(error.InvalidAuthenticatedExecutionStatement, receiver.verifyOwned(a, wrong_policy, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
        var missing = public;
        missing.ram = null;
        missing.after = missing.before;
        try std.testing.expectError(error.InvalidAuthenticatedRamRoster, receiver.verifyOwned(a, missing, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
    }
    return encoded;
}

test "authenticated execution omits RAM only for unchanged roots and closed CPU obligations" {
    const pc: u64 = 4096;
    const program = [_]u32{0x01100093}; // addi x1,x0,17
    var memory = rv.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = pc, .size = 4, .permissions = .{ .read = true, .execute = true } });
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, program[0], .little);
    try memory.initialize(pc, &raw);
    var cpu = rv.machine.Cpu.init(pc, 0);
    const initial = cpu.regs;
    const record = try cpu.step(&memory);
    var mappings = try R.policy.Policy.init(a, &.{.{ .first = pc, .last = pc + 7, .flags = 5 }});
    defer mappings.deinit();
    var clocks: [32]u32 = @splat(0);
    clocks[1] = 3;
    const public = A.Public{ .cpu = .{ .roster = .none, .state_policy = .cyclic_v2, .division_requests = 0, .keccak_calls = 0, .statement = .{ .program = .{ .base = pc, .words = &program }, .steps = 1, .initial_pc = pc, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .cells = &.{}, .register_clocks = clocks, .memory_clocks = &.{}, .opcodes = try A.rv.program.opcode_policy.derive(.{ .base = pc, .words = &program }, .keccak_service_v1) } }, .geometry = .chunk512, .before = @splat(0), .after = @splat(0), .policy_identity = mappings.identity, .ram = null };
    var setup = try A.Prepared.init(a, public, &mappings);
    defer setup.deinit();
    var full = try A.Full.Trace.initWithPrivateBoundary(a, &.{record}, .{}, public.cpu.statement, .{ .cells = &.{}, .memory_clocks = &.{} }, &setup.cpu.base.program, &setup.cpu.base.plan);
    var owns = true;
    defer if (owns) full.deinit();
    var trace = try A.CPU.Trace.fromCpu(a, full, public.cpu, &setup.cpu);
    owns = false;
    defer trace.deinit();
    var bundle = try A.proveTrace(a, &setup, public, &trace, null);
    defer bundle.deinit(a);
    const wire = @import("stwo_proof_wire");
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    try setup.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var changed = public;
    changed.after[0] = 1;
    try std.testing.expectError(error.UnchangedRamRootRequired, changed.validate(&mappings));
}

test "authenticated Ethereum all27 one-arena proof bytes match owned sources in both control encodings" {
    for ([_]rv.execution_profile.Profile{ .ethereum_services_v1, .ethereum_services_v2 }) |profile| {
        for ([_]A.rv.control_policy.Policy{ .bytes_v1, .limbs24_v2 }) |control| {
            const owned = try ethereum(profile, false, control, .{});
            defer a.free(owned);
            const borrowed = try ethereum(profile, true, control, .{});
            defer a.free(borrowed);
            try std.testing.expectEqualSlices(u8, owned, borrowed);
        }
    }
}
const Stage = @import("stwo_prover_engine").stage_profile;
const EthereumOptions = struct { state_policy: A.rv.state_policy.Policy = .cyclic_v2, recorder: ?*Stage.Recorder = null };
fn ethereum(profile: rv.execution_profile.Profile, borrowed: bool, control: A.rv.control_policy.Policy, options: EthereumOptions) ![]u8 {
    const Fixture = @import("rv64_ethereum_fixture.zig");
    const fixture = try Fixture.Fixture.create(a, profile);
    defer fixture.deinit();
    // Independently initialize the expected input image from fixture inputs;
    // no final image, captured hash, or producer root establishes this authority.
    var initial_memory = rv.memory.Memory.init(a, .{});
    defer initial_memory.deinit();
    try initial_memory.map(.{ .start = Fixture.pc, .size = Fixture.program.len * 4, .permissions = .{ .read = true, .execute = true } });
    try initial_memory.map(.{ .start = Fixture.pointer, .size = 512, .permissions = .{ .read = true, .write = true } });
    for (Fixture.program, 0..) |raw, index| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, raw, .little);
        try initial_memory.initialize(Fixture.pc + 4 * index, &bytes);
    }
    for (fixture.initial_words, 0..) |value, index| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try initial_memory.initialize(Fixture.pointer + 8 * index, &bytes);
    }
    var cache = try R.values.Cache.fromMemory(a, .chunk512, &initial_memory);
    defer cache.deinit();
    const expected_before = cache.root();
    var mappings = try R.policy.Policy.init(a, &.{ .{ .first = Fixture.pc, .last = Fixture.pc + 4 * Fixture.program.len - 1, .flags = 5 }, .{ .first = Fixture.pointer, .last = Fixture.pointer + 511, .flags = 3 } });
    defer mappings.deinit();
    var openings = try R.openings.Owned.init(a, .chunk512, &mappings, &fixture.memory, fixture.captured);
    defer openings.deinit();
    var preparation = try R.private_trace.Preparation.init(a, .chunk512, &mappings, openings.chunks);
    defer preparation.deinit();
    var authority = try A.Full.ProgramAuthority.initWithControl(a, fixture.public.statement.program, profile, control);
    defer authority.deinit();
    var cpu_public = fixture.public;
    cpu_public.control_policy = control;
    cpu_public.state_policy = options.state_policy;
    cpu_public.statement.program = authority.expectedProgram();
    cpu_public.statement.cells = &.{};
    cpu_public.statement.memory_clocks = &.{};
    const layout = A.Layout{ .cpu = cpu_public, .geometry = .chunk512, .policy_identity = mappings.identity, .ram = A.RAM.Counts.fromShapes(preparation.shapes) };
    var setup = try A.Prepared.initForLayout(a, layout, &mappings, &authority);
    defer setup.deinit();
    const Main = @import("../rv64_authenticated_main_arena.zig").MainArena;
    var arena: ?Main = if (borrowed) try Main.initForLayout(a, &setup, layout) else null;
    defer if (arena) |*value| value.deinit();
    var ram_trace = if (arena) |*value| try R.private_trace.Trace.initPreparedBorrowedOwned(a, &cache, &preparation, &openings, try value.ramBuffers()) else try R.private_trace.Trace.initOwned(a, &cache, &mappings, &openings);
    defer ram_trace.deinit();
    try std.testing.expectEqualSlices(u32, &expected_before, &ram_trace.witness.before);
    var expected_after = try R.values.Cache.fromMemory(a, .chunk512, &fixture.memory);
    defer expected_after.deinit();
    try std.testing.expectEqualSlices(u32, &expected_after.root(), &ram_trace.witness.after);
    const public = A.Public{ .cpu = cpu_public, .geometry = .chunk512, .before = expected_before, .after = ram_trace.witness.after, .policy_identity = mappings.identity, .ram = layout.ram };
    var tape: ?rv.compact_tape.Tape = if (borrowed) try fixtureTape(fixture, profile) else null;
    defer if (tape) |*value| value.deinit();
    const boundary = A.Full.Trace.PrivateBoundary{ .cells = fixture.public.statement.cells, .memory_clocks = fixture.public.statement.memory_clocks };
    var full = if (arena) |*value| try A.Full.Trace.initWithPrivateTapeBorrowedMain(a, &tape.?, cpu_public.first_call_id, cpu_public.secp.firstIds(), cpu_public.statement, boundary, &setup.cpu.base.program, &setup.cpu.base.plan, try value.cpuMain()) else try A.Full.Trace.initWithPrivateBoundary(a, &fixture.records, .{ .keccak = &fixture.kcalls, .secp = &fixture.scalls }, cpu_public.statement, boundary, &setup.cpu.base.program, &setup.cpu.base.plan);
    var owns = true;
    defer if (owns) full.deinit();
    var trace = if (arena) |*value| try A.CPU.Trace.fromCpuBorrowed(a, full, cpu_public, &setup.cpu, try value.coreBuffers()) else try A.CPU.Trace.fromCpu(a, full, cpu_public, &setup.cpu);
    owns = false;
    defer trace.deinit();
    var bundle = if (arena) |*value| try A.proveArena(a, &setup, public, &trace, A.RAM.Source.fromTrace(&ram_trace), value, options.recorder) else if (options.recorder) |recorder| try A.proveProfiled(a, &setup, public, &trace, A.RAM.Source.fromTrace(&ram_trace), recorder) else try A.proveTrace(a, &setup, public, &trace, A.RAM.Source.fromTrace(&ram_trace));
    defer bundle.deinit(a);
    const wire = @import("stwo_proof_wire");
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    errdefer a.free(encoded);
    var receiver_authority = try A.Full.ProgramAuthority.initWithControl(a, fixture.public.statement.program, profile, control);
    defer receiver_authority.deinit();
    var receiver = try A.Prepared.initWithAuthority(a, public, &mappings, &receiver_authority);
    defer receiver.deinit();
    try receiver.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    var downgraded = public;
    downgraded.cpu.control_policy = if (control == .bytes_v1) .limbs24_v2 else .bytes_v1;
    try std.testing.expectError(error.InvalidRv64ServiceSetup, receiver.validate(downgraded));
    const receipt = @import("../rv64_ethereum_batch_receipt.zig").Receipt.create(0, 0, downgraded, bundle.claims, encoded);
    try std.testing.expectError(error.InvalidEthereumBatchReceipt, receipt.bound(&receiver_authority));

    var wrong_state = public;
    wrong_state.cpu.state_policy = if (options.state_policy == .cyclic_v2) .cyclic_canonical_v3 else .cyclic_v2;
    try std.testing.expectError(error.InvalidRv64ServiceSetup, receiver.validate(wrong_state));
    try std.testing.expectError(error.InvalidRv64ServiceSetup, receiver.verifyOwned(a, wrong_state, bundle.claims, try wire.decodeProofBytesBinary(a, encoded)));
    // Even a fresh setup selected for the other representation cannot verify
    // this proof: public transcript/schema and physical BYTE prefixes differ.
    var other_state = try A.Prepared.initWithAuthority(a, wrong_state, &mappings, &receiver_authority);
    defer other_state.deinit();
    if (other_state.verifyOwned(a, wrong_state, bundle.claims, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.AcceptedStatePolicyDowngrade else |_| {}

    try std.testing.expectEqual(@as(usize, 0), trace.cpu.main.len);
    try std.testing.expectEqual(@as(usize, 0), ram_trace.main_backing.len);
    try std.testing.expectEqual(R.private_trace.Phase.retired, ram_trace.phase);
    var bad = bundle.claims;
    bad.cpu.secp_header = bad.cpu.secp_header.add(A.Q.one());
    bad.cpu.secp_add.bridge = bad.cpu.secp_add.bridge.sub(A.Q.one());
    if (receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.AcceptedBalancedFalseSecpClaims else |_| {}
    bad = bundle.claims;
    bad.cpu.cpu.state = bad.cpu.cpu.state.add(A.Q.one());
    bad.ram.?.callers.tables[@intFromEnum(R.private_trace.Table.common_cells)][R.cell_air.STATE_SUM] = bad.ram.?.callers.tables[@intFromEnum(R.private_trace.Table.common_cells)][R.cell_air.STATE_SUM].sub(A.Q.one());
    if (receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.AcceptedBalancedFalseStateClaims else |_| {}
    bad = bundle.claims;
    bad.ram.?.provider[1] = bad.ram.?.provider[1].add(A.Q.one());
    bad.ram.?.callers.tables[@intFromEnum(R.private_trace.Table.chunk)][0] = bad.ram.?.callers.tables[@intFromEnum(R.private_trace.Table.chunk)][0].sub(A.Q.one());
    if (receiver.verifyOwned(a, public, bad, try wire.decodeProofBytesBinary(a, encoded))) |_| return error.AcceptedBalancedFalseHashClaims else |_| {}
    return encoded;
}

fn fixtureTape(fixture: *const @import("rv64_ethereum_fixture.zig").Fixture, profile: rv.execution_profile.Profile) !rv.compact_tape.Tape {
    var tape = try rv.compact_tape.Tape.init(a, fixture.records.len, fixture.public.statement.initial_pc, 1 << 40, profile);
    errdefer tape.deinit();
    var ki: usize = 0;
    var si: usize = 0;
    for (fixture.records) |record| {
        if (record.opcode == .ECALL) {
            if (record.rhs.toInt() == rv.execution_profile.KECCAK_TAG) {
                var call = fixture.kcalls[ki];
                call.clock += tape.initial_clock;
                try tape.appendService(call);
                ki += 1;
            } else {
                var call = fixture.scalls[si];
                call.clock += tape.initial_clock;
                try tape.appendSecp(call);
                si += 1;
            }
        } else {
            var row = record;
            row.clock += tape.initial_clock;
            try tape.append(row);
        }
    }
    return tape;
}

test "canonical state v3 all27 strong proofs preserve owned arena parity across both ABIs and controls" {
    for ([_]rv.execution_profile.Profile{ .ethereum_services_v1, .ethereum_services_v2 }) |profile| {
        for ([_]A.rv.control_policy.Policy{ .bytes_v1, .limbs24_v2 }) |control| {
            const owned = try ethereum(profile, false, control, .{ .state_policy = .cyclic_canonical_v3 });
            defer a.free(owned);
            const borrowed = try ethereum(profile, true, control, .{ .state_policy = .cyclic_canonical_v3 });
            defer a.free(borrowed);
            try std.testing.expectEqualSlices(u8, owned, borrowed);
        }
    }
}

// Private component timers must be root siblings, never children of a concurrently
// running component or of an unrelated PCS task. These counts cover all11 timed
// components in the all27 roster, four cosets and two leaf scopes per component.
fn privateIndex(id: []const u8) ?usize {
    for ([_][]const u8{ "cpu_coset_fft", "cpu_constraint_rows", "keccak_coset_fft", "keccak_constraint_rows", "keccak_bridge_fft", "keccak_bridge_rows", "secp_coset_fft", "secp_constraint_rows", "secp_bridge_fft", "secp_bridge_rows" }, 0..) |name, i| if (std.mem.eql(u8, id, name)) return i;
    return null;
}
fn auditChildren(nodes: []const Stage.StageNode) !void {
    for (nodes) |node| {
        try std.testing.expect(privateIndex(node.id) == null);
        try std.testing.expect(std.math.isFinite(node.seconds) and node.seconds >= 0);
        if (node.children) |children| try auditChildren(children);
    }
}
fn auditProfile(recorder: *Stage.Recorder) !void {
    try std.testing.expectEqual(@as(usize, 0), recorder.stack.items.len);
    var snapshot = try recorder.snapshot(a);
    defer snapshot.deinit(a);
    var counts: [10]usize = @splat(0);
    for (snapshot.stages) |node| {
        try std.testing.expect(std.math.isFinite(node.seconds) and node.seconds >= 0);
        if (privateIndex(node.id)) |i| counts[i] += 1;
        if (node.children) |children| try auditChildren(children);
    }
    try std.testing.expectEqualSlices(usize, &.{ 4, 4, 12, 12, 4, 4, 16, 16, 8, 8 }, &counts);
}

test "all27 private component recording is complete with identical proofs under scoped pools" {
    const work = @import("stwo_prover_engine").work_pool;
    for ([_]A.rv.control_policy.Policy{ .bytes_v1, .limbs24_v2 }) |control| {
        const reference = blk: {
            var untiled = A.rv.full.parallel.testing.GatherBinding.init(false);
            defer untiled.deinit();
            break :blk try ethereum(.ethereum_services_v2, true, control, .{});
        };
        defer a.free(reference);
        for ([_]usize{ 3, 8, 16 }) |workers| {
            var pool: work.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = A.rv.full.parallel.MIN_STACK_BYTES, .backing_allocator = a });
            defer pool.deinit();
            var binding = try work.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            var recorder = Stage.Recorder.init(a, "ReleaseSafe", "authenticated-private-recorders");
            defer recorder.deinit();
            const recorded = try ethereum(.ethereum_services_v2, true, control, .{ .recorder = &recorder });
            defer a.free(recorded);
            try std.testing.expectEqualSlices(u8, reference, recorded);
            try auditProfile(&recorder);
        }
    }
}

test "private component recording adoption failure retains partial owner custody and drains stacks" {
    var fail = std.testing.FailingAllocator.init(a, .{});
    {
        var parent = Stage.Recorder.init(fail.allocator(), "ReleaseSafe", "joined-failure");
        defer parent.deinit();
        var group = @import("../rv64_component_profiles.zig").Group.init(&parent);
        defer group.deinit();
        var child = try Stage.StageScope.begin(group.next(), "cpu_constraint_rows", "CPU");
        child.end();
        const second = group.next();
        for (0..64) |_| {
            var next = try Stage.StageScope.begin(second, "secp_constraint_rows", "Secp");
            next.end();
        }
        // First adoption succeeds, the second must grow beyond its capacity.
        fail.fail_index = fail.alloc_index + 1;
        try std.testing.expectError(error.OutOfMemory, group.join());
        try std.testing.expectEqual(@as(usize, 1), parent.roots.items.len);
        try std.testing.expectEqual(@as(usize, 0), group.children[0].roots.items.len);
        try std.testing.expectEqual(@as(usize, 64), group.children[1].roots.items.len);
        for (group.children[0..group.used]) |*owner| try std.testing.expectEqual(@as(usize, 0), owner.stack.items.len);
        fail.fail_index = std.math.maxInt(usize);
        try group.join();
        try std.testing.expectEqual(@as(usize, 65), parent.roots.items.len);
        for (group.children[0..group.used]) |*owner| try std.testing.expectEqual(@as(usize, 0), owner.roots.items.len);
    }
    try std.testing.expectEqual(fail.allocated_bytes, fail.freed_bytes);
}
