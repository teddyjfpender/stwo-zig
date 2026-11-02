const std = @import("std");
const front = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const P = @import("program.zig");
const Metadata = P.Metadata;
const Cache = Metadata.Cache;
const Program = P.Program;
const Full = @import("../rv64_full.zig");
const Setup = @import("setup.zig");
const E = @import("execution.zig");
const a = std.testing.allocator;
const words = [_]u32{ 0x00700093, 0x0010c133 };
fn authority(allocator: std.mem.Allocator) !Full.ProgramAuthority {
    return Full.ProgramAuthority.init(allocator, .{ .base = 4096, .words = &words }, .ethereum_services_v2);
}
fn same(left: *const Program, right: *const Program) !void {
    try std.testing.expectEqual(left.identity, right.identity);
    try std.testing.expectEqualDeep(left.metadataView(), right.metadataView());
    try std.testing.expectEqualSlices(core.fields.m31.M31, left.fixed, right.fixed);
}
test "Program metadata prelookup shares owned arrays but current raw authority views" {
    var expected = try authority(a);
    defer expected.deinit();
    var another = try authority(a);
    defer another.deinit();
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var normal = try Program.initWithAuthority(a, &expected);
    defer normal.deinit();
    var first = try Program.initWithAuthorityAndMetadataCache(a, &expected, &cache);
    defer first.deinit();
    var second = try Program.initWithAuthorityAndMetadataCache(a, &another, &cache);
    defer second.deinit();
    try same(&normal, &first);
    try same(&normal, &second);
    try std.testing.expectEqual(first.entries.ptr, second.entries.ptr);
    try std.testing.expectEqual(first.word_rows.ptr, second.word_rows.ptr);
    try std.testing.expectEqual(another.words.ptr, second.words.ptr);
    try std.testing.expectEqual(another.program.addresses.ptr, second.addresses.ptr);
    try std.testing.expect(first.words.ptr != second.words.ptr);
    const stats = cache.snapshot();
    try std.testing.expectEqual(@as(usize, 1), stats.programs);
    try std.testing.expectEqual(@as(u64, 1), stats.hits);
    try std.testing.expectEqual(@as(u64, stats.payload_bytes), stats.metadata_bytes_not_rebuilt);
    try std.testing.expect(stats.retained_bytes <= stats.limit_bytes);
    const allocations = try cache.ownedAllocations(a);
    defer a.free(allocations);
    var accounted: usize = 0;
    for (allocations) |value| accounted += value.bytes;
    try std.testing.expectEqual(stats.retained_bytes, accounted);
}
test "Program metadata outlives original image and cache manager without retaining raw pointers" {
    var cache = try Cache.init(a, 1024 * 1024);
    var original = try authority(a);
    var first = try Program.initWithAuthorityAndMetadataCache(a, &original, &cache);
    const entries = first.entries.ptr;
    first.deinit();
    original.deinit();
    var current = try authority(a);
    defer current.deinit();
    var second = try Program.initWithAuthorityAndMetadataCache(a, &current, &cache);
    defer second.deinit();
    cache.deinit();
    try std.testing.expectEqual(entries, second.entries.ptr);
    try std.testing.expectEqual(current.words.ptr, second.words.ptr);
    try std.testing.expectEqual(@as(usize, 1), try second.lookup(4100));
    try std.testing.expectEqual(@as(u64, 4104), second.entries[1].staticNext(false));
}
test "Program metadata exact full64 sparse raw profile and branch map identity" {
    const sparse_words = [_]u32{ 0x00000463, 0xffffffff, 0x00008067 };
    const addresses = [_]u64{ 0x1_0000_1000, 0xffff_ffff_ffff_fff8, 0xffff_ffff_ffff_fffc };
    var expected = try Full.ProgramAuthority.init(a, .{ .base = addresses[0], .words = &sparse_words, .addresses = &addresses }, .ethereum_services_v2);
    defer expected.deinit();
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var first = try Program.initWithAuthorityAndMetadataCache(a, &expected, &cache);
    defer first.deinit();
    var second = try Program.initWithAuthorityAndMetadataCache(a, &expected, &cache);
    defer second.deinit();
    try same(&first, &second);
    try std.testing.expectEqual(@as(usize, 2), try second.lookup(addresses[2]));
    try std.testing.expectError(error.InvalidExecutionProgramWord, second.lookup(addresses[1]));
    try std.testing.expectError(error.UnknownExecutionPc, second.lookup(4096));
    for (0..second.size()) |i| try std.testing.expectEqualDeep(try first.tupleAt(i), try second.tupleAt(i));
    var changed_addresses = addresses;
    changed_addresses[0] += 4;
    try std.testing.expect((try cache.lookup(.{ .words = &sparse_words, .addresses = &changed_addresses, .profile = expected.profile })) == null);
    var changed_words = sparse_words;
    changed_words[2] ^= 1 << 20;
    try std.testing.expect((try cache.lookup(.{ .words = &changed_words, .addresses = &addresses, .profile = expected.profile })) == null);
    try std.testing.expect((try cache.lookup(.{ .words = &sparse_words, .addresses = &addresses, .profile = .keccak_service_v1 })) == null);
    try std.testing.expect((try cache.lookup(.{ .words = &sparse_words, .addresses = &addresses, .profile = expected.profile, .identity = @splat(0) })) == null);
}
test "Program metadata disabled and bounded capacity preserve private custody" {
    var expected = try authority(a);
    defer expected.deinit();
    var disabled = try Cache.init(a, 0);
    defer disabled.deinit();
    var private = try Program.initWithAuthorityAndMetadataCache(a, &expected, &disabled);
    defer private.deinit();
    try std.testing.expect(private.metadata_lease == null);
    try std.testing.expectEqual(@as(usize, 0), disabled.snapshot().retained_bytes);
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var first = try Program.initWithAuthorityAndMetadataCache(a, &expected, &cache);
    defer first.deinit();
    var bounded = try Cache.init(a, cache.snapshot().retained_bytes - 1);
    defer bounded.deinit();
    var miss = try Program.initWithAuthorityAndMetadataCache(a, &expected, &bounded);
    defer miss.deinit();
    try std.testing.expect(miss.metadata_lease == null);
    try same(&first, &miss);
}
fn oomCase(allocator: std.mem.Allocator, expected: *const Full.ProgramAuthority) !void {
    var cache = try Cache.init(allocator, 1024 * 1024);
    defer cache.deinit();
    var first = try Program.initWithAuthorityAndMetadataCache(allocator, expected, &cache);
    defer first.deinit();
    var second = try Program.initWithAuthorityAndMetadataCache(allocator, expected, &cache);
    defer second.deinit();
    try std.testing.expectEqual(first.entries.ptr, second.entries.ptr);
}
test "Program metadata every allocation failure retains exactly one owner and allows retry" {
    var expected = try authority(a);
    defer expected.deinit();
    try std.testing.checkAllAllocationFailures(a, oomCase, .{&expected});
}
test "Program metadata SMP mixed allocators and origin budget leases preserve lifetime" {
    var expected = try authority(a);
    defer expected.deinit();
    for (0..3) |mode| {
        const meta = if (mode == 1) a else std.heap.smp_allocator;
        const payload = if (mode == 2) a else std.heap.smp_allocator;
        var cache = try Cache.init(meta, 1024 * 1024);
        defer cache.deinit();
        var first = try Program.initWithAuthorityAndMetadataCache(payload, &expected, &cache);
        defer first.deinit();
        var second = try Program.initWithAuthorityAndMetadataCache(payload, &expected, &cache);
        defer second.deinit();
        try std.testing.expectEqual(first.entries.ptr, second.entries.ptr);
        try std.testing.expect(cache.snapshot().hits > 0);
    }
    const Budget = engine.host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(a, 16 * 1024 * 1024);
    var cache = try Cache.init(a, 1024 * 1024);
    var first = try Program.initWithAuthorityAndMetadataCache(budget.allocator(), &expected, &cache);
    var second = try Program.initWithAuthorityAndMetadataCache(a, &expected, &cache);
    defer second.deinit();
    first.deinit();
    budget.destroy();
    cache.deinit();
    try std.testing.expectEqual(@as(usize, 1), try second.lookup(4100));
}
const Job = struct {
    cache: *const Cache,
    expected: *const Full.ProgramAuthority,
    result: ?Program = null,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        self.result = Program.initWithAuthorityAndMetadataCache(a, self.expected, self.cache) catch |err| {
            self.failure = err;
            return;
        };
    }
};
test "Concurrent Program metadata publication deduplicates independently constructed maps" {
    var expected = try authority(a);
    defer expected.deinit();
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var jobs = [_]Job{ .{ .cache = &cache, .expected = &expected }, .{ .cache = &cache, .expected = &expected } };
    const first = try std.Thread.spawn(.{}, Job.run, .{&jobs[0]});
    const second = std.Thread.spawn(.{}, Job.run, .{&jobs[1]}) catch |err| {
        first.join();
        if (jobs[0].result) |*p| p.deinit();
        return err;
    };
    first.join();
    second.join();
    defer for (&jobs) |*job| if (job.result) |*p| p.deinit();
    for (jobs) |job| if (job.failure) |err| return err;
    try std.testing.expectEqual(jobs[0].result.?.entries.ptr, jobs[1].result.?.entries.ptr);
    try std.testing.expectEqual(@as(usize, 1), cache.snapshot().programs);
}
var context: u8 = 0;
const Zero = struct {
    fn word(_: *const anyopaque, _: u64) !u64 {
        return 0;
    }
    fn rights(_: *const anyopaque, _: u64) !u2 {
        return 0;
    }
};
fn admission() E.Admission {
    return .{ .image = .{ .context = &context, .initial_word = Zero.word, .rights_at = Zero.rights }, .image_identity = @splat(9), .initial_pc = 4096, .initial_registers = @splat(0) };
}
test "Program and native cache combined preserve F1 F4 full q70 proofs and fresh receiver" {
    var expected = try authority(a);
    defer expected.deinit();
    for ([_]Setup.Suite{ Setup.Suite.production(), Setup.Suite.experimentalFold4() }) |suite| {
        const geometry = Setup.Geometry{ .cpu_log = 5, .omit_empty_division = true };
        var cache = try Cache.init(a, 1024 * 1024);
        defer cache.deinit();
        var native = try Setup.NativeCache.Cache.init(a, 64 * 1024 * 1024);
        defer native.deinit();
        const caches = Setup.ImmutableCaches{ .program = &cache, .native = &native };
        var normal = try Setup.Setup.initWithAuthorityAndSuite(a, &expected, geometry, suite);
        defer normal.deinit();
        var first = try Setup.Setup.initWithAuthorityAndSuiteAndCaches(a, &expected, geometry, suite, caches);
        defer first.deinit();
        try std.testing.expectEqual(normal.fixed_root, first.fixed_root);
        var tape = try front.rv64.compact_tape.Tape.init(a, 2, 4096, 0, .ethereum_services_v2);
        defer tape.deinit();
        tape.len = 2;
        tape.storage[0] = .{ .next_pc = 4100, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 7, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        tape.storage[1] = .{ .next_pc = 4104, .lhs = 7, .rhs = 7, .previous_rd = 0, .result = 0, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        var public: front.rv64_air.word16_execution.types.Boundary = .{ .steps = 2, .initial_pc = 4096, .final_pc = 4104, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
        public.final_registers[1] = 7;
        public.register_clocks[1] = 6;
        public.register_clocks[2] = 7;
        var control = try E.prove(a, &normal, admission(), public, &tape, null);
        defer control.deinit(a);
        var proof = try E.prove(a, &first, admission(), public, &tape, null);
        defer proof.deinit(a);
        try std.testing.expectEqualSlices(u8, control.bytes, proof.bytes);
        try std.testing.expectEqualDeep(control.claims, proof.claims);
        var fresh = try Setup.Setup.initWithAuthorityAndSuiteAndCaches(a, &expected, geometry, suite, caches);
        defer fresh.deinit();
        try fresh.releaseFixedWitness();
        try E.verify(a, &fresh, admission(), proof);
        try std.testing.expectEqual(first.materials.program.entries.ptr, fresh.materials.program.entries.ptr);
        try std.testing.expect(fresh.materials.suite.eql(suite));
    }
}

test "Program metadata admission rejects mutated maps and decoded semantics before transfer" {
    var expected = try authority(a);
    defer expected.deinit();
    var program = try Program.initWithAuthority(a, &expected);
    defer program.deinit();
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    const input = Metadata.Input{ .words = program.words, .addresses = program.addresses, .profile = program.profile, .identity = program.identity };
    var data = program.metadataView();
    var wrong = program.identity;
    wrong[0] ^= 1;
    var bad_input = input;
    bad_input.identity = wrong;
    try std.testing.expectError(error.InvalidProgramMetadataIdentity, cache.adopt(bad_input, data, a));
    data.log_size += 1;
    try std.testing.expectError(error.InvalidProgramMetadataShape, cache.adopt(input, data, a));
    data = program.metadataView();
    const mutable = @constCast(data.entries);
    const saved = mutable[0];
    mutable[0].operation ^= 1;
    try std.testing.expectError(error.InvalidProgramMetadataIdentity, cache.adopt(input, data, a));
    mutable[0] = saved;
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().programs);
    var successful = (try cache.adopt(input, data, a)).?;
    program.metadata_lease = successful;
    // Transfer moved into program; cache manager can go before final owner.
    successful = undefined;
}

test "Program metadata duplicate adopt transfers once and frees independent loser arrays" {
    var expected = try authority(a);
    defer expected.deinit();
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var first = try Program.initWithAuthority(a, &expected);
    defer first.deinit();
    var second = try Program.initWithAuthority(a, &expected);
    defer second.deinit();
    const input = Metadata.Input{ .words = expected.words, .addresses = expected.program.addresses, .profile = expected.profile, .identity = first.identity };
    first.metadata_lease = (try cache.adopt(input, first.metadataView(), a)).?;
    const lease = (try cache.adopt(input, second.metadataView(), a)).?;
    const shared = lease.view();
    second.entries = shared.entries;
    second.word_rows = shared.word_rows;
    second.row_to_entry = shared.row_to_entry;
    second.row_taken = shared.row_taken;
    second.metadata_lease = lease;
    try std.testing.expectEqual(first.entries.ptr, second.entries.ptr);
    try std.testing.expectEqual(@as(u64, cache.snapshot().payload_bytes), cache.snapshot().duplicate_metadata_bytes_released);
}

test "Program metadata hit fixed allocation failure drains lease and permits retry" {
    var expected = try authority(a);
    defer expected.deinit();
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var first = try Program.initWithAuthorityAndMetadataCache(a, &expected, &cache);
    defer first.deinit();
    const before = cache.snapshot();
    var failure = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, Program.initWithAuthorityAndMetadataCache(failure.allocator(), &expected, &cache));
    try std.testing.expectEqual(before.owner_leases, cache.snapshot().owner_leases);
    try std.testing.expectEqual(before.payload_bytes, cache.snapshot().payload_bytes);
    var retry = try Program.initWithAuthorityAndMetadataCache(a, &expected, &cache);
    defer retry.deinit();
    try same(&first, &retry);
}
