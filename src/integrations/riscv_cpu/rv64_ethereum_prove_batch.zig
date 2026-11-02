//! Prepared compact advice/boundaries -> one wide witness -> joined physical
//! proof -> receiver -> durable artifact -> sparse frontier publication. The
//! native adapter finishes all guest-dependent capture before entering worker.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const rv = A.frontend.rv64;
const R = A.R;
const Native = @import("rv64_ethereum_batch.zig");
const Request = @import("rv64_ethereum_request.zig");
const Receipt = @import("rv64_ethereum_batch_receipt.zig");
const Chain = @import("rv64_ethereum_chain.zig");
const Memory = @import("rv64_batch_memory.zig");
const MainArena = @import("rv64_authenticated_main_arena.zig").MainArena;
pub const Metrics = struct {
    memory: ?Memory.Report = null,
    index: u32,
    first_step: u64,
    instructions: u32,
    ram_cells: usize,
    keccak_calls: u32,
    secp_add_calls: u32,
    secp_double_calls: u32,
    source_cells: Receipt.SourceCells,
    proof_bytes: usize,
    native_ns: u64,
    openings_ns: u64,
    ram_witness_ns: u64,
    setup_ns: u64,
    cpu_witness_ns: u64,
    prove_ns: u64,
    receiver_setup_ns: u64,
    encode_ns: u64,
    verify_ns: u64,
    write_ns: u64,
    cache_publish_ns: u64,
    total_after_native_ns: u64,
    reused_expected_setup: bool = false,
    shared_main_arena_adopted: bool = false,
    constraint_diagnostics_enabled: bool = false,
};
/// Detached native advice carries only an owned sparse graph/I/O payload. It
/// has no Cache, VM, image or capture borrow. An empty-RAM job needs no graph.
pub const DetachedFrontier = struct {
    before: R.values.Digest,
    graph: ?*R.native_frontier.Prepared = null,
};
pub const Frontier = union(enum) {
    cache: *R.values.Cache,
    detached: DetachedFrontier,
    const Snapshot = struct { before: R.values.Digest, expected_after: ?R.values.Digest = null };
    fn snapshot(self: Frontier, has_openings: bool) !Snapshot {
        const result: Snapshot = switch (self) {
            .cache => |value| blk: {
                if (value.geometry != .chunk512) return error.InvalidEthereumPreparedFrontier;
                break :blk .{ .before = value.root() };
            },
            .detached => |value| blk: {
                if ((value.graph != null) != has_openings) return error.InvalidEthereumPreparedFrontier;
                if (value.graph) |graph| {
                    try graph.requireMovable();
                    if (graph.witness.geometry != .chunk512 or !std.mem.eql(u32, &value.before, &graph.witness.before)) return error.InvalidEthereumPreparedFrontier;
                    break :blk .{ .before = value.before, .expected_after = graph.witness.after };
                }
                break :blk .{ .before = value.before, .expected_after = value.before };
            },
        };
        for (result.before) |limb| if (limb >= A.core.fields.m31.Modulus) return error.NonCanonicalDigest;
        if (result.expected_after) |after| for (after) |limb| {
            if (limb >= A.core.fields.m31.Modulus) return error.NonCanonicalDigest;
        };
        return result;
    }
    fn publish(self: Frontier, roots: Snapshot, public: A.Public, ram: ?*const R.private_trace.Trace) !void {
        switch (self) {
            .cache => |value| {
                if (!std.mem.eql(u32, &value.root(), &roots.before)) return error.EthereumPublishedRootMismatch;
                if (ram) |trace| try value.applyPatch(trace.witness.patches);
                if (!std.mem.eql(u32, &value.root(), &public.after)) return error.EthereumPublishedRootMismatch;
            },
            // The graph was consumed into RAM. Only saved endpoint values are
            // read here; the collector owns separate native-frontier progress.
            .detached => if (!std.mem.eql(u32, &roots.expected_after.?, &public.after)) return error.EthereumPublishedRootMismatch,
        }
    }
};
/// Immutable expected material is borrowed for this invocation. The frontier
/// and cursor are exclusive mutable request state. A serial caller supplies an
/// accepted continuation; an out-of-order worker supplies explicitly OPEN
/// boundary conditions. Neither makes packet metadata execution authority:
/// the final independent chain receiver establishes global endpoint authority.
pub const PreparedContext = struct {
    authority: *const A.Full.ProgramAuthority,
    policy: *const R.policy.Policy,
    frontier: Frontier,
};
pub const PreparedTiming = struct {
    native_ns: u64 = 0,
    openings_ns: u64 = 0,
    /// Serial callers include capture release and finish overhead here. A
    /// deserialized worker may omit it; native openings time is then included
    /// once in total_after_native_ns, independently of the worker timer.
    before_worker_ns: ?u64 = null,
};

/// Native-only adapter. A failed finish leaves the original capture intact.
/// After successful finish every boundary/chunk is owned by Finished, so the
/// capture can be reused independently of the pure proving worker. Any later
/// failure aborts this one-shot packet; no in-place OOM retry is supported.
pub fn prove(a: std.mem.Allocator, request: *Request.Request, config: Request.Config, tape: *rv.compact_tape.Tape, capture: *rv.boundary_capture.Capture, batch: *const Native.Batch, cpu: *const rv.machine.Cpu, cursor: *Chain.Cursor, directory: std.fs.Dir, native_ns: u64) !Metrics {
    var timer = try std.time.Timer.start();
    var finished = try batch.finish(a, cpu, &request.loaded.memory, &request.policy, .chunk512);
    defer finished.deinit();
    const openings_ns = timer.read();
    try capture.clearRetainingCapacity();
    return provePrepared(a, .{ .authority = &request.authority, .policy = &request.policy, .frontier = .{ .cache = &request.initial_cache } }, config, tape, &finished, cursor, directory, .{ .native_ns = native_ns, .openings_ns = openings_ns, .before_worker_ns = timer.read() });
}

/// One canonical one-shot proving/publication path. Finished owns copied native
/// boundaries and chunks; Tape owns its compact advice. On success/failure the
/// caller must deinit both owners. Openings may move into RAM before an error;
/// Tape is cleared only after every witness builder has copied its advice.
/// Authority/policy/frontier/cursor must outlive the call; no references escape.
/// This function performs no execution, replay, guest-memory or Capture reads.
pub fn provePrepared(a: std.mem.Allocator, context: PreparedContext, config: Request.Config, tape: *rv.compact_tape.Tape, finished: *Native.Finished, cursor: *Chain.Cursor, directory: std.fs.Dir, timing: PreparedTiming) !Metrics {
    var memory = Memory.Sampler{};
    if (config.profile_stages) try memory.start();
    defer if (config.profile_stages) {
        _ = memory.finish();
    };
    var total = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    // Request-specific control, endpoints, call IDs, roots and expected program
    // are checked before any wide allocation. The later check also binds the
    // actual newly computed RAM root; its value is not needed for adjacency.
    if (context.authority.profile != finished.public.execution_profile or context.authority.control_policy != finished.public.control_policy or config.control_policy != finished.public.control_policy or config.state_policy != finished.public.state_policy) return error.InvalidEthereumPreparedProfile;
    if (tape.len == 0 or tape.len > tape.storage.len or tape.len != finished.public.statement.steps or tape.len > config.batch_steps or tape.initial_pc != finished.public.statement.initial_pc or tape.execution_profile != finished.public.execution_profile or tape.service_calls.items.len != finished.public.keccak_calls or tape.secp_calls.items.len != @as(u64, finished.public.secp.add.calls) + finished.public.secp.double.calls or finished.cells.len != finished.memory_clocks.len or (finished.openings != null) != (finished.cells.len != 0)) return error.InvalidEthereumPreparedBoundary;
    try A.Full.validateAuthorityProgram(context.authority, finished.public.statement.program);
    const roots = try context.frontier.snapshot(finished.openings != null);
    const initial_root = roots.before;
    try cursor.check(.{ .cpu = finished.public, .geometry = .chunk512, .before = initial_root, .after = initial_root, .policy_identity = context.policy.identity, .ram = null }, cursor.batches, tape.initial_clock, config.max_steps);
    if (!config.omit_unused_arithmetic) {
        finished.public.division_roster = .present;
        finished.public.multiplication_roster = .present;
    }
    // Plan/admit the complete roster before allocating any wide witness. Roots
    // are established by the RAM construction below, never used as setup keys.
    var preparation: ?R.private_trace.Preparation = if (finished.openings) |*value| try R.private_trace.Preparation.init(a, .chunk512, context.policy, value.chunks) else null;
    defer if (preparation) |*value| value.deinit();
    // A shared main arena is allocated before RAM's concrete constructor. Admit
    // detached framing/counts/absorption now as well, while all owners are still
    // narrow; the constructor independently protects its standalone API.
    if (context.frontier == .detached) if (context.frontier.detached.graph) |graph| {
        try graph.validate();
        if (!std.meta.eql(graph.counts, preparation.?.counts)) return error.PrivateRamPreparationChanged;
        try graph.validateOpenings(finished.openings.?.chunks);
    };
    const layout = A.Layout{ .cpu = finished.public, .geometry = .chunk512, .policy_identity = context.policy.identity, .ram = if (preparation) |*value| A.RAM.Counts.fromShapes(value.shapes) else null };
    var setup = try A.Prepared.initForLayout(a, layout, context.policy, context.authority);
    defer setup.deinit();
    var arena: ?MainArena = if (config.shared_main_arena) try MainArena.initForLayout(a, &setup, layout) else null;
    defer if (arena) |*value| value.deinit();
    const setup_ns = timer.lap();
    var ram: ?R.private_trace.Trace = if (finished.openings) |*value| switch (context.frontier) {
        .cache => |cache| if (arena) |*storage| try R.private_trace.Trace.initPreparedBorrowedOwned(a, cache, &preparation.?, value, try storage.ramBuffers()) else try R.private_trace.Trace.initOwned(a, cache, context.policy, value),
        .detached => |detached| if (arena) |*storage| try R.private_trace.Trace.initFromPreparedGraphBorrowedOwned(a, detached.graph.?, &preparation.?, value, try storage.ramBuffers()) else try R.private_trace.Trace.initFromPreparedGraphOwned(a, detached.graph.?, &preparation.?, value),
    } else null;
    defer if (ram) |*value| value.deinit();
    const ram_witness_ns = timer.lap();
    const before = roots.before;
    const public = A.Public{ .cpu = finished.public, .geometry = .chunk512, .before = before, .after = if (ram) |*value| value.witness.after else before, .policy_identity = context.policy.identity, .ram = layout.ram };
    if (roots.expected_after) |expected| if (!std.mem.eql(u32, &expected, &public.after)) return error.EthereumPublishedRootMismatch;
    try cursor.check(public, cursor.batches, tape.initial_clock, config.max_steps);
    const cells = try Receipt.sourceCells(a, &setup, public);
    const boundary = A.Full.Trace.PrivateBoundary{ .cells = finished.cells, .memory_clocks = finished.memory_clocks };
    var full = if (arena) |*value| try A.Full.Trace.initWithPrivateTapeBorrowedMain(a, tape, public.cpu.first_call_id, public.cpu.secp.firstIds(), public.cpu.statement, boundary, &setup.cpu.base.program, &setup.cpu.base.plan, try value.cpuMain()) else try A.Full.Trace.initWithPrivateTape(a, tape, public.cpu.first_call_id, public.cpu.secp.firstIds(), public.cpu.statement, boundary, &setup.cpu.base.program, &setup.cpu.base.plan);
    var owns_full = true;
    defer if (owns_full) full.deinit();
    var trace = if (arena) |*value| try A.CPU.Trace.fromCpuBorrowed(a, full, public.cpu, &setup.cpu, try value.coreBuffers()) else try A.CPU.Trace.fromCpu(a, full, public.cpu, &setup.cpu);
    owns_full = false;
    defer trace.deinit();
    const cpu_witness_ns = timer.lap();
    // Neither wide builders nor the proof retain compact execution advice.
    tape.clearRetainingCapacity();
    var recorder = @import("stwo_prover_api").stage_profile.Recorder.initWithOptions(a, "rv64", "ethereum_batch", .{ .capture_tasks = false, .capture_process_usage = true });
    defer recorder.deinit();
    const ram_source = if (ram) |*value| A.RAM.Source.fromTrace(value) else null;
    const outcome = if (config.diagnose_constraints != .none) A.proveDiagnosed(a, &setup, public, &trace, ram_source, if (arena) |*value| value else null, if (config.profile_stages) &recorder else null, .{ .cpu = config.diagnose_constraints == .cpu or config.diagnose_constraints == .all, .ram = config.diagnose_constraints == .ram or config.diagnose_constraints == .providers or config.diagnose_constraints == .all, .arithmetic = config.diagnose_constraints == .arithmetic or config.diagnose_constraints == .providers or config.diagnose_constraints == .all, .crypto = config.diagnose_constraints == .crypto or config.diagnose_constraints == .providers or config.diagnose_constraints == .all }) else if (arena) |*value| A.proveArena(a, &setup, public, &trace, ram_source, value, if (config.profile_stages) &recorder else null) else if (config.profile_stages) A.proveProfiled(a, &setup, public, &trace, ram_source, &recorder) else A.proveTrace(a, &setup, public, &trace, ram_source);
    var bundle = outcome catch |err| {
        @import("rv64_ethereum_proof_failure.zig").write(a, directory, cursor.batches, cursor.steps, public, cells, &recorder, err) catch |report_error| {
            std.debug.print("Could not retain failed-batch profile: {s}\n", .{@errorName(report_error)});
        };
        return err;
    };
    defer bundle.deinit(a);
    const prove_ns = timer.lap();
    // This owner was derived from the independently pinned request authority
    // before witness construction. Verification reuses only immutable setup;
    // verifyOwned creates a fresh channel/verifier and checks this request again.
    // Re-deriving the same fixed tree here adds no independent authority.
    const receiver_setup_ns: u64 = 0;
    const wire = @import("stwo_proof_wire");
    const encoded = try wire.encodeProofBytesBinary(a, bundle.proof);
    defer a.free(encoded);
    const encode_ns = timer.lap();
    try setup.verifyOwned(a, public, bundle.claims, try wire.decodeProofBytesBinary(a, encoded));
    const verify_ns = timer.lap();
    _ = try Receipt.writeEncoded(a, directory, cursor.batches, cursor.steps, public, bundle.claims, encoded);
    if (config.profile_stages) {
        var profile = try recorder.snapshot(a);
        defer profile.deinit(a);
        const measured = Memory.WithMemory(@TypeOf(profile)){ .profile = profile, .memory = memory.finish() };
        const json = try std.json.Stringify.valueAlloc(a, measured, .{ .whitespace = .indent_2 });
        defer a.free(json);
        const name = try std.fmt.allocPrint(a, "batch-{d:0>6}.stages.json", .{cursor.batches});
        defer a.free(name);
        try Receipt.writeExclusive(directory, name, json);
    }
    const write_ns = timer.lap();
    try context.frontier.publish(roots, public, if (ram) |*value| value else null);
    try cursor.advanceVerified(public);
    return .{ .memory = if (config.profile_stages) memory.report else null, .index = cursor.batches - 1, .first_step = cursor.steps - public.cpu.statement.steps, .instructions = public.cpu.statement.steps, .ram_cells = finished.cells.len, .keccak_calls = public.cpu.keccak_calls, .secp_add_calls = public.cpu.secp.add.calls, .secp_double_calls = public.cpu.secp.double.calls, .source_cells = cells, .proof_bytes = encoded.len, .native_ns = timing.native_ns, .openings_ns = timing.openings_ns, .ram_witness_ns = ram_witness_ns, .setup_ns = setup_ns, .cpu_witness_ns = cpu_witness_ns, .prove_ns = prove_ns, .receiver_setup_ns = receiver_setup_ns, .encode_ns = encode_ns, .verify_ns = verify_ns, .write_ns = write_ns, .cache_publish_ns = timer.lap(), .total_after_native_ns = total.read() +| (timing.before_worker_ns orelse timing.openings_ns), .reused_expected_setup = true, .shared_main_arena_adopted = config.shared_main_arena, .constraint_diagnostics_enabled = config.diagnose_constraints != .none };
}
