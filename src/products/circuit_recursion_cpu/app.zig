//! The circuit recursion CPU product: the leaf wrap, the recursive tree and
//! registry generation of https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, byte for byte (design §7.4).
//!
//! `leaf-wrap` is the Zig counterpart of upstream `leaf-prover`
//! (`crates/leaf_prover/src/main.rs`): it proves an execution as a leaf Cairo
//! proof under the registry's `cairo_prover_params`, wraps that proof in the
//! registry's leaf verifier circuit and writes the `SerializedLeafProof` file
//! byte for byte as `leaf-prover` does (pretty JSON, no trailing newline).
//! The Zig lane has no Cairo VM, so it starts from the execution the VM and
//! upstream adapter produce (`ProverInput` JSON, as `stwo-circuit-oracle
//! adapt-program` writes it); `leaf-prover` runs those steps itself from the
//! compiled program. The compiled program is still read: its felts are the
//! program the leaf circuit interns, as upstream's `program_felts`.
//!
//! `verify` is upstream `verify_circuit` on a `CircuitSerialize` proof: it
//! prints `accepted` (with the verifier's output digest) and exits 0, or
//! prints where the proof was rejected and exits 3.
//!
//! The circuit AIR's compiled-constraint projection and recorded evaluation
//! programs are embedded at build time and authenticated by SHA-256 before
//! use. `leaf-wrap` also reads the Cairo lane's witness and AIR bundles from
//! the `--assets` repository root.

const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const cairo_leaf = @import("stwo_cairo_cpu_integration").prover.leaf_transaction;
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
/// The wire formats, for callers that hand this module parsed inputs.
pub const wire = @import("stwo_circuit_recursion_wire");
const prover = @import("stwo_prover_engine");
const cli = @import("cli.zig");

const recursion = circuit_cpu.recursion;
const leaf_wrap = recursion.leaf_wrap;
const fold_stage = @import("stage.zig");

const projection_bytes = @embedFile("circuit_air_projection");
const air_programs_bytes = @embedFile("circuit_air_programs");
pub fn authenticatedAirPrograms() ![]const u8 {
    try authenticate(air_programs_bytes, circuit_cpu.air.bundle_sha256);
    return air_programs_bytes;
}
/// SHA-256 of `vectors/circuit/official/compiled_air_constraints_v1.bin`
/// (`vectors/circuit/provenance.json`).
const projection_sha256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09";

/// Largest JSON input read (a leaf file is about 0.7 MB, a compiled
/// program 1.6 MB).
const max_input_bytes = 64 << 20;

pub fn main() !void {
    return mainWith(cairo_leaf, &circuit_cpu.prove.cpu_provers);
}

/// Backend selection is confined to proving; protocol bytes and CLI stay shared.
pub fn mainWith(comptime CairoLeaf: type, provers: *const circuit_cpu.prove.Provers) !void {
    const gpa = std.heap.smp_allocator;
    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);
    var stderr_buffer: [4096]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&stderr_buffer);
    const parsed = cli.parse(argv[1..]) catch |err| {
        try stderr.interface.print("error: {s}\n{s}", .{ @errorName(err), cli.usage });
        try stderr.interface.flush();
        std.process.exit(2);
    };
    runWith(CairoLeaf, provers, gpa, parsed) catch |err| {
        try stderr.interface.print("error: {s}\n", .{@errorName(err)});
        try stderr.interface.flush();
        std.process.exit(1);
    };
}

fn runWith(comptime CairoLeaf: type, provers: *const circuit_cpu.prove.Provers, gpa: std.mem.Allocator, parsed: cli.Parsed) !void {
    switch (parsed) {
        .help => try std.fs.File.stdout().writeAll(cli.usage),
        .leaf_wrap => |command| try leafWrapCommandWith(CairoLeaf, provers, gpa, command),
        .fold_tree => |command| try foldTreeCommandWith(provers, gpa, command),
        .fold_stage => |command| try foldStageCommandWith(provers, gpa, command.manifest, command.registry, false, command.checkpoint, null, null, null),
        .fold_stage_root => |command| try foldStageCommandWith(provers, gpa, command.manifest, command.registry, true, null, command.proof, command.outputs, command.packed_output),
        .circuit_params => |command| try circuitParams(gpa, command),
        .verify => |command| if (!try verifyCommand(gpa, command)) std.process.exit(3),
    }
}

const StageManifestEntry = struct {
    kind: []const u8,
    path: []const u8,
};

const StageManifest = struct { entries: []const StageManifestEntry };

/// Shared by Metal/CPU and CUDA CLIs; input arenas remain live until the
/// checkpoint or final root has been rendered.
pub fn loadStageInputs(allocator: std.mem.Allocator, path: []const u8) ![]StageInput {
    const parsed = try std.json.parseFromSlice(StageManifest, allocator, try readFile(allocator, path), .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    if (parsed.value.entries.len == 0 or parsed.value.entries.len > 256) return error.InvalidFoldStageSize;
    const inputs = try allocator.alloc(StageInput, parsed.value.entries.len);
    for (parsed.value.entries, inputs) |entry, *input| {
        input.* = if (std.mem.eql(u8, entry.kind, "leaf"))
            .{ .leaf = (try wire.leaf_proof_json.parseLeafInput(allocator, try readFile(allocator, entry.path))).value }
        else if (std.mem.eql(u8, entry.kind, "checkpoint"))
            .{ .checkpoint = (try wire.checkpoint.parse(allocator, try readFile(allocator, entry.path))).node }
        else
            return error.InvalidFoldStageEntry;
    }
    return inputs;
}

fn foldStageCommandWith(
    provers: *const circuit_cpu.prove.Provers,
    gpa: std.mem.Allocator,
    manifest_path: []const u8,
    registry_path: []const u8,
    terminal_root: bool,
    checkpoint_path: ?[]const u8,
    proof_path: ?[]const u8,
    outputs_path: ?[]const u8,
    packed_path: ?[]const u8,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const inputs = try loadStageInputs(a, manifest_path);
    const registry = try wire.registry.parseRegistry(a, try readFile(a, registry_path));
    var files = try foldStageWithSource(gpa, registry.registry, inputs, provers, null, terminal_root);
    defer files.deinit();
    if (terminal_root) {
        try writeFile(proof_path.?, files.proof.written());
        try writeFile(outputs_path.?, files.outputs.written());
        try writeFile(packed_path.?, files.packed_tree.written());
    } else {
        try writeFile(checkpoint_path.?, files.checkpoint.written());
    }
}

/// The embedded circuit AIR projection, authenticated.
const Air = struct {
    projection: circuit.air_eval.projection.Projection,

    fn init(gpa: std.mem.Allocator) !Air {
        try authenticate(projection_bytes, projection_sha256);
        return .{ .projection = try circuit.air_eval.projection.parse(gpa, projection_bytes) };
    }

    fn deinit(self: *Air) void {
        self.projection.deinit();
    }

    /// The circuit AIR's evaluator table; borrows the projection.
    fn circuitTable(self: *const Air, gpa: std.mem.Allocator) !circuit.air_eval.component_table.Table {
        return circuit.air_eval.circuit_components.build(gpa, &self.projection);
    }

    /// The 83-slot Cairo evaluator table; borrows the projection.
    fn cairoTable(self: *const Air, gpa: std.mem.Allocator) !circuit.air_eval.component_table.Table {
        return circuit.air_eval.cairo_components.build(gpa, &self.projection);
    }
};

/// The embedded circuit AIR evaluation programs, authenticated.
fn airBundle(gpa: std.mem.Allocator) !circuit_cpu.air.Bundle {
    try authenticate(air_programs_bytes, circuit_cpu.air.bundle_sha256);
    return circuit_cpu.air.parse(gpa, air_programs_bytes);
}

fn authenticate(bytes: []const u8, comptime expected: *const [64]u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected)) return error.EmbeddedAssetDigestMismatch;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, max_input_bytes) catch |err| {
        std.log.err("cannot read {s}: {s}", .{ path, @errorName(err) });
        return err;
    };
}

fn writeFile(path: []const u8, bytes: []const u8) !void {
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = bytes });
}

/// The Cairo lane's committed bundles `leaf-wrap` reads, relative to the
/// assets root.
pub const cairo_asset_paths = struct {
    pub const witness_programs = "vectors/cairo/official/witness_programs_v1.bin";
    pub const feed_topology = "vectors/cairo/official/witness_feed_topology_v1.json";
    pub const fixed_tables = "vectors/cairo/cairo_fixed_tables.bin";
    pub const relation_templates = "vectors/cairo/cairo_relation_templates.bin";
    pub const air_templates = "vectors/cairo/official/air_template_library_v1.json";
};

pub const LeafWrapRequest = struct {
    registry_path: []const u8,
    program_path: []const u8,
    prover_input_path: []const u8,
    cairo_proof_path: ?[]const u8 = null,
    assets: []const u8 = ".",
    /// Execution choices of the circuit prover; never change bytes.
    options: circuit_cpu.prove.Options = .{},
    /// The backend that proves the wrap (the CPU here; `circuit_metal`'s
    /// device rungs inject theirs); never changes bytes.
    provers: *const circuit_cpu.prove.Provers = &circuit_cpu.prove.cpu_provers,
    source: ?recursion.proof_source.Source = null,
};

/// Wall time of each stage, in nanoseconds.
pub const Timings = struct {
    load_ns: u64 = 0,
    cairo_prove_ns: u64 = 0,
    wrap_ns: u64 = 0,
};

/// `prove_leaf` from an adapted execution: the leaf Cairo proof, then the
/// wrap. The Cairo trace is released before the wrap starts.
pub fn leafWrap(allocator: std.mem.Allocator, request: LeafWrapRequest, timings: *Timings) !leaf_wrap.LeafProof {
    return leafWrapWith(cairo_leaf, allocator, request, timings);
}

pub fn leafWrapWith(comptime CairoLeaf: type, allocator: std.mem.Allocator, request: LeafWrapRequest, timings: *Timings) !leaf_wrap.LeafProof {
    var timer = try std.time.Timer.start();

    const registry_text = try readFile(allocator, request.registry_path);
    defer allocator.free(registry_text);
    var registry = try wire.registry.parseRegistry(allocator, registry_text);
    defer registry.deinit();

    const program_json = try readFile(allocator, request.program_path);
    const program = blk: {
        defer allocator.free(program_json);
        break :blk try cairo.statement.circuit_leaf.programFeltsFromCompiledJson(allocator, program_json);
    };
    defer allocator.free(program);

    var input = try cairo.adapter.official_input.readFile(allocator, request.prover_input_path);
    defer input.deinit(allocator);
    timings.load_ns = timer.lap();

    // Steps 1-3 of `prove_leaf`: the leaf Cairo proof.
    var cairo_proof = blk: {
        const programs_path = try std.fs.path.join(allocator, &.{ request.assets, cairo_asset_paths.witness_programs });
        defer allocator.free(programs_path);
        var programs = try cairo.witness.bundle.Bundle.readFile(allocator, programs_path);
        defer programs.deinit();
        const topology_path = try std.fs.path.join(allocator, &.{ request.assets, cairo_asset_paths.feed_topology });
        defer allocator.free(topology_path);
        var topology = try cairo.witness.feed_topology.readOfficial(allocator, topology_path);
        defer topology.deinit();
        const fixed_path = try std.fs.path.join(allocator, &.{ request.assets, cairo_asset_paths.fixed_tables });
        defer allocator.free(fixed_path);
        var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(allocator, fixed_path);
        defer fixed.deinit();
        const relations_path = try std.fs.path.join(allocator, &.{ request.assets, cairo_asset_paths.relation_templates });
        defer allocator.free(relations_path);
        var relations = try cairo.witness.relation_bundle.Bundle.readFile(allocator, relations_path);
        defer relations.deinit();
        const templates_path = try std.fs.path.join(allocator, &.{ request.assets, cairo_asset_paths.air_templates });
        defer allocator.free(templates_path);
        var air_templates = try cairo.air.template_library.Library.readFile(allocator, templates_path);
        defer air_templates.deinit();
        break :blk try CairoLeaf.proveLeafCairo(allocator, .{
            .input = &input,
            .programs = &programs,
            .topology = topology,
            .fixed = &fixed,
            .relations = &relations,
            .air_templates = &air_templates,
            .composition_device = CairoLeaf.compositionDevice(request.assets),
        }, registry.registry.cairo_prover_params, null);
    };
    defer cairo_proof.deinit();
    timings.cairo_prove_ns = timer.lap();

    // Steps 4-8: the wrap.
    var leaf = try wrapAfterCairoProof(allocator, request, &registry.registry, program, &cairo_proof, &input, false);
    errdefer leaf.deinit();
    timings.wrap_ns = timer.lap();
    if (request.cairo_proof_path) |path| {
        const lane = try cairo.proving.leaf_lane.Lane.fromParameters(registry.registry.cairo_prover_params);
        var max_trace_log: u32 = 0;
        for (cairo_proof.composition.components) |component|
            max_trace_log = @max(max_trace_log, component.trace_log_size);
        const pcs = try lane.pcsConfig(max_trace_log);
        try writeCairoProof(path, &input, &cairo_proof, pcs.trace_lifting_log_size);
    }
    return leaf;
}

fn writeCairoProof(path: []const u8, input: anytype, result: anytype, lifting: u32) !void {
    var buffer: [64 * 1024]u8 = undefined;
    var atomic = try std.fs.cwd().atomicFile(path, .{ .write_buffer = &buffer });
    defer atomic.deinit();
    const Pinned = cairo.proof.json.PinnedLeafDocument(@TypeOf(result.proof.proof));
    try std.json.Stringify.value(Pinned{
        .document = .{
            .input = input,
            .composition = &result.composition,
            .claimed_sums = result.claimed_sums,
            .interaction_pow = result.interaction_pow,
            .channel_salt = result.channel_salt,
            .preprocessed_variant = result.preprocessed_variant,
            .stark_proof = &result.proof.proof,
        },
        .trace_lifting_log_size = lifting,
        .preprocessed_lifting_log_size = lifting,
    }, .{}, &atomic.file_writer.interface);
    try atomic.file_writer.interface.writeByte('\n');
    try atomic.finish();
}

/// The CUDA Cairo product supplies an independently verified compressed proof
/// and its opening capture. This path never starts the Cairo CPU prover.
pub fn leafWrapVerified(
    allocator: std.mem.Allocator,
    request: LeafWrapRequest,
    verified: leaf_wrap.VerifiedCairoLeaf,
    input: *const cairo.adapter.ProverInput,
) !leaf_wrap.LeafProof {
    var session = try VerifiedLeafSession.init(allocator, request);
    defer session.deinit();
    return session.wrap(verified, input);
}

/// Retains the registry, compiled program, AIR tables, and checked leaf
/// topology across distinct verified Cairo proofs with the same leaf program.
/// A cache hit still rebuilds the witness and checks the circuit hash against
/// the registry; no proof-dependent data is retained between wraps.
pub const VerifiedLeafSession = struct {
    allocator: std.mem.Allocator,
    request: LeafWrapRequest,
    registry: wire.registry.OwnedRegistry,
    program: []cairo.statement.circuit_leaf.ProgramFelt,
    air: *Air,
    cairo_table: circuit.air_eval.component_table.Table,
    bundle: circuit_cpu.air.Bundle,
    cache: leaf_wrap.Cache,

    pub fn init(allocator: std.mem.Allocator, request: LeafWrapRequest) !VerifiedLeafSession {
        const registry_text = try readFile(allocator, request.registry_path);
        defer allocator.free(registry_text);
        var registry = try wire.registry.parseRegistry(allocator, registry_text);
        errdefer registry.deinit();
        const program_json = try readFile(allocator, request.program_path);
        defer allocator.free(program_json);
        const program = try cairo.statement.circuit_leaf.programFeltsFromCompiledJson(allocator, program_json);
        errdefer allocator.free(program);
        const air = try allocator.create(Air);
        errdefer allocator.destroy(air);
        air.* = try Air.init(allocator);
        errdefer air.deinit();
        var cairo_table = try air.cairoTable(allocator);
        errdefer cairo_table.deinit();
        var bundle = try airBundle(allocator);
        errdefer bundle.deinit();
        return .{
            .allocator = allocator,
            .request = request,
            .registry = registry,
            .program = program,
            .air = air,
            .cairo_table = cairo_table,
            .bundle = bundle,
            .cache = leaf_wrap.Cache.init(allocator, .{}),
        };
    }

    pub fn deinit(self: *VerifiedLeafSession) void {
        self.cache.deinit();
        self.bundle.deinit();
        self.cairo_table.deinit();
        self.air.deinit();
        self.allocator.destroy(self.air);
        self.allocator.free(self.program);
        self.registry.deinit();
        self.* = undefined;
    }

    pub fn wrap(
        self: *VerifiedLeafSession,
        verified: leaf_wrap.VerifiedCairoLeaf,
        input: *const cairo.adapter.ProverInput,
    ) !leaf_wrap.LeafProof {
        const context = leaf_wrap.LeafWrap{
            .registry = &self.registry.registry,
            .cairo_table = &self.cairo_table,
            .bundle = &self.bundle,
            .program = self.program,
            .cache = &self.cache,
            .options = self.request.options,
            .provers = self.request.provers,
            .source = self.request.source,
        };
        return leaf_wrap.wrapVerifiedCairoLeaf(self.allocator, &context, verified, input);
    }
};

fn wrapAfterCairoProof(
    allocator: std.mem.Allocator,
    request: LeafWrapRequest,
    registry: *const wire.registry.CircuitRegistry,
    program: anytype,
    cairo_proof: anytype,
    input: *const cairo.adapter.ProverInput,
    comptime verified: bool,
) !leaf_wrap.LeafProof {
    var air = try Air.init(allocator);
    defer air.deinit();
    var cairo_table = try air.cairoTable(allocator);
    defer cairo_table.deinit();
    var bundle = try airBundle(allocator);
    defer bundle.deinit();

    var cache = leaf_wrap.Cache.init(allocator, .{});
    defer cache.deinit();
    const wrap = leaf_wrap.LeafWrap{
        .registry = registry,
        .cairo_table = &cairo_table,
        .bundle = &bundle,
        .program = program,
        .cache = &cache,
        .options = request.options,
        .provers = request.provers,
        .source = request.source,
    };
    return if (comptime verified)
        leaf_wrap.wrapVerifiedCairoLeaf(allocator, &wrap, cairo_proof, input)
    else
        leaf_wrap.wrapCairoProof(allocator, &wrap, cairo_proof, input);
}

/// Writes `leaf` to `path` atomically.
pub fn writeLeafProof(leaf: *const leaf_wrap.LeafProof, path: []const u8) !void {
    var buffer: [64 * 1024]u8 = undefined;
    var atomic = try std.fs.cwd().atomicFile(path, .{ .write_buffer = &buffer });
    defer atomic.deinit();
    try leaf.writeJson(&atomic.file_writer.interface);
    try atomic.finish();
}

fn leafWrapCommandWith(comptime CairoLeaf: type, provers: *const circuit_cpu.prove.Provers, gpa: std.mem.Allocator, command: cli.LeafWrap) !void {
    var stderr_buffer: [4096]u8 = undefined;
    var stderr = std.fs.File.stderr().writerStreaming(&stderr_buffer);
    const out = &stderr.interface;
    defer out.flush() catch {};

    var recorder = prover.stage_profile.Recorder.init(gpa, provers.backend_name, "circuit-leaf-wrap");
    defer recorder.deinit();
    var timings = Timings{};
    var leaf = try leafWrapWith(CairoLeaf, gpa, .{
        .registry_path = command.registry,
        .program_path = command.program,
        .prover_input_path = command.prover_input,
        .cairo_proof_path = command.cairo_proof,
        .assets = command.assets,
        .options = .{
            .compact_polynomial_min_log = command.compact_min_log,
            .recorder = if (command.profile) &recorder else null,
        },
        .provers = provers,
    }, &timings);
    defer leaf.deinit();
    try writeLeafProof(&leaf, command.output);
    try out.print(
        "leaf-wrap: load {d:.2} s, cairo prove {d:.2} s, wrap {d:.2} s; circuit hash {f}\n",
        .{ seconds(timings.load_ns), seconds(timings.cairo_prove_ns), seconds(timings.wrap_ns), HashText{ .words = leaf.circuit_hash.words } },
    );
    if (command.profile) {
        var profile = try recorder.snapshot(gpa);
        defer profile.deinit(gpa);
        for (profile.stages) |stage| try printStage(out, stage, 0);
    }
}

fn seconds(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}

fn printStage(out: *std.Io.Writer, stage: prover.stage_profile.StageNode, depth: usize) !void {
    try out.print("{s: >[3]}{s} {d:.3} s\n", .{ "", stage.id, stage.seconds, depth * 2 });
    if (stage.children) |children| for (children) |child| try printStage(out, child, depth + 1);
}

const HashText = struct {
    words: [8]u32,

    pub fn format(self: HashText, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.words) |word| try writer.print("{x:0>8}", .{word});
    }
};

/// The three root files of a recursive tree, as upstream writes them.
pub const RootFiles = struct {
    /// `root.proof`: the Cairo circuit verifier's felt stream.
    proof: std.Io.Writer.Allocating,
    /// `root_outputs.json`.
    outputs: std.Io.Writer.Allocating,
    /// `root_packed.json`.
    packed_tree: std.Io.Writer.Allocating,
    stats: recursion.Stats,

    pub fn deinit(self: *RootFiles) void {
        self.proof.deinit();
        self.outputs.deinit();
        self.packed_tree.deinit();
        self.* = undefined;
    }
};

pub const StageInput = fold_stage.Input;
pub const StageFiles = fold_stage.Files;

/// Fold a bounded, contiguous subtree. Intermediate stages use only the
/// internal circuit profile and publish a resumable proof; the final stage
/// uses the ordinary root profile and publishes the three canonical files.
pub fn foldStageWithSource(
    gpa: std.mem.Allocator,
    registry: wire.registry.CircuitRegistry,
    inputs: []const StageInput,
    provers: *const circuit_cpu.prove.Provers,
    source: ?recursion.proof_source.Source,
    terminal_root: bool,
) !StageFiles {
    if (inputs.len == 0 or (!terminal_root and inputs.len < 2)) return error.InvalidFoldStageSize;
    var stage_timer = try std.time.Timer.start();
    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    var air = try Air.init(gpa);
    defer air.deinit();
    var circuit_table = try air.circuitTable(gpa);
    defer circuit_table.deinit();
    var bundle = try airBundle(gpa);
    defer bundle.deinit();
    const options = recursion.fold.default_options;
    var topologies = recursion.canonical.Cache.init(gpa, .{});
    defer topologies.deinit();
    var device_canonical: ?recursion.CanonicalCircuit = null;
    defer if (device_canonical) |*item| item.deinit(gpa);
    const canonical = blk: {
        if (source != null) {
            device_canonical = try recursion.CanonicalCircuit.buildForDevice(gpa, &circuit_table, registry);
            break :blk &device_canonical.?;
        }
        break :blk try recursion.canonical.acquire(gpa, &topologies, &circuit_table, registry, options);
    };
    const setup_ns = stage_timer.lap();
    var packed_arena = std.heap.ArenaAllocator.init(gpa);
    defer packed_arena.deinit();
    var packed_safe = std.heap.ThreadSafeAllocator{ .child_allocator = packed_arena.allocator() };
    const fold: recursion.Fold = .{
        .canonical = canonical,
        .table = &circuit_table,
        .bundle = &bundle,
        .options = options,
        .provers = provers,
        .source = source,
        .packed_allocator = packed_safe.allocator(),
    };
    const jobs = if (source == null and std.mem.eql(u8, provers.backend_name, "cpu")) parallelFoldJobs(gpa) else 1;
    return fold_stage.run(gpa, &fold, inputs, jobs, terminal_root, &stage_timer, setup_ns);
}

/// `stwo_run_and_prove_recursive_tree` after `load_leaves`: builds the
/// canonical multiverifier of `registry` (checked against it), folds
/// `leaves` in order and renders the three root files.
pub fn foldTree(gpa: std.mem.Allocator, registry: wire.registry.CircuitRegistry, leaves: []const wire.leaf_proof_json.LeafInput) !RootFiles {
    return foldTreeProfiled(gpa, registry, leaves, null);
}

/// `foldTree` with every reduction's stages (build, then the prover's)
/// recorded into `recorder`. Recording never changes the bytes.
pub fn foldTreeProfiled(
    gpa: std.mem.Allocator,
    registry: wire.registry.CircuitRegistry,
    leaves: []const wire.leaf_proof_json.LeafInput,
    recorder: ?*prover.stage_profile.Recorder,
) !RootFiles {
    return foldTreeWithProfiled(gpa, registry, leaves, &circuit_cpu.prove.cpu_provers, recorder);
}

/// `foldTree` with every reduction proved by `provers` (bytes unchanged).
pub fn foldTreeWith(
    gpa: std.mem.Allocator,
    registry: wire.registry.CircuitRegistry,
    leaves: []const wire.leaf_proof_json.LeafInput,
    provers: *const circuit_cpu.prove.Provers,
) !RootFiles {
    return foldTreeWithProfiled(gpa, registry, leaves, provers, null);
}

pub fn foldTreeWithProfiled(
    gpa: std.mem.Allocator,
    registry: wire.registry.CircuitRegistry,
    leaves: []const wire.leaf_proof_json.LeafInput,
    provers: *const circuit_cpu.prove.Provers,
    recorder: ?*prover.stage_profile.Recorder,
) !RootFiles {
    return foldTreeWithSource(gpa, registry, leaves, provers, recorder, null);
}

/// Proof production can be injected without changing the byte-level tree
/// driver. A non-null source performs all circuit STARK proving on its backend.
pub fn foldTreeWithSource(
    gpa: std.mem.Allocator,
    registry: wire.registry.CircuitRegistry,
    leaves: []const wire.leaf_proof_json.LeafInput,
    provers: *const circuit_cpu.prove.Provers,
    recorder: ?*prover.stage_profile.Recorder,
    source: ?recursion.proof_source.Source,
) !RootFiles {
    return foldTreeWithSourceMode(gpa, registry, leaves, provers, recorder, source, false);
}

/// `compact_terminal` keeps the canonical child proof config but sizes the
/// final outer circuit independently. It is valid only for a single root
/// reduction; an internal node must retain the homogeneous registry shape.
pub fn foldTreeWithSourceMode(
    gpa: std.mem.Allocator,
    registry: wire.registry.CircuitRegistry,
    leaves: []const wire.leaf_proof_json.LeafInput,
    provers: *const circuit_cpu.prove.Provers,
    recorder: ?*prover.stage_profile.Recorder,
    source: ?recursion.proof_source.Source,
    compact_terminal: bool,
) !RootFiles {
    if (leaves.len == 0) return error.EmptyLeaves;
    if (compact_terminal and (source == null or leaves.len > 2)) return error.CompactTerminalRequiresSingleDeviceFold;
    var source_stage_timer = try std.time.Timer.start();
    // A proof-scoped worker pool (`STWO_ZIG_WORKERS` sizes it), as R9 folds.
    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    var air = try Air.init(gpa);
    defer air.deinit();
    var circuit_table = try air.circuitTable(gpa);
    defer circuit_table.deinit();
    var bundle = try airBundle(gpa);
    defer bundle.deinit();
    // The canonical circuit with its committed preprocessed tree, by fold
    // topology; every reduction of the tree leases that one commitment.
    // Every reduction stores its trees as `fold.default_options` says.
    var options = recursion.fold.default_options;
    options.recorder = recorder;
    var topologies = recursion.canonical.Cache.init(gpa, .{});
    defer topologies.deinit();
    var device_canonical: ?recursion.CanonicalCircuit = null;
    defer if (device_canonical) |*item| item.deinit(gpa);
    const canonical = blk: {
        var stage = try circuit_cpu.prove.StageScope.begin(recorder, "fold_canonical_build", "build and preprocess the canonical multiverifier");
        defer stage.end();
        if (source != null) {
            device_canonical = if (compact_terminal)
                try recursion.CanonicalCircuit.buildTerminal(gpa, &circuit_table, registry)
            else
                try recursion.CanonicalCircuit.buildForDevice(gpa, &circuit_table, registry);
            if (compact_terminal) std.debug.print("circuit-compact-terminal preprocessed_root_hex={s} circuit_hash_hex={s} target={f}\n", .{
                std.fmt.bytesToHex(device_canonical.?.preprocessed_root, .lower),
                std.fmt.bytesToHex(device_canonical.?.circuit_hash, .lower),
                device_canonical.?.target_sizes,
            });
            break :blk &device_canonical.?;
        }
        break :blk try recursion.canonical.acquire(gpa, &topologies, &circuit_table, registry, options);
    };
    if (source != null) std.debug.print("circuit-fold-stage setup_and_canonical_ns={} leaves={}\n", .{ source_stage_timer.lap(), leaves.len });

    var packed_arena = std.heap.ArenaAllocator.init(gpa);
    defer packed_arena.deinit();
    var packed_safe = std.heap.ThreadSafeAllocator{ .child_allocator = packed_arena.allocator() };
    const fold: recursion.Fold = .{
        .canonical = canonical,
        .table = &circuit_table,
        .bundle = &bundle,
        .options = options,
        .provers = provers,
        .source = source,
        .packed_allocator = packed_safe.allocator(),
    };
    const jobs = if (source == null and recorder == null and std.mem.eql(u8, provers.backend_name, "cpu"))
        parallelFoldJobs(gpa)
    else
        1;
    var folded = try recursion.tree.foldLeavesBounded(gpa, &fold, leaves, jobs);
    defer folded.root.deinit();
    if (source != null) std.debug.print("circuit-fold-stage reductions_ns={} count={}\n", .{ source_stage_timer.lap(), folded.stats.n_pair_reductions });

    var files: RootFiles = .{ .proof = .init(gpa), .outputs = .init(gpa), .packed_tree = .init(gpa), .stats = folded.stats };
    errdefer files.deinit();
    try recursion.tree.writeRootOutputs(&folded.root, &files.proof.writer, &files.outputs.writer, &files.packed_tree.writer);
    if (source != null) std.debug.print("circuit-fold-stage render_ns={}\n", .{source_stage_timer.read()});
    return files;
}

/// Two simultaneous folds nearly double peak memory for a modest M5 speedup.
/// Keep the memory-efficient serial path as the default; operators with a
/// larger memory budget can request two sibling jobs explicitly.
fn parallelFoldJobs(allocator: std.mem.Allocator) usize {
    const override = std.process.getEnvVarOwned(allocator, "STWO_CIRCUIT_FOLD_JOBS") catch null;
    if (override) |value| {
        defer allocator.free(value);
        const parsed = std.fmt.parseInt(usize, value, 10) catch return 1;
        return @min(@max(parsed, 1), 2);
    }
    return 1;
}

/// `stwo_run_and_prove_recursive_tree`: loads the leaves and the registry,
/// folds and writes the three root files.
fn foldTreeCommandWith(provers: *const circuit_cpu.prove.Provers, gpa: std.mem.Allocator, command: cli.FoldTree) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `load_leaves`: the manifest, then every leaf file in order.
    const manifest = try wire.leaf_proof_json.parseLeavesManifest(arena, try readFile(arena, command.program_input));
    const leaves = try arena.alloc(wire.leaf_proof_json.LeafInput, manifest.value.len);
    for (leaves, manifest.value) |*leaf, path| {
        leaf.* = (try wire.leaf_proof_json.parseLeafInput(arena, try readFile(arena, path))).value;
    }
    const registry = try wire.registry.parseRegistry(arena, try readFile(arena, command.circuit_registry_json));

    var recorder = prover.stage_profile.Recorder.init(gpa, provers.backend_name, "circuit-fold-tree");
    defer recorder.deinit();
    var files = try foldTreeWithProfiled(gpa, registry.registry, leaves, provers, if (command.profile) &recorder else null);
    defer files.deinit();
    try writeFile(command.proof_path, files.proof.written());
    try writeFile(command.program_output, files.outputs.written());
    try writeFile(command.packed_output_path, files.packed_tree.written());
    std.log.info("recursive tree: {d} leaves, {d} layers, {d} reductions", .{
        files.stats.n_leaves,
        files.stats.n_layers,
        files.stats.n_pair_reductions,
    });
    if (command.profile) {
        var stderr_buffer: [4096]u8 = undefined;
        var stderr = std.fs.File.stderr().writerStreaming(&stderr_buffer);
        const out = &stderr.interface;
        defer out.flush() catch {};
        var profile = try recorder.snapshot(gpa);
        defer profile.deinit(gpa);
        for (profile.stages) |stage| try printStage(out, stage, 0);
    }
}

/// `verify_circuit` on a proof file: prints the verdict; false when the
/// proof is rejected.
fn verifyCommand(gpa: std.mem.Allocator, command: cli.Verify) !bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const request = try wire.verify_request.parseVerifyRequest(arena, try readFile(arena, command.request));
    const proof = try readFile(arena, command.proof);

    var air = try Air.init(gpa);
    defer air.deinit();
    var circuit_table = try air.circuitTable(gpa);
    defer circuit_table.deinit();
    const verdict = try circuit_cpu.verify.verifyProofBytes(gpa, &circuit_table, &request.request, proof);

    var buffer: [256]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buffer);
    const out = &stdout.interface;
    switch (verdict) {
        .accepted => |digest| try out.print("accepted: output digest {f}\n", .{HashText{ .words = digest }}),
        .rejected => |why| try out.print("rejected at {s}: {s}\n", .{ @tagName(why.stage), @errorName(why.reason) }),
    }
    try out.flush();
    return verdict.isAccepted();
}

/// `circuit-params --registry`: the definition's files are read relative to
/// the working directory, as upstream reads them.
fn circuitParams(gpa: std.mem.Allocator, command: cli.CircuitParams) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const definition = (try wire.registry_definition.parseRegistryDefinition(arena, try readFile(arena, command.definition))).definition;
    const inputs: recursion.circuit_params.Inputs = .{
        .definition = definition,
        .cairo_params = try wire.registry.parseProverParameters(arena, try readFile(arena, definition.cairo_prover_params_json)),
        .circuit_fri_config = try wire.registry.parseFriConfig(arena, try readFile(arena, definition.circuit_fri_config_json)),
        .program = try cairo.statement.circuit_leaf.programFeltsFromCompiledJson(arena, try readFile(arena, definition.program)),
    };

    var air = try Air.init(gpa);
    defer air.deinit();
    var circuit_table = try air.circuitTable(gpa);
    defer circuit_table.deinit();
    var cairo_table = try air.cairoTable(gpa);
    defer cairo_table.deinit();
    var generated = try recursion.circuit_params.generate(gpa, .{ .cairo = &cairo_table, .circuit = &circuit_table }, inputs);
    defer generated.deinit();

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try generated.write(&out.writer);
    if (command.output_path) |path| {
        try writeFile(path, out.written());
    } else {
        try std.fs.File.stdout().writeAll(out.written());
    }
}

test "circuit recursion app: the embedded assets are the authenticated ones" {
    try authenticate(projection_bytes, projection_sha256);
    try authenticate(air_programs_bytes, circuit_cpu.air.bundle_sha256);
}

test {
    _ = cli;
}
