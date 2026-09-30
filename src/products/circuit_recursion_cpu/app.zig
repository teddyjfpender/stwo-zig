//! `stwo-circuit-recursion-cpu`: the circuit recursion stage on the CPU
//! (design §7.4).
//!
//! `leaf-wrap` is the Zig counterpart of upstream `leaf-prover`
//! (`crates/leaf_prover/src/main.rs`, https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230): it proves an execution as a
//! leaf Cairo proof under the registry's `cairo_prover_params`, wraps that
//! proof in the registry's leaf verifier circuit and writes the
//! `SerializedLeafProof` file byte for byte as `leaf-prover` does (pretty
//! JSON, no trailing newline).
//!
//! The Zig lane has no Cairo VM, so it starts from the execution the VM and
//! upstream adapter produce (`ProverInput` JSON, as `stwo-circuit-oracle
//! adapt-program` writes it); `leaf-prover` runs those steps itself from the
//! compiled program. The compiled program is still read: its felts are the
//! program the leaf circuit interns, as upstream's `program_felts`.

const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const cairo_leaf = @import("stwo_cairo_cpu_integration").prover.leaf_transaction;
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const prover = @import("stwo_prover_engine");

const leaf_wrap = circuit_cpu.recursion.leaf_wrap;

const usage =
    \\usage: stwo-circuit-recursion-cpu <command> [options]
    \\
    \\commands:
    \\  leaf-wrap   prove an execution as a leaf Cairo proof and wrap it in the
    \\              registry's leaf verifier circuit (upstream leaf-prover)
    \\
    \\leaf-wrap options:
    \\  --registry <path>       circuit registry JSON (cairo_prover_params, leaf verifiers)
    \\  --program <path>        the compiled Cairo program the execution ran
    \\  --prover-input <path>   the adapted execution (ProverInput JSON)
    \\  --output <path>         where to write the SerializedLeafProof JSON
    \\  --assets <dir>          repository root holding vectors/ (default: .)
    \\  --compact-min-log <n|off>
    \\                          keep only coefficients of circuit columns of at least
    \\                          this log size after hashing (default: 18); never
    \\                          changes the proof bytes
    \\  --profile               print the circuit prover's stage times
    \\
;

/// Committed artifacts both proofs read, relative to the assets root.
pub const asset_paths = struct {
    pub const projection = "vectors/circuit/official/compiled_air_constraints_v1.bin";
    pub const circuit_air = circuit_cpu.air.bundle_path;
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
    assets: []const u8 = ".",
    /// Execution choices of the circuit prover; never change bytes.
    options: circuit_cpu.prove.Options = .{},
};

/// Wall time of each stage, in nanoseconds.
pub const Timings = struct {
    load_ns: u64 = 0,
    cairo_prove_ns: u64 = 0,
    wrap_ns: u64 = 0,
};

fn readAsset(allocator: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, limit: usize) ![]u8 {
    return dir.readFileAlloc(allocator, path, limit) catch |err| {
        std.log.err("cannot read {s}: {s}", .{ path, @errorName(err) });
        return err;
    };
}

/// `prove_leaf` from an adapted execution: the leaf Cairo proof, then the
/// wrap. The Cairo trace is released before the wrap starts.
pub fn leafWrap(allocator: std.mem.Allocator, request: LeafWrapRequest, timings: *Timings) !leaf_wrap.LeafProof {
    var timer = try std.time.Timer.start();
    var assets = try std.fs.cwd().openDir(request.assets, .{});
    defer assets.close();

    const registry_text = try readAsset(allocator, std.fs.cwd(), request.registry_path, 64 << 20);
    defer allocator.free(registry_text);
    var registry = try wire.registry.parseRegistry(allocator, registry_text);
    defer registry.deinit();

    const program_json = try readAsset(allocator, std.fs.cwd(), request.program_path, 256 << 20);
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
        const programs_path = try std.fs.path.join(allocator, &.{ request.assets, asset_paths.witness_programs });
        defer allocator.free(programs_path);
        var programs = try cairo.witness.bundle.Bundle.readFile(allocator, programs_path);
        defer programs.deinit();
        const topology_path = try std.fs.path.join(allocator, &.{ request.assets, asset_paths.feed_topology });
        defer allocator.free(topology_path);
        var topology = try cairo.witness.feed_topology.readOfficial(allocator, topology_path);
        defer topology.deinit();
        const fixed_path = try std.fs.path.join(allocator, &.{ request.assets, asset_paths.fixed_tables });
        defer allocator.free(fixed_path);
        var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(allocator, fixed_path);
        defer fixed.deinit();
        const relations_path = try std.fs.path.join(allocator, &.{ request.assets, asset_paths.relation_templates });
        defer allocator.free(relations_path);
        var relations = try cairo.witness.relation_bundle.Bundle.readFile(allocator, relations_path);
        defer relations.deinit();
        const templates_path = try std.fs.path.join(allocator, &.{ request.assets, asset_paths.air_templates });
        defer allocator.free(templates_path);
        var air_templates = try cairo.air.template_library.Library.readFile(allocator, templates_path);
        defer air_templates.deinit();
        break :blk try cairo_leaf.proveLeafCairo(allocator, .{
            .input = &input,
            .programs = &programs,
            .topology = topology,
            .fixed = &fixed,
            .relations = &relations,
            .air_templates = &air_templates,
        }, registry.registry.cairo_prover_params, null);
    };
    defer cairo_proof.deinit();
    timings.cairo_prove_ns = timer.lap();

    // Steps 4-8: the wrap.
    const projection_bytes = try readAsset(allocator, assets, asset_paths.projection, 64 << 20);
    defer allocator.free(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(allocator, projection_bytes);
    defer projection.deinit();
    var cairo_table = try circuit.air_eval.cairo_components.build(allocator, &projection);
    defer cairo_table.deinit();
    const bundle_bytes = try readAsset(allocator, assets, asset_paths.circuit_air, 64 << 20);
    defer allocator.free(bundle_bytes);
    var bundle = try circuit_cpu.air.parse(allocator, bundle_bytes);
    defer bundle.deinit();

    var cache = leaf_wrap.Cache.init(allocator, .{});
    defer cache.deinit();
    const wrap = leaf_wrap.LeafWrap{
        .registry = &registry.registry,
        .cairo_table = &cairo_table,
        .bundle = &bundle,
        .program = program,
        .cache = &cache,
        .options = request.options,
    };
    const leaf = try leaf_wrap.wrapCairoProof(allocator, &wrap, &cairo_proof, &input);
    timings.wrap_ns = timer.lap();
    return leaf;
}

/// Writes `leaf` to `path` atomically.
pub fn writeLeafProof(leaf: *const leaf_wrap.LeafProof, path: []const u8) !void {
    var buffer: [64 * 1024]u8 = undefined;
    var atomic = try std.fs.cwd().atomicFile(path, .{ .write_buffer = &buffer });
    defer atomic.deinit();
    try leaf.writeJson(&atomic.file_writer.interface);
    try atomic.finish();
}

const Arguments = struct {
    registry: ?[]const u8 = null,
    program: ?[]const u8 = null,
    prover_input: ?[]const u8 = null,
    output: ?[]const u8 = null,
    assets: []const u8 = ".",
    compact_min_log: ?u32 = default_compact_min_log,
    profile: bool = false,
};

/// Compact storage from 2^18-row columns: the circuit proof's large columns
/// keep coefficients only, which bounds the wrap's resident memory.
pub const default_compact_min_log: u32 = 18;

fn parseLeafWrap(args: []const []const u8) !Arguments {
    var parsed = Arguments{};
    var index: usize = 0;
    while (index < args.len) {
        const name = args[index];
        if (std.mem.eql(u8, name, "--profile")) {
            parsed.profile = true;
            index += 1;
            continue;
        }
        if (index + 1 >= args.len) return error.MissingOptionValue;
        const value = args[index + 1];
        index += 2;
        if (std.mem.eql(u8, name, "--compact-min-log")) {
            parsed.compact_min_log = if (std.mem.eql(u8, value, "off"))
                null
            else
                std.fmt.parseInt(u32, value, 10) catch return error.InvalidOptionValue;
        } else if (std.mem.eql(u8, name, "--registry")) {
            parsed.registry = value;
        } else if (std.mem.eql(u8, name, "--program")) {
            parsed.program = value;
        } else if (std.mem.eql(u8, name, "--prover-input")) {
            parsed.prover_input = value;
        } else if (std.mem.eql(u8, name, "--output")) {
            parsed.output = value;
        } else if (std.mem.eql(u8, name, "--assets")) {
            parsed.assets = value;
        } else return error.UnknownOption;
    }
    return parsed;
}

fn seconds(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var stderr_buffer: [4096]u8 = undefined;
    var stderr = std.fs.File.stderr().writerStreaming(&stderr_buffer);
    const err_out = &stderr.interface;
    defer err_out.flush() catch {};

    if (args.len < 2 or !std.mem.eql(u8, args[1], "leaf-wrap")) {
        try err_out.writeAll(usage);
        std.process.exit(2);
    }
    const parsed = parseLeafWrap(args[2..]) catch |err| {
        try err_out.print("leaf-wrap: {s}\n{s}", .{ @errorName(err), usage });
        std.process.exit(2);
    };
    const registry = parsed.registry orelse return usageError(err_out, "--registry");
    const program = parsed.program orelse return usageError(err_out, "--program");
    const prover_input = parsed.prover_input orelse return usageError(err_out, "--prover-input");
    const output = parsed.output orelse return usageError(err_out, "--output");

    var recorder = prover.stage_profile.Recorder.init(allocator, "cpu", "circuit-leaf-wrap");
    defer recorder.deinit();
    var timings = Timings{};
    var leaf = try leafWrap(allocator, .{
        .registry_path = registry,
        .program_path = program,
        .prover_input_path = prover_input,
        .assets = parsed.assets,
        .options = .{
            .compact_polynomial_min_log = parsed.compact_min_log,
            .recorder = if (parsed.profile) &recorder else null,
        },
    }, &timings);
    defer leaf.deinit();
    try writeLeafProof(&leaf, output);
    try err_out.print(
        "leaf-wrap: load {d:.2} s, cairo prove {d:.2} s, wrap {d:.2} s; circuit hash {f}\n",
        .{ seconds(timings.load_ns), seconds(timings.cairo_prove_ns), seconds(timings.wrap_ns), HashText{ .words = leaf.circuit_hash.words } },
    );
    if (parsed.profile) {
        var profile = try recorder.snapshot(allocator);
        defer profile.deinit(allocator);
        for (profile.stages) |stage| try printStage(err_out, stage, 0);
    }
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

fn usageError(out: *std.Io.Writer, option: []const u8) !void {
    try out.print("leaf-wrap: missing {s}\n{s}", .{ option, usage });
    try out.flush();
    std.process.exit(2);
}

test "leaf-wrap arguments: every option, and failures" {
    const parsed = try parseLeafWrap(&.{ "--registry", "r.json", "--program", "p.json", "--prover-input", "i.json", "--output", "o.json", "--assets", "/repo" });
    try std.testing.expectEqualStrings("r.json", parsed.registry.?);
    try std.testing.expectEqualStrings("p.json", parsed.program.?);
    try std.testing.expectEqualStrings("i.json", parsed.prover_input.?);
    try std.testing.expectEqualStrings("o.json", parsed.output.?);
    try std.testing.expectEqualStrings("/repo", parsed.assets);
    try std.testing.expectEqual(@as(?u32, default_compact_min_log), parsed.compact_min_log);
    try std.testing.expect(!parsed.profile);
    const tuned = try parseLeafWrap(&.{ "--profile", "--compact-min-log", "off", "--output", "o.json" });
    try std.testing.expect(tuned.profile);
    try std.testing.expectEqual(@as(?u32, null), tuned.compact_min_log);
    try std.testing.expectEqualStrings("o.json", tuned.output.?);
    try std.testing.expectError(error.InvalidOptionValue, parseLeafWrap(&.{ "--compact-min-log", "x" }));
    try std.testing.expectError(error.MissingOptionValue, parseLeafWrap(&.{"--registry"}));
    try std.testing.expectError(error.UnknownOption, parseLeafWrap(&.{ "--bogus", "x" }));
}
