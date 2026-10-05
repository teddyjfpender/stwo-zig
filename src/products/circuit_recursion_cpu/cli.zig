//! Command contract of the circuit recursion CPU product (design §7.4).
//!
//! Flag names follow the upstream binaries of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 where the inputs are the same,
//! spelt as clap spells them (each `--flag value` or `--flag=value`):
//!
//! - `leaf-wrap`: `leaf-prover` from an adapted execution (`--registry`,
//!   `--program`, `--prover-input`, `--output`, `--assets`,
//!   `--compact-min-log`, `--profile`; upstream's `--circuit_registry_json`
//!   and `--output_path` are accepted for `--registry` and `--output`). The
//!   Zig lane has no Cairo VM, so the execution arrives as upstream's adapter
//!   writes it (`stwo-circuit-oracle adapt-program`) instead of as
//!   `leaf-prover`'s `--program_input`: that step still needs the Rust VM,
//!   and a pipeline runs the adapter, then this command;
//! - `fold-tree`: `stwo_run_and_prove_recursive_tree` (`--program_input`,
//!   `--proof_path`, `--program_output`, `--packed_output_path`,
//!   `--circuit_registry_json`), drop-in, plus this product's `--profile`;
//! - `fold-stage`, `fold-stage-campaign`, and `fold-stage-root`: bounded, resumable subtrees over
//!   typed leaf/checkpoint entries. The root command emits the same three
//!   files as `fold-tree`;
//! - `circuit-params`: `circuit-params --definition D --registry
//!   [--output-path P]`. Only the registry output exists; upstream's
//!   human-readable sizes report is not ported;
//! - `verify`: upstream `verify_circuit` on a `CircuitSerialize` proof
//!   (`--proof`, `--request`), the request in the format of
//!   `stwo-circuit-oracle verify-circuit --request`. Upstream ships no
//!   binary for it; the flags are the oracle's.

const std = @import("std");

pub const Command = enum {
    @"leaf-wrap",
    @"prove-cairo",
    @"fold-tree",
    @"fold-stage",
    @"fold-stage-campaign",
    @"fold-stage-root",
    @"circuit-params",
    verify,
};

pub const LeafWrap = struct {
    /// The circuit registry (`cairo_prover_params`, the leaf verifiers).
    registry: []const u8,
    /// The compiled Cairo program the execution ran; its felts are the
    /// program the leaf circuit interns.
    program: []const u8,
    /// The adapted execution (`ProverInput` JSON or compact CPI).
    prover_input: []const u8,
    /// Where the `SerializedLeafProof` JSON goes.
    output: []const u8,
    /// Optional pinned-Rust-verifier JSON of the embedded Cairo proof.
    cairo_proof: ?[]const u8,
    /// The repository root holding the Cairo lane's committed bundles.
    assets: []const u8,
    /// Circuit columns of at least this log size keep only coefficients
    /// once hashed; null keeps evaluations too. Never changes the bytes.
    compact_min_log: ?u32,
    /// Print the circuit prover's stage times.
    profile: bool,
};

pub const ProveCairo = struct {
    registry: []const u8,
    prover_input: []const u8,
    output: []const u8,
    assets: ?[]const u8,
};

/// Compact storage from 2^18-row columns: the circuit proof's large columns
/// keep coefficients only, which bounds the wrap's resident memory.
pub const default_compact_min_log: u32 = 18;

pub const FoldTree = struct {
    /// `{"leaves": ["<path>", ...]}`, leaf files in fold order.
    program_input: []const u8,
    /// The root proof: the Cairo circuit verifier's felt stream.
    proof_path: []const u8,
    /// The root output digest (`root_outputs.json`).
    program_output: []const u8,
    /// The packed-output tree (`root_packed.json`).
    packed_output_path: []const u8,
    /// The registry the leaves were proven against.
    circuit_registry_json: []const u8,
    /// Print each reduction's stage times (this product's flag; upstream
    /// has none).
    profile: bool = false,
};

pub const FoldStage = struct {
    manifest: []const u8,
    registry: []const u8,
    checkpoint: []const u8,
};

pub const FoldStageCampaign = struct {
    jobs: []const u8,
    registry: []const u8,
};

pub const FoldStageRoot = struct {
    manifest: []const u8,
    registry: []const u8,
    proof: []const u8,
    outputs: []const u8,
    packed_output: []const u8,
};

pub const CircuitParams = struct {
    /// The registry definition; the paths inside resolve against the
    /// working directory, as upstream's.
    definition: []const u8,
    /// Standard output when absent.
    output_path: ?[]const u8,
};

pub const Verify = struct {
    /// The `CircuitSerialize` proof bytes.
    proof: []const u8,
    /// The verified circuit's config, layout, root and claimed output
    /// digest (`wire.verify_request`).
    request: []const u8,
};

pub const Parsed = union(enum) {
    leaf_wrap: LeafWrap,
    prove_cairo: ProveCairo,
    fold_tree: FoldTree,
    fold_stage: FoldStage,
    fold_stage_campaign: FoldStageCampaign,
    fold_stage_root: FoldStageRoot,
    circuit_params: CircuitParams,
    verify: Verify,
    help: void,
};

pub const Error = error{
    MissingCommand,
    UnknownCommand,
    UnknownFlag,
    MissingValue,
    DuplicateFlag,
    MissingRequiredFlag,
    /// `circuit-params` without `--registry`: the sizes report is not ported.
    RegistryOutputRequired,
    UnexpectedArgument,
    /// `--compact-min-log` is neither a log size nor `off`.
    InvalidValue,
};

pub const usage =
    \\usage: stwo-circuit-recursion-cpu leaf-wrap --registry REGISTRY.json --program PROGRAM.json
    \\           --prover-input PROVER_INPUT.json --output LEAF.json [--assets DIR]
    \\           [--cairo-proof CAIRO.json] [--compact-min-log N|off] [--profile]
    \\       stwo-circuit-recursion-cpu prove-cairo --registry REGISTRY.json
    \\           --prover-input PROVER_INPUT.json --output CAIRO.json [--assets DIR]
    \\       stwo-circuit-recursion-cpu fold-tree --program_input LEAVES.json --proof_path ROOT.proof
    \\           --program_output ROOT_OUTPUTS.json --packed_output_path ROOT_PACKED.json
    \\           --circuit_registry_json REGISTRY.json [--profile]
    \\       stwo-circuit-recursion-cpu fold-stage --manifest ENTRIES.json --registry REGISTRY.json
    \\           --checkpoint NODE.json
    \\       stwo-circuit-recursion-cpu fold-stage-campaign --jobs JOBS.json --registry REGISTRY.json
    \\       stwo-circuit-recursion-cpu fold-stage-root --manifest ENTRIES.json --registry REGISTRY.json
    \\           --proof ROOT.proof --outputs ROOT_OUTPUTS.json --packed-output ROOT_PACKED.json
    \\       stwo-circuit-recursion-cpu circuit-params --definition DEFINITION.json --registry
    \\           [--output-path REGISTRY.json]
    \\       stwo-circuit-recursion-cpu verify --proof PROOF.bin --request REQUEST.json
    \\
;

pub fn parse(argv: []const []const u8) Error!Parsed {
    if (argv.len == 0) return error.MissingCommand;
    if (isHelp(argv[0])) {
        if (argv.len != 1) return error.UnexpectedArgument;
        return .{ .help = {} };
    }
    const command = std.meta.stringToEnum(Command, argv[0]) orelse return error.UnknownCommand;
    return switch (command) {
        .@"leaf-wrap" => blk: {
            var profile = false;
            const parsed = try parseFlags(struct {
                registry: []const u8,
                program: []const u8,
                prover_input: []const u8,
                output: []const u8,
                cairo_proof: ?[]const u8,
                assets: ?[]const u8,
                compact_min_log: ?[]const u8,
            }, argv[1..], .{
                .spelling = .kebab,
                .switches = &.{.{ .name = "--profile", .set = &profile }},
                .aliases = &.{
                    .{ .flag = "circuit_registry_json", .field = "registry" },
                    .{ .flag = "output_path", .field = "output" },
                },
            });
            if (parsed.cairo_proof) |path| {
                if (std.mem.eql(u8, path, parsed.output) or
                    std.mem.eql(u8, path, parsed.prover_input) or
                    std.mem.eql(u8, path, parsed.registry) or
                    std.mem.eql(u8, path, parsed.program))
                    return error.InvalidValue;
            }
            break :blk .{ .leaf_wrap = .{
                .registry = parsed.registry,
                .program = parsed.program,
                .prover_input = parsed.prover_input,
                .output = parsed.output,
                .cairo_proof = parsed.cairo_proof,
                .assets = parsed.assets orelse ".",
                .compact_min_log = try compactMinLog(parsed.compact_min_log),
                .profile = profile,
            } };
        },
        .@"prove-cairo" => .{ .prove_cairo = try parseFlags(ProveCairo, argv[1..], .{ .spelling = .kebab }) },
        .@"fold-tree" => blk: {
            var profile = false;
            const parsed = try parseFlags(struct {
                program_input: []const u8,
                proof_path: []const u8,
                program_output: []const u8,
                packed_output_path: []const u8,
                circuit_registry_json: []const u8,
            }, argv[1..], .{
                .spelling = .snake,
                .switches = &.{.{ .name = "--profile", .set = &profile }},
            });
            break :blk .{ .fold_tree = .{
                .program_input = parsed.program_input,
                .proof_path = parsed.proof_path,
                .program_output = parsed.program_output,
                .packed_output_path = parsed.packed_output_path,
                .circuit_registry_json = parsed.circuit_registry_json,
                .profile = profile,
            } };
        },
        .@"fold-stage" => .{ .fold_stage = try parseFlags(FoldStage, argv[1..], .{ .spelling = .kebab }) },
        .@"fold-stage-campaign" => .{ .fold_stage_campaign = try parseFlags(FoldStageCampaign, argv[1..], .{ .spelling = .kebab }) },
        .@"fold-stage-root" => .{ .fold_stage_root = try parseFlags(FoldStageRoot, argv[1..], .{ .spelling = .kebab }) },
        .@"circuit-params" => blk: {
            var registry = false;
            const parsed = try parseFlags(struct { definition: []const u8, output_path: ?[]const u8 }, argv[1..], .{
                .spelling = .kebab,
                .switches = &.{.{ .name = "--registry", .set = &registry }},
            });
            if (!registry) return error.RegistryOutputRequired;
            break :blk .{ .circuit_params = .{ .definition = parsed.definition, .output_path = parsed.output_path } };
        },
        .verify => .{ .verify = try parseFlags(Verify, argv[1..], .{ .spelling = .kebab }) },
    };
}

fn compactMinLog(value: ?[]const u8) Error!?u32 {
    const text = value orelse return default_compact_min_log;
    if (std.mem.eql(u8, text, "off")) return null;
    return std.fmt.parseInt(u32, text, 10) catch error.InvalidValue;
}

fn isHelp(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "help");
}

const Switch = struct { name: []const u8, set: *bool };

/// How a field's flag is spelt: `snake` is the field name
/// (`#[clap(long = "proof_path")]`), `kebab` has each `_` as `-` (clap's
/// derived `#[clap(long)]`, and this product's own flags).
const Spelling = enum { snake, kebab };

/// Another flag name for a field (upstream's spelling of the same input).
const Alias = struct { flag: []const u8, field: []const u8 };

const FlagOptions = struct {
    spelling: Spelling,
    switches: []const Switch = &.{},
    aliases: []const Alias = &.{},
};

/// Fills `T`'s string fields from `--field value` or `--field=value`, the
/// name spelt as `options.spelling` says or as an alias. Optional fields may
/// be absent; a field given twice, under any name, is an error.
fn parseFlags(comptime T: type, argv: []const []const u8, options: FlagOptions) Error!T {
    const fields = std.meta.fields(T);
    var values: [fields.len]?[]const u8 = @splat(null);
    var index: usize = 0;
    next: while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (!std.mem.startsWith(u8, arg, "--")) return error.UnexpectedArgument;
        for (options.switches) |flag| if (std.mem.eql(u8, arg, flag.name)) {
            if (flag.set.*) return error.DuplicateFlag;
            flag.set.* = true;
            continue :next;
        };
        const eq = std.mem.indexOfScalar(u8, arg, '=');
        const given = arg[2 .. eq orelse arg.len];
        var aliased: ?[]const u8 = null;
        for (options.aliases) |alias| if (std.mem.eql(u8, given, alias.flag)) {
            aliased = alias.field;
        };
        inline for (fields, 0..) |field, slot| {
            const matches = if (aliased) |name| std.mem.eql(u8, field.name, name) else flagMatches(field.name, given, options.spelling);
            if (matches) {
                if (values[slot] != null) return error.DuplicateFlag;
                if (eq) |at| {
                    values[slot] = arg[at + 1 ..];
                } else {
                    index += 1;
                    if (index == argv.len) return error.MissingValue;
                    values[slot] = argv[index];
                }
                continue :next;
            }
        }
        return error.UnknownFlag;
    }
    var result: T = undefined;
    inline for (fields, 0..) |field, slot| {
        if (field.type == ?[]const u8) {
            @field(result, field.name) = values[slot];
        } else {
            @field(result, field.name) = values[slot] orelse return error.MissingRequiredFlag;
        }
    }
    return result;
}

fn flagMatches(comptime field: []const u8, name: []const u8, spelling: Spelling) bool {
    if (name.len != field.len) return false;
    for (field, name) |want, got| {
        const expected = if (want == '_' and spelling == .kebab) '-' else want;
        if (expected != got) return false;
    }
    return true;
}

test "circuit recursion cli: leaf-wrap options, defaults and failures" {
    const parsed = try parse(&.{ "leaf-wrap", "--registry", "r.json", "--program", "p.json", "--prover-input", "i.json", "--output", "o.json", "--assets", "/repo" });
    try std.testing.expectEqualStrings("r.json", parsed.leaf_wrap.registry);
    try std.testing.expectEqualStrings("p.json", parsed.leaf_wrap.program);
    try std.testing.expectEqualStrings("i.json", parsed.leaf_wrap.prover_input);
    try std.testing.expectEqualStrings("o.json", parsed.leaf_wrap.output);
    try std.testing.expectEqualStrings("/repo", parsed.leaf_wrap.assets);
    const cairo_dump = try parse(&.{ "leaf-wrap", "--registry", "r.json", "--program", "p.json", "--prover-input", "i.json", "--output", "o.json", "--cairo-proof", "c.json" });
    try std.testing.expectEqualStrings("c.json", cairo_dump.leaf_wrap.cairo_proof.?);
    try std.testing.expectError(error.InvalidValue, parse(&.{ "leaf-wrap", "--registry", "r.json", "--program", "p.json", "--prover-input", "i.json", "--output", "o.json", "--cairo-proof", "i.json" }));
    try std.testing.expectEqual(@as(?u32, default_compact_min_log), parsed.leaf_wrap.compact_min_log);
    try std.testing.expect(!parsed.leaf_wrap.profile);
    const tuned = try parse(&.{ "leaf-wrap", "--profile", "--compact-min-log", "off", "--registry=r", "--program=p", "--prover-input=i", "--output=o" });
    try std.testing.expect(tuned.leaf_wrap.profile);
    try std.testing.expectEqual(@as(?u32, null), tuned.leaf_wrap.compact_min_log);
    try std.testing.expectEqualStrings(".", tuned.leaf_wrap.assets);
    const sized = try parse(&.{ "leaf-wrap", "--compact-min-log", "20", "--registry=r", "--program=p", "--prover-input=i", "--output=o" });
    try std.testing.expectEqual(@as(?u32, 20), sized.leaf_wrap.compact_min_log);
    try std.testing.expectError(error.InvalidValue, parse(&.{ "leaf-wrap", "--compact-min-log", "x", "--registry=r", "--program=p", "--prover-input=i", "--output=o" }));
    try std.testing.expectError(error.MissingRequiredFlag, parse(&.{ "leaf-wrap", "--registry", "r.json" }));
    try std.testing.expectError(error.MissingValue, parse(&.{ "leaf-wrap", "--registry" }));
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "leaf-wrap", "--bogus", "x" }));
    try std.testing.expectError(error.DuplicateFlag, parse(&.{ "leaf-wrap", "--profile", "--profile" }));
    // Upstream `leaf-prover`'s spellings of the registry and output.
    const upstream = try parse(&.{ "leaf-wrap", "--circuit_registry_json", "r", "--program", "p", "--prover-input", "i", "--output_path=o" });
    try std.testing.expectEqualStrings("r", upstream.leaf_wrap.registry);
    try std.testing.expectEqualStrings("o", upstream.leaf_wrap.output);
    try std.testing.expectError(error.DuplicateFlag, parse(&.{ "leaf-wrap", "--registry", "a", "--circuit_registry_json", "b" }));
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "leaf-wrap", "--prover_input", "i" }));
}

test "circuit recursion cli: pinned Cairo proof accepts an adapted input" {
    const parsed = try parse(&.{ "prove-cairo", "--registry=r.json", "--prover-input", "a.cpi", "--output", "proof.json" });
    try std.testing.expectEqualStrings("r.json", parsed.prove_cairo.registry);
    try std.testing.expectEqualStrings("a.cpi", parsed.prove_cairo.prover_input);
    try std.testing.expectEqualStrings("proof.json", parsed.prove_cairo.output);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.prove_cairo.assets);
    try std.testing.expectError(error.MissingRequiredFlag, parse(&.{ "prove-cairo", "--registry", "r.json" }));
}

test "circuit recursion cli: fold-tree takes upstream's flags, in either value form" {
    const parsed = try parse(&.{
        "fold-tree",
        "--program_input",
        "leaves.json",
        "--proof_path=root.proof",
        "--program_output",
        "out.json",
        "--packed_output_path",
        "packed.json",
        "--circuit_registry_json",
        "registry.json",
    });
    try std.testing.expectEqualStrings("leaves.json", parsed.fold_tree.program_input);
    try std.testing.expectEqualStrings("root.proof", parsed.fold_tree.proof_path);
    try std.testing.expectEqualStrings("registry.json", parsed.fold_tree.circuit_registry_json);
    try std.testing.expect(!parsed.fold_tree.profile);
    const profiled = try parse(&.{ "fold-tree", "--profile", "--program_input=l", "--proof_path=p", "--program_output=o", "--packed_output_path=k", "--circuit_registry_json=r" });
    try std.testing.expect(profiled.fold_tree.profile);
    try std.testing.expectError(error.DuplicateFlag, parse(&.{ "fold-tree", "--profile", "--profile" }));
    try std.testing.expectError(error.MissingRequiredFlag, parse(&.{ "fold-tree", "--program_input", "x" }));
    try std.testing.expectError(error.MissingValue, parse(&.{ "fold-tree", "--program_input" }));
    try std.testing.expectError(error.DuplicateFlag, parse(&.{ "fold-tree", "--proof_path", "a", "--proof_path", "b" }));
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "fold-tree", "--leaves", "a" }));
    // clap's `long = "proof_path"` takes no dashed spelling.
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "fold-tree", "--proof-path", "a" }));
}

test "circuit recursion cli: circuit-params requires --registry" {
    const parsed = try parse(&.{ "circuit-params", "--definition", "d.json", "--registry", "--output-path", "r.json" });
    try std.testing.expectEqualStrings("d.json", parsed.circuit_params.definition);
    try std.testing.expectEqualStrings("r.json", parsed.circuit_params.output_path.?);
    const stdout = try parse(&.{ "circuit-params", "--registry", "--definition=d.json" });
    try std.testing.expectEqual(@as(?[]const u8, null), stdout.circuit_params.output_path);
    try std.testing.expectError(error.RegistryOutputRequired, parse(&.{ "circuit-params", "--definition", "d.json" }));
    // clap's derived `--output-path`, not the field name.
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "circuit-params", "--registry", "--definition=d", "--output_path", "r" }));
    try std.testing.expectError(error.UnknownCommand, parse(&.{"verify-circuit"}));
    try std.testing.expectError(error.MissingCommand, parse(&.{}));
}

test "circuit recursion cli: verify takes a proof and a request" {
    const parsed = try parse(&.{ "verify", "--proof", "p.bin", "--request=r.json" });
    try std.testing.expectEqualStrings("p.bin", parsed.verify.proof);
    try std.testing.expectEqualStrings("r.json", parsed.verify.request);
    try std.testing.expectError(error.MissingRequiredFlag, parse(&.{ "verify", "--proof", "p.bin" }));
}
