//! Command contract of the circuit recursion CPU product (design §7.4).
//!
//! Flag names follow the upstream binaries of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, so a pipeline that runs them can
//! run this product unchanged:
//!
//! - `fold-tree`: `stwo_run_and_prove_recursive_tree` (`--program_input`,
//!   `--proof_path`, `--program_output`, `--packed_output_path`,
//!   `--circuit_registry_json`, each `--flag value` or `--flag=value`);
//! - `circuit-params`: `circuit-params --definition D --registry
//!   [--output-path P]`. Only the registry output exists; upstream's
//!   human-readable sizes report is not ported.

const std = @import("std");

pub const Command = enum {
    @"fold-tree",
    @"circuit-params",
};

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
};

pub const CircuitParams = struct {
    /// The registry definition; the paths inside resolve against the
    /// working directory, as upstream's.
    definition: []const u8,
    /// Standard output when absent.
    output_path: ?[]const u8,
};

pub const Parsed = union(enum) {
    fold_tree: FoldTree,
    circuit_params: CircuitParams,
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
};

pub const usage =
    \\usage: stwo-circuit-recursion-cpu fold-tree --program_input LEAVES.json --proof_path ROOT.proof
    \\           --program_output ROOT_OUTPUTS.json --packed_output_path ROOT_PACKED.json
    \\           --circuit_registry_json REGISTRY.json
    \\       stwo-circuit-recursion-cpu circuit-params --definition DEFINITION.json --registry
    \\           [--output-path REGISTRY.json]
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
        .@"fold-tree" => .{ .fold_tree = try parseFlags(FoldTree, argv[1..], &.{}) },
        .@"circuit-params" => blk: {
            var registry = false;
            const parsed = try parseFlags(struct { definition: []const u8, output_path: ?[]const u8 }, argv[1..], &.{.{ .name = "--registry", .set = &registry }});
            if (!registry) return error.RegistryOutputRequired;
            break :blk .{ .circuit_params = .{ .definition = parsed.definition, .output_path = parsed.output_path } };
        },
    };
}

fn isHelp(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "help");
}

const Switch = struct { name: []const u8, set: *bool };

/// Fills `T`'s string fields from `--field value`, `--field=value` or, for
/// fields named with `_`, the same flag spelt with `-` (upstream's
/// `circuit-params` uses `--output-path`). Optional fields may be absent.
fn parseFlags(comptime T: type, argv: []const []const u8, switches: []const Switch) Error!T {
    const fields = std.meta.fields(T);
    var values: [fields.len]?[]const u8 = @splat(null);
    var index: usize = 0;
    next: while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (!std.mem.startsWith(u8, arg, "--")) return error.UnexpectedArgument;
        for (switches) |flag| if (std.mem.eql(u8, arg, flag.name)) {
            if (flag.set.*) return error.DuplicateFlag;
            flag.set.* = true;
            continue :next;
        };
        const eq = std.mem.indexOfScalar(u8, arg, '=');
        const name = arg[2 .. eq orelse arg.len];
        inline for (fields, 0..) |field, slot| {
            if (flagMatches(field.name, name)) {
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

fn flagMatches(comptime field: []const u8, name: []const u8) bool {
    if (std.mem.eql(u8, field, name)) return true;
    if (name.len != field.len) return false;
    for (field, name) |want, got| {
        if (want == got) continue;
        if (want == '_' and got == '-') continue;
        return false;
    }
    return true;
}

test "circuit recursion cli: fold-tree takes upstream's flags in either spelling" {
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
    try std.testing.expectError(error.MissingRequiredFlag, parse(&.{ "fold-tree", "--program_input", "x" }));
    try std.testing.expectError(error.MissingValue, parse(&.{ "fold-tree", "--program_input" }));
    try std.testing.expectError(error.DuplicateFlag, parse(&.{ "fold-tree", "--proof_path", "a", "--proof_path", "b" }));
    try std.testing.expectError(error.UnknownFlag, parse(&.{ "fold-tree", "--leaves", "a" }));
}

test "circuit recursion cli: circuit-params requires --registry" {
    const parsed = try parse(&.{ "circuit-params", "--definition", "d.json", "--registry", "--output-path", "r.json" });
    try std.testing.expectEqualStrings("d.json", parsed.circuit_params.definition);
    try std.testing.expectEqualStrings("r.json", parsed.circuit_params.output_path.?);
    const stdout = try parse(&.{ "circuit-params", "--registry", "--definition=d.json" });
    try std.testing.expectEqual(@as(?[]const u8, null), stdout.circuit_params.output_path);
    try std.testing.expectError(error.RegistryOutputRequired, parse(&.{ "circuit-params", "--definition", "d.json" }));
    try std.testing.expectError(error.UnknownCommand, parse(&.{"leaf-wrap"}));
    try std.testing.expectError(error.MissingCommand, parse(&.{}));
}
