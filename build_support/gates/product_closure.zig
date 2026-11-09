//! Descriptor-driven transitive source, dynamic-link, and static-ELF gate.

const std = @import("std");
const policy = @import("../graph/product.zig");

pub const Inputs = struct {
    b: *std.Build,
    descriptor: policy.Descriptor,
    binary: ?*std.Build.Step.Compile = null,
    static_binary: ?*std.Build.Step.Compile = null,
    static_machine: []const u8 = "x86_64",
    static_bits: u16 = 64,
};

pub fn addCheck(inputs: Inputs) *std.Build.Step.Run {
    const descriptor = inputs.descriptor;
    descriptor.validate() catch |err| std.debug.panic(
        "invalid closure descriptor {s}: {s}",
        .{ descriptor.product.name, @errorName(err) },
    );
    const closure = descriptor.source_closure.?;
    const check = inputs.b.addSystemCommand(&.{
        "python3",
        "scripts/repo/check_product_closure.py",
        "--product",
        descriptor.product.name,
    });
    addRepeated(check, "--entry-root", closure.entry_roots);
    for (closure.named_imports) |named| {
        check.addArg("--named-import");
        check.addArg(inputs.b.fmt("{s}={s}", .{ named.name, named.source }));
    }
    addRepeated(check, "--generated-import", closure.generated_imports);
    addRepeated(check, "--allow-file", closure.allowed_files);
    addRepeated(check, "--allow-prefix", closure.allowed_prefixes);
    addRepeated(check, "--require-link", closure.required_dynamic_dependencies);
    addRepeated(check, "--forbid-link", closure.forbidden_dynamic_dependencies);
    if (inputs.binary) |binary| {
        check.addArg("--binary");
        check.addArtifactArg(binary);
    }
    if (inputs.static_binary) |binary| {
        check.addArg("--static-binary");
        check.addArtifactArg(binary);
        check.addArgs(&.{
            "--static-machine",
            inputs.static_machine,
            "--static-bits",
            inputs.b.fmt("{d}", .{inputs.static_bits}),
        });
    }
    check.addArg("--receipt");
    check.addArg(inputs.b.pathFromRoot(inputs.b.fmt(
        "zig-out/release-evidence/architecture/product-closures/{s}.json",
        .{descriptor.product.name},
    )));
    return check;
}

fn addRepeated(run: *std.Build.Step.Run, flag: []const u8, values: []const []const u8) void {
    for (values) |value| {
        run.addArg(flag);
        run.addArg(value);
    }
}
