//! Exact Cairo / RISC-V CSP fixture preparation and derivation.
//!
//! Source validation is cheap and always runs.  A fixture is sent through the
//! pinned Cairo VM adapter only after its provenance status says the exact
//! compiled program is authenticated and still awaits derivation.  The output
//! is a review candidate, not authenticated evidence; exact-runnable rows are
//! immutable and are never overwritten by this build step.

const std = @import("std");
const cairo_vm_adapter = @import("vm_adapter.zig");

const provenance_path = "vectors/cairo/csp/fixture-provenance-v1.json";
const validator_path = "scripts/cairo_csp_fixtures.py";
const output_directory = "zig-out/cairo-csp";

pub fn addSteps(b: *std.Build) void {
    const validate = addValidation(b, false);
    const fixtures_step = b.step(
        "cairo-csp-fixtures",
        "Validate exact Cairo CSP sources and derive review candidates for compiled fixtures",
    );
    fixtures_step.dependOn(&validate.step);

    const adapter_install = cairo_vm_adapter.addInstall(b);
    b.build_root.handle.makePath(output_directory) catch
        @panic("cannot create the Cairo CSP output directory");

    const encoded = b.build_root.handle.readFileAlloc(
        b.allocator,
        provenance_path,
        16 * 1024 * 1024,
    ) catch @panic("cannot read the Cairo CSP fixture provenance");
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        b.allocator,
        encoded,
        .{},
    ) catch @panic("cannot parse the Cairo CSP fixture provenance");
    const fixtures = (parsed.value.object.get("fixtures") orelse
        @panic("Cairo CSP fixture provenance has no fixtures")).object;
    const adapter_binary = b.getInstallPath(.bin, cairo_vm_adapter.executable_name);

    var iterator = fixtures.iterator();
    while (iterator.next()) |entry| {
        const name = entry.key_ptr.*;
        const fixture = entry.value_ptr.*.object;
        const status = (fixture.get("status") orelse
            @panic("Cairo CSP fixture has no status")).string;
        if (std.mem.eql(u8, status, "source_ready_compilation_pending") or
            std.mem.eql(u8, status, "exact_runnable"))
            continue;
        if (!std.mem.eql(u8, status, "compiled_ready_derivation_pending")) {
            std.debug.panic(
                "Cairo CSP fixture {s} has unsupported status {s}",
                .{ name, status },
            );
        }

        const compiled = (fixture.get("compiled_program") orelse
            @panic("compiled Cairo CSP fixture has no program")).object;
        const program_path = (compiled.get("path") orelse
            @panic("compiled Cairo CSP program has no path")).string;
        const arguments = (fixture.get("arguments") orelse
            @panic("Cairo CSP fixture has no arguments")).object;
        const arguments_path = (arguments.get("path") orelse
            @panic("Cairo CSP fixture arguments have no path")).string;
        const run = b.addSystemCommand(&.{
            adapter_binary,
            "run",
            "--program",
            b.pathFromRoot(program_path),
            "--program-type",
            "json",
            "--arguments",
            b.pathFromRoot(arguments_path),
            "--prover-input-out",
            b.fmt("{s}/{s}.candidate.prover_input.json", .{ output_directory, name }),
            "--overwrite",
        });
        run.setName(b.fmt("derive Cairo CSP review candidate {s}", .{name}));
        run.step.dependOn(adapter_install);
        run.step.dependOn(&validate.step);
        fixtures_step.dependOn(&run.step);
    }

    const runnable = addValidation(b, true);
    const runnable_step = b.step(
        "cairo-csp-runnable",
        "Require at least one cryptographically linked exact Cairo CSP proof fixture",
    );
    runnable_step.dependOn(&runnable.step);
}

fn addValidation(b: *std.Build, require_runnable: bool) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{
        "python3",
        b.pathFromRoot(validator_path),
        "--root",
        b.pathFromRoot("."),
        "--provenance",
        b.pathFromRoot(provenance_path),
    });
    if (require_runnable)
        command.addArg("--require-runnable");
    command.setName(
        if (require_runnable)
            "require exact runnable Cairo CSP fixture"
        else
            "validate exact Cairo CSP fixture sources",
    );
    return command;
}
