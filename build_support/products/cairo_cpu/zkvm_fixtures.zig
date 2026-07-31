//! Derives the zkvm function-basket ProverInputs from committed programs.
//!
//! The committed artifacts (`vectors/cairo/zkvm/`) are the sha-pinned
//! compiled programs (gzip, deterministic) plus per-case arguments; the big
//! ProverInputs are NOT committed — this step regenerates them through the
//! pinned Cairo VM adapter sidecar into `zig-out/cairo-zkvm/`, and
//! `corpus.provenance.json` records the exact digest and VM-step count every
//! derived file must reproduce. The case list is read from that provenance
//! record at configure time, so a new committed case is picked up with no
//! build change and the two can never drift.

const std = @import("std");
const cairo_vm_adapter = @import("vm_adapter.zig");

const provenance_path = "vectors/cairo/zkvm/corpus.provenance.json";
const output_directory = "zig-out/cairo-zkvm";

pub fn addStep(b: *std.Build) *std.Build.Step {
    const step = b.step(
        "cairo-zkvm-fixtures",
        "Derive the zkvm basket ProverInputs through the pinned Cairo VM adapter",
    );
    const adapter_install = cairo_vm_adapter.addInstall(b);
    b.build_root.handle.makePath(output_directory) catch
        @panic("cannot create the cairo-zkvm output directory");

    const encoded = b.build_root.handle.readFileAlloc(
        b.allocator,
        provenance_path,
        16 * 1024 * 1024,
    ) catch @panic("cannot read the zkvm fixture provenance");
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        b.allocator,
        encoded,
        .{},
    ) catch @panic("cannot parse the zkvm fixture provenance");
    const programs = (parsed.value.object.get("programs") orelse
        @panic("zkvm fixture provenance has no programs")).object;
    const cases = (parsed.value.object.get("cases") orelse
        @panic("zkvm fixture provenance has no cases")).object;

    const adapter_binary = b.getInstallPath(.bin, cairo_vm_adapter.executable_name);
    var it = cases.iterator();
    while (it.next()) |entry| {
        const tag = entry.key_ptr.*;
        const case = entry.value_ptr.*.object;
        const slug = (case.get("program") orelse
            @panic("zkvm fixture case has no program")).string;
        const program = (programs.get(slug) orelse
            @panic("zkvm fixture case names an uncommitted program")).object;
        const compiled = (program.get("compiled_gz") orelse
            @panic("zkvm fixture program has no compiled_gz")).string;
        const arguments = (case.get("arguments") orelse
            @panic("zkvm fixture case has no arguments")).string;
        const run = b.addSystemCommand(&.{
            adapter_binary,
            "run",
            "--program",
            b.pathFromRoot(compiled),
            "--program-type",
            "json",
            "--arguments",
            b.pathFromRoot(arguments),
            "--prover-input-out",
            b.fmt("{s}/{s}.prover_input.json", .{ output_directory, tag }),
            "--overwrite",
        });
        run.step.dependOn(adapter_install);
        step.dependOn(&run.step);
    }
    return step;
}
