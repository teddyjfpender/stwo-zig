const std = @import("std");

pub const Context = struct {
    b: *std.Build,
    release_phase: []const u8,
    evidence_dir: []const u8,
};

pub fn addGates(context: Context) void {
    const b = context.b;

    // The local gate consumes the committed Sail/Spike evidence. A live formal
    // release run is owned by scripts/riscv_release_gate.py --strict and its
    // caller-supplied formal workspace; legacy Stark-V receipts are not an
    // admission input.
    const contract = b.addSystemCommand(&.{
        "python3", "scripts/check_riscv_release_contract.py", "--all", "--phase", context.release_phase,
    });
    const refinement_contract = b.addSystemCommand(&.{
        "python3", "scripts/riscv_opcode_coverage.py", "check",
    });
    refinement_contract.step.dependOn(&contract.step);
    const vectors = b.addSystemCommand(&.{ "python3", "scripts/riscv_trace_vectors.py" });
    vectors.step.dependOn(&refinement_contract.step);
    const smoke = b.addSystemCommand(&.{
        "python3", "scripts/riscv_staged_smoke.py", "--phase", context.release_phase,
    });
    smoke.step.dependOn(&vectors.step);
    const sail_evidence = b.addSystemCommand(&.{
        "python3", "scripts/riscv_sail_gate.py", "bind",
    });
    sail_evidence.step.dependOn(&smoke.step);
    b.step(
        "riscv-release-gate",
        "Run the staged CLI and validate committed Sail/Spike evidence",
    ).dependOn(&sail_evidence.step);
}
