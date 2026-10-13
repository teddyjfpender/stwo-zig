//! One-shot check of the circuit AIR's native mask offsets.
//!
//! The native verifier derives each component's mask points from the
//! captured programs' `trace_col` immediates (`resident_geometry.
//! componentOffsets`). The Lean `circuitAir.maskPoints` hard-codes the
//! expected shape: every base-trace column at offset `[0]`, every
//! interaction column at `[0]` except the last four per component (the
//! cumulative sums) at `[-1, 0]`. This tool parses
//! `vectors/circuit/official/circuit_air.air_programs_v1.bin` and verifies
//! that shape, exiting nonzero on any deviation.
//!
//! Build (from the repo root):
//!   zig build-exe \
//!     --dep stwo_core --dep composition_bundle \
//!     -Mroot=formal/in-circuit-verifier/harness/maskcheck.zig \
//!     --dep stwo_core \
//!     -Mcomposition_bundle=src/frontends/cairo/witness/composition_bundle.zig \
//!     -Mstwo_core=src/core/mod.zig -O ReleaseSafe

const std = @import("std");
const bundle_mod = @import("composition_bundle");

const bundle_path = "vectors/circuit/official/circuit_air.air_programs_v1.bin";

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = gpa_state.allocator();

    const bytes = try std.fs.cwd().readFileAlloc(gpa, bundle_path, 1 << 28);
    var bundle = try bundle_mod.Bundle.parse(gpa, bytes);
    defer bundle.deinit();

    var bad: usize = 0;
    for (bundle.components) |component| {
        std.debug.print("{s}: eval_delta {d} rc_offset {d} n_constraints {d}\n", .{
            component.label,
            component.evaluation_log_size - component.trace_log_size,
            component.random_coefficient_offset,
            component.n_constraints,
        });
        inline for ([_]u32{ 1, 2 }) |tree| {
            // `resident_geometry.componentOffsets`, inlined: first-use-order
            // distinct `trace_col` immediates per column of this tree.
            var span_len: usize = 0;
            for (component.trace_spans) |span| if (span.tree == tree) {
                span_len = span.end - span.start;
            };
            const offsets = try gpa.alloc(std.ArrayList(i32), span_len);
            for (offsets) |*list| list.* = .empty;
            defer {
                for (offsets) |*list| list.deinit(gpa);
                gpa.free(offsets);
            }
            for (component.parts) |part| for (part.program.base_insts) |instruction| {
                if (instruction.op != .trace_col or instruction.interaction != tree) continue;
                var exists = false;
                for (offsets[instruction.a].items) |existing| exists = exists or existing == instruction.imm;
                if (!exists) try offsets[instruction.a].append(gpa, instruction.imm);
            };
            for (offsets, 0..) |list, column| {
                const is_cumsum = tree == 2 and column + 4 >= offsets.len;
                const ok = if (is_cumsum)
                    list.items.len == 2 and list.items[0] == -1 and list.items[1] == 0
                else
                    list.items.len == 1 and list.items[0] == 0;
                if (!ok) {
                    bad += 1;
                    std.debug.print("UNEXPECTED {s} tree {d} column {d}: {any}\n", .{
                        component.label, tree, column, list.items,
                    });
                }
            }
        }
    }
    if (bad == 0) {
        std.debug.print(
            "mask offsets as modeled for all {d} components: base [0], cumsum [-1, 0], other interaction [0]\n",
            .{bundle.components.len},
        );
    } else {
        std.debug.print("{d} deviating columns\n", .{bad});
        std.process.exit(1);
    }
}
