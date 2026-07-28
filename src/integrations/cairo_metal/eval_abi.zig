//! The two trace-indexing ABIs an emitted composition kernel can implement.
//!
//! Increment 3.7 §3 recorded the mismatch this file exists to close: the
//! compiled kernels read columns at *evaluation-domain* length and the product
//! publishes them at *trace-domain* length, so increment 3.8's hook has to
//! materialise a lifted `2^eval_log`-word copy of every column before it can
//! dispatch (8.4-53.4 ms and 0.76-4.80 GB of staging per proof, 3.7 §4).
//!
//! `stored_domain` is 3.7 §5's option B: teach the kernel the shift and let it
//! read the stored column in place.

const eval = @import("stwo_cairo_frontend").witness.eval_program;

/// How an emitted kernel indexes a trace column.
///
/// `eval_domain` is the ABI every compiled library in the tree implements and
/// stays the codegen default: `row` runs over the evaluation domain and indexes
/// the column directly.
///
/// `stored_domain` applies the product's own lifting map
/// `((row >> shift) << 1) + (row & 1)` inside the kernel, with `shift` —
/// `simd_evaluator.ResolvedColumn.shift_amt`, i.e. `eval_log - column_log + 1`
/// — read per column out of the runtime base-parameter block.
///
/// **Base-parameter block layout under `stored_domain`**, chosen so that no
/// `EvalLayout` offset, FFI signature or Objective-C binding changes: the block
/// begins at `args.base_params` with the program's own `n_base_params` words,
/// immediately followed by one `shift_amt` word per *global* column. The kernel
/// therefore addresses the table at `args.base_params + n_base_params`, a
/// compile-time constant of the program, so no new kernel argument is needed and
/// `.param` emission is untouched — which is what lets a parameterized program
/// (increment 3.10 part B) use this ABI unchanged.
pub const TraceAbi = enum {
    eval_domain,
    stored_domain,

    /// Kernels of the two ABIs read different arena shapes out of the same
    /// offsets, so they are named apart: a library-ABI mismatch then surfaces as
    /// a by-name resolution failure instead of as silent corruption.
    pub fn nameInfix(self: TraceAbi) []const u8 {
        return switch (self) {
            .eval_domain => "",
            .stored_domain => "sd_",
        };
    }

    /// Where a part's shift table starts, given the part's own parameter count.
    pub fn shiftTableOffset(self: TraceAbi, base_params: u32, program: eval.Program) u32 {
        return switch (self) {
            .eval_domain => base_params,
            .stored_domain => base_params + program.header.n_base_params,
        };
    }
};

/// Option B's reader, appended to the shared preamble for `stored_domain`
/// emission only — so the default preamble stays byte-identical to the source
/// the pending eval-domain mint is compiled from.
///
/// The offset map is applied first and the lift second, which is the order the
/// host row loop uses (`simd_evaluator.evaluatePartRange` computes `positions`
/// and only then applies `shift_amt`).
pub const stored_domain_reader =
    \\inline uint trace_value_stored(device uint *arena, constant EvalArgs &args, uint interaction, uint column, uint row, int offset, uint shift_base) {
    \\    uint target=offset==0 ? row : offset_circle(row,args.domain_log_size,ctz(args.row_count),offset);
    \\    uint global=arena[args.interaction_offsets+interaction]+column;
    \\    uint index=((target>>arena[shift_base+global])<<1)+(target&1u);
    \\    return arena[arena[args.trace_offsets+global]+index];
    \\}
    \\
;
