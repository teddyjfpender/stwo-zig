# Caller-only native segment completeness

The existing streaming cut of three cycles can place only precompile instructions
in one segment. `block_v7_native_source_v1.Pin.validate` rejected every
`n_components == 0` shape, despite genuine executed retirements and a caller proof.
Changing segment boundaries to avoid it hides a supported-program gap.

The problem matches a finite empty execution envelope: no ordinary opcode
constraint exists, but public machine boundaries and every external retirement
still require authentication. The exact existing primitive is
`block_v5_native_frame_v1`: one fixed selector, four constant geometry columns,
one constrained zero interaction column, and six equations at log size two.
`block_v6_partitioned_native_components_v1` and the shared recursive
`block_v6_partitioned_composition_v1.recordEquations` already implement it.

Chosen design (implementation brief agreed before coding):

- Keep the ordinary opcode route and its identities unchanged.
- Admit a separate all-external shape only when there are zero opcode components,
  `external_retirements == total_steps > 0`, and the public cycle count agrees.
  Any retained infrastructure must be the original clock-update component.
- For a completely empty logical native/clock shape, reuse the exact physical
  frame above. Declare and commit its zero interaction pad, which the six
  original equations constrain. Empty projection claims do not replace this
  physical proof.
- Add the B7BN source discriminator only for these previously rejected shapes.
  Existing nonempty source keys and proof transcripts remain unchanged.
- Retain all original clock rows, per-window register/state residuals, caller
  retirement proofs, ROM boundary compensation, independent ELF initialization,
  and the RAM first-halt/terminal-output argument. The frame itself proves only
  geometry; it never claims to prove a precompile or global execution alone.

A planner merge was rejected as the primary fix: runs of caller instructions can
exceed the maximum allowed segment size, and silently extending that bound is
not a sound resource policy. The finite envelope supports the requested cut
without skipping or adding cycles.

Required qualification: original full execution at cuts one and three; mutations
of PC/register endpoints, external retirement count, ROM root, halt address and
public output; exact cold/live frame geometry and a freshly verified recursive
parent. Source proof and recursive root qualification must be reported separately.
The previous nonempty small/large execution tests remain regression coverage.

Current original-proof status: all three source runs pass 11 tests at q=8,
PoW=0. Cut three produces seven native, one caller and three provider proofs,
including one genuine physical native frame. Cut one produces twenty native,
three caller and three provider proofs, including three physical native frames.
All 103 RAM events remain accounted for; ROM requests are respectively 26 and 39
because each additional native segment has its authenticated boundary request.
No cycles are skipped, extended or invented.

The original receiver runs after every checkpoint file has been deleted. Tests
reject changed register/PC endpoints, external count, ROM root, halt address and
public result, plus an altered OODS opening of the actual constrained frame pad.
The ordinary three-segment path also passes on the same binary. Diagnostic whole
source times were 6.62 seconds at cut three and 10.54 seconds at cut one; these
are shared-host correctness observations, not controlled benchmarks.

Evidence: `vectors/reports/block-v7-boundary-envelope-20261029/receipt.json`,
`results.tsv` and the three logs. The exact existing frame algebra is shared with
the cold symbolic recorder, but final recursive-parent qualification of these
new source geometries remains a separate required gate. All-external shapes with
retained clock infrastructure preserve the original clock equations; these
specific executions exercise the zero-infrastructure physical-frame case.
