# Coefficient-sized selective openings at every extension rate

The previous half-scratch path only recognized a2x extension. The beta2
engineering candidate uses4x, so every large opening fell back to a full LDE
scratch window. At CPU log22 this meant64MiB per worker and only two workers
under the existing128MiB scratch target. The new window is16MiB, allowing eight
workers under the same target. No expanded polynomial is retained or cached.

Zero padding makes each leading FFT layer duplicate its lower input: its upper
operand is zero. After all such layers, each aligned coefficient-sized window
therefore starts with the original coefficients. We visit only windows with
requested positions and run the existing selected-tail butterfly authority
from `log2(coefficient_count)-1`. Global twiddle indices retain the full-domain
offset. The radix8 window primitive already used these indices; its former
half-only assertion now admits any aligned power-of-two subwindow and checks
that its highest stage fits that window.

The32-row bottom kernel sets the minimum window size. Smaller coefficients use
the old full-buffer path. Existing callers may still pass a full buffer.
Sorted targets, duplicates and output order are preserved; alias, size and
twiddle validation precede stores. Both queue and wave scratch planners use
one length authority. There is no allocation proportional to unqueried windows
and no change to proof geometry, fields, transcript or receiver rules.

Safe/Fast tests compare all outputs at small logs against full packed FFTs and
scalar circle-basis evaluation, plus sparse larger logs, high extension rates,
window boundaries, repeated targets, mixed-height Merkle bytes, invalid inputs
and all allocation-failure exits. An independent source review accepted the
basis, twiddle, ownership and admission arguments.

Six alternating real4.19M-step beta2 candidate runs give median trace decommit
1.891→0.722 seconds and total proving13.495→12.036 seconds. All four durable
artifacts match in every run and all six fresh receivers accept. These are
shared-host observations, not hardware-isolated performance claims. The
engineering profile remains explicitly unqualified for whole-protocol128
security. Evidence is in
`vectors/reports/rv64-coefficient-window-20261102/qualification.json`.
