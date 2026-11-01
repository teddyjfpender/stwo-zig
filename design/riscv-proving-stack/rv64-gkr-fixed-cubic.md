# GKR cubic interpolation without generic factors

GKR's correction polynomial is a cubic with values `r(0)=r0`, `r(1)=r1`, `r(2)=r2` and `r(b)=0`. The previous implementation, like the pinned Rust Stwo implementation, calls generic Lagrange interpolation. It performs12secure inversions, including for the zero fourth value, and allocates intermediate polynomial factors.

The shared field-generic correction now uses Newton's basis. Set `delta=r1-r0`, `A=(r2-2r1+r0)/2` and `C=-(r0+delta*b+A*b*(b-1))/(b*(b-1)*(b-2))`. The monomial coefficients are `{r0,delta-A+2C,A-3C,C}`. This needs one secure inversion and one four-coordinate polynomial allocation. The existing prefix and b inversions remain, so the complete correction uses three inversions instead of14.

This is the same polynomial and transcript. No challenge is resampled. Poles `b=0,1,2` reject even for zero numerator values; the original degenerate y challenges retain their DivisionByZero errors. Existing `UnivariatePoly.initOwned` applies the same trailing-zero trimming, including zero, linear and quadratic cases. Tests compare actual coefficient slices with generic Lagrange for dense Q/OM values, lower degrees and poles, and inject every new allocation failure.

The explicit pre-change capture also repairs a pre-existing test harness flaw: checking `@hasDecl(@import("root"),"baseline")` inside a Zig test saw the test runner rather than the capture root. The harness now passes the reference type directly. The initial packed-slice32-test pre-change claim is superseded by this actual38-test pinned-source comparison; its independent scalar numerical tests remain valid.

With the packed numerical slice, the shared-host mixed-height four-gate fixture measured Q101.2ms→24.2ms and OM151.6ms→42.1ms at one worker against the actual171de6ab8 scalar source. Four-worker new times were21.8ms and34.4ms respectively. Complete proof bytes and next transcript draws match exactly, with fresh independent terminal-MLE binding verification. A100-iteration interpolation micro measured about68×Q and65×OM; that isolates removal of small heap factors as well as inversions. These are fixture/micro timings, not a full-block or GPU performance claim.

Raw logs, reproduction command and qualification scope live in `vectors/reports/rv64-gkr-cubic-20261101/`. The native proof-system security profile and production admission policy remain unchanged.
