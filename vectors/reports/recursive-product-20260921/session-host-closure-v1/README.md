# Typed session host dependency boundary

The session imported the broad host facade for HostInterface. That facade also
imports block proving, creating a source path into prover orchestration and legacy
test oracles. Extracted the unchanged host ABI to host/interface.zig, preserved
public aliases, and changed session/options/runtime consumers to narrow imports.
The runtime imports HintOracle directly. No syscall or retirement body changed.

The session source closure shrank from 764 files to 273. A transitive guard now
rejects frontend proving, recursion, legacy/Sail oracles and test files from the
session and runtime closures. Core's existing test import remains outside that
frontend restriction. Stale registry comments now describe host-only non-retirement.

Validation: 55 execution/session/host tests, 49 ownership/isolation guards, two
inventory tests, and git diff whitespace checks pass. Directly invoking zig test
on host/runtime.zig was rejected by Zig's module-root boundary; the existing
frontend test root now explicitly collects host tests and is the supported check.

Full integration qualification follows on frozen source. This report alone does
not qualify complete products. Broader baseline size findings remain open.
