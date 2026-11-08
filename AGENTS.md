# Project execution rules

This repository is in the consolidation and productionisation phase described
in [the delivery contract](design/riscv-proving-stack/rv64-gpu-hygiene.md).
That contract includes the ordered GPU-native promotion and legacy deletion
gates. Do not declare this phase complete from component tests or warm timings.

- [ENGINEERING_STANDARDS.md](ENGINEERING_STANDARDS.md) is binding on every change.
- Use the canonical checkout `/Users/theodorepender/Coding/stwo-zig`.
  Do not create component worktrees. Inspect historical work through its
  archive refs; preserve unique work before retiring a working copy.
- Give each change a subtraction budget before editing. Report code lines
  added/removed/net, flags added/removed/live and scripts added/removed.
  Report documentation, configuration and receipt changes separately.
  Positive code growth needs an explicit ownership or invariant justification.
  File moves do not count as code removal.
- The developer entrypoints are `scripts/dev_test.py`,
  `scripts/rv64_gate.sh` before every push, and `scripts/rv64_m8_bench15.py`
  for the regression basket. Extend these entrypoints and their shared
  libraries; do not add another top-level launcher. Everything else in
  `scripts/` lives in a `scripts/<area>/` package (`scripts/README.md`).
- Keep installation, new-block setup, request execution and publication
  ownership explicit. Derive budgets from the allocation schedule. Preserve
  cancellation, failure and teardown invariants with the owner being moved.
- Never relax proof checks, pins, ceilings, test discovery or rejection
  classification to obtain a passing result. Archive retired code and its
  tests together; retain tests that protect live behavior.
- Keep the pod source frozen during builds, gates and measurements. Use the
  build locks; let hardware harnesses own the GPU lock. Do not run heavy
  compiler or complete-block work on the laptop.
- Pin source, binaries, runtime and workloads. Distinguish host/fake-device,
  hardware correctness, physical memory and qualified timing evidence.
  Require fresh CPU acceptance and the selected semantic negative corpus.
- GPU-native becomes default only after the ordered comparison, setup-miss
  and full-basket gates. Retire legacy paths as one complete sweep afterwards.
  Subsequent performance work starts with measured late feeding and the
  architectural steps in handoff section 5.
