This is a necessary-condition candidate-policy qualification, not a 128-bit
certificate, proof acceptance change, performance measurement or full-paper
security audit. The main protocol, engineering q70 control and all defaults are
unchanged. See design/riscv-proving-stack/rv64-om31-128-candidate-ledger.md for
source authority, costs, assumptions and explicit remaining gates.

Reproduce from repository root:

```
zig test -OReleaseSafe --dep stwo_core -Mroot=src/integrations/riscv_cpu/rv64_om31_security_candidate_test_root.zig -Mstwo_core=src/core/mod.zig
zig test -OReleaseFast --dep stwo_core -Mroot=src/integrations/riscv_cpu/rv64_om31_security_candidate_test_root.zig -Mstwo_core=src/core/mod.zig
```

Both pass 7 reachable tests. The budget JSON records conditional root counts,
explicitly unreviewed theorem/envelope categories, exact query rational
arithmetic, the candidate identity and final registry refusal. Native β1 setup
is rejected by the β2 candidate parameter admission. An unrestricted 128-work
security claim is not inferred from the bounded T≤2^120 RO arithmetic audit.
