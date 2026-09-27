# Canonical mixed standalone source

`src/frontends/riscv/block_v5_cpu_mixed_fixture_write.zig` writes the exact
canonical `csp_q70_pow26` source used by `block_v5_cpu_driver_test.zig`:
three setup instructions, three NOPs, SHA/Keccak/SHA, three NOPs, and six
terminal instructions. `buildReleaseProgram` supplies the same production
Ethereum/SHA ABI and 256-byte initialized data. Input is empty; oracle is the
single byte `01`. With the maximum segment length of six cycles, the qualified
canonical driver test executes 17 cycles in three segments, with sparse caller
ordinal one, 132 memory events and 21 proof files.

The generator imports only fixture/ISA code and the Zig standard library; it
does not import the proof driver or require a protocol module map. It creates
the requested directory and all files exclusively. Choose fresh paths:

```sh
zig build-exe -OReleaseFast -lc -mcpu=native \
  src/frontends/riscv/block_v5_cpu_mixed_fixture_write.zig \
  -femit-bin=/tmp/block-v5-canonical-fixture
/tmp/block-v5-canonical-fixture /tmp/block-v5-canonical-source

zig build stwo-ethereum-block-v5-cpu-produce -Doptimize=ReleaseFast
zig-out/bin/stwo-ethereum-block-v5-cpu-produce \
  /tmp/block-v5-canonical-source/mixed.elf \
  /tmp/block-v5-canonical-source/input.bin \
  /tmp/block-v5-canonical-source/oracle.bin \
  6 \
  5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b \
  /tmp/block-v5-canonical-bundle
```

The explicit job ID matches the test's `[32]u8` filled with decimal 91. The
production CLI selects q70/PoW26 and fresh complete reception internally;
its report records process timing, RSS, hashes and proof sizes. This note
does not claim that the generator or this standalone command has run: only
source formatting/AST checks were authorized for the generator while another
task held the build lane. It does not infer independent detached-verifier pins
from the generated source or from bundle proof metadata.
