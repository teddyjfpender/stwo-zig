# Admit both base execution witnesses before consuming either

Status: four-leaf tree gate passed, including invalid second-child rejection before first-child consumption.

Base paired aggregation previously checked verifier identity and custody for both
children, but deferred witness-phase and hash-plan checks to each child's proving
call. A consumed or mismatched second witness could therefore fail after the first
child had generated interactions. Ethereum already used non-consuming admission.

Base execution now shares its non-consuming phase/hash-plan validation between
one-shot proving and segment admission. The existing four-leaf tree fixture checks
that a consumed or mismatched second child rejects while leaving the first child
unconsumed, then proves the ordinary tree. This fixture also exercises the new
parent coefficient-retention/streaming policy across multiple aggregate levels.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation '-Driscv-test-filter=BLAKE3 adjacent segments form a four-leaf tree' -Doptimize=ReleaseSafe --summary all
```

The waiting wrapper was stopped before it spawned any build/test child so the
small layout and PCS ownership regressions can run first. Those checks passed; the gate is now requeued behind the canonical Metal retry. No passing runtime
result is claimed yet.

## Qualification result

The four-leaf/two-level CPU tree gate passed with compact fixed rows and the
non-consuming base paired-admission checks. It verified two height-one nodes and
an independently verified root; retained root rows were 669,671,752 bytes.
The two-job bounded pipeline reused its plan, overlapped preparation/proving
(10,780,157,791 ns measured overlap), and verified outputs after worker destruction.
Tracked worker peak: 3,862,465,628 bytes under an 8 GiB cap. Root artifact: 131,497
bytes. Wrapper: 5 minutes, 6 GiB MaxRSS including compilation. This remains the
diagnostic q8/PoW0 tree, not canonical-parameter aggregation or a speed benchmark.
