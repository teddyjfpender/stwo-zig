# Canonical typed execution and recursion cleanup qualified

The final frozen cleanup source passed complete CPU/Metal/AOT products and
the useful 16-address 1/2/4/8 continuation ladder. This qualifies the legacy
executor/opcode AIR retirement, test-oracle isolation, shared commitment/session
ownership and narrow execution/host dependency boundary.

- 384 complete-product acceptance/rejection checks; 21 baseline-identical artifacts.
- 1,110 continuation checks; 78 baseline-identical artifacts.
- Eight fresh standalone root verification and RSS measurements, without native inputs.
- Required native, leaf and parent GPU interaction dispatches passed.
- All 6,208 frozen source files replayed from the archived patch using temporary indexes.
- All 114 pinned inputs and archive contents rechecked.
- Focused validation before freeze: 55 session/host tests, 49 ownership guards,
  two inventory tests; earlier batches retain their affected-test evidence.

| Segments | Backend | Production s | Root bytes | Verify ms | Root RSS bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | cpu | 9.800 | 2481525 | 73.690 | 19529728 |
| 1 | metal | 8.244 | 2481525 | 73.071 | 19529728 |
| 2 | cpu | 30.179 | 2418969 | 69.650 | 15745024 |
| 2 | metal | 23.734 | 2418969 | 68.404 | 16367616 |
| 4 | cpu | 72.094 | 2287573 | 67.092 | 15253504 |
| 4 | metal | 54.378 | 2287573 | 69.584 | 16236544 |
| 8 | cpu | 153.198 | 2297319 | 70.442 | 15450112 |
| 8 | metal | 115.526 | 2297319 | 69.838 | 16252928 |

Measurements are individual observations, not speed claims. The admitted q193
profile is developmental and Metal execution is hybrid. This does not certify
production security, strict GPU execution or Ethereum readiness.

The broader baseline goal remains open with 103 source-size findings. Those
findings are not additional typed execution/recursion implementation tasks.
Source snapshots, patch replay, pinned inputs, commands and result summaries
are retained beside this report. All qualification subprocesses exited successfully.
