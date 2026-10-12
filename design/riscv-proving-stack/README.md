# RISC-V proving stack design

Start with the [current bounded plan](plan.md). The notes are grouped by the system they describe:

| Directory | Scope |
| --- | --- |
| [architecture/](architecture/) | Frontend authority, component layout, replay, and hash migration. |
| [block-v5/execution/](block-v5/execution/) | Block execution, scoping, public exports, and scheduling. |
| [block-v5/memory/](block-v5/memory/) | Block memory ownership, page and word transport, read-only inputs. |
| [block-v5/recursion/](block-v5/recursion/) | Recursive verifier transport and closure for block-v5. |
| [block-v5/performance/](block-v5/performance/) | Capacity and production performance studies. |
| [memory/](memory/) | General memory-source and Keccak design. |
| [recursion/](recursion/) | General recursive AIR and verifier architecture. |
| [performance/](performance/) | Benchmarks, budgets, and workload ladders. |
| [operations/](operations/) | Checkpoints and operational goals. |

Retained measurements and reports live under [`vectors/reports/`](../../vectors/reports/), not in this design dossier.
