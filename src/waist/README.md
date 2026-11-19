# Protocol waist

This layer owns the shared interfaces that frontends, engines and backends
use to exchange proof data and operations. Import the smallest package
that supplies the needed contract.

| Module | Contract guide |
| --- | --- |
| `stwo_core` | [Fields, domains, transcript, proof types and verification](core/README.md) |
| `stwo_backend_contracts` | [Backend capabilities and operation contracts](backend/README.md) |
| `stwo_prover_api` | [Prover transaction and observability](prover_api/README.md) |
| `stwo_proof_wire` | [Proof encodings](proof_wire/README.md) |
| `stwo_circuit_recursion_wire` | [Circuit recursion encodings](recursion_wire/README.md) |

The package contracts and their consumer tests define compatibility.
Use the [engineering standards](../../ENGINEERING_STANDARDS.md) when proposing
a change to one of these interfaces.
