# Prover engine and artifact storage

- [Prover](prover/README.md) owns the backend-generic proving pipeline.
  Import `stwo_prover_engine` for concrete prover construction and use
  [`stwo_prover_api`](../waist/prover_api/README.md) for the transaction contract.
- [Artifact store](artifact_store/README.md) owns persistent artifact storage.
  Its package guide documents `stwo_artifact_store` and its ownership rules.

Products supply the request and publication policy. Frontends provide the AIR
and witness, and backends provide the computation.
