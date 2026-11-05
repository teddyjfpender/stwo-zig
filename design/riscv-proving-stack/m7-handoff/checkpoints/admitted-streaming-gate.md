# Admitted early recursion dispatch

Status: source hook only; runtime capability, producer pressure handling, actual retirement and both-block artifact gates remain required. No performance claim or default activation.

`Streaming.deviceOpen()` permits prepared GPU jobs before global native completion only if every lane's device factory supplies `memory_admission_enabled(context)` and returns true. This capability must mean all requested physical devices enforce the global arena/allocation envelope; a local cap or environment flag is insufficient. Factories lacking the optional field or callback preserve the global native barrier.

Leaves enter the prepared queue only after native proof/frame publication with release/acquire ordering. Folds require completed children. Host preparation retains its original during-native throttle. RootCheck continues to wait for `nativeComplete()` and therefore never reads the unfinished native bundle. The report records admitted overlap separately.

This hook cannot itself guarantee progress. Native producer admission must yield outside owner callbacks under pressure, successor demand must include the consumer's retained outputs plus scratch, and consumed native GPU owners must physically retire before their charge disappears. Integration must reject configurations that cannot make progress. Shared pool and physical CUDA ownership also require qualification before activation.
