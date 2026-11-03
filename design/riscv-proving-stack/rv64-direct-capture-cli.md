# Direct execution in the GKR Ethereum CLI

Use `JOBS=-` in the existing `produce-candidate`, `produce-control`, `plan` or
`capture` command to execute and hand off compact tapes in process. Other
JOBS arguments retain the packet-directory route. The existing `direct.zig`
authority performs the same packet admission and ordered execution checks;
this change selects that already-qualified implementation from the CLI.

`capture_options.execution_workers` is an explicit operational choice:
zero uses the serial executing walk, and 1–32 select the existing fast
checkpoint pass plus concurrent segment replay. `max_inflight_packets`
continues to bound execution-to-capture handoff. Execution workers are rejected
on the directory route instead of being silently ignored. These options do not
enter any statement, verifier identity or transcript.

```
rv64-word16-ethereum-gkr capture REQUEST.json - 1 RESOURCES.json
rv64-word16-ethereum-gkr --security-profile conjectured128_b2_q108_p20_fold4 \
  produce-candidate REQUEST.json - OUTPUT 0 RESOURCES.json
```

RESOURCES is a JSON **file**, as on the historical CLI. Add
`"execution_workers": 2` inside its `capture_options` object to select a
two-worker replay. The `capture` diagnostic uses the control resource schema;
candidate production additionally requires `fixed_setup_bytes`.

Reports label `capture_source` and expose `direct_capture` execution/join and
segment statistics. `packet_import_ns` is zero on the direct route, while
`capture_ns` includes execution and capture. The earlier cached-packet numbers
excluded execution/job production and must not be compared as end-to-end
execution time. Removing serialization and overlapping replay does not by
itself establish a two-second block execution claim.

Validation: the capture-prefetch ReleaseFast suite and the actual ReleaseFast
GKR Ethereum driver build pass. The suite includes direct/disk parity,
parallel segment parity and forged tape/identity/resource rejection.
