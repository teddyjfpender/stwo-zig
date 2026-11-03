# Strict existing-proof OM31 recursion receiver

`execution_wrap.verifyExisting(a, setups, truths, bundle, expected, config,
fixed, recursive_dir)` is a separate receiver API. Existing proving and resume
entries remain controls. The caller independently admits the native execution,
expected image/output, roster and fixed authority before this recursion check.

The receiver first requires every canonical binary-carry leaf and fold filename,
plus `root.proof` and `tree.json`. Missing or non-file nodes fail before verifier
graph construction. Every later node read must still return encoded proof bytes;
there is no proving factory or missing-node fallback. All node counts must be
reported as restored, with zero new CPU or GPU proofs.

Leaves and parents use the same original trace-only verifier graph constructors
as GPU proving. The receiver explicitly requires empty assignment storage. It
rebuilds each original PP/Authority, decodes against that authority and expected
digest, and independently verifies the native OM31 proof. It then performs the
same ordered fold adjacency, root verification and complete execution/manifest
closure as the ordinary route. Generation metadata is not an accepted proof or
an alternate constraint authority.

The physical root proof must exactly match the freshly verified final node.
The physical tree must match the canonical tree reconstructed from admitted
statements and fresh node verifications. Root/tree reads are bounded by their
expected canonical sizes. The receiver does not rewrite node proofs, root,
tree or producer report, preserving artifact hashes and producer timings.
Its returned report names `cpu_trace_only_receiver` and
`none_receiver_trace_only` explicitly.

Fast checks force the actual API's semantic reachability, reject missing last
fold/root/tree and non-file nodes before graph construction, and reject flipped
root/tree bytes without publication. Actual proof/reference qualification also
checks a CPU leaf proof restored under its independently rebuilt trace-only
key, identical proof bytes and zero assignment storage. Complete production-root
and basket receiver qualification remains a separate physical gate.
