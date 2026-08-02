# Security policy

## Reporting

Please report suspected proof-soundness, verifier, memory-safety, artifact
binding, or backend-fallback vulnerabilities privately to the repository owner
through GitHub's private vulnerability reporting interface. Do not open a
public issue containing an exploit or an unreleased proof forgery.

Include the affected commit, product/backend, smallest reproducer, expected
behavior, observed behavior, and whether an accepted proof or public statement
can be changed. Reports involving Metal or CUDA should also include device and
OS/driver identity.

## Supported surface

Security support follows product state and the exact source identity embedded
in its report. Released CPU products receive fixes on `main`. Parity-gated
Metal products are security reviewed but retain their documented release
gates. Development SM83 and distribution-deferred CUDA surfaces do not carry a
production support promise.

Formal frontend refinement and proof-system soundness are separate claims. The
current RISC-V boundaries are recorded in
[`soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md`](soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md);
no frontend proof should be interpreted as an unconditional cryptographic
soundness theorem.

## Disclosure

The owner will acknowledge a complete report, reproduce it against the named
revision, coordinate a fix and regression test, and publish an advisory after
affected users have a reasonable update path. Timelines depend on severity and
whether an upstream semantic authority is involved.
