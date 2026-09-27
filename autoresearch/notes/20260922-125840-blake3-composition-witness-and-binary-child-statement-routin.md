---
title: BLAKE3 composition witness and binary child statement routing
author: Teddy Pender
created_utc: 2026-09-22T12:58:40Z
---

# BLAKE3 composition witness and binary statement-word routing

The composition input writer now has a BLAKE3 profile selecting the new
composition compiler and separate witness/schedule domains. Legacy and BLAKE3
profiles share the direct column implementation. Source validation delegates to
the corresponding compiler, removing a duplicate bound/type check implementation.
The BLAKE3 writer-binding digest is
`4a0996766809b948198f02a8c7de5c1d04cc240c542ccae8b79b6280e87e10fb`.

Qualification:

```
python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Doptimize=ReleaseSafe --summary all
```

Passed; final outer build reported 11 seconds and 909 MB peak RSS. The focused
gate has a 63-named-test minimum and includes the seven existing row-18 checks,
the prior compiler/statement gates and two new composition-witness tests.
The authenticated synthetic compiler fixture also calls the new writer via
`Preprocessed.initFromReference`, verifies emitted values and padding, and rejects
a modified schedule seal before changing any output column. This exercises the
authenticated compiled-schedule path, not the raw-schedule test constructor.

The new routing test authenticates the row-10, row-11 and row-18 typed interaction
plans. For every word of two distinct canonical child statements (1,050 tuples),
it checks domain, arity and all tuple coordinates, and confirms that the provider's
multiplicity two cancels one statement-semantics request plus one composition
request. The statement-semantics schedule comes from the sealed BLAKE3 graph;
composition rows in this tuple test are explicit coordinate fixtures. The separate
compiled-reference test covers compiler/writer admission. This is not a full
production composition graph or a global relation-closure proof.

Remaining: construct production BLAKE3 source/public-claim projections and graph
references, replace the Poseidon identity preimages/hash constraints, migrate
artifact/key admission and qualify recursive proofs across levels. Other relation
domains, native memory commitments and production defaults are not qualified by
this routing test. The original recursion/performance goal remains incomplete.
