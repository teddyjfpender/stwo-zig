# Wrapper2 independent verification preparation

Prepared only for actual `real-wrapper-segment2-devex-v4`, frozen source-v14.
No candidate or expected key is admitted yet; no command was launched.

1. Wait for this exact producer execution to finish with exit0 and guarded3/3
   tests. Preserve/hash its terminal execution and complete-proof log. Require
   selected global2, empty producer allocator and successful internal root-only
   verification, which compares exact public values saved before destruction.
2. Recheck every pinned prerequisite in plan.json. Extract the unique candidate
   path and expected key pin from that trusted run's ROOT_CANDIDATE emission.
   Require the path directly under this run's corpus/root-candidates. Candidate
   key hashing checks consistency with the emitted pin; it cannot admit a key.
3. Require candidate coordinate exactly height0/index2. Record the exact node
   statement/output words as public custody established by the successful
   internal checkExpectedRootPublic; pin key, inputs and proof bytes in a new
   finalized request. Do not recreate protocol hashing or infer a public value
   merely from an unaccepted candidate. Recheck transport length/hash.
4. Run the existing frozen wrapper-root-check-v2 command from plan.json with the
   finalized path/pin. It holds the existing heavy lock per child, limits each
   process to600s and checks genuine verification plus four typed mutations.
   The native-verifier concurrent lane is not admitted for this command.
5. Require checker exit0, all five cases pass, source/verifier unchanged, and
   genuine receipt exact coordinate, statement, output, key/proof pins and size
   equal the finalized request. Retain terminal/scheduling/receipt evidence.

This avoids another preparation or native proof. It proves external acceptance
of one ordinary wrapper leaf; it does not claim a whole-block recursive root.
