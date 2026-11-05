# Native arena admission V2

This is an additive runtime interface. V1 remains a singleton owner window;
V2 permits one window per execution context and multiple contexts per device.
The modes cannot mix within one physical arena. No arithmetic kernel changes.
See `admission_v2.h` for the 176-byte snapshot and seven exports.

`configure_v2`, `enter_v2`, and `end_v2` run on the context owner thread.
`reserve_v2`, `snapshot_v2`, `cancel_v2`, and `finish_v2` are host-safe: they do
not submit owner jobs or call CUDA. They validate the registered raw handle and
monotonic context identity before dereferencing context state. The caller owns
context lifetime and its planner transaction lock. The runtime arena mutex
independently serializes all reservation and allocation accounting.

For each window, `ceiling - baseline` is its rounded **new allocation** budget.
An allocation must belong to its creator context's entered, unended window,
and its current ticket's new live bytes plus the allocation must fit that
budget. Freeing old retained allocations does not enlarge the new budget.
Allocation records retain creator context and ticket across scope promotions;
a free debits that creator, regardless of which context performs it.

On each physical GPU, independently for large chunks and the small slab:

```
unused = sum(window.new_budget - window.new_live)
stable = global_live - sum(window.new_live)
global_live + unused = stable + sum(window.new_budget) <= capacity
```

`reserve_v2` checks that invariant atomically before installing its window.
Unentered cancellation removes only that reservation. A joined owner calls
`end_v2`, which closes its allocation permission and NVTX range while retaining
its window. Its new allocations remain excluded from stable retention.
Under the host planner transaction, `finish_v2` removes only that ended window
and returns a snapshot in which its surviving allocations are now stable.
The end snapshot's `owner_new_live` must be checked against the stage's retained
upper bound before finish; finish zeroes the removed window fields. Peer
active new allocations remain excluded throughout.

A successful context destructor first verifies no allocations and joins its
lanes, then removes only its own terminal window and registered identity.
Foreign identities/tickets, repeated entry/end/finish, cancellation after entry,
allocation before entry/after end, mixed V1/V2, and overflow refuse.

Source implementation is not a performance or proof-parity qualification.
The selected image must replace only `context.o`, retain all math object hashes,
and avoid loading a second old arena runtime through addon dependencies.
