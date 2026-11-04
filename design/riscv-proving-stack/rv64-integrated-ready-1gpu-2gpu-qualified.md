# Integrated one/two GPU full-block qualification

All three configurations below freshly proved Ethereum block24628607 and passed
an independent ARM CPU receiver. Every19native proof/accounting binary, bundle,
34recursive proof files including root, and ordered tree match the previously
accepted block exactly. The receiver independently rebuilt authority, restored
all17leaves and16folds, proved zero new nodes, and preserved every artifact.

| Configuration | Request wall | Native proving | Recursion | Process wall | Process peak RSS |
|---|---:|---:|---:|---:|---:|
|2GPU, CPU FIXED setup (D1)|147.555s|12.085s|110.880s|153.812s|19.725GB|
|2GPU, device FIXED setup (A8)|98.924s|10.326s|63.621s|104.862s|14.924GB|
|1GPU, device FIXED setup (A8)|136.901s|12.810s|99.897s|142.120s|12.609GB|

Request wall includes capture, native setup/proving/verification, fresh GPU
recursion, publication and lifecycle audit. Process wall additionally includes
initial pool creation and teardown. GPU FIXED1/2 uses the same executable,
runtime, request, profile and8total workers, partitioned8 versus4+4. Its observed
request ratio is1.384× and recursion ratio1.570×. These are single ordered
observations, not medians or a complete basket scaling result.

The2GPU CPU/device FIXED comparison uses different D1/A8 source binaries.
Observed request wall falls33.0% and recursion42.6%, but native proving also
varies12.085→10.326s. This is not a same-binary flag-only causal comparison.
Old239s one-GPU results used another host/source and are not a clean scaling
control. No4GPU or worst-shape qualification is established here.

Hardware was two RTX5090s on one AMD EPYC9654 host,40.8CPU quota,93GBcontainer
memory and PHB connectivity. Shared prover host admission remained48GiB and
logical device admission28GiB per device. Sampled whole-device peak was
33,663,483,904 bytes per used device in every case; pool/driver retention is
included and this is not an exact process allocation peak. Recovered owner OOM
events were16,28and27 respectively, so no memory/recovery improvement is claimed.
Every endBlock audited zero request leases. The producer's broader hardware
qualification flag remains closed; these receipts qualify this one block only.

The independent0025 ARM receiver used4workers,32GiBrequested live heap and its
qualified4GiBrecycler. Setup-cache environment was unset. Original producer
plans/requests stayed immutable; only explicit hash-checked local guest/input
paths and worker4 were used in receiver operational copies. All three CPU checks
accepted. The compact JSON receipt pins results, logs, plans, binaries, manifests,
full original artifact hashes and exact timing/memory units.

An initial attempt failed because the pinned circuit AIR file was absent before
any outer proof. It was preserved, the authentic AIR supplied, and the successful
retry ran fresh. That failed attempt is excluded from the table. Security remains
a128-bit target under documented assumptions, not a whole-protocol certificate.
