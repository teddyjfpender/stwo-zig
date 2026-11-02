# Actual V3 block: bounded native128 assumption review

This is a new numerical instantiation for block24,628,607's **26,894,777-step V3 guest,7CPU plus11truth proofs**. It does not reuse the older25CPU/5truth result. The complete block and an independent fresh receiver accept; the reproducible evidence is `vectors/reports/rv64-v3-gkr-full-block-20261102/`. Functional acceptance does not prove the security assumptions below.

The explicit `--v3-source-bounds` mode in `vectors/reports/rv64-composed-security-20261102/model.py` pins that18-proof roster, geometry and source bounds. The old V2 exact/subset assertions remain unchanged. Reproduce from the repository root:

```
python3 vectors/reports/rv64-composed-security-20261102/model.py \
  vectors/reports/rv64-v3-gkr-full-block-20261102/bundle.json \
  vectors/reports/rv64-v3-gkr-full-block-20261102/fresh-receiver.json \
  /tmp/V3security-model.json \
  --v3-source-bounds vectors/reports/rv64-v3-gkr-full-block-20261102/candidate-source-bounds.json
```

The construction is OM31/raw-mod Blake,β2,q256,P0,fold4. The maximum point probability is exactly bounded by `mu=3^8/2^256`, rather than uniform1/p^8. First-word FRI rate is1/4; quotient-only original-coordinate extraction uses the conservative enlarged rate17/64. Analysis agreement41/64 and distance23/64 remain strictly inside unique decoding, with `2*agreement−1>17/64` for descent to the small polynomial spaces. The prior written single-word16-sibling unique-FRI/DEEP/OODS correspondence applies to the source-validated degree≤5/mask≤5 shapes; it remains an independently auditable proof outline, not a formal certificate.

| Actual source quantity | Bound used |
|---|---:|
| Native proof count / CPU local-GKR scopes |18 /7|
| Maximum committed columns / constraints / trace rows |7,444 /7,751 /2^22|
| Maximum local instances / GKR variables |36 /26|
| Local relation namespaces |10 in all7 byte-paired CPU scopes|
| Joint cleared lookup degree, all actual scopes |1,482,915,616|
| Extra conservative physical-pole allowance |1,482,915,616|
| Cubic GKR sumcheck degree weight |245,700|
| GKR instance/layer mixing / late eta weights |6,916 /252|
| OODS / DEEP / unique-curve FRI weights |89,920,509,050,880 /11,240,063,631,360 /36,238,786,560|

The GKR envelope permits36instances with26variables per CPU, hence at most325sumcheck rounds per instance across layers; every such round has degree3. It does not misreport these maxima as measured exact transcript operations. The conservative actual-roster transcript-operation envelope is33,403; the previously derived all-cap ten-namespace envelope is2,749,952<2^22. The model retainsR=2^22.

Table policies are checked explicitly. Three Keccak truths use magic policy word`1770517=(27<<16)|(4<<8)|21`, meaning **throughput_r27_v1**,27rows/pair, quartet clearing/degree5, chi tablelog21 and xor5 tablelog16. That magic word is not a table log. The last Keccak truth uses legacy word0,29rows/pair,triple clearing/degree4,chi log13/xor5 log10. Every active pair fits its declared rows. All five secp proofs have `logs[1]=0`: they are **row_v1 exact carried-byte RCB equations, degree4**. SHA uses Boolean/round/feed-forward degree3; arith256 uses exact carried16-bit coefficient equations, degree3. None uses the old random62-degree secp product compression, so the model does not charge62times every non-Keccak row or silently treat SHA/arith as old secp providers. Local BYTE memberships and all padded Wire denominators come from the actual source-derived report.

All ordinary unit positive/negative and consumer masses are checked below p, including weighted JUMPDEST's separate unit-consumer/support partition. Source signed KIO bounds need not be equal: they are conservative upper bounds, while independently verified physical claims must close exactly. The extra pole term is retained even if some core inverse authorities reject poles: the V3 cumulative-only classic constraints must not be given an unproved zero-pole exemption.

Let E be the sum of the listed degree weights times mu, plus `18*(41/64)^256`. There are18native PCS,7local-GKR and1shared-manifest scopes. Keeping the conservative BCS hash term separately per scope, plus identity hashing, gives

`eps_native(T) <= (T+2^22)*E +79*(T^2+1)/2^256`.

The exact-rational model gives query-union error2^-160.2968 and algebraic-union error2^-196.7961. Bounding both ends of the work interval proves **success per total adversarial RO query below2^-129.6925 uniformly for1<=T<=2^120**, under the stated assumptions. This is not a2^-128 total failure-probability claim for a2^120-query attacker. It is not an unrestricted literal128-bit work-factor theorem near2^128 queries, where the256-bit hash reduction's exact constants are insufficient.

The remaining assumptions are explicit: valid source integer/canonical/range-inheritance semantics and characteristic arguments; nonzero cleared rational identities including the weighted facts; applicability of the unique decoding FRI/DEEP/OODS correspondence to these actual source authorities; the adaptive multi-scope BCS/Fiat–Shamir reduction and ideal raw-Blake/SHA hash model. The new V3 roster is now numerically reviewed within those assumptions. Independent security audit and a formal whole-protocol certificate remain incomplete. Outer recursion is excluded and needs its own field/profile/error and statement-closure analysis. All production reports must continue to distinguish `security_qualified=false` from this bounded native128-target review.
