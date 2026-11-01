# Derived BINARY payload encoding

Encoding v3 commits 29 MAIN columns: active, three opcode selectors, eight
A bytes, eight B bytes, eight AND bytes, and one fact multiplicity. INTER stays
24 columns. The thirteen FUNCTION coordinates are derived at every native,
packed, OODS and external-circuit evaluation; there is no committed payload copy.

For byte positions `i`, `T_i` is the authenticated byte-AND result. Selectors
`S_and`, `S_or`, `S_xor` give

```
op = 16*active + S_or + 2*S_xor
A_j = a_(2j) + 256*a_(2j+1)
B_j = b_(2j) + 256*b_(2j+1)
c_i = S_and*T_i + S_or*(a_i+b_i-T_i) + S_xor*(a_i+b_i-2*T_i)
C_j = c_(2j) + 256*c_(2j+1)
```

`derivePayloadFor` is the shared expression authority. The 42-equation logical
row diagnostic retains its thirteen payload equalities. The physical evaluator
omits those substitution identities and emits 29 local equations plus eight
lookup/prefix equations, for 37 residuals. The selector and padding equations
are shared by both evaluators.

AND-table membership authenticates A, B and AND bytes separately. Boolean
selectors with sum=active establish exactly one operation on an active row and
zero selectors on padding. Thus every derived result limb is canonical; no new
range-inheritance assumption is introduced. Every physical row still emits eight
AND requests, including padding, and the admitted mass bounds are unchanged.

FUNCTION13 has quadratic coordinates because C uses selector times byte. Its
inverse MUST remain a strict single inverse: `inverse*D_function-1` has degree
three. Pairing it with an AND denominator would exceed the native 2n degree
budget. The four existing linear AND pairs, one FUNCTION inverse and one cyclic
prefix retain their previous physical representation and closure obligations.

Native advice keeps its narrow 46-byte metadata record after MAIN retirement.
The constructor validates each fact's opcode and integer result before filling
MAIN; metadata is not a second committed authority. The complete proof must close
FUNCTION against CPU/JALR consumers and AND against the canonical provider.
An independently valid BINARY component is not an execution certificate.

Changing MAIN and residual count intentionally changes the transcript. The v3
encoding identity binds main29/inter24/residuals37 and is mixed by the ordinary
Word16 protocol. Old proof bytes are controls for old layouts, not parity
fixtures for v3. Qualification compares complete statements and fresh verification.
