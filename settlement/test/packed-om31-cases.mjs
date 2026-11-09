import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
const P = (1n << 31n) - 1n;
const zero = () => Array(8).fill(0n);
const mod = (x) => ((x % P) + P) % P;
const encode = (a) => {
  const b = Buffer.alloc(32);
  a.forEach((v, i) => b.writeUInt32LE(Number(v), 4 * i));
  return b;
};
const packed = (a) => "0x" + encode(a).reverse().toString("hex");
// Formal basis reduction independent of the Solidity Karatsuba implementation.
export function product(a, b) {
  const out = zero();
  function term(i, u, v, x) {
    if (v >= 2) term(i, u + 1, v - 2, x);
    else if (u >= 2) {
      term(i, u - 2, v, 2n * x);
      term(i + 1, u - 2, v, x);
    } else if (i >= 2) term(i - 2, u, v, -x);
    else out[i + 2 * u + 4 * v] += x;
  }
  a.forEach((x, i) =>
    b.forEach((y, j) =>
      term(
        (i & 1) + (j & 1),
        ((i >> 1) & 1) + ((j >> 1) & 1),
        (i >> 2) + (j >> 2),
        x * y,
      ),
    ),
  );
  return out.map(mod);
}
export function registerPackedOm31Tests(deploy) {
  test("packed OM31 matches formal field arithmetic and keeps multiplication scratch bounded", async () => {
    const c = await deploy("test/PackedOm31Harness.sol", "PackedOm31Harness");
    const a = [],
      b = [];
    for (let i = 0; i < 8; ++i)
      for (let j = 0; j < 8; ++j) {
        const x = zero(),
          y = zero();
        x[i] = 1n;
        y[j] = 1n;
        a.push(x);
        b.push(y);
      }
    for (const x of [0n, 1n, P - 1n, P - 2n, P / 2n])
      for (const y of [0n, 1n, P - 1n, P - 2n, P / 2n]) {
        a.push(Array(8).fill(x));
        b.push(Array(8).fill(y));
      }
    for (let k = 0; k < 64; ++k) {
      const draw = (tag) => {
        const bytes = createHash("sha256")
          .update(`packed-om31/${tag}/${k}`)
          .digest();
        return Array.from(
          { length: 8 },
          (_, i) => BigInt(bytes.readUInt32LE(4 * i)) % P,
        );
      };
      a.push(draw("a"));
      b.push(draw("b"));
    }
    // Base scalars exercise both operand orders and the zero/identity shortcuts.
    const dense = Array.from({ length: 8 }, (_, i) => P - 1n - BigInt(i));
    for (const scalar of [0n, 1n, 2n, P / 2n, P - 2n, P - 1n]) {
      const base = zero();
      base[0] = scalar;
      a.push(base, dense);
      b.push(dense, base);
    }
    const values = await c.vectors(a, b);
    a.forEach((x, i) => {
      const y = b[i];
      assert.equal(values[4 * i], packed(x));
      assert.equal(values[4 * i + 1], packed(x.map((v, j) => mod(v + y[j]))));
      assert.equal(values[4 * i + 2], packed(x.map((v, j) => mod(v - y[j]))));
      assert.equal(values[4 * i + 3], packed(product(x, y)));
    });
    for (let i = 0; i < 8; ++i) {
      const invalid = zero();
      invalid[i] = P;
      await assert.rejects(c.vectors([invalid], [zero()]), /NonCanonicalField/);
    }
    for (const x of [
      a.at(-1),
      Array(8).fill(P - 1n),
      [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n],
    ])
      assert.deepEqual(Array.from(await c.wire(encode(x))), x);
    const initial = a.at(-1),
      multiplier = b[100];
    for (const count of [0, 1, 2, 64, 256]) {
      let value = initial;
      for (let i = 0; i < count; ++i) value = product(value, multiplier);
      const [growth, result] = await c.repeated(initial, multiplier, count);
      assert.equal(growth, 0n, `temporary scratch grows at count ${count}`);
      assert.deepEqual(Array.from(result), value);
    }
    for (const scalar of [0n, 1n, 2n, P - 1n]) {
      const base = zero();
      base[0] = scalar;
      let expected = initial;
      for (let i = 0; i < 64; ++i) expected = product(expected, base);
      const [growth, result] = await c.repeated(initial, base, 64);
      assert.equal(growth, 0n);
      assert.deepEqual(Array.from(result), expected);
      const receipt = await (await c.repeated.send(initial, base, 64)).wait();
      console.log(JSON.stringify({ packedBaseScalar: String(scalar), multiplications: 64, gas: Number(receipt.gasUsed) }));
    }
    const receipt = await (await c.repeated.send(initial, multiplier, 64)).wait();
    console.log(JSON.stringify({ packedDenseMultiplications: 64, gas: Number(receipt.gasUsed) }));
  });
}
