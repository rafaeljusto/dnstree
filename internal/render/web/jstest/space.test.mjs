import { test } from "node:test";
import assert from "node:assert/strict";

import { SHAPES, sub, cross, dot, norm, mix, perspective, lookAt, multiply, project } from "../assets/scene/space.js";

const near = (got, want, eps = 1e-5) => Math.abs(got - want) < eps;
const IDENTITY = new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]);

test("a vector with no length stays one rather than turning into NaN", () => {
  assert.deepEqual(norm([0, 0, 0]), [0, 0, 0]);
  assert.ok(near(Math.hypot(...norm([3, -4, 12])), 1));
  assert.deepEqual(mix([0, 0, 0], [2, 4, 6], 0.5), [1, 2, 3]);
  assert.deepEqual(cross([1, 0, 0], [0, 1, 0]), [0, 0, 1]);
});

test("multiplying by the identity changes nothing", () => {
  const m = lookAt([3, 4, 5], [0, 0, 0], [0, 1, 0]);
  // Compared as numbers: -0 and 0 are the same place.
  const same = (a, b) => a.every((v, i) => v === b[i]);
  assert.ok(same(multiply(m, IDENTITY), m));
  assert.ok(same(multiply(IDENTITY, m), m));
});

test("the camera looks at what it is aimed at", () => {
  const eye = [4, 6, 10];
  const target = [1, -1, 2];
  const view = lookAt(eye, target, [0, 1, 0]);
  const viewProj = multiply(perspective(0.8, 16 / 9, 0.1, 500), view);

  const [x, y, w] = project(viewProj, target);
  assert.ok(near(x / w, 0) && near(y / w, 0), "the target lands in the middle of the screen");
  assert.ok(near(w, Math.hypot(...sub(eye, target)), 1e-4), "w is how far away it is");

  const behind = sub(eye, sub(target, eye));
  assert.ok(project(viewProj, behind)[2] < 0, "a point behind the camera has no place on screen");

  // What is above the target is drawn higher up the screen.
  const [, above, aw] = project(viewProj, [target[0], target[1] + 1, target[2]]);
  assert.ok(above / aw > 0);
});

test("a wider screen squeezes the picture sideways, not up and down", () => {
  const square = perspective(0.8, 1, 0.1, 500);
  const wide = perspective(0.8, 2, 0.1, 500);
  assert.ok(near(wide[0], square[0] / 2));
  assert.equal(wide[5], square[5]);
});

/* ── shapes ────────────────────────────────────────────────────────────── */

// Each vertex is a position, a normal and a barycentric, nine floats.
const triangles = (data) => {
  const out = [];
  for (let t = 0; t < data.length; t += 27) {
    out.push([0, 1, 2].map((k) => {
      const at = t + k * 9;
      return { p: [...data.slice(at, at + 3)], n: [...data.slice(at + 3, at + 6)], bary: [...data.slice(at + 6, at + 9)] };
    }));
  }
  return out;
};

test("every shape is whole triangles of real numbers", () => {
  const want = { ico: 20, sphere: 80, octa: 8, tetra: 4, cube: 12, torus: 20 * 8 * 2, ring: 56 * 3 * 2 };
  for (const [name, data] of Object.entries(SHAPES)) {
    assert.equal(data.length % 27, 0, name);
    assert.equal(data.length / 27, want[name], name);
    assert.ok(data.every(Number.isFinite), `${name} has a NaN in it`);
  }
});

test("a face's normal is a unit, square to the face", () => {
  for (const [name, data] of Object.entries(SHAPES)) {
    for (const [a, b, c] of triangles(data)) {
      assert.ok(near(Math.hypot(...a.n), 1), name);
      const face = norm(cross(sub(b.p, a.p), sub(c.p, a.p)));
      assert.ok(near(Math.abs(dot(face, a.n)), 1, 1e-4), name);
    }
  }
});

test("the convex shapes are lit from outside", () => {
  for (const name of ["ico", "sphere", "octa", "tetra", "cube"]) {
    for (const [a, b, c] of triangles(SHAPES[name])) {
      const centre = [0, 1, 2].map((i) => (a.p[i] + b.p[i] + c.p[i]) / 3);
      assert.ok(dot(a.n, centre) > 0, name);
    }
  }
});

test("the sphere is round, and the solids fit the same size", () => {
  for (const [a] of triangles(SHAPES.sphere)) assert.ok(near(Math.hypot(...a.p), 1), "on the unit sphere");
  for (const name of ["ico", "octa", "tetra"]) {
    for (const [a] of triangles(SHAPES[name])) assert.ok(near(Math.hypot(...a.p), 1), name);
  }
});

// A corner's own barycentric coordinate is 1; the other two say whether the
// edge opposite each is drawn (0) or is a diagonal inside a face (1).
test("a cube is outlined four edges a face, not five", () => {
  let drawn = 0;
  for (const tri of triangles(SHAPES.cube)) {
    tri.forEach((v, k) => assert.equal(v.bary[k], 1));
    // The edge opposite corner k is drawn when some other corner has 0 there.
    for (let k = 0; k < 3; k++) if (tri.some((v, j) => j !== k && v.bary[k] === 0)) drawn++;
  }
  assert.equal(drawn, 6 * 4);
});

test("a triangle's three edges are all drawn", () => {
  for (const name of ["ico", "sphere", "octa", "tetra"]) {
    for (const tri of triangles(SHAPES[name])) {
      assert.deepEqual(tri.map((v) => v.bary), [[1, 0, 0], [0, 1, 0], [0, 0, 1]], name);
    }
  }
});
