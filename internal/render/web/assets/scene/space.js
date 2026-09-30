// The sums the scene is drawn with: vectors, the camera's matrices, and the
// shapes a hop can take. Nothing here touches the page.

/* ── matrices ──────────────────────────────────────────────────────────── */

export const sub = (a, b) => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
export const add = (a, b) => [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
export const scale = (a, s) => [a[0] * s, a[1] * s, a[2] * s];
export const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
export const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
export const norm = (a) => scale(a, 1 / (Math.hypot(...a) || 1));
export const mix = (a, b, k) => add(a, scale(sub(b, a), k));

export function perspective(fovy, aspect, near, far) {
  const f = 1 / Math.tan(fovy / 2);
  const nf = 1 / (near - far);
  return new Float32Array([f / aspect, 0, 0, 0, 0, f, 0, 0, 0, 0, (far + near) * nf, -1, 0, 0, 2 * far * near * nf, 0]);
}

export function lookAt(eye, center, up) {
  const z = norm(sub(eye, center));
  const x = norm(cross(up, z));
  const y = cross(z, x);
  return new Float32Array([
    x[0], y[0], z[0], 0, x[1], y[1], z[1], 0, x[2], y[2], z[2], 0,
    -dot(x, eye), -dot(y, eye), -dot(z, eye), 1,
  ]);
}

export function multiply(a, b) {
  const out = new Float32Array(16);
  for (let col = 0; col < 4; col++) {
    for (let row = 0; row < 4; row++) {
      let sum = 0;
      for (let k = 0; k < 4; k++) sum += a[row + 4 * k] * b[k + 4 * col];
      out[row + 4 * col] = sum;
    }
  }
  return out;
}

// A point in clip space as [x, y, w]: z is never read.
export const project = (m, p) => [
  m[0] * p[0] + m[4] * p[1] + m[8] * p[2] + m[12],
  m[1] * p[0] + m[5] * p[1] + m[9] * p[2] + m[13],
  m[3] * p[0] + m[7] * p[1] + m[11] * p[2] + m[15],
];

/* ── shapes ────────────────────────────────────────────────────────────── */

// Every shape is a list of faces, each drawn with its own normal and with
// barycentric coordinates the fragment shader turns into its outline. The
// diagonals a polygon is cut into triangles along are marked as inside, so a
// cube is drawn with four edges a face rather than five.
export function solid(verts, faces) {
  const out = [];
  for (const face of faces) {
    const p = face.map((i) => verts[i]);
    const centre = scale(p.reduce(add, [0, 0, 0]), 1 / p.length);
    let n = norm(cross(sub(p[1], p[0]), sub(p[2], p[0])));
    if (dot(n, centre) < 0) n = scale(n, -1);
    for (let i = 1; i < p.length - 1; i++) {
      const hideY = i + 1 !== p.length - 1 ? 1 : 0;
      const hideZ = i !== 1 ? 1 : 0;
      const bary = [[1, hideY, hideZ], [0, 1, hideZ], [0, hideY, 1]];
      [p[0], p[i], p[i + 1]].forEach((v, k) => out.push(...v, ...n, ...bary[k]));
    }
  }
  return new Float32Array(out);
}

const PHI = (1 + Math.sqrt(5)) / 2;
const ICO_VERTS = [
  [-1, PHI, 0], [1, PHI, 0], [-1, -PHI, 0], [1, -PHI, 0],
  [0, -1, PHI], [0, 1, PHI], [0, -1, -PHI], [0, 1, -PHI],
  [PHI, 0, -1], [PHI, 0, 1], [-PHI, 0, -1], [-PHI, 0, 1],
].map(norm);
const ICO_FACES = [
  [0, 11, 5], [0, 5, 1], [0, 1, 7], [0, 7, 10], [0, 10, 11], [1, 5, 9], [5, 11, 4], [11, 10, 2], [10, 7, 6], [7, 1, 8],
  [3, 9, 4], [3, 4, 2], [3, 2, 6], [3, 6, 8], [3, 8, 9], [4, 9, 5], [2, 4, 11], [6, 2, 10], [8, 6, 7], [9, 8, 1],
];

function geodesic() {
  const verts = [...ICO_VERTS];
  const cache = new Map();
  const middle = (a, b) => {
    const key = a < b ? `${a}:${b}` : `${b}:${a}`;
    if (!cache.has(key)) cache.set(key, verts.push(norm(scale(add(verts[a], verts[b]), 0.5)) ) - 1);
    return cache.get(key);
  };
  const faces = ICO_FACES.flatMap(([a, b, c]) => {
    const ab = middle(a, b), bc = middle(b, c), ca = middle(c, a);
    return [[a, ab, ca], [b, bc, ab], [c, ca, bc], [ab, bc, ca]];
  });
  return solid(verts, faces);
}

function torus(major, minor, segments, sides) {
  const verts = [];
  const faces = [];
  for (let i = 0; i < segments; i++) {
    const u = (i / segments) * Math.PI * 2;
    for (let j = 0; j < sides; j++) {
      const v = (j / sides) * Math.PI * 2;
      const r = major + minor * Math.cos(v);
      verts.push([r * Math.cos(u), minor * Math.sin(v), r * Math.sin(u)]);
    }
  }
  const at = (i, j) => (i % segments) * sides + (j % sides);
  for (let i = 0; i < segments; i++) {
    for (let j = 0; j < sides; j++) faces.push([at(i, j), at(i + 1, j), at(i + 1, j + 1), at(i, j + 1)]);
  }
  // A torus is not convex, so the outward test in solid() is wrong for half of
  // it; the shader lights both sides alike, which makes that harmless.
  return solid(verts, faces);
}

export const SHAPES = {
  ico: solid(ICO_VERTS, ICO_FACES),
  sphere: geodesic(),
  octa: solid(
    [[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]],
    [[0, 2, 4], [0, 4, 3], [0, 3, 5], [0, 5, 2], [1, 4, 2], [1, 3, 4], [1, 5, 3], [1, 2, 5]],
  ),
  tetra: solid(
    [[1, 1, 1], [1, -1, -1], [-1, 1, -1], [-1, -1, 1]].map(norm),
    [[0, 1, 2], [0, 3, 1], [0, 2, 3], [1, 3, 2]],
  ),
  cube: solid(
    [[-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1], [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1]].map((v) => scale(v, 0.62)),
    [[0, 3, 2, 1], [4, 5, 6, 7], [0, 1, 5, 4], [2, 3, 7, 6], [1, 2, 6, 5], [0, 4, 7, 3]],
  ),
  torus: torus(0.8, 0.28, 20, 8),
  ring: torus(1, 0.025, 56, 3),
};
